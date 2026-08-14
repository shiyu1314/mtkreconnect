#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <stdbool.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <uci.h>

#define RTPRIV_IOCTL_SET (SIOCIWFIRSTPRIV + 0x02)
#define MAX_STA 4
#define RECONNECT_COOLDOWN 45
#define MAX_BACKOFF_SHIFT 4
#define TICK_INTERVAL 5
#define RECONNECT_JITTER 5
/* 连续多少个 tick(每 tick 5s) 判为在线才确认连接。
 * MTK 驱动在 ApCliEnable=1 后约 15-30s 内会短暂上报目标 BSSID 与
 * 残留速率，造成假连接；确认窗口须覆盖该时段(留余量取 40s)，
 * 防止假连接把 fail_count 与退避 next_try 清零后立刻重试。 */
#define CONNECT_CONFIRM_TICKS 8

typedef struct {
    char ifname[IFNAMSIZ];
    char parent[IFNAMSIZ];
    char ssid[64];
    char key[64];
    char auth[32];
    char enc[32];
    time_t next_try;
    int fail_count;
    int disconn_streak;
    int connected_streak;
    int last_connected;   /* 0 断连, 1 在线，用于状态转换日志 */
} StaInterface;

static volatile sig_atomic_t g_reload;
static volatile sig_atomic_t g_stop;

static void handle_hup(int sig) { (void)sig; g_reload = 1; }
static void handle_term(int sig) { (void)sig; g_stop = 1; }

static void install_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_term;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sa.sa_handler = handle_hup;
    sigaction(SIGHUP, &sa, NULL);
    /* 守护进程写日志时若管道断裂会收到 SIGPIPE，忽略之以免被误杀 */
    signal(SIGPIPE, SIG_IGN);
}

/* 带边界的安全拷贝：始终以 '\0' 结尾，超长截断（snprintf 语义，规避 strncpy 不补 '\0' 的坑） */
static void safe_copy(char *dst, size_t dst_size, const char *src) {
    if (dst_size > 0)
        snprintf(dst, dst_size, "%s", src);
}

/* 单调时钟秒数：不受系统时间跳变(NTP/手动改时)影响，用于重连退避计时 */
static time_t mono_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

static int set_if_up(int sock, const char *ifname) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) return -1;
    if (!(ifr.ifr_flags & IFF_UP)) {
        ifr.ifr_flags |= IFF_UP;
        return ioctl(sock, SIOCSIFFLAGS, &ifr);
    }
    return 0;
}

static int mtk_ioctl_set(int sock, const char *ifname, const char *fmt, ...) {
    struct iwreq wrq;
    char buffer[256];
    va_list args;
    int ret;

    va_start(args, fmt);
    int len = vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    if (len < 0 || (size_t)len >= sizeof(buffer)) {
        printf("[MTK-WiFi] ioctl command too long for %s, skipping\n", ifname);
        return -1;
    }

    memset(&wrq, 0, sizeof(wrq));
    snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", ifname);
    wrq.u.data.pointer = buffer;
    wrq.u.data.length = strlen(buffer);
    wrq.u.data.flags = 0;

    ret = ioctl(sock, RTPRIV_IOCTL_SET, &wrq);
    if (ret < 0) {
        /* 对包含明文密钥的命令脱敏，避免密码泄漏进 syslog */
        if (strncmp(buffer, "ApCliWPAPSK=", 12) == 0)
            printf("[MTK-WiFi] ioctl \"ApCliWPAPSK=***\" on %s failed: %s\n", ifname, strerror(errno));
        else
            printf("[MTK-WiFi] ioctl \"%s\" on %s failed: %s\n", buffer, ifname, strerror(errno));
    }
    return ret;
}

static bool is_connected(int sock, const char *ifname) {
    struct iwreq wrq;
    memset(&wrq, 0, sizeof(wrq));
    snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", ifname);

    if (ioctl(sock, SIOCGIWAP, &wrq) < 0) return false;

    unsigned char *mac = (unsigned char *)wrq.u.ap_addr.sa_data;
    int sum = 0;
    for (int i = 0; i < 6; i++) sum += mac[i];

    if (sum == 0 || sum == 255 * 6) return false;

    /* 第二重防御：仅在驱动标记 qual 已更新时才采信，避免陈旧零值误判 */
    struct iw_statistics stats;
    memset(&stats, 0, sizeof(stats));
    memset(&wrq, 0, sizeof(wrq));
    snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", ifname);
    wrq.u.data.pointer = (char *)&stats;
    wrq.u.data.length = sizeof(stats);
    wrq.u.data.flags = 0;

    if (ioctl(sock, SIOCGIWSTATS, &wrq) >= 0) {
        if ((stats.qual.updated & IW_QUAL_QUAL_UPDATED) && stats.qual.qual == 0)
            return false;
    }

    /* 第三重探测：链路速率为零视为未建立连接；仅对驱动不支持该查询的情况放行 */
    memset(&wrq, 0, sizeof(wrq));
    snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", ifname);
    if (ioctl(sock, SIOCGIWRATE, &wrq) < 0) {
        if (errno != EOPNOTSUPP && errno != ENOTTY)
            return false;
    } else if (wrq.u.bitrate.value == 0) {
        return false;
    }

    return true;
}

static void map_encryption(const char *uci_enc, char *auth, size_t auth_size,
                           char *enc, size_t enc_size) {
    if (!uci_enc) {
        safe_copy(auth, auth_size, "WPA2PSK"); safe_copy(enc, enc_size, "AES");
        return;
    }

    /* 开放式网络：encryption 为 none/open 时无需加密，直接返回避免多余告警 */
    if (strstr(uci_enc, "none") || strstr(uci_enc, "open")) {
        safe_copy(auth, auth_size, "OPEN");
        safe_copy(enc, enc_size, "NONE");
        return;
    }

    const int sae   = strstr(uci_enc, "sae")   != NULL;
    const int wpa3  = strstr(uci_enc, "wpa3")  != NULL;
    const int psk2  = strstr(uci_enc, "psk2")  != NULL;
    const int psk   = strstr(uci_enc, "psk")   != NULL;
    const int mixed = strstr(uci_enc, "mixed") != NULL;
    const int tkip  = strstr(uci_enc, "tkip")  != NULL;
    const int aes   = strstr(uci_enc, "aes")   != NULL;
    const int ccmp  = strstr(uci_enc, "ccmp")  != NULL;

    if (sae || wpa3) {
        /* WPA3-SAE，或 WPA2/WPA3 过渡模式（sae-mixed / psk2+ccmp+sae）。
         * 必须先于 psk2 判断，否则 psk2+ccmp+sae 会被误判为纯 WPA2。 */
        safe_copy(auth, auth_size, (mixed || psk2) ? "WPA2PSKWPA3SAE" : "WPA3SAE");
        safe_copy(enc, enc_size, "AES");
    } else if (strstr(uci_enc, "owe")) {
        safe_copy(auth, auth_size, "OWE");
        safe_copy(enc, enc_size, "AES");
    } else if (psk || psk2 || ccmp) {
        /* WPA/WPA2 PSK 系：区分混合模式与纯模式，并尊重 tkip/aes 加密后缀 */
        if (mixed)
            safe_copy(auth, auth_size, "WPA1PSKWPA2PSK");
        else if (psk2 || ccmp)
            safe_copy(auth, auth_size, "WPA2PSK");
        else
            safe_copy(auth, auth_size, "WPAPSK");

        if (tkip && aes)
            safe_copy(enc, enc_size, "TKIPAES");
        else if (tkip)
            safe_copy(enc, enc_size, "TKIP");
        else if (mixed)
            safe_copy(enc, enc_size, "TKIPAES");   /* psk-mixed 默认 TKIP+AES */
        else
            safe_copy(enc, enc_size, "AES");
    } else {
        printf("[MTK-WiFi] Unsupported encryption \"%s\", falling back to OPEN\n", uci_enc);
        safe_copy(auth, auth_size, "OPEN");
        safe_copy(enc, enc_size, "NONE");
    }
}

static void resolve_parent(struct uci_context *ctx, struct uci_package *pkg,
                           const char *devname, const char *ifname, char *parent,
                           size_t parent_size) {
    /* 优先根据 wifi-device 段的 band/hwmode 推断父接口，避免对 ifname 命名的脆弱依赖 */
    struct uci_section *dsec = uci_lookup_section(ctx, pkg, devname);
    if (dsec) {
        struct uci_option *band = uci_lookup_option(ctx, dsec, "band");
        if (band && band->v.string) {
            if (strcmp(band->v.string, "5g") == 0) { safe_copy(parent, parent_size, "rax0"); return; }
            if (strcmp(band->v.string, "2g") == 0) { safe_copy(parent, parent_size, "ra0"); return; }
        }
        struct uci_option *hwmode = uci_lookup_option(ctx, dsec, "hwmode");
        if (hwmode && hwmode->v.string) {
            if (strcmp(hwmode->v.string, "11a") == 0) { safe_copy(parent, parent_size, "rax0"); return; }
            if (strcmp(hwmode->v.string, "11g") == 0 || strcmp(hwmode->v.string, "11b") == 0) {
                safe_copy(parent, parent_size, "ra0");
                return;
            }
        }
    }
    /* 回退：按 STA 接口名前缀推断（apclix* 为 5G，其余为 2.4G） */
    if (strncmp(ifname, "apclix", 6) == 0)
        safe_copy(parent, parent_size, "rax0");
    else
        safe_copy(parent, parent_size, "ra0");
    printf("[MTK-WiFi] Warning: inferring parent %s for %s from ifname; "
           "set band/hwmode or parent_iface to be explicit\n", parent, ifname);
}

static int load_sta_configs(struct uci_context *ctx, StaInterface *list) {
    struct uci_package *pkg = NULL;
    int count = 0;
    StaInterface old[MAX_STA];
    int old_count = 0;

    /* 备份旧配置的运行状态（退避/失败计数），重载后按 ifname+ssid 恢复，
     * 避免 UCI 重载（SIGHUP）把冷却与失败计数清零，导致退避被反复打断 */
    memset(old, 0, sizeof(old));
    for (int i = 0; i < MAX_STA && old_count < MAX_STA; i++) {
        if (list[i].ssid[0])
            old[old_count++] = list[i];
    }

    memset(list, 0, sizeof(StaInterface) * MAX_STA);
    if (uci_load(ctx, "wireless", &pkg) != UCI_OK) {
        printf("[MTK-WiFi] Failed to load wireless UCI config\n");
        /* 载入失败时保留旧配置与运行状态，避免 daemon 退化为 0 个 profile */
        memcpy(list, old, sizeof(old));
        return old_count;
    }

    struct uci_element *e;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);
        if (strcmp(s->type, "wifi-iface") != 0) continue;

        struct uci_option *m = uci_lookup_option(ctx, s, "mode");
        if (!m || !m->v.string || strcmp(m->v.string, "sta") != 0) continue;

        struct uci_option *dev = uci_lookup_option(ctx, s, "device");
        struct uci_option *ifn = uci_lookup_option(ctx, s, "ifname");
        struct uci_option *s_id = uci_lookup_option(ctx, s, "ssid");
        struct uci_option *key = uci_lookup_option(ctx, s, "key");
        struct uci_option *enc = uci_lookup_option(ctx, s, "encryption");

        if (dev && s_id && dev->v.string && s_id->v.string) {
            if (count >= MAX_STA) {
                printf("[MTK-WiFi] Too many STA profiles (max %d), ignoring \"%s\"\n",
                       MAX_STA, s_id->v.string);
                continue;
            }
            if (ifn && ifn->v.string) {
                snprintf(list[count].ifname, sizeof(list[count].ifname), "%s", ifn->v.string);
            } else {
                /* 按 radio 设备名末位数字推断：radio0/mt7981_0 -> 2.4G(apcli0)，radio1/mt7986_1 -> 5G(apclix0) */
                const char *devname = dev->v.string;
                size_t devlen = strlen(devname);
                char devlast = devlen ? devname[devlen - 1] : '\0';
                if (strstr(devname, "rax") || (devlast >= '1' && devlast <= '9'))
                    safe_copy(list[count].ifname, sizeof(list[count].ifname), "apclix0");
                else
                    safe_copy(list[count].ifname, sizeof(list[count].ifname), "apcli0");
            }

            struct uci_option *pif = uci_lookup_option(ctx, s, "parent_iface");
            if (pif && pif->v.string && pif->v.string[0])
                snprintf(list[count].parent, sizeof(list[count].parent), "%s", pif->v.string);
            else
                resolve_parent(ctx, pkg, dev->v.string, list[count].ifname, list[count].parent,
                               sizeof(list[count].parent));

            snprintf(list[count].ssid, sizeof(list[count].ssid), "%s", s_id->v.string);
            snprintf(list[count].key, sizeof(list[count].key), "%s", key && key->v.string ? key->v.string : "");
            map_encryption(enc ? enc->v.string : NULL,
                           list[count].auth, sizeof(list[count].auth),
                           list[count].enc, sizeof(list[count].enc));

            list[count].next_try = 0;
            list[count].fail_count = 0;
            count++;
        }
    }
    uci_unload(ctx, pkg);

    /* 恢复匹配 profile 的运行状态（ifname+ssid 相同视为同一接口） */
    for (int i = 0; i < count; i++) {
        for (int j = 0; j < old_count; j++) {
            if (strcmp(list[i].ifname, old[j].ifname) == 0 &&
                strcmp(list[i].ssid, old[j].ssid) == 0) {
                list[i].next_try = old[j].next_try;
                list[i].fail_count = old[j].fail_count;
                list[i].disconn_streak = old[j].disconn_streak;
                list[i].connected_streak = old[j].connected_streak;
                list[i].last_connected = old[j].last_connected;
                break;
            }
        }
    }
    return count;
}

/* fail_count 为已累计的失败次数(>=1)；第一次失败即退避 RECONNECT_COOLDOWN 秒 */
static time_t next_cooldown(int fail_count) {
    int shift = fail_count - 1;
    if (shift < 0) shift = 0;
    if (shift > MAX_BACKOFF_SHIFT) shift = MAX_BACKOFF_SHIFT;
    return RECONNECT_COOLDOWN * (1 << shift);
}

static void record_failure(StaInterface *iface, time_t now) {
    iface->fail_count++;
    /* 叠加小范围随机抖动，避免多接口同步重试造成并发 ioctl 突发 */
    iface->next_try = now + next_cooldown(iface->fail_count) + (rand() % RECONNECT_JITTER);
}

static void do_connect_transaction(int sock, StaInterface *iface, time_t now) {
    int failed = 0, total = 0;

    printf("[MTK-WiFi] Connecting %s -> SSID [%s] (attempt %d)\n",
           iface->ifname, iface->ssid, iface->fail_count + 1);

    /* 拉起父接口与 STA 接口；失败仅记录，由后续 ioctl 结果决定成败。
     * 注意：apcli* 虚拟接口可能尚未被驱动创建（需 ApCliEnable 激活），
     * 故拉起失败不能作为致命错误中止事务。 */
    if (set_if_up(sock, iface->parent) < 0)
        printf("[MTK-WiFi] Warning: failed to bring parent %s up\n", iface->parent);
    if (set_if_up(sock, iface->ifname) < 0)
        printf("[MTK-WiFi] Warning: failed to bring %s up (may not exist yet)\n", iface->ifname);

    if (iface->fail_count >= 1) {
        if (mtk_ioctl_set(sock, iface->ifname, "ApCliEnable=0") < 0) failed++;
        total++;
        usleep(500000);
    }

    if (mtk_ioctl_set(sock, iface->ifname, "ApCliAuthMode=%s", iface->auth) < 0) failed++;
    total++;
    if (mtk_ioctl_set(sock, iface->ifname, "ApCliEncrypType=%s", iface->enc) < 0) failed++;
    total++;
    if (strlen(iface->key) > 0) {
        if (mtk_ioctl_set(sock, iface->ifname, "ApCliWPAPSK=%s", iface->key) < 0) failed++;
        total++;
    }

    if (mtk_ioctl_set(sock, iface->ifname, "ApCliSsid=%s", iface->ssid) < 0) failed++;
    total++;

    if (mtk_ioctl_set(sock, iface->ifname, "ApCliAutoConnect=1") < 0) failed++;
    total++;
    if (mtk_ioctl_set(sock, iface->ifname, "ApCliEnable=1") < 0) failed++;
    total++;

    if (failed > 0)
        printf("[MTK-WiFi] %s: %d/%d ioctl commands failed during reconnect\n",
               iface->ifname, failed, total);

    record_failure(iface, now);
}

int main(void) {
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) return 1;

    StaInterface ifaces[MAX_STA] = {{0}};
    int count = load_sta_configs(ctx, ifaces);
    for (int i = 0; i < count; i++) {
        ifaces[i].next_try = mono_now() + i * 15; /* 启动错峰，避免并发扫描 */
        /* 打印映射后的认证配置（不含密钥明文），便于排查加密方式映射错误 */
        printf("[MTK-WiFi] Profile %s: SSID [%s] auth=%s enc=%s key=%s\n",
               ifaces[i].ifname, ifaces[i].ssid, ifaces[i].auth, ifaces[i].enc,
               ifaces[i].key[0] ? "set" : "empty");
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        uci_free_context(ctx);
        return 1;
    }
    /* 防止 socket 被 exec 的子进程意外继承 */
    fcntl(sock, F_SETFD, FD_CLOEXEC);

    install_signals();
    srand(time(NULL)); /* 为退避抖动提供种子(非加密用途) */
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("[Daemon] MTK WiFi monitor started. Active profiles: %d\n", count);

    while (!g_stop) {
        time_t now = mono_now();

        if (g_reload) {
            g_reload = 0;
            struct uci_context *newctx = uci_alloc_context();
            if (!newctx) {
                printf("[Daemon] Failed to allocate UCI context on reload, keeping old config\n");
            } else {
                uci_free_context(ctx);
                ctx = newctx;
                count = load_sta_configs(ctx, ifaces);
                printf("[Daemon] Config reloaded. Active profiles: %d\n", count);
                /* 重载后轻微错峰，兼顾 netifd 重建窗口与响应速度。
                 * 既有接口的退避节奏由 load_sta_configs 恢复，这里仅对
                 * 无待执行退避的接口重新排期，避免重载清零冷却。 */
                for (int i = 0; i < count; i++) {
                    if (now >= ifaces[i].next_try)
                        ifaces[i].next_try = now + 5 + i * 10;
                    ifaces[i].disconn_streak = 0;
                    ifaces[i].connected_streak = 0;
                }
            }
        }

        for (int i = 0; i < count; i++) {
            bool conn = is_connected(sock, ifaces[i].ifname);

            /* 状态转换日志：驱动/链路状态翻转时输出，便于诊断假连接窗口 */
            if (conn != ifaces[i].last_connected) {
                printf("[MTK-WiFi] %s: link %s\n", ifaces[i].ifname, conn ? "up" : "down");
                ifaces[i].last_connected = conn ? 1 : 0;
            }

            if (conn) {
                /* 连续多个 tick 判为在线且退避期已过，才确认连接并清空
                 * 失败计数与退避。驱动在关联后短暂上报 BSSID/速率造成假连接
                 * 时，退避期未过则不清零，避免以 "(attempt 1)" 疯狂重试 */
                if (++ifaces[i].connected_streak >= CONNECT_CONFIRM_TICKS &&
                    now >= ifaces[i].next_try) {
                    if (ifaces[i].fail_count != 0 || ifaces[i].next_try != 0)
                        printf("[MTK-WiFi] %s: link confirmed stable, retry state reset\n",
                               ifaces[i].ifname);
                    ifaces[i].next_try = 0;
                    ifaces[i].fail_count = 0;
                }
                ifaces[i].disconn_streak = 0;
            } else {
                ifaces[i].connected_streak = 0;
                /* 滞回：连续两个 tick 判为断连才动作，过滤瞬时抖动 */
                if (++ifaces[i].disconn_streak >= 2 && now >= ifaces[i].next_try) {
                    do_connect_transaction(sock, &ifaces[i], now);
                    /* 事务后清零滞回计数：next_try 已退避，避免长期断连时计数无限增长(理论上会溢出) */
                    ifaces[i].disconn_streak = 0;
                }
            }
        }
        sleep(TICK_INTERVAL);
    }

    close(sock);
    uci_free_context(ctx);
    return 0;
}
