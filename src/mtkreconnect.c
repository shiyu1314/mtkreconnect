#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <stdbool.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <uci.h>

#define RTPRIV_IOCTL_SET (SIOCIWFIRSTPRIV + 0x02)
#define MAX_STA 4
#define RECONNECT_COOLDOWN 45
#define MAX_BACKOFF_SHIFT 4
#define TICK_INTERVAL 5

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
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    memset(&wrq, 0, sizeof(wrq));
    snprintf(wrq.ifr_name, sizeof(wrq.ifr_name), "%s", ifname);
    wrq.u.data.pointer = buffer;
    wrq.u.data.length = strlen(buffer);
    wrq.u.data.flags = 0;

    ret = ioctl(sock, RTPRIV_IOCTL_SET, &wrq);
    if (ret < 0)
        printf("[MTK-WiFi] ioctl \"%s\" on %s failed: %s\n", buffer, ifname, strerror(errno));
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
    wrq.u.data.pointer = (char *)&stats;
    wrq.u.data.length = sizeof(stats);

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

static void map_encryption(const char *uci_enc, char *auth, char *enc) {
    if (!uci_enc) {
        strcpy(auth, "WPA2PSK"); strcpy(enc, "AES");
        return;
    }
    if (strstr(uci_enc, "psk2") || strstr(uci_enc, "ccmp")) {
        strcpy(auth, "WPA2PSK"); strcpy(enc, "AES");
    } else if (strstr(uci_enc, "sae") || strstr(uci_enc, "wpa3")) {
        if (strstr(uci_enc, "mixed"))
            strcpy(auth, "WPA2PSKWPA3SAE");
        else
            strcpy(auth, "WPA3SAE");
        strcpy(enc, "AES");
    } else if (strstr(uci_enc, "psk")) {
        strcpy(auth, "WPAPSK"); strcpy(enc, "TKIP");
    } else if (strstr(uci_enc, "owe")) {
        strcpy(auth, "OWE"); strcpy(enc, "AES");
    } else {
        printf("[MTK-WiFi] Unsupported encryption \"%s\", falling back to OPEN\n", uci_enc);
        strcpy(auth, "OPEN"); strcpy(enc, "NONE");
    }
}

static int load_sta_configs(struct uci_context *ctx, StaInterface *list) {
    struct uci_package *pkg = NULL;
    int count = 0;

    memset(list, 0, sizeof(StaInterface) * MAX_STA);
    if (uci_load(ctx, "wireless", &pkg) != UCI_OK) return 0;

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

        if (dev && s_id && dev->v.string && s_id->v.string && count < MAX_STA) {
            if (ifn && ifn->v.string) {
                snprintf(list[count].ifname, sizeof(list[count].ifname), "%s", ifn->v.string);
            } else {
                /* 按 radio 设备名末位数字推断：radio0/mt7981_0 -> 2.4G(apcli0)，radio1/mt7986_1 -> 5G(apclix0) */
                const char *devname = dev->v.string;
                size_t devlen = strlen(devname);
                char devlast = devlen ? devname[devlen - 1] : '\0';
                if (strstr(devname, "rax") || (devlast >= '1' && devlast <= '9'))
                    strcpy(list[count].ifname, "apclix0");
                else
                    strcpy(list[count].ifname, "apcli0");
            }

            if (strncmp(list[count].ifname, "apclix", 6) == 0)
                strcpy(list[count].parent, "rax0");
            else
                strcpy(list[count].parent, "ra0");

            snprintf(list[count].ssid, sizeof(list[count].ssid), "%s", s_id->v.string);
            snprintf(list[count].key, sizeof(list[count].key), "%s", key && key->v.string ? key->v.string : "");
            map_encryption(enc ? enc->v.string : NULL, list[count].auth, list[count].enc);

            list[count].next_try = 0;
            list[count].fail_count = 0;
            count++;
        }
    }
    uci_unload(ctx, pkg);
    return count;
}

static time_t next_cooldown(int fail_count) {
    int shift = fail_count > MAX_BACKOFF_SHIFT ? MAX_BACKOFF_SHIFT : fail_count;
    return RECONNECT_COOLDOWN * (1 << shift);
}

static void do_connect_transaction(int sock, StaInterface *iface, time_t now) {
    printf("[MTK-WiFi] Connecting %s -> SSID [%s] (attempt %d)\n",
           iface->ifname, iface->ssid, iface->fail_count + 1);

    set_if_up(sock, iface->parent);
    set_if_up(sock, iface->ifname);

    if (iface->fail_count >= 1) {
        mtk_ioctl_set(sock, iface->ifname, "ApCliEnable=0");
        usleep(500000);
    }

    mtk_ioctl_set(sock, iface->ifname, "ApCliAuthMode=%s", iface->auth);
    mtk_ioctl_set(sock, iface->ifname, "ApCliEncrypType=%s", iface->enc);
    if (strlen(iface->key) > 0)
        mtk_ioctl_set(sock, iface->ifname, "ApCliWPAPSK=%s", iface->key);

    mtk_ioctl_set(sock, iface->ifname, "ApCliSsid=%s", iface->ssid);

    mtk_ioctl_set(sock, iface->ifname, "ApCliAutoConnect=1");
    mtk_ioctl_set(sock, iface->ifname, "ApCliEnable=1");

    iface->fail_count++;
    iface->next_try = now + next_cooldown(iface->fail_count);
}

int main(void) {
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) return 1;

    StaInterface ifaces[MAX_STA];
    int count = load_sta_configs(ctx, ifaces);
    for (int i = 0; i < count; i++)
        ifaces[i].next_try = time(NULL) + i * 15; /* 启动错峰，避免并发扫描 */

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        uci_free_context(ctx);
        return 1;
    }

    install_signals();
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("[Daemon] MTK WiFi monitor started. Active profiles: %d\n", count);

    while (!g_stop) {
        time_t now = time(NULL);

        if (g_reload) {
            g_reload = 0;
            uci_free_context(ctx);
            ctx = uci_alloc_context();
            count = ctx ? load_sta_configs(ctx, ifaces) : 0;
            printf("[Daemon] Config reloaded. Active profiles: %d\n", count);
            /* 重载后轻微错峰，兼顾 netifd 重建窗口与响应速度 */
            for (int i = 0; i < count; i++)
                ifaces[i].next_try = time(NULL) + 5 + i * 10;
        }

        for (int i = 0; i < count; i++) {
            if (is_connected(sock, ifaces[i].ifname)) {
                ifaces[i].next_try = 0;
                ifaces[i].fail_count = 0;
                ifaces[i].disconn_streak = 0;
            } else {
                /* 滞回：连续两个 tick 判为断连才动作，过滤瞬时抖动 */
                if (++ifaces[i].disconn_streak >= 2 && now >= ifaces[i].next_try)
                    do_connect_transaction(sock, &ifaces[i], now);
            }
        }
        sleep(TICK_INTERVAL);
    }

    close(sock);
    uci_free_context(ctx);
    return 0;
}
