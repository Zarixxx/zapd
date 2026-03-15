#include "zapd.h"
#include <netinet/udp.h>
#include <netinet/ip.h>

/*
 * ZapD — Port Scanner Module
 * Author: Zarixxx (github.com/Zarixxx/zapd)
 *
 * MODES:
 *   TCP Connect Scan  — Full 3-way handshake. Reliable but visible in logs.
 *   UDP Scan          — Sends empty UDP datagram. Open = no response or data.
 *                       Closed = ICMP port unreachable. Filtered = nothing.
 *
 * FIREWALL DETECTION:
 *   A port is "filtered" when it doesn't respond at all within timeout,
 *   neither accepting (open) nor refusing (closed/RST). This usually means
 *   a firewall is silently dropping packets to that port.
 *
 * TIMING:
 *   -T1  Paranoid   — 1 thread,  5.0s timeout. Extremely slow, minimal noise.
 *   -T2  Sneaky     — 10 threads, 3.0s timeout. Slow, low noise.
 *   -T3  Normal     — 100 threads, 1.5s timeout. Default balanced mode.
 *   -T4  Aggressive — 300 threads, 0.8s timeout. Fast, more noise.
 *   -T5  Insane     — 500 threads, 0.3s timeout. Very fast, may miss ports.
 *
 * PORT RANDOMIZATION (-r):
 *   Shuffles the port list before scanning using Fisher-Yates algorithm.
 *   Avoids sequential patterns that some IDS systems flag.
 */

static PortResult     *g_results;
static ScanWork       *g_work;
static int             g_total;
static int             g_done;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ── TCP connect scan ─────────────────────────────────────────────────── */
int scan_port(const char *ip, int port, double timeout_s, char *banner_out) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return 0;

    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(sockfd, &wset);

    struct timeval tv;
    tv.tv_sec  = (int)timeout_s;
    tv.tv_usec = (int)((timeout_s - (int)timeout_s) * 1000000);

    int ready = select(sockfd + 1, NULL, &wset, NULL, &tv);
    if (ready <= 0) { close(sockfd); return PORT_FILTERED; }

    int err = 0;
    socklen_t elen = sizeof(err);
    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &elen);
    if (err != 0) { close(sockfd); return PORT_CLOSED; }

    /* Banner grab */
    if (banner_out) {
        banner_out[0] = '\0';
        if (port == 80 || port == 8080 || port == 8000) {
            char req[128];
            snprintf(req, sizeof(req),
                     "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", ip);
            send(sockfd, req, strlen(req), 0);
        }
        struct timeval btv = {2, 0};
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &btv, sizeof(btv));
        char buf[256] = {0};
        int n = recv(sockfd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            char *nl = strpbrk(buf, "\r\n");
            if (nl) *nl = '\0';
            strncpy(banner_out, buf, 126);
            banner_out[126] = '\0';
        }
    }

    close(sockfd);
    return PORT_OPEN;
}

/* ── UDP scan ─────────────────────────────────────────────────────────── */
/*
 * UDP scan works by sending an empty datagram to the target port.
 *   - If we get an ICMP "port unreachable" back → port is CLOSED.
 *   - If we get a UDP response → port is OPEN.
 *   - If we get nothing within timeout → port is OPEN|FILTERED
 *     (firewall may be dropping packets, or service doesn't respond to empty packets).
 *
 * Note: requires root/CAP_NET_RAW to receive ICMP responses.
 */
static int scan_port_udp(const char *ip, int port, double timeout_s) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return PORT_FILTERED;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    struct timeval tv;
    tv.tv_sec  = (int)timeout_s;
    tv.tv_usec = (int)((timeout_s - (int)timeout_s) * 1000000);
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Send empty UDP datagram */
    sendto(sockfd, "", 1, 0, (struct sockaddr *)&addr, sizeof(addr));

    /* Try to receive response */
    char buf[256];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    int n = recvfrom(sockfd, buf, sizeof(buf), 0,
                     (struct sockaddr *)&from, &fromlen);

    close(sockfd);

    if (n > 0) return PORT_OPEN;       /* Got UDP response → open */
    if (errno == ECONNREFUSED)         /* ICMP port unreachable → closed */
        return PORT_CLOSED;
    return PORT_FILTERED;              /* No response → open|filtered */
}

/* ── Fisher-Yates shuffle for port randomization ──────────────────────── */
/*
 * Randomizes the order of ports before scanning.
 * This avoids sequential port patterns (1,2,3,4...) that some
 * intrusion detection systems use as a signature to identify scans.
 */
static void shuffle_ports(int *ports, int count) {
    srand((unsigned int)time(NULL));
    for (int i = count - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = ports[i];
        ports[i] = ports[j];
        ports[j] = tmp;
    }
}

/* ── Timing presets ───────────────────────────────────────────────────── */
typedef struct { int threads; double timeout; const char *name; } Timing;

static Timing get_timing(int t) {
    switch (t) {
        case 1:  return (Timing){1,   5.0, "Paranoid"};
        case 2:  return (Timing){10,  3.0, "Sneaky"};
        case 3:  return (Timing){100, 1.5, "Normal"};
        case 4:  return (Timing){300, 0.8, "Aggressive"};
        case 5:  return (Timing){500, 0.3, "Insane"};
        default: return (Timing){100, 1.5, "Normal"};
    }
}

/* ── Worker thread ────────────────────────────────────────────────────── */
static void *scan_worker(void *arg) {
    ScanWork *work = (ScanWork *)arg;
    double t0 = get_time_ms();
    char banner[128] = {0};
    int state;

    if (work->udp_mode)
        state = scan_port_udp(work->ip, work->port, work->timeout);
    else
        state = scan_port(work->ip, work->port, work->timeout,
                          work->grab_banner ? banner : NULL);

    double latency = get_time_ms() - t0;

    work->result->port       = work->port;
    work->result->state      = state;
    work->result->latency_ms = latency;
    if (work->grab_banner) {
        strncpy(work->result->banner, banner, 126);
        work->result->banner[126] = '\0';
    }

    pthread_mutex_lock(&g_mutex);
    g_done++;
    progress_bar(g_done, g_total);
    pthread_mutex_unlock(&g_mutex);
    return NULL;
}

static int compare_port(const void *a, const void *b) {
    return ((PortResult*)a)->port - ((PortResult*)b)->port;
}

static const char *state_str(int state) {
    switch (state) {
        case PORT_OPEN:     return "open";
        case PORT_CLOSED:   return "closed";
        case PORT_FILTERED: return "filtered";
        default:            return "unknown";
    }
}

static const char *state_color(int state) {
    switch (state) {
        case PORT_OPEN:     return GREEN;
        case PORT_CLOSED:   return GRAY;
        case PORT_FILTERED: return YELLOW;
        default:            return GRAY;
    }
}

/* ── Main scan command ────────────────────────────────────────────────── */
int cmd_scan(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, RED "  [!] Usage: zapd scan <target> [options]\n\n" RESET);
        fprintf(stderr, WHITE "  Options:\n" RESET);
        fprintf(stderr, GRAY
            "    -p <ports>     Port range (e.g. 1-1024, 22,80,443)\n"
            "    -T <1-5>       Timing: 1=Paranoid 2=Sneaky 3=Normal 4=Aggressive 5=Insane\n"
            "    -t <n>         Override thread count manually\n"
            "    --timeout <s>  Override timeout manually (seconds)\n"
            "    -u             UDP scan instead of TCP\n"
            "    -r             Randomize port order\n"
            "    -b             Grab service banners (TCP only)\n"
            "    -O             OS fingerprint via TTL\n"
            "    --show-closed  Also show closed and filtered ports\n"
            "    -o <file>      Save results to JSON\n"
            RESET);
        return 1;
    }

    ScanConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.target, argv[1], sizeof(cfg.target) - 1);
    cfg.threads      = -1;   /* -1 = use timing preset */
    cfg.timeout      = -1;
    cfg.grab_banner  = 0;
    cfg.os_detect    = 0;
    cfg.udp_mode     = 0;
    cfg.randomize    = 0;
    cfg.show_closed  = 0;
    int timing_level = 3;    /* Default: Normal */

    char port_str[256] = "1-1024";

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
            strncpy(port_str, argv[++i], sizeof(port_str) - 1);
        else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc)
            timing_level = atoi(argv[++i]);
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
            cfg.threads = atoi(argv[++i]);
        else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc)
            cfg.timeout = atof(argv[++i]);
        else if (strcmp(argv[i], "-u") == 0)
            cfg.udp_mode = 1;
        else if (strcmp(argv[i], "-r") == 0)
            cfg.randomize = 1;
        else if (strcmp(argv[i], "-b") == 0)
            cfg.grab_banner = 1;
        else if (strcmp(argv[i], "-O") == 0)
            cfg.os_detect = 1;
        else if (strcmp(argv[i], "--show-closed") == 0)
            cfg.show_closed = 1;
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc)
            strncpy(cfg.output, argv[++i], sizeof(cfg.output) - 1);
    }

    /* Apply timing preset, allow manual overrides */
    Timing timing = get_timing(timing_level);
    if (cfg.threads < 0) cfg.threads = timing.threads;
    if (cfg.timeout < 0) cfg.timeout = timing.timeout;
    if (cfg.threads > MAX_THREADS) cfg.threads = MAX_THREADS;
    if (cfg.threads < 1) cfg.threads = 1;

    /* Header */
    char section_title[300];
    snprintf(section_title, sizeof(section_title), "PORT SCAN — %s", cfg.target);
    print_section(section_title);

    printf(GRAY "  [*] " RESET "Resolving " WHITE "%s" RESET " ...\n", cfg.target);
    if (resolve_host(cfg.target, cfg.ip, sizeof(cfg.ip)) != 0) {
        fprintf(stderr, RED "  [!] Cannot resolve host: %s\n" RESET, cfg.target);
        return 1;
    }

    char tmp[128];
    print_info("Target IP",  cfg.ip,     WHITE);
    print_info("Hostname",   cfg.target, WHITE);
    print_info("Protocol",   cfg.udp_mode ? "UDP" : "TCP", WHITE);
    snprintf(tmp, sizeof(tmp), "%d — %s", timing_level, timing.name);
    print_info("Timing",     tmp, WHITE);
    snprintf(tmp, sizeof(tmp), "%d", cfg.threads);
    print_info("Threads",    tmp, WHITE);
    snprintf(tmp, sizeof(tmp), "%.2fs", cfg.timeout);
    print_info("Timeout",    tmp, WHITE);
    print_info("Randomized", cfg.randomize ? "yes" : "no", WHITE);
    print_info("Port range", port_str, WHITE);
    printf("\n");

    if (parse_ports(port_str, cfg.ports, &cfg.port_count) != 0 || cfg.port_count == 0) {
        fprintf(stderr, RED "  [!] Invalid port range: %s\n" RESET, port_str);
        return 1;
    }

    /* Randomize port order if requested */
    if (cfg.randomize)
        shuffle_ports(cfg.ports, cfg.port_count);

    /* Allocate */
    g_results = calloc(cfg.port_count, sizeof(PortResult));
    g_work    = calloc(cfg.port_count, sizeof(ScanWork));
    g_total   = cfg.port_count;
    g_done    = 0;

    for (int i = 0; i < cfg.port_count; i++) {
        strncpy(g_work[i].ip, cfg.ip, sizeof(g_work[i].ip) - 1);
        g_work[i].ip[sizeof(g_work[i].ip)-1] = '\0';
        g_work[i].port        = cfg.ports[i];
        g_work[i].timeout     = cfg.timeout;
        g_work[i].grab_banner = cfg.grab_banner;
        g_work[i].udp_mode    = cfg.udp_mode;
        g_work[i].result      = &g_results[i];
    }

    /* Scan */
    struct timespec ts0, ts1;
    clock_gettime(CLOCK_MONOTONIC, &ts0);

    pthread_t *threads = malloc(cfg.threads * sizeof(pthread_t));
    int next = 0;
    while (next < cfg.port_count) {
        int batch = 0;
        while (batch < cfg.threads && next < cfg.port_count) {
            pthread_create(&threads[batch], NULL, scan_worker, &g_work[next]);
            batch++; next++;
        }
        for (int i = 0; i < batch; i++)
            pthread_join(threads[i], NULL);
    }
    free(threads);

    clock_gettime(CLOCK_MONOTONIC, &ts1);
    double elapsed = (ts1.tv_sec - ts0.tv_sec) +
                     (ts1.tv_nsec - ts0.tv_nsec) / 1e9;

    printf("\n\n");
    qsort(g_results, cfg.port_count, sizeof(PortResult), compare_port);

    /* Count states */
    int open_count = 0, filtered_count = 0, closed_count = 0;
    for (int i = 0; i < cfg.port_count; i++) {
        if      (g_results[i].state == PORT_OPEN)     open_count++;
        else if (g_results[i].state == PORT_FILTERED) filtered_count++;
        else                                           closed_count++;
    }

    /* Results table */
    char title[64];
    snprintf(title, sizeof(title), "RESULTS (%d open, %d filtered, %d closed)",
             open_count, filtered_count, closed_count);
    print_section(title);

    printf("  %-16s  %-12s  %-18s  %-10s  %s\n",
           WHITE "PORT" RESET, WHITE "STATE" RESET,
           WHITE "SERVICE" RESET, WHITE "LATENCY" RESET,
           WHITE "BANNER" RESET);
    printf(GRAY "  %-16s  %-12s  %-18s  %-10s  %s\n" RESET,
           "────────────────","────────────",
           "──────────────────","──────────","──────────────────────────");

    for (int i = 0; i < cfg.port_count; i++) {
        int state = g_results[i].state;

        /* Skip closed unless --show-closed */
        if (state == PORT_CLOSED && !cfg.show_closed) continue;

        const char *svc = get_service_name(g_results[i].port);
        const char *col = state_color(state);
        const char *st  = state_str(state);
        char port_buf[16], lat_buf[16];
        snprintf(port_buf, sizeof(port_buf), "%d/%s",
                 g_results[i].port, cfg.udp_mode ? "udp" : "tcp");
        snprintf(lat_buf, sizeof(lat_buf), "%.1f ms", g_results[i].latency_ms);

        printf("  " RED "%-16s" RESET "  %s%-12s" RESET "  " WHITE "%-18s" RESET
               "  " GRAY "%-10s" RESET "  " GRAY "%s\n" RESET,
               port_buf, col, st, svc, lat_buf,
               (cfg.grab_banner && g_results[i].banner[0])
                   ? g_results[i].banner : "—");
    }

    /* OS fingerprint */
    if (cfg.os_detect) {
        print_section("OS FINGERPRINT");
        char cmd[128];
        snprintf(cmd, sizeof(cmd),
                 "ping -c 1 -W 1 %s 2>/dev/null | grep -i ttl=", cfg.ip);
        FILE *fp = popen(cmd, "r");
        if (fp) {
            char line[256] = {0};
            if (fgets(line, sizeof(line), fp)) {
                char *ttl_pos = strcasestr(line, "ttl=");
                if (ttl_pos) {
                    int ttl = atoi(ttl_pos + 4);
                    const char *os = ttl <= 64  ? "Linux / Unix" :
                                     ttl <= 128 ? "Windows" :
                                                  "Cisco / Network device";
                    printf(GRAY "  [*] " RESET "TTL=%d → " WHITE "%s\n" RESET, ttl, os);
                }
            }
            pclose(fp);
        }
    }

    /* Summary */
    print_section("SUMMARY");
    snprintf(tmp, sizeof(tmp), "%s (%s)", cfg.ip, cfg.target);
    print_info("Host",          tmp,                   WHITE);
    snprintf(tmp, sizeof(tmp), "%d", open_count);
    print_info("Open",          tmp,                   open_count > 0 ? GREEN : GRAY);
    snprintf(tmp, sizeof(tmp), "%d", filtered_count);
    print_info("Filtered",      tmp,                   filtered_count > 0 ? YELLOW : GRAY);
    snprintf(tmp, sizeof(tmp), "%d", closed_count);
    print_info("Closed",        tmp,                   GRAY);
    snprintf(tmp, sizeof(tmp), "%d", cfg.port_count);
    print_info("Total scanned", tmp,                   WHITE);
    snprintf(tmp, sizeof(tmp), "%.2fs", elapsed);
    print_info("Duration",      tmp,                   WHITE);
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", tm_info);
    print_info("Scan date",     tmp,                   GRAY);

    /* JSON output */
    if (cfg.output[0]) {
        FILE *f = fopen(cfg.output, "w");
        if (f) {
            fprintf(f, "{\n"
                    "  \"target\": \"%s\",\n"
                    "  \"ip\": \"%s\",\n"
                    "  \"protocol\": \"%s\",\n"
                    "  \"ports_scanned\": %d,\n"
                    "  \"results\": [\n",
                    cfg.target, cfg.ip,
                    cfg.udp_mode ? "udp" : "tcp",
                    cfg.port_count);
            int first = 1;
            for (int i = 0; i < cfg.port_count; i++) {
                if (g_results[i].state == PORT_CLOSED && !cfg.show_closed)
                    continue;
                if (!first) fprintf(f, ",\n");
                fprintf(f,
                    "    {\"port\": %d, \"state\": \"%s\", "
                    "\"service\": \"%s\", \"latency_ms\": %.1f}",
                    g_results[i].port,
                    state_str(g_results[i].state),
                    get_service_name(g_results[i].port),
                    g_results[i].latency_ms);
                first = 0;
            }
            fprintf(f, "\n  ],\n  \"duration_s\": %.2f\n}\n", elapsed);
            fclose(f);
            printf(GREEN "\n  [+] Results saved to %s\n" RESET, cfg.output);
        }
    }

    free(g_results);
    free(g_work);
    printf("\n");
    return 0;
}
