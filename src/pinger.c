#include "zapd.h"

int cmd_ping(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, RED "  [!] Usage: zapd ping <target> [options]\n" RESET);
        fprintf(stderr, GRAY "      -c <count>     Number of packets (default: 4)\n" RESET);
        fprintf(stderr, GRAY "      --trace        Run traceroute after ping\n" RESET);
        fprintf(stderr, GRAY "      --max-hops <n> Max hops for traceroute (default: 30)\n" RESET);
        return 1;
    }

    char target[256];
    strncpy(target, argv[1], sizeof(target) - 1);
    int count    = 4;
    int do_trace = 0;
    int max_hops = 30;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc)
            count = atoi(argv[++i]);
        else if (strcmp(argv[i], "--trace") == 0)
            do_trace = 1;
        else if (strcmp(argv[i], "--max-hops") == 0 && i + 1 < argc)
            max_hops = atoi(argv[++i]);
    }

    char ip[64] = {0};
    printf(GRAY "  [*] " RESET "Resolving " WHITE "%s" RESET " ...\n", target);
    if (resolve_host(target, ip, sizeof(ip)) == 0)
        print_info("Resolved IP", ip, WHITE);
    else
        printf(YELLOW "  [~] Could not resolve, using target directly\n" RESET);

    /* Ping */
    char section_title[300];
    snprintf(section_title, sizeof(section_title), "PING — %s", target);
    print_section(section_title);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ping -c %d %s 2>&1", count, target);

    printf(GRAY "  [*] " RESET "Sending %d ICMP packets to " WHITE "%s" RESET " ...\n\n", count, target);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, RED "  [!] Failed to run ping\n" RESET);
        return 1;
    }

    char line[512];
    int  seq = 0;
    while (fgets(line, sizeof(line), fp)) {
        /* Strip newline */
        line[strcspn(line, "\n")] = '\0';
        if (!line[0]) continue;

        if (strstr(line, "bytes from") || strstr(line, "time=")) {
            /* Extract time for color */
            char *tp = strcasestr(line, "time=");
            double rtt = tp ? atof(tp + 5) : 0;
            const char *col = rtt < 50 ? GREEN : rtt < 150 ? YELLOW : RED;
            printf("  %s%s\n" RESET, col, line);
            seq++;
        } else if (strstr(line, "Request timeout") || strstr(line, "100% packet loss")) {
            printf("  " RED "%s\n" RESET, line);
        } else if (strstr(line, "statistics") || strstr(line, "packets") ||
                   strstr(line, "round-trip") || strstr(line, "rtt")) {
            printf("  " GREEN "%s\n" RESET, line);
        } else {
            printf("  " GRAY "%s\n" RESET, line);
        }
    }
    pclose(fp);

    /* Traceroute */
    if (do_trace) {
        char tr_title[300];
        snprintf(tr_title, sizeof(tr_title), "TRACEROUTE — %s (max %d hops)", target, max_hops);
        print_section(tr_title);

        printf("  %-6s  %-42s  %s\n",
               WHITE "HOP" RESET, WHITE "HOST / IP" RESET, WHITE "RTT" RESET);
        printf(GRAY "  %-6s  %-42s  %s\n" RESET,
               "──────", "──────────────────────────────────────────", "──────────");

        snprintf(cmd, sizeof(cmd), "traceroute -m %d %s 2>&1", max_hops, target);
        fp = popen(cmd, "r");
        if (!fp) {
            snprintf(cmd, sizeof(cmd), "tracepath -m %d %s 2>&1", max_hops, target);
            fp = popen(cmd, "r");
        }
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                line[strcspn(line, "\n")] = '\0';
                if (!line[0]) continue;
                if (strstr(line, "traceroute") || strstr(line, "tracepath")) continue;

                char *p = line;
                while (*p == ' ') p++;
                if (!*p) continue;

                /* Extract hop number */
                char hop[8] = "?";
                int hop_n = atoi(p);
                if (hop_n > 0) snprintf(hop, sizeof(hop), "%d", hop_n);

                /* Check for timeout */
                if (strstr(line, "* * *") || strstr(line, "!H") || strstr(line, "!N")) {
                    printf("  " RED "%-6s" RESET "  " GRAY "%-42s" RESET "  " YELLOW "timeout\n" RESET, hop, "* * *");
                    continue;
                }

                /* Extract host and rtt roughly */
                char host_part[64] = "—";
                char rtt_part[16]  = "—";

                /* Find IP in parens or plain */
                char *lp = strchr(line, '(');
                char *rp = strchr(line, ')');
                if (lp && rp && rp > lp) {
                    int len = rp - lp - 1;
                    if (len > 0 && len < 63) {
                        strncpy(host_part, lp + 1, len);
                        host_part[len] = '\0';
                    }
                } else {
                    /* Try tokens */
                    char tmp[512];
                    strncpy(tmp, line, sizeof(tmp)-1);
                    char *tok = strtok(tmp, " ");
                    int ti = 0;
                    while (tok) {
                        if (ti == 1) strncpy(host_part, tok, sizeof(host_part)-1);
                        tok = strtok(NULL, " ");
                        ti++;
                    }
                }

                /* Find ms */
                char *ms = strstr(line, " ms");
                if (ms) {
                    char *start = ms - 1;
                    while (start > line && (*start == '.' || (*start >= '0' && *start <= '9')))
                        start--;
                    start++;
                    int len = ms - start;
                    if (len > 0 && len < 15) {
                        strncpy(rtt_part, start, len);
                        rtt_part[len] = '\0';
                        strncat(rtt_part, " ms", sizeof(rtt_part) - strlen(rtt_part) - 1);
                    }
                }

                double rtt_v = atof(rtt_part);
                const char *rtt_col = rtt_v < 50 ? GREEN : rtt_v < 150 ? YELLOW : RED;

                printf("  " RED "%-6s" RESET "  " WHITE "%-42s" RESET "  %s%s\n" RESET,
                       hop, host_part, rtt_col, rtt_part);
            }
            pclose(fp);
        } else {
            printf(YELLOW "  [~] traceroute not found. Install with: sudo pacman -S traceroute\n" RESET);
        }
    }

    printf("\n");
    return 0;
}
