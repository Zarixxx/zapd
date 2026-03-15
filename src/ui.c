#include "zapd.h"

void print_banner(void) {
    printf("\n");
    printf(GRAY "%-35s%s\n" RESET, "", "                                                                                    ");
    printf(GRAY "%-35s%s\n" RESET, "", "              ▒███████░                                              ░              ");
    printf(GRAY "%-35s%s\n" RESET, "", "              ▒█████▒                                                               ");
    printf(GRAY "%-35s%s\n" RESET, "", "              ▒███▓                                                                 ");
    printf(GRAY "%-35s%s\n" RESET, "", "              ▒██░                              ░          ░                        ");
    printf(GRAY "%-35s%s\n" RESET, "", "              ▒█                                ░   ░░     ░                        ");
    printf(GRAY "%-35s%s\n" RESET, "", "              ▒                ░               ░░░  ░░░    ░░                       ");
    printf(GRAY "%-35s%s\n" RESET, "", "                    ░    ░░░░░ ░░   ░░        ░░░░  ░░░   ░░░ ░░                    ");
    printf(RED "%-34s " GRAY "%s\n" RESET, "███████╣ █████╣ ██████╣ ██████╣", "                  ░░░░   ░░░░░░░ ░░ ░░░       ░░░░░░░░░  ░░░░ ░░                    ");
    printf(RED "%-34s " GRAY "%s\n" RESET, "╚══███╔╝██╔══██╣██╔══██╣██╔══██╣", "                  ░░░░  ░░      ░░░░░░░       ░░░░  ░░     ░░░░░                    ");
    printf(RED "%-34s " GRAY "%s\n" RESET, "  ███╔╝ ██████║██████╔╝██║  ██║", "                  ░░░░          ░░ ░░░░░░    ░░░░░▒████       ░                     ");
    printf(RED "%-34s " GRAY "%s\n" RESET, " ███╔╝  ██╔══██║██╔═══╝ ██║  ██║", "                  ░░  ▒██▓   ░▒░▒▒░░░░░░░   ░░░░░▒▒ ▒▓░  ░░▓▒░░                    ");
    printf(RED "%-34s " GRAY "%s\n" RESET, "███████╣██║  ██║██║     ██████╔╝", "                    ░▒░▒▒▒  ▒▒░░▓▒░░░░░░░░  ░░░░░▒▓███▒▒▓▓▓░▓▓                     ");
    printf(RED "%-34s " GRAY "%s\n" RESET, "╚══════╝╚═╝  ╚═╝╚═╝     ╚═════╝", "                  ░░▒▓░▒██▒▓█▓▒▒▒░░░░░░░░░░ ░░░░░░░░░░░▒░░ ▒▒▒                     ");
    printf("%-35s" GRAY "%s\n" RESET, "", "                  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒░▒▓▓▓▓▓██▒    ░                 ");
    printf(WHITE "%-34s " GRAY "%s\n" RESET, "Network & Threat", "                   ░░░░░░░░░░░▒░░░▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██▒░░ ░░  ░              ");
    printf(WHITE "%-34s " GRAY "%s\n" RESET, "Analysis Tool v1.1.0", "                   ░▒░░░░▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓██████████████░░░    ░░              ");
    printf("%-35s" GRAY "%s\n" RESET, "", "                    ▒▒▒▒▒▒▒▒▒▓▓▓▓▓████████▓████████████████▒▓█    ░░░              ");
    printf(GRAY "%-34s %s\n" RESET, "by Zarixxx", "                    ░▒▒▓▓▓▓▓▓█████████████▓▓██████████████▓██    ░░░░              ");
    printf(GRAY "%-34s %s\n" RESET, "github.com/Zarixxx/zapd", "                      ▒▓████████████████████████████████████    ░░░░               ");
    printf(GRAY "%-35s%s\n" RESET, "", "                     ░░░▒█████████████████████████████████░    ░░░░░ ░             ");
    printf(GRAY "%-35s%s\n" RESET, "", "                      ░░░░▒████████████▓█████▓██████████▓░     ░░░░░░▒             ");
    printf(GRAY "%-35s%s\n" RESET, "", "                    ░  ░░░░░▒▓███████████████████████▓▒▒▒     ░░░░░░▒▒             ");
    printf(GRAY "%-35s%s\n" RESET, "", "                    ░░▒░░▒░░▒▒░▒███████████████████▒▒▓▓▓░    ░░░░░░▒▒▒             ");
    printf(GRAY "%-35s%s\n" RESET, "", "               ░   ░▒░░▒▒░▒▒▒▒▒▒▒▒▒▓█████████████▒▓▓▒▒▓▓    ░░░░░░▒▒▒▒            ");
    printf(GRAY "%-35s%s\n" RESET, "", "               ░   ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒███████▒▒▒▒▓▒▒▓▓▒    ░░░░░░▒▒▒▒             ");
    printf(GRAY "%-35s%s\n" RESET, "", "               ░   ▒▒░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▓▒▒▒▒▓▓░   ░░░░░░▒▒▒▒▒             ");
    printf(GRAY "%-35s%s\n" RESET, "", "               ░   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▒▒▒▒▒▒▒▒▒▒   ░░░░░░▒▒▒▒▒▒             ");
    printf(GRAY "%-35s%s\n" RESET, "", "              ░░   ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒    ░░░░░▒▒▒▒▒▒▒             ");
    printf(RED2 "\n  ──────────────────────────────────────────────────────────────────\n" RESET);
    printf(WHITE BOLD "  Network & Threat Analysis Tool" RESET GRAY "  v%s\n" RESET, ZAPD_VERSION);
    printf(GRAY "  by %s — %s\n\n" RESET, ZAPD_AUTHOR, ZAPD_GITHUB);
}

void print_usage(void) {
    // updated below
    printf(WHITE "  Usage:\n" RESET);
    printf(GRAY  "    zapd <command> [options]\n\n" RESET);
    printf(WHITE "  Commands:\n" RESET);
    printf(RED   "    scan " RESET GRAY " <target>    " RESET WHITE "Port scanner (TCP/UDP)\n" RESET);
    printf(RED   "    vt   " RESET GRAY " <target>    " RESET WHITE "VirusTotal threat analysis\n" RESET);
    printf(RED   "    ping " RESET GRAY " <target>    " RESET WHITE "Ping & traceroute\n" RESET);
    printf(RED   "    whois" RESET GRAY " <target>    " RESET WHITE "WHOIS & DNS lookup\n" RESET);
    printf("\n");
    printf(WHITE "  Examples:\n" RESET);
    printf(GRAY  "    zapd scan 192.168.1.1\n" RESET);
    printf(GRAY  "    zapd scan 192.168.1.1 -p 1-65535 -T4\n" RESET);
    printf(GRAY  "    zapd vt https://sitio-sospechoso.com\n" RESET);
    printf(GRAY  "    zapd vt 8.8.8.8 -t ip\n" RESET);
    printf(GRAY  "    zapd ping 8.8.8.8 --trace\n" RESET);
    printf(GRAY  "    zapd whois google.com --dns\n" RESET);
    printf("\n");
    printf(GRAY  "  Tip: zapd <command> --help  para ver todas las opciones\n" RESET);
    printf("\n");
}

void print_section(const char *title) {
    printf("\n");
    printf(RED2 "  ──────────────────────────────────────────────────────\n" RESET);
    printf(RED  "  [ " RESET WHITE BOLD "%s" RESET RED " ]\n" RESET, title);
    printf(RED2 "  ──────────────────────────────────────────────────────\n" RESET);
}

void print_info(const char *label, const char *value, const char *color) {
    printf(GRAY "  %-22s" RESET, label);
    if (color) printf("%s%s" RESET "\n", color, value);
    else       printf(WHITE "%s\n" RESET, value);
}

void progress_bar(int current, int total) {
    int width = 36;
    float pct = (float)current / total;
    int filled = (int)(pct * width);
    printf("\r  " RED2 "[" RESET RED);
    for (int i = 0; i < filled; i++)  printf("█");
    printf(RESET GRAY);
    for (int i = filled; i < width; i++) printf("░");
    printf(RESET RED2 "]" RESET " %3d%%  %d/%d ports",
           (int)(pct * 100), current, total);
    fflush(stdout);
}

double get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

const char *get_service_name(int port) {
    switch (port) {
        case 21:    return "ftp";
        case 22:    return "ssh";
        case 23:    return "telnet";
        case 25:    return "smtp";
        case 53:    return "dns";
        case 80:    return "http";
        case 110:   return "pop3";
        case 111:   return "rpcbind";
        case 135:   return "msrpc";
        case 139:   return "netbios";
        case 143:   return "imap";
        case 443:   return "https";
        case 445:   return "smb";
        case 993:   return "imaps";
        case 995:   return "pop3s";
        case 1433:  return "mssql";
        case 1521:  return "oracle";
        case 3000:  return "dev-server";
        case 3306:  return "mysql";
        case 3389:  return "rdp";
        case 5432:  return "postgresql";
        case 5900:  return "vnc";
        case 6379:  return "redis";
        case 8080:  return "http-alt";
        case 8443:  return "https-alt";
        case 8888:  return "jupyter";
        case 9200:  return "elasticsearch";
        case 27017: return "mongodb";
        case 6443:  return "kubernetes";
        case 2375:  return "docker";
        case 2376:  return "docker-tls";
        default:    return "unknown";
    }
}

int resolve_host(const char *host, char *ip_out, size_t len) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) return -1;
    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ip_out, len);
    freeaddrinfo(res);
    return 0;
}

int parse_ports(const char *port_str, int *ports, int *count) {
    *count = 0;
    char buf[4096];
    strncpy(buf, port_str, sizeof(buf) - 1);
    char *token = strtok(buf, ",");
    while (token) {
        char *dash = strchr(token, '-');
        if (dash) {
            int start = atoi(token);
            int end   = atoi(dash + 1);
            if (start < 1 || end > 65535 || start > end) return -1;
            for (int p = start; p <= end && *count < MAX_PORTS; p++)
                ports[(*count)++] = p;
        } else {
            int p = atoi(token);
            if (p < 1 || p > 65535) return -1;
            ports[(*count)++] = p;
        }
        token = strtok(NULL, ",");
    }
    return 0;
}

void print_help_scan(void) {
    printf(WHITE BOLD "  zapd scan <target> [options]\n\n" RESET);
    printf(GRAY  "  Scans TCP or UDP ports on a target host.\n\n" RESET);

    printf(WHITE "  TARGET\n" RESET);
    printf(GRAY  "    Hostname or IP address (e.g. 192.168.1.1, google.com)\n\n" RESET);

    printf(WHITE "  OPTIONS\n" RESET);
    printf(RED   "    -p <ports>       " RESET WHITE "Port range to scan\n" RESET);
    printf(GRAY  "                     Examples: 1-1024  |  80,443,22  |  1-65535\n"
                 "                     Default: 1-1024\n\n" RESET);

    printf(RED   "    -T <1-5>         " RESET WHITE "Timing preset\n" RESET);
    printf(GRAY  "                     1 = Paranoid   (1 thread,   5.0s timeout) — very slow\n"
                 "                     2 = Sneaky     (10 threads, 3.0s timeout) — slow\n"
                 "                     3 = Normal     (100 threads,1.5s timeout) — default\n"
                 "                     4 = Aggressive (300 threads,0.8s timeout) — fast\n"
                 "                     5 = Insane     (500 threads,0.3s timeout) — very fast\n\n" RESET);

    printf(RED   "    -t <n>           " RESET WHITE "Override thread count manually\n" RESET);
    printf(GRAY  "                     Overrides the thread count from -T\n\n" RESET);

    printf(RED   "    --timeout <s>    " RESET WHITE "Override timeout manually (seconds)\n" RESET);
    printf(GRAY  "                     Overrides the timeout from -T. Accepts decimals (e.g. 0.5)\n\n" RESET);

    printf(RED   "    -u               " RESET WHITE "UDP scan instead of TCP\n" RESET);
    printf(GRAY  "                     Sends empty UDP datagrams. Useful for DNS (53),\n"
                 "                     SNMP (161), DHCP (67/68), NTP (123), etc.\n"
                 "                     Note: open|filtered ports show as 'filtered' if no response.\n\n" RESET);

    printf(RED   "    -r               " RESET WHITE "Randomize port order\n" RESET);
    printf(GRAY  "                     Shuffles ports before scanning (Fisher-Yates).\n"
                 "                     Avoids sequential scan patterns.\n\n" RESET);

    printf(RED   "    -b               " RESET WHITE "Banner grabbing (TCP only)\n" RESET);
    printf(GRAY  "                     Attempts to read the service banner on open ports.\n"
                 "                     Sends HTTP HEAD to web ports (80, 8080, 8000).\n\n" RESET);

    printf(RED   "    -O               " RESET WHITE "OS fingerprinting via TTL\n" RESET);
    printf(GRAY  "                     Pings the host and reads the TTL value:\n"
                 "                     TTL <= 64  → Linux / Unix\n"
                 "                     TTL <= 128 → Windows\n"
                 "                     TTL > 128  → Cisco / Network device\n\n" RESET);

    printf(RED   "    --show-closed    " RESET WHITE "Show closed and filtered ports too\n" RESET);
    printf(GRAY  "                     By default only open ports are shown.\n"
                 "                     Filtered = firewall silently dropping packets.\n"
                 "                     Closed   = host actively refusing connection (RST).\n\n" RESET);

    printf(RED   "    -o <file>        " RESET WHITE "Save results to JSON file\n" RESET);
    printf(GRAY  "                     Saves all results (port, state, service, latency).\n\n" RESET);

    printf(WHITE "  EXAMPLES\n" RESET);
    printf(GRAY  "    zapd scan 192.168.1.1\n"
                 "    zapd scan 192.168.1.1 -p 1-65535 -T4\n"
                 "    zapd scan 192.168.1.1 -p 22,80,443 -b -O\n"
                 "    zapd scan 192.168.1.1 -u -p 53,161,67\n"
                 "    zapd scan 192.168.1.1 -T2 -r --show-closed\n"
                 "    zapd scan 192.168.1.1 -p 1-1024 -T5 -b -O -o results.json\n\n" RESET);
}

void print_help_ping(void) {
    printf(WHITE BOLD "  zapd ping <target> [options]\n\n" RESET);
    printf(GRAY  "  Sends ICMP ping packets and optionally runs a traceroute.\n\n" RESET);

    printf(WHITE "  OPTIONS\n" RESET);
    printf(RED   "    -c <n>           " RESET WHITE "Number of ping packets to send\n" RESET);
    printf(GRAY  "                     Default: 4\n\n" RESET);

    printf(RED   "    --trace          " RESET WHITE "Run traceroute after ping\n" RESET);
    printf(GRAY  "                     Shows every hop (router) between you and the target.\n"
                 "                     Requires traceroute installed: sudo pacman -S traceroute\n\n" RESET);

    printf(RED   "    --max-hops <n>   " RESET WHITE "Max hops for traceroute\n" RESET);
    printf(GRAY  "                     Default: 30\n\n" RESET);

    printf(WHITE "  EXAMPLES\n" RESET);
    printf(GRAY  "    zapd ping 8.8.8.8\n"
                 "    zapd ping google.com -c 10\n"
                 "    zapd ping 8.8.8.8 --trace\n"
                 "    zapd ping google.com --trace --max-hops 20\n\n" RESET);
}

void print_help_whois(void) {
    printf(WHITE BOLD "  zapd whois <target> [options]\n\n" RESET);
    printf(GRAY  "  Queries WHOIS servers directly (TCP port 43) and fetches DNS records.\n\n" RESET);

    printf(WHITE "  OPTIONS\n" RESET);
    printf(RED   "    --dns            " RESET WHITE "Fetch full DNS records\n" RESET);
    printf(GRAY  "                     Queries A, AAAA, MX, NS, TXT, CNAME, SOA records.\n"
                 "                     Requires dig installed: sudo pacman -S bind-tools\n\n" RESET);

    printf(RED   "    -o <file>        " RESET WHITE "Save results to JSON\n\n" RESET);

    printf(WHITE "  EXAMPLES\n" RESET);
    printf(GRAY  "    zapd whois google.com\n"
                 "    zapd whois mozilla.org --dns\n"
                 "    zapd whois 8.8.8.8\n"
                 "    zapd whois example.com --dns -o whois.json\n\n" RESET);
}

void print_help_vt(void) {
    printf(WHITE BOLD "  zapd vt <target> [options]\n\n" RESET);
    printf(GRAY  "  Analyzes a URL, IP, domain or file hash using the VirusTotal API.\n"
                 "  Checks against 70+ antivirus engines in real time.\n\n" RESET);

    printf(WHITE "  SETUP (one time)\n" RESET);
    printf(GRAY  "    Get a free API key at: https://www.virustotal.com/gui/join-us\n"
                 "    Then set it permanently:\n"
                 "      echo 'export VT_API_KEY=your_key' >> ~/.zshrc && source ~/.zshrc\n\n" RESET);

    printf(WHITE "  OPTIONS\n" RESET);
    printf(RED   "    -t <type>        " RESET WHITE "Type of target\n" RESET);
    printf(GRAY  "                     url    — a full URL (default)\n"
                 "                     ip     — an IP address\n"
                 "                     domain — a domain name\n"
                 "                     hash   — MD5, SHA1 or SHA256 of a file\n\n" RESET);

    printf(RED   "    -k <key>         " RESET WHITE "VirusTotal API key\n" RESET);
    printf(GRAY  "                     Can also be set via VT_API_KEY environment variable\n\n" RESET);

    printf(RED   "    -o <file>        " RESET WHITE "Save raw JSON report to file\n\n" RESET);

    printf(WHITE "  EXAMPLES\n" RESET);
    printf(GRAY  "    zapd vt https://suspicious-site.com\n"
                 "    zapd vt 8.8.8.8 -t ip\n"
                 "    zapd vt malware.example.com -t domain\n"
                 "    zapd vt d41d8cd98f00b204e9800998ecf8427e -t hash\n"
                 "    zapd vt https://site.com -k YOUR_API_KEY -o report.json\n\n" RESET);
}
