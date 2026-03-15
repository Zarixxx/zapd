#include "zapd.h"

/* Raw WHOIS query over TCP port 43 */
static int whois_query(const char *server, const char *query, char *out, size_t outlen) {
    char ip[64] = {0};
    if (resolve_host(server, ip, sizeof(ip)) != 0) return -1;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(43);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    struct timeval tv = {10, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock);
        return -1;
    }

    /* Send query */
    char req[512];
    snprintf(req, sizeof(req), "%s\r\n", query);
    send(sock, req, strlen(req), 0);

    /* Read response */
    size_t total = 0;
    char buf[4096];
    int n;
    while ((n = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
        if (total + n >= outlen - 1) n = outlen - total - 1;
        memcpy(out + total, buf, n);
        total += n;
        if (total >= outlen - 1) break;
    }
    out[total] = '\0';
    close(sock);
    return total > 0 ? 0 : -1;
}

static void print_whois_field(const char *response, const char *field_name, const char *label) {
    char search[128];
    snprintf(search, sizeof(search), "%s:", field_name);

    const char *pos = response;
    int found = 0;
    while ((pos = strcasestr(pos, search)) != NULL) {
        pos += strlen(search);
        while (*pos == ' ' || *pos == '\t') pos++;
        char value[256] = {0};
        int i = 0;
        while (*pos && *pos != '\r' && *pos != '\n' && i < 255)
            value[i++] = *pos++;
        value[i] = '\0';
        if (strlen(value) > 0) {
            print_info(label, value, WHITE);
            found = 1;
            break;
        }
    }
    (void)found;
}

static void do_dns_lookup(const char *target) {
    print_section("DNS RECORDS");

    const char *types[] = {"A", "AAAA", "MX", "NS", "TXT", NULL};
    for (int t = 0; types[t]; t++) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "dig +short %s %s 2>/dev/null | head -5", target, types[t]);
        FILE *fp = popen(cmd, "r");
        if (!fp) continue;
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = '\0';
            if (!line[0]) continue;
            printf("  " RED "%-8s" RESET "  " WHITE "%s\n" RESET, types[t], line);
        }
        pclose(fp);
    }
}

int cmd_whois(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, RED "  [!] Usage: zapd whois <domain|ip> [--dns]\n" RESET);
        return 1;
    }

    char target[256];
    strncpy(target, argv[1], sizeof(target) - 1);
    int do_dns = 0;
    char output[256] = {0};

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--dns") == 0)  do_dns = 1;
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc)
            strncpy(output, argv[++i], sizeof(output) - 1);
    }

    char section_title[300];
    snprintf(section_title, sizeof(section_title), "WHOIS — %s", target);
    print_section(section_title);

    /* Resolve IP */
    char ip[64] = {0};
    if (resolve_host(target, ip, sizeof(ip)) == 0)
        print_info("Resolved IP", ip, WHITE);
    printf("\n");

    /* Determine WHOIS server */
    const char *whois_server = "whois.iana.org";

    /* Try to find the right WHOIS server from IANA first */
    char *dot = strrchr(target, '.');
    if (dot) {
        const char *tld = dot + 1;
        if      (strcmp(tld, "com") == 0 || strcmp(tld, "net") == 0)
            whois_server = "whois.verisign-grs.com";
        else if (strcmp(tld, "org") == 0)
            whois_server = "whois.pir.org";
        else if (strcmp(tld, "io") == 0)
            whois_server = "whois.nic.io";
        else if (strcmp(tld, "es") == 0)
            whois_server = "whois.nic.es";
        else if (strcmp(tld, "uk") == 0)
            whois_server = "whois.nic.uk";
        else if (strcmp(tld, "de") == 0)
            whois_server = "whois.denic.de";
        else if (strcmp(tld, "fr") == 0)
            whois_server = "whois.afnic.fr";
    }

    printf(GRAY "  [*] " RESET "Querying " WHITE "%s" RESET " ...\n\n", whois_server);

    static char response[65536];
    if (whois_query(whois_server, target, response, sizeof(response)) != 0) {
        fprintf(stderr, RED "  [!] WHOIS query failed (no network or server unreachable)\n" RESET);
        fprintf(stderr, GRAY "  [~] Try: whois %s\n" RESET, target);
        /* Fallback: call system whois */
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "whois %s 2>&1 | head -40", target);
        FILE *fp = popen(cmd, "r");
        if (fp) {
            char line[512];
            while (fgets(line, sizeof(line), fp))
                printf("  " GRAY "%s" RESET, line);
            pclose(fp);
        }
        goto dns;
    }

    print_section("WHOIS RECORD");

    /* Print key fields */
    print_whois_field(response, "Domain Name",          "Domain Name");
    print_whois_field(response, "Registrar",            "Registrar");
    print_whois_field(response, "Registrar URL",        "Registrar URL");
    print_whois_field(response, "Creation Date",        "Created");
    print_whois_field(response, "Registry Expiry Date", "Expires");
    print_whois_field(response, "Updated Date",         "Updated");
    print_whois_field(response, "Domain Status",        "Status");
    print_whois_field(response, "Name Server",          "Name Server");
    print_whois_field(response, "Registrant Organization", "Org");
    print_whois_field(response, "Registrant Country",   "Country");

dns:
    if (do_dns)
        do_dns_lookup(target);
    else {
        /* Always show basic A record */
        print_section("DNS (A RECORD)");
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "dig +short A %s 2>/dev/null", target);
        FILE *fp = popen(cmd, "r");
        if (fp) {
            char line[128];
            while (fgets(line, sizeof(line), fp)) {
                line[strcspn(line, "\n")] = '\0';
                if (line[0]) printf("  " RED "A" RESET "         " WHITE "%s\n" RESET, line);
            }
            pclose(fp);
        }
    }

    printf("\n");
    return 0;
}
