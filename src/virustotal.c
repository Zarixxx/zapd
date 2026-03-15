#include "zapd.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

/*
 * ZapD — VirusTotal Module
 * Author: Zarixxx (github.com/Zarixxx/zapd)
 *
 * Uses the VirusTotal API v3 over HTTPS (port 443).
 * Requires a free API key from: https://www.virustotal.com/gui/join-us
 *
 * Set your key with:  export VT_API_KEY=your_key_here
 * Or pass it with:    zapd vt <target> -k YOUR_KEY
 *
 * SUPPORTED TYPES:
 *   url    — Analyze a URL
 *   ip     — Analyze an IP address reputation
 *   domain — Analyze a domain reputation
 *   hash   — Analyze a file by MD5 / SHA1 / SHA256
 */

/* ── HTTPS GET via OpenSSL ─────────────────────────────────────────────── */
static int vt_https_get(const char *path, const char *api_key,
                        char *out, size_t outlen) {
    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return -1;

    char ip[64] = {0};
    if (resolve_host("www.virustotal.com", ip, sizeof(ip)) != 0) {
        SSL_CTX_free(ctx);
        return -1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { SSL_CTX_free(ctx); return -1; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(443);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    struct timeval tv = {15, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(sock); SSL_CTX_free(ctx); return -1;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, "www.virustotal.com");

    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl); close(sock); SSL_CTX_free(ctx); return -1;
    }

    char req[1024];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\n"
             "Host: www.virustotal.com\r\n"
             "x-apikey: %s\r\n"
             "Accept: application/json\r\n"
             "Connection: close\r\n\r\n",
             path, api_key);

    SSL_write(ssl, req, strlen(req));

    /* Skip HTTP headers, get to JSON body */
    size_t total = 0;
    char buf[8192];
    int n;
    int in_body = 0;
    char carry[4] = {0};

    while ((n = SSL_read(ssl, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        if (!in_body) {
            char *body = strstr(buf, "\r\n\r\n");
            if (body) {
                body += 4;
                in_body = 1;
                int blen = n - (body - buf);
                if (blen > 0 && total + blen < outlen - 1) {
                    memcpy(out + total, body, blen);
                    total += blen;
                }
            }
        } else {
            if (total + n < outlen - 1) {
                memcpy(out + total, buf, n);
                total += n;
            }
        }
    }
    out[total] = '\0';

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return total > 0 ? 0 : -1;
}

/* ── JSON helpers ──────────────────────────────────────────────────────── */
static int json_get_str(const char *json, const char *key,
                        char *out, size_t outlen) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return -1;
    p += strlen(search);
    while (*p == ' ' || *p == ':') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < outlen - 1)
        out[i++] = *p++;
    out[i] = '\0';
    return 0;
}

static int json_get_int(const char *json, const char *key, int *out) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return -1;
    p += strlen(search);
    while (*p == ' ' || *p == ':') p++;
    if (*p == '"') return -1;
    *out = atoi(p);
    return 0;
}

/* Extract value after "key": inside a specific engine block */
static void print_detections(const char *json, int limit) {
    const char *p = json;
    int found = 0;

    printf("  %-28s  %-14s  %s\n",
           WHITE "ENGINE" RESET,
           WHITE "CATEGORY" RESET,
           WHITE "RESULT" RESET);
    printf(GRAY "  %-28s  %-14s  %s\n" RESET,
           "────────────────────────────",
           "──────────────",
           "──────────────────────────────");

    while ((p = strstr(p, "\"category\":")) != NULL && found < limit) {
        /* Get category */
        char category[32] = {0};
        const char *cp = p + strlen("\"category\":");
        while (*cp == ' ') cp++;
        if (*cp == '"') {
            cp++;
            int i = 0;
            while (*cp && *cp != '"' && i < 31) category[i++] = *cp++;
            category[i] = '\0';
        }

        /* Only show malicious/suspicious */
        if (strcmp(category, "malicious") != 0 &&
            strcmp(category, "suspicious") != 0) {
            p++;
            continue;
        }

        /* Backtrack to find engine name (key before this block) */
        char engine[64] = "unknown";
        const char *ep = p;
        while (ep > json && *ep != '{') ep--;
        const char *np = ep;
        while ((np = strstr(np, "\"")) != NULL) {
            np++;
            char candidate[64] = {0};
            int i = 0;
            const char *tp = np;
            while (*tp && *tp != '"' && i < 63) candidate[i++] = *tp++;
            candidate[i] = '\0';
            /* Skip known field names */
            if (strcmp(candidate, "category") != 0 &&
                strcmp(candidate, "result")   != 0 &&
                strcmp(candidate, "method")   != 0 &&
                strcmp(candidate, "engine_name") != 0 &&
                strlen(candidate) > 2) {
                strncpy(engine, candidate, sizeof(engine) - 1);
            }
            np = tp + 1;
            if (np >= p) break;
        }

        /* Get result */
        char result[64] = "—";
        const char *rp = strstr(p, "\"result\":");
        if (rp && rp < p + 200) {
            rp += strlen("\"result\":");
            while (*rp == ' ') rp++;
            if (*rp == '"') {
                rp++;
                int i = 0;
                while (*rp && *rp != '"' && i < 63) result[i++] = *rp++;
                result[i] = '\0';
            }
        }

        const char *col = strcmp(category, "malicious") == 0 ? RED : YELLOW;
        printf("  " WHITE "%-28s" RESET "  %s%-14s" RESET "  " GRAY "%s\n" RESET,
               engine, col, category, result[0] ? result : "—");
        found++;
        p++;
    }

    if (found == 0)
        printf(GREEN "  [+] No detections from any engine.\n" RESET);
}

/* ── URL base64 encode (VT requires this) ─────────────────────────────── */
static void base64url_encode(const char *input, char *out, size_t outlen) {
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t len = strlen(input);
    size_t i = 0, j = 0;
    unsigned char c3[3], c4[4];

    while (i < len && j + 4 < outlen) {
        int k = 0;
        while (k < 3 && i < len) c3[k++] = (unsigned char)input[i++];
        while (k < 3) c3[k++] = 0;

        c4[0] = (c3[0] & 0xfc) >> 2;
        c4[1] = ((c3[0] & 0x03) << 4) + ((c3[1] & 0xf0) >> 4);
        c4[2] = ((c3[1] & 0x0f) << 2) + ((c3[2] & 0xc0) >> 6);
        c4[3] = c3[2] & 0x3f;

        for (int m = 0; m < 4; m++) {
            char ch = b64[c4[m]];
            /* URL-safe: replace + with - and / with _ */
            if (ch == '+') ch = '-';
            if (ch == '/') ch = '_';
            out[j++] = ch;
        }
    }
    /* Strip padding = */
    while (j > 0 && out[j-1] == '=') j--;
    out[j] = '\0';
}

/* ── Main VT command ───────────────────────────────────────────────────── */
int cmd_vt(int argc, char *argv[]) {
    if (argc < 2) {
        print_help_vt();
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_help_vt();
        return 0;
    }

    char target[512];
    strncpy(target, argv[1], sizeof(target) - 1);
    char api_key[128] = {0};
    char type[16]     = "url";
    char output[256]  = {0};

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-k") == 0 && i + 1 < argc)
            strncpy(api_key, argv[++i], sizeof(api_key) - 1);
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
            strncpy(type, argv[++i], sizeof(type) - 1);
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc)
            strncpy(output, argv[++i], sizeof(output) - 1);
    }

    /* Resolve API key from env if not passed */
    if (!api_key[0]) {
        char *env = getenv("VT_API_KEY");
        if (env) strncpy(api_key, env, sizeof(api_key) - 1);
    }

    if (!api_key[0]) {
        fprintf(stderr, RED "  [!] No VirusTotal API key found.\n" RESET);
        fprintf(stderr, GRAY "  [~] Set it with:  export VT_API_KEY=your_key\n" RESET);
        fprintf(stderr, GRAY "  [~] Or pass it:   zapd vt <target> -k YOUR_KEY\n" RESET);
        fprintf(stderr, GRAY "  [~] Get free key: https://www.virustotal.com/gui/join-us\n" RESET);
        return 1;
    }

    char section_title[300];
    snprintf(section_title, sizeof(section_title), "VIRUSTOTAL — %s", target);
    print_section(section_title);

    print_info("Target",  target,  WHITE);
    print_info("Type",    type,    WHITE);
    print_info("API Key", "********", GRAY);
    printf("\n");

    /* Build API path */
    char path[1024] = {0};
    char encoded[1024] = {0};

    if (strcmp(type, "url") == 0) {
        base64url_encode(target, encoded, sizeof(encoded));
        snprintf(path, sizeof(path), "/api/v3/urls/%s", encoded);
    } else if (strcmp(type, "ip") == 0) {
        snprintf(path, sizeof(path), "/api/v3/ip_addresses/%s", target);
    } else if (strcmp(type, "domain") == 0) {
        snprintf(path, sizeof(path), "/api/v3/domains/%s", target);
    } else if (strcmp(type, "hash") == 0) {
        snprintf(path, sizeof(path), "/api/v3/files/%s", target);
    } else {
        fprintf(stderr, RED "  [!] Unknown type: %s (use url, ip, domain, hash)\n" RESET, type);
        return 1;
    }

    printf(GRAY "  [*] " RESET "Querying VirusTotal API...\n");

    static char response[131072]; /* 128KB */
    if (vt_https_get(path, api_key, response, sizeof(response)) != 0) {
        fprintf(stderr, RED "  [!] Request failed. Check your internet connection or API key.\n" RESET);
        return 1;
    }

    /* Check for API error */
    if (strstr(response, "\"error\"")) {
        char errmsg[256] = "Unknown error";
        json_get_str(response, "message", errmsg, sizeof(errmsg));
        fprintf(stderr, RED "  [!] API Error: %s\n" RESET, errmsg);
        return 1;
    }

    /* ── Stats ── */
    print_section("ANALYSIS STATS");

    int malicious  = 0, suspicious = 0, undetected = 0,
        harmless   = 0, timeout    = 0;
    json_get_int(response, "malicious",  &malicious);
    json_get_int(response, "suspicious", &suspicious);
    json_get_int(response, "undetected", &undetected);
    json_get_int(response, "harmless",   &harmless);
    json_get_int(response, "timeout",    &timeout);
    int total_engines = malicious + suspicious + undetected + harmless + timeout;

    const char *verdict_col = malicious > 0 ? RED :
                              suspicious > 0 ? YELLOW : GREEN;
    const char *verdict     = malicious > 0 ? "MALICIOUS" :
                              suspicious > 0 ? "SUSPICIOUS" : "CLEAN";

    printf("\n  %s%-22s" RESET " %s%s\n" RESET,
           GRAY, "Verdict", verdict_col, verdict);
    printf("  " GRAY "%-22s" RESET " " RED    "%d\n" RESET, "Malicious",  malicious);
    printf("  " GRAY "%-22s" RESET " " YELLOW "%d\n" RESET, "Suspicious", suspicious);
    printf("  " GRAY "%-22s" RESET " " GREEN  "%d\n" RESET, "Clean",      harmless + undetected);
    printf("  " GRAY "%-22s" RESET " " WHITE  "%d\n" RESET, "Total engines", total_engines);

    /* Reputation */
    int reputation = 0;
    if (json_get_int(response, "reputation", &reputation) == 0) {
        const char *rc = reputation < -10 ? RED :
                         reputation < 0   ? YELLOW : GREEN;
        printf("  " GRAY "%-22s" RESET " %s%d\n" RESET, "Reputation", rc, reputation);
    }

    /* Country / ASN (for IPs) */
    char country[64] = {0}, as_owner[128] = {0};
    if (json_get_str(response, "country",  country,  sizeof(country))  == 0)
        print_info("Country",  country,  WHITE);
    if (json_get_str(response, "as_owner", as_owner, sizeof(as_owner)) == 0)
        print_info("ASN Owner", as_owner, WHITE);

    /* File-specific fields */
    char fname[256] = {0}, ftype[128] = {0};
    char md5[64]={0}, sha1[64]={0}, sha256[128]={0};
    if (json_get_str(response, "meaningful_name",  fname,  sizeof(fname))  == 0)
        print_info("Filename",  fname,  WHITE);
    if (json_get_str(response, "type_description", ftype,  sizeof(ftype))  == 0)
        print_info("File type", ftype,  WHITE);
    if (json_get_str(response, "md5",    md5,    sizeof(md5))    == 0)
        print_info("MD5",    md5,    GRAY);
    if (json_get_str(response, "sha256", sha256, sizeof(sha256)) == 0)
        print_info("SHA256", sha256, GRAY);

    /* Last analysis date */
    int last_ts = 0;
    if (json_get_int(response, "last_analysis_date", &last_ts) == 0 && last_ts > 0) {
        time_t t = (time_t)last_ts;
        char tstr[64];
        strftime(tstr, sizeof(tstr), "%Y-%m-%d %H:%M:%S UTC", gmtime(&t));
        print_info("Last analysis", tstr, GRAY);
    }

    /* ── Detections ── */
    if (malicious > 0 || suspicious > 0) {
        char dtitle[64];
        snprintf(dtitle, sizeof(dtitle),
                 "DETECTIONS (%d engines flagged)", malicious + suspicious);
        print_section(dtitle);
        print_detections(response, 30);
    }

    /* Save JSON */
    if (output[0]) {
        FILE *f = fopen(output, "w");
        if (f) {
            fprintf(f, "%s\n", response);
            fclose(f);
            printf(GREEN "\n  [+] Report saved to %s\n" RESET, output);
        }
    }

    printf("\n");
    return 0;
}
