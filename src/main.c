#include "zapd.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_banner();
        print_usage();
        return 0;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_banner();
        print_usage();
        return 0;
    }

    if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0) {
        printf("ZapD %s by %s\n", ZAPD_VERSION, ZAPD_AUTHOR);
        return 0;
    }

    /* Per-command help: zapd scan --help */
    if (argc >= 3 &&
        (strcmp(argv[2], "--help") == 0 || strcmp(argv[2], "-h") == 0)) {
        print_banner();
        if      (strcmp(argv[1], "scan")  == 0) print_help_scan();
        else if (strcmp(argv[1], "ping")  == 0) print_help_ping();
        else if (strcmp(argv[1], "whois") == 0) print_help_whois();
        else if (strcmp(argv[1], "vt")    == 0) print_help_vt();
        else { fprintf(stderr, RED "[!] Unknown command: %s\n" RESET, argv[1]); return 1; }
        return 0;
    }

    print_banner();

    if      (strcmp(argv[1], "scan")  == 0) return cmd_scan(argc - 1, argv + 1);
    else if (strcmp(argv[1], "ping")  == 0) return cmd_ping(argc - 1, argv + 1);
    else if (strcmp(argv[1], "whois") == 0) return cmd_whois(argc - 1, argv + 1);
    else if (strcmp(argv[1], "vt")    == 0) return cmd_vt(argc - 1, argv + 1);
    else {
        fprintf(stderr, RED "[!] Unknown command: %s\n" RESET, argv[1]);
        print_usage();
        return 1;
    }
}
