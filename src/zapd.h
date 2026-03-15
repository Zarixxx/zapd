#ifndef ZAPD_H
#define ZAPD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>

#define ZAPD_VERSION    "1.1.0"
#define ZAPD_AUTHOR     "Zarixxx"
#define ZAPD_GITHUB     "github.com/Zarixxx/zapd"

/* ANSI colors */
#define RED     "\033[91m"
#define RED2    "\033[31m"
#define WHITE   "\033[97m"
#define GRAY    "\033[90m"
#define GREEN   "\033[92m"
#define YELLOW  "\033[93m"
#define BOLD    "\033[1m"
#define RESET   "\033[0m"

#define MAX_PORTS       65535
#define MAX_THREADS     500
#define DEFAULT_THREADS 100

/* Port states */
#define PORT_OPEN       1
#define PORT_CLOSED     2
#define PORT_FILTERED   3

typedef struct {
    int    port;
    int    state;       /* PORT_OPEN / PORT_CLOSED / PORT_FILTERED */
    double latency_ms;
    char   banner[128];
} PortResult;

typedef struct {
    char   target[256];
    char   ip[64];
    int    ports[MAX_PORTS];
    int    port_count;
    int    threads;
    double timeout;
    int    grab_banner;
    int    os_detect;
    int    udp_mode;
    int    randomize;
    int    show_closed;
    char   output[256];
} ScanConfig;

typedef struct {
    char        ip[64];
    int         port;
    double      timeout;
    int         grab_banner;
    int         udp_mode;
    PortResult *result;
} ScanWork;

/* ui.c */
void        print_banner(void);
void        print_usage(void);
void        print_section(const char *title);
void        print_info(const char *label, const char *value, const char *color);
void        progress_bar(int current, int total);
double      get_time_ms(void);
const char *get_service_name(int port);
int         resolve_host(const char *host, char *ip_out, size_t len);
int         parse_ports(const char *port_str, int *ports, int *count);

/* commands */
int cmd_scan(int argc, char *argv[]);
int cmd_ping(int argc, char *argv[]);
int cmd_whois(int argc, char *argv[]);

#endif

/* help functions */
void print_help_scan(void);
void print_help_ping(void);
void print_help_whois(void);

/* virustotal.c */
int cmd_vt(int argc, char *argv[]);
void print_help_vt(void);
