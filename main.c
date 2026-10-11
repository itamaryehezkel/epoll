/* ====================================================================
 *  Backend_epoll/main.c
 *
 *  epoll edition of Backend/main.c.
 *
 *  Same TLS server, same routes, same header table, same handlers --
 *  only the concurrency engine changed:
 *
 *      Backend/main.c        one detached pthread per connection,
 *                            blocking socket, blocking SSL_read/SSL_write.
 *
 *      Backend_epoll/main.c  a fixed pool of N worker threads, each
 *                            running its own epoll_wait() loop over many
 *                            connections.  Sockets are O_NONBLOCK and every
 *                            connection is a small state machine:
 *
 *                              CS_HANDSHAKE -> CS_READ -> CS_HANDLE
 *                                           -> CS_WRITE -> CS_SHUTDOWN
 *
 *                            SSL_accept / SSL_read / SSL_write that return
 *                            SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE do
 *                            not spin or block: the connection re-arms
 *                            itself for EPOLLIN / EPOLLOUT and the worker
 *                            moves on to other connections.
 *
 *  Both listeners live in those same loops -- :443 over TLS and :80 in the
 *  clear -- and both take the same path through the state machine. The only
 *  place they differ is which handler CS_HANDLE calls:
 *
 *      parse_request(c)  ->  Request        (shared by both)
 *                             |
 *              :443 --> handle_request()        the routes
 *              :80  --> handle_http_redirect()  302 to https://<Host>/
 *
 *  parse_request() is handle_client()'s parsing half from Backend/main.c
 *  pulled out into a function. It never touches the SSL object, so plain
 *  HTTP and HTTPS are parsed by exactly the same code.
 *
 *  Layout follows the Backend/main.c convention: includes, macros, globals,
 *  typedefs, ONE forward-declaration block covering every function in all
 *  three files, main(), then the definitions below it.
 *
 *  The definitions live in three files:
 *
 *      main.c            types, globals, the forward block, main(),
 *                        startup path discovery, argument parsing, and
 *                        the general helpers (get_file, mime,
 *                        SSL context, certificates, signals, ...)
 *      epoll_helpers.c   the TCP engine: listeners, workers, the
 *                        per-connection state machine, non-blocking I/O,
 *                        HTTP framing -- no need to touch it for routes
 *      handlers.c        the routes: parse_request(), the header-table
 *                        API, the ROUTE TABLE, static files, :80 redirect
 *
 *  epoll_helpers.c and handlers.c are #included, not compiled separately
 *  -- do not add them to the gcc line (see ./compile).
 *
 *  Paths are discovered at startup, not compiled in.  resolve_paths()
 *  reads /proc/self/exe, so everything hangs off the binary's folder:
 *
 *      home       ./                  the binary's own folder
 *      workspace  ../                 site root: the folder ABOVE the binary,
 *                                     holding one folder per (sub)domain:
 *                                     ../opaq.co.il/, ../tv.opaq.co.il/, ...
 *      cert_dir   certs/              fullchain.pem + privkey.pem, plus any
 *                                     fullchain.pem.<tag> + privkey.pem.<tag>
 *
 *  certs/ is looked for next to the binary first, then in the nearest
 *  parent folder that has it (up to 3 levels). -r / -c override both.
 * ==================================================================== */

#define _GNU_SOURCE         /* accept4, memmem, pthread_setaffinity_np */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <ctype.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <dirent.h>

#include <sys/stat.h>
#include <sys/resource.h>   /* RLIMIT_NOFILE */
#include <sys/ioctl.h>      /* FIONREAD */
#include <signal.h>
#include <limits.h>
#include <netdb.h>

#include <errno.h>          /* errno, strerror                           */
#include <time.h>           /* time()                                    */
#include <strings.h>        /* strcasecmp, strncasecmp                   */
#include <stdint.h>

/* --- the epoll machinery --- */
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>    /* TCP_NODELAY, TCP_DEFER_ACCEPT, TCP_FASTOPEN */
#include <sched.h>          /* CPU pinning                               */
#include <linux/filter.h>   /* cBPF reuseport steering                   */


#define BACKLOG 4096         /* per listener, capped by net.core.somaxconn */
#define DEBUG_LEVEL 0

/* The only debug hook with a call site (parse_request dumps the header
   table). The other DEBUG_LEVEL bits had no users and were dropped. */
#define TOKEN_DUMP if(DEBUG_LEVEL & 1)

#define PORT 443
#define HTTP_PORT 80
#define BIND_ADDR "10.0.0.2"
#define DOMAIN "opaq.co.il"

/* Filesystem paths are NOT compile-time constants any more. resolve_paths()
   reads /proc/self/exe at startup and derives everything from where the
   binary actually sits, so the tree can be moved or checked out anywhere
   without editing this file:

       home       = the directory holding the binary   ./
       workspace  = the folder above the binary (one subfolder per domain)
       cert_dir   = certs/ next to the binary or in the nearest parent

   `workspace` replaces what used to be the HOME macro (site lookups:
   get_file, is_file_allowed, is_known_host). `cert_dir` replaces the
   CERT_FILE / KEY_FILE macros. Both can be overridden with -r and -c. */
#define CERT_SUBDIR "certs/"
#define CERT_NAME   "fullchain.pem"
#define KEY_NAME    "privkey.pem"


#define ANSI_RESET    "\e[0m"
#define ANSI_GREEN    "\e[32m"
#define ANSI_CYAN     "\e[36m"
#define ANSI_YELLOW   "\e[33m"
#define ANSI_BOLD_RED "\e[1;31m"
#define ANSI_DIM_GRAY "\e[2;37m"
#define ANSI_MAGENTA  "\e[35m"

#define BUFFER_SIZE 8192
#define MAX_HEADER_BLOCK 65536
#define MAX_REQUEST_SIZE (8 * 1024 * 1024)   /* headers + body hard cap   */

/* epoll engine tuning */
#define MAX_EVENTS          128   /* epoll_wait batch size per worker     */
#define DEFAULT_WORKERS       0   /* 0 = one per CPU; override with -w N  */
#define MAX_WORKERS          64
#define IDLE_TIMEOUT_SECS    15   /* connection killed if it goes quiet   */
#define SWEEP_INTERVAL_MS   250   /* epoll_wait timeout / sweep cadence   */
#define SHUTDOWN_MAX_TRIES    2   /* SSL_shutdown attempts before close   */

/* TCP path tuning (see the notes at the top of epoll_helpers.c) */
#define ACCEPT_BATCH         64   /* accepts per listener wakeup          */
#define DEFER_ACCEPT_SECS     5   /* TCP_DEFER_ACCEPT                     */
#define FASTOPEN_QLEN      4096   /* TCP_FASTOPEN queue                   */
#define DEFAULT_KEEPALIVE    15   /* -k: keep-alive idle seconds, 0 = off */
#define MAX_KEEPALIVE_REQS 10000  /* requests per connection              */
#define TMO_HANDSHAKE_MS  10000
#define TMO_LINGER_MS      2000   /* wait for the peer's FIN after ours   */
#define POOL_KEEP_FREE     4096   /* pooled conn_t per worker             */
#define POOL_BUF_MAX      65536   /* shrink buffers above this on reuse   */
#define LOG_BUF_SIZE      65536   /* per-worker request log batch         */

char * domain;
char * bind_addr;
int https_port;
int http_port;
int num_workers;

int keepalive_secs = DEFAULT_KEEPALIVE; /* -k */
int log_requests   = 1;                 /* -l */
int max_conns      = 0;                 /* -m, 0 = as many as fds allow */
int busy_poll_us   = 0;                 /* -B, 0 = off */
int pin_cpus       = 1;                 /* -a */
int g_ncpu         = 1;

/* Filled in by resolve_paths() before the arguments are parsed; -r and -c
   may then replace workspace / cert_dir. All three keep a trailing '/'. */
char * home;        /* directory this binary lives in                     */
char * workspace;   /* ../ -- the site root, one folder per (sub)domain   */
char * cert_dir;    /* where fullchain.pem and privkey.pem are read from  */
char   cert_file[PATH_MAX];
char   key_file[PATH_MAX];

typedef struct {
    size_t size;
    char *data;
} FileInfo;

typedef enum {
    M_OPTIONS,
    M_DELETE,
    M_CONNECT,
    M_GET,
    M_PUT,
    M_PATCH,
    M_TRACE,
    M_HEAD,
    M_POST,
    M_UNSUPPORTED
} Method;

/* ------------------------------------------------------------------ *
 *  Connection state machine
 * ------------------------------------------------------------------ */
typedef enum {
    CS_HANDSHAKE,   /* SSL_accept in progress (skipped for plain :80)   */
    CS_READ,        /* pulling request-line + headers + body            */
    CS_HANDLE,      /* transient: parse + route + fill the out buffer   */
    CS_WRITE,       /* draining the out buffer                          */
    CS_SHUTDOWN,    /* close_notify + FIN                               */
    CS_LINGER,      /* drain input until the peer's FIN (avoids a RST)  */
    CS_DEAD         /* closed, recycled at the end of the epoll batch   */
} conn_state;

/* what the last non-blocking I/O attempt wants next */
typedef enum {
    IO_OK,
    IO_WANT_READ,
    IO_WANT_WRITE,
    IO_EOF,
    IO_ERR
} io_state;

/* what conn_drive()'s per-state helpers report back */
typedef enum {
    DR_AGAIN,   /* state advanced, run the machine again                */
    DR_WAIT,    /* armed in epoll, return to the loop                   */
    DR_DEAD     /* connection destroyed, pointer no longer valid        */
} drive_r;

typedef struct worker worker_t;

/* things that can sit in epoll's data.ptr -- the first int says which */
enum { EP_CONN = 1, EP_LISTEN_TLS, EP_LISTEN_PLAIN, EP_STOP };

/* timer classes: one FIFO list each, sorted by deadline for free because
   every member of a list shares the same timeout */
enum { TL_HANDSHAKE = 0, TL_IDLE, TL_IO, TL_LINGER, TL_COUNT };

typedef struct conn {
    int                 kind;        /* EP_CONN -- must stay first       */
    int                 fd;
    int                 is_tls;      /* 0 for the plain :80 redirector   */
    SSL                *ssl;
    SSL_CTX            *ctx;
    struct sockaddr_in  address;
    char                ip[INET_ADDRSTRLEN];

    conn_state          state;
    uint32_t            armed;       /* events registered (once, ET)     */
    int                 in_epoll;
    int                 shutdown_tries;
    time_t              last_active;

    /* readiness, tracked so no syscall is made that would EAGAIN */
    io_state            want;        /* what the last op is waiting for  */
    unsigned            rd_ready:1;
    unsigned            wr_ready:1;
    unsigned            rdhup:1;     /* peer sent FIN                    */
    unsigned            keepalive:1; /* this request allows reuse        */
    unsigned            close_after:1;
    unsigned            http10:1;
    unsigned            requests;

    /* inbound: request-line + headers + body, always NUL-terminated */
    char               *in;
    size_t              in_len;
    size_t              in_cap;
    size_t              scan_from;   /* resume point for the CRLFCRLF scan */
    long                headers_end; /* index just past CRLFCRLF, -1 = unknown */
    long                need;        /* total bytes wanted, -1 = unknown  */

    /* outbound: the complete response, written as the socket allows */
    char               *out;
    size_t              out_len;
    size_t              out_cap;
    size_t              out_sent;

    worker_t           *w;
    struct conn        *next_pending;   /* pool / close-batch link        */
    struct conn        *prev, *next;    /* timer list                     */
    int                 tlist;          /* which timer list, -1 = none    */
    uint64_t            deadline;
} conn_t;

typedef struct { conn_t *head, *tail; uint64_t timeout_ms; } tlist_t;
typedef struct { int kind; } ep_tag;

struct worker {
    int              id;
    int              cpu;               /* pinned CPU, -1 = not pinned    */
    pthread_t        tid;
    int              epfd;
    int              evfd;              /* stop doorbell (main -> worker) */
    int              lfd_tls;           /* this worker's own listeners    */
    int              lfd_plain;
    ep_tag           tag_tls, tag_plain, tag_stop;
    SSL_CTX         *ctx;
    int              nlive;             /* open connections right now     */
    int              max_live;          /* this worker's share of -m      */
    int              peak;              /* most open at once              */
    unsigned long    accepted;
    unsigned long    shed;              /* refused: at cap / out of fds   */
    int              spare_fd;          /* kept for EMFILE recovery       */
    uint64_t         last_emfile_log;

    conn_t          *free_list;         /* pooled conn_t                  */
    int              nfree;
    conn_t          *grave;             /* closed during this batch       */
    tlist_t          tl[TL_COUNT];
    uint64_t         now_ms;

    char             log[LOG_BUF_SIZE];
    size_t           log_len;
} __attribute__((aligned(64)));

/* The request view over conn->in. Every string below points into
   conn->in -- the table owns no character data, only the char** rows
   and the outer char*** array. Same contract as Backend/main.c.

   Produced by parse_request(), which both the HTTPS handler and the
   plain-HTTP handler call: the parse does not care which listener the
   bytes arrived on, only that a whole request is sitting in conn->in. */
typedef struct {
    conn_t *c;

    /* 1 once the request-line, header table and body are all set.
       0 means the request was malformed -- headers may still hold a
       partly built table, so callers must free_headers() either way. */
    int parsed;
    int is_tls;         /* which listener this arrived on              */

    Method method;
    char ip[INET_ADDRSTRLEN];

    char * buffer;
    int buffer_size;
    int total_read;

    char * version;

    char * uri;
    char * query;

    char *** headers;
    int headers_count;

    char * body;
    size_t body_len;

    /* No `host` field: the Host header is in the table like every other
       header. Read it with get_header(req, "Host"), or
       get_header_default(req, "Host", domain) where a missing Host would
       otherwise be a NULL. */
} Request;

typedef struct {
    const char *extension;
    const char *mime_type;
} MimeType;


static const MimeType mime_map[] = {
    { "aac", "audio/aac" },
    { "abw", "application/x-abiword" },
    { "arc", "application/x-freearc" },
    { "avi", "video/x-msvideo" },
    { "azw", "application/vnd.amazon.ebook" },
    { "bin", "application/octet-stream" },
    { "bmp", "image/bmp" },
    { "bz", "application/x-bzip" },
    { "bz2", "application/x-bzip2" },
    { "csh", "application/x-csh" },
    { "css", "text/css" },
    { "csv", "text/csv" },
    { "doc", "application/msword" },
    { "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
    { "eot", "application/vnd.ms-fontobject" },
    { "epub", "application/epub+zip" },
    { "gz", "application/gzip" },
    { "gif", "image/gif" },
    { "htm", "text/html" },
    { "html", "text/html" },
    { "ico", "image/vnd.microsoft.icon" },
    { "ics", "text/calendar" },
    { "jar", "application/java-archive" },
    { "jpeg", "image/jpeg" },
    { "jpg", "image/jpeg" },
    { "js", "application/javascript" },
    { "json", "application/json" },
    { "jsonld", "application/ld+json" },
    { "mid", "audio/midi" },
    { "midi", "audio/midi" },
    { "mjs", "text/javascript" },
    { "mp3", "audio/mpeg" },
    { "mp4", "video/mp4" },
    { "mpeg", "video/mpeg" },
    { "mpkg", "application/vnd.apple.installer+xml" },
    { "odp", "application/vnd.oasis.opendocument.presentation" },
    { "ods", "application/vnd.oasis.opendocument.spreadsheet" },
    { "odt", "application/vnd.oasis.opendocument.text" },
    { "oga", "audio/ogg" },
    { "ogv", "video/ogg" },
    { "ogx", "application/ogg" },
    { "opus", "audio/opus" },
    { "otf", "font/otf" },
    { "png", "image/png" },
    { "pdf", "application/pdf" },
    { "php", "application/x-httpd-php" },
    { "ppt", "application/vnd.ms-powerpoint" },
    { "pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation" },
    { "rar", "application/vnd.rar" },
    { "rtf", "application/rtf" },
    { "sh", "application/x-sh" },
    { "svg", "image/svg+xml" },
    { "tar", "application/x-tar" },
    { "tif", "image/tiff" },
    { "tiff", "image/tiff" },
    { "ts", "video/mp2t" },
    { "ttf", "font/ttf" },
    { "txt", "text/plain" },
    { "vsd", "application/vnd.visio" },
    { "wav", "audio/wav" },
    { "weba", "audio/webm" },
    { "webm", "video/webm" },
    { "webp", "image/webp" },
    { "woff", "font/woff" },
    { "woff2", "font/woff2" },
    { "xhtml", "application/xhtml+xml" },
    { "xls", "application/vnd.ms-excel" },
    { "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
    { "xml", "application/xml" },
    { "xul", "application/vnd.mozilla.xul+xml" },
    { "zip", "application/zip" },
    { "3gp", "video/3gpp" },
    { "3g2", "video/3gpp2" },
    { "7z", "application/x-7z-compressed" },
    { "MOV", "video/quicktime" },
    { "mov", "video/quicktime"},
    { NULL, NULL }
};

/* ------------------------------------------------------------------ *
 *  Forward declarations - every function is defined below main(),     *
 *  in one of the textually-included files.                          *
 * ------------------------------------------------------------------ */

static int contains_dotdot(const char *s);
int is_file_allowed(const char *home, const char *host, const char *uri);
FileInfo get_file(const char* host, const char* filename);
void print_signal_error(int sig_num);
void handler(int sig);
void bind_signal_handlers();
SSL_CTX *create_ssl_context();
static int ktls_available(void);
void configure_ssl_context(SSL_CTX *ctx);
char * method_to_str(Method method);
static char *trim_inplace(char *s);
char * get_header(Request * req, const char * name);
char * get_header_default(Request * req, const char * name, char * fallback);
void free_headers(Request * req);
const char *get_mime_type(const char *filename);

/* --- startup: path discovery and arguments --- */
static char *   dir_with_slash(const char *p);
static int      resolve_paths(const char *argv0);
static char *   find_up(const char *start, const char *sub);
static void     print_sites(void);
static void     build_cert_paths(void);
static int      parse_int_arg(const char *s, int lo, int hi, int *out);
static void     usage(const char *prog);

/* --- the epoll engine --- */
static int      set_nonblocking(int fd) __attribute__((unused));
static int      make_listener(const char *addr, int port);
static int      attach_cpu_steering(int fd, int n);
static conn_t * conn_new(worker_t *w, int fd, struct sockaddr_in *addr, SSL_CTX *ctx, int is_tls);
static void     conn_destroy(conn_t *c);
static void     conn_touch(conn_t *c) __attribute__((unused));
static void     conn_timer(conn_t *c, int list);
static void     conn_timer_unlink(conn_t *c);
static io_state conn_recv(conn_t *c, void *buf, size_t len, size_t *got);
static io_state conn_send(conn_t *c, const void *buf, size_t len, size_t *sent);
static int      in_reserve(conn_t *c, size_t extra);
static int      out_append(conn_t *c, const void *data, size_t len);
static int      request_complete(conn_t *c);
static int      response_wants_close(conn_t *c);
static void     send_error_close(conn_t *c, int status);
static drive_r  do_handshake(conn_t *c);
static drive_r  do_read(conn_t *c);
static drive_r  do_handle(conn_t *c);
static drive_r  do_write(conn_t *c);
static drive_r  do_shutdown(conn_t *c);
static drive_r  do_linger(conn_t *c);
static void     conn_drive(conn_t *c);
static void     worker_accept(worker_t *w, int lfd, int is_tls);
static void     worker_sweep_idle(worker_t *w);
static void     conn_drop_buffers(conn_t *c);
static void     worker_shed_one(worker_t *w, int lfd);
static const char *conn_keepalive_hdr(conn_t *c) __attribute__((unused));
static void     worker_reap(worker_t *w);
static void  *  worker_main(void *arg);

/* --- request handling (the part that is the same server as before) --- */
Request      parse_request(conn_t *c);                      /* http + https */
static void  handle_request(conn_t *c, Request *req);       /* https routes */
static void  handle_http_redirect(conn_t *c, Request *req); /* :80 redirect */
static int   is_known_host(const char *host);
static const char *redirect_host(Request *req, char *buf, size_t buflen);

static worker_t workers[MAX_WORKERS];


int main(int argc, char *argv[]) {

    setbuf(stdout, NULL);

    /* Where am I? Everything on disk hangs off this, so it happens before
       the arguments are read -- -r and -c overwrite the results below. */
    if (resolve_paths(argc > 0 ? argv[0] : NULL) != 0)
        exit(EXIT_FAILURE);

    cert_dir = find_up(home, CERT_SUBDIR);
    if (!cert_dir) { perror("malloc cert_dir"); exit(EXIT_FAILURE); }

    /* FIX: these were malloc(16)/malloc(256) written with strcpy() straight
       from argv, so a long -b or -d overflowed the heap. */
    bind_addr = malloc(64*sizeof(char));
    domain = malloc(256*sizeof(char));
    if (!bind_addr || !domain) { perror("malloc"); exit(EXIT_FAILURE); }
    snprintf(domain, 256, "%s", DOMAIN);
    snprintf(bind_addr, 64, "%s", BIND_ADDR);
    https_port = PORT;
    http_port  = HTTP_PORT;
    num_workers = DEFAULT_WORKERS;
    g_ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (g_ncpu < 1) g_ncpu = 1;

    /* ---- arguments ----------------------------------------------------
       No arguments at all is the normal case (that is how the systemd
       unit starts it) and runs with the defaults above. Anything the
       parser does not understand -- an unknown flag, a flag with no
       value, a port that is not a number, an address that is not an
       IPv4 -- prints what was wrong, prints the help page, and exits
       instead of limping on with a half-applied configuration.
       -h / -help / --help / -? / ? print the help page and exit 0. */
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (!strcmp(a, "-h")     || !strcmp(a, "-help") ||
            !strcmp(a, "--help") || !strcmp(a, "-?")    ||
            !strcmp(a, "?")      || !strcmp(a, "/?")) {
            usage(argv[0]);
            exit(EXIT_SUCCESS);
        }

        /* everything else is a single-letter flag taking one value */
        if (a[0] != '-' || a[1] == '\0' || a[2] != '\0') {
            fprintf(stderr, "ERROR: unrecognised argument: %s\n\n", a);
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }

        if (i + 1 >= argc) {
            fprintf(stderr, "ERROR: option %s needs a value\n\n", a);
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }

        const char *val = argv[++i];

        switch (a[1]) {
          case 'b': {
            struct in_addr probe;
            if (inet_pton(AF_INET, val, &probe) != 1) {
                fprintf(stderr, "ERROR: -b expects an IPv4 address, got: %s\n\n", val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            snprintf(bind_addr, 64, "%s", val);
            break;
          }

          case 'p':
            if (parse_int_arg(val, 1, 65535, &https_port) != 0) {
                fprintf(stderr, "ERROR: -p expects a port in 1..65535, got: %s\n\n", val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;

          case 'P':                      /* the plain-HTTP listener */
            if (parse_int_arg(val, 1, 65535, &http_port) != 0) {
                fprintf(stderr, "ERROR: -P expects a port in 1..65535, got: %s\n\n", val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;

          case 'd':
            if (*val == '\0' || strlen(val) >= 256) {
                fprintf(stderr, "ERROR: -d expects a domain of 1..255 characters\n\n");
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            memset(domain, '\0', 256*sizeof(char));
            snprintf(domain, 256, "%s", val);
            break;

          case 'm':                      /* max open connections, all workers */
            if (parse_int_arg(val, 0, 10000000, &max_conns) != 0) {
                fprintf(stderr, "ERROR: -m expects a connection count (0 = auto), got: %s\n\n", val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;

          case 'B':                      /* busy-poll microseconds */
            if (parse_int_arg(val, 0, 100000, &busy_poll_us) != 0) {
                fprintf(stderr, "ERROR: -B expects microseconds in 0..100000, got: %s\n\n", val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;

          case 'w':
            if (parse_int_arg(val, 1, MAX_WORKERS, &num_workers) != 0) {
                fprintf(stderr, "ERROR: -w expects a worker count in 1..%d, got: %s\n\n",
                        MAX_WORKERS, val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;

          case 'k':                      /* keep-alive idle timeout */
            if (parse_int_arg(val, 0, 3600, &keepalive_secs) != 0) {
                fprintf(stderr, "ERROR: -k expects seconds in 0..3600, got: %s\n\n", val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;

          case 'l':                      /* per-request log line */
          case 'a':                      /* CPU pinning + steering */
            if (parse_int_arg(val, 0, 1, a[1] == 'l' ? &log_requests : &pin_cpus) != 0) {
                fprintf(stderr, "ERROR: %s expects 0 or 1, got: %s\n\n", a, val);
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            break;

          case 'r': {                    /* override the site root */
            char *w = dir_with_slash(val);
            if (!w) {
                fprintf(stderr, "ERROR: -r expects a directory: %s\n\n", strerror(errno));
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            free(workspace);
            workspace = w;
            break;
          }

          case 'c': {                    /* override the cert directory */
            char *d = dir_with_slash(val);
            if (!d) {
                fprintf(stderr, "ERROR: -c expects a directory: %s\n\n", strerror(errno));
                usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            free(cert_dir);
            cert_dir = d;
            break;
          }

          default:
            fprintf(stderr, "ERROR: unknown option: %s\n\n", a);
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    // bind_signal_handlers();

    /* A single process now owns every connection, so one write to a
       socket the peer already closed must not take the server down. */
    signal(SIGPIPE, SIG_IGN);

    build_cert_paths();

    /* ---- how many connections can we hold? ------------------------------
       Every connection is one file descriptor, and the default soft limit
       is often 1024. Raise it to the hard limit, then give each worker an
       equal share of it (or of -m) so a flood is refused cleanly instead
       of running out of descriptors mid-handshake. */
    if (num_workers == 0) num_workers = g_ncpu < MAX_WORKERS ? g_ncpu : MAX_WORKERS;
    struct rlimit rl;
    long fd_limit = 1024;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        if (rl.rlim_cur < rl.rlim_max) {
            rl.rlim_cur = rl.rlim_max;
            setrlimit(RLIMIT_NOFILE, &rl);
            getrlimit(RLIMIT_NOFILE, &rl);
        }
        fd_limit = (rl.rlim_cur == RLIM_INFINITY || rl.rlim_cur > 10000000) ? 10000000 : (long)rl.rlim_cur;
    }
    long usable = fd_limit - 64 - 4L * num_workers;   /* listeners, epoll, certs, logs */
    if (usable < num_workers) usable = num_workers;
    long cap = (max_conns > 0 && max_conns < usable) ? max_conns : usable;
    for (int i = 0; i < num_workers; i++)
        workers[i].max_live = (int)(cap / num_workers);

    fprintf(stdout,"\e[0;93mbinary dir  \e[96m%s\e[0m\n", home);
    fprintf(stdout,"\e[0;93msite root   \e[96m%s\e[0m\n", workspace);
    print_sites();
    fprintf(stdout,"\e[0;93mcerts       \e[96m%s\e[0m\n", cert_dir);

    /* Say plainly which file is missing rather than letting OpenSSL
       report a bare "no such file" from inside the handshake setup. */
    if (access(cert_file, R_OK) != 0 || access(key_file, R_OK) != 0) {
        fprintf(stderr,
            "\e[1;31mcertificates not readable\e[0m\n"
            "  expected: %s\n"
            "            %s\n"
            "  put them there, or point elsewhere with -c <dir>\n",
            cert_file, key_file);
        exit(EXIT_FAILURE);
    }

    SSL_CTX *ctx = create_ssl_context();
    configure_ssl_context(ctx);

    /* ---- listeners: every worker gets its OWN pair (SO_REUSEPORT), made
       in worker order so reuseport member i belongs to worker i ---- */
    for (int i = 0; i < num_workers; i++) {
        workers[i].lfd_tls   = make_listener(bind_addr, https_port);
        workers[i].lfd_plain = make_listener(bind_addr, http_port);
        if (workers[i].lfd_tls < 0 || workers[i].lfd_plain < 0) {
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
    }

    /* SYN on CPU k -> worker k, when there is exactly one worker per CPU */
    int steering = 0;
    if (pin_cpus && num_workers == g_ncpu && num_workers > 1) {
        steering = attach_cpu_steering(workers[0].lfd_tls, num_workers) == 0;
        if (steering) attach_cpu_steering(workers[0].lfd_plain, num_workers);
    }

    /* only the main thread takes SIGINT/SIGTERM; workers inherit the mask */
    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigaddset(&sigs, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);

    /* ---- spin up the worker pool: one epoll instance per worker ---- */
    for (int i = 0; i < num_workers; i++) {
        worker_t *w = &workers[i];
        w->id  = i;
        w->ctx = ctx;
        w->cpu = (pin_cpus && num_workers <= g_ncpu) ? i : -1;
        w->tag_tls.kind   = EP_LISTEN_TLS;
        w->tag_plain.kind = EP_LISTEN_PLAIN;
        w->tag_stop.kind  = EP_STOP;

        w->epfd = epoll_create1(EPOLL_CLOEXEC);
        if (w->epfd < 0) { perror("epoll_create1"); exit(EXIT_FAILURE); }

        w->evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (w->evfd < 0) { perror("eventfd"); exit(EXIT_FAILURE); }

        if (pthread_create(&w->tid, NULL, worker_main, w) != 0) {
            perror("worker thread creation failed");
            exit(EXIT_FAILURE);
        }
    }

    fprintf(stdout,"\033[95mHTTP Server is listening on \e[96m%s\e[97m:\e[92m%d\e[0m\n", bind_addr, http_port);
    fprintf(stdout,"\e[0;93mHTTPS Server is listening on \e[96m%s\e[97m:\e[92m%d\e[0m\n", bind_addr, https_port);
    fprintf(stdout,"\e[0;93mepoll workers: \e[92m%d\e[0m (cpus %d, pinned %s, SYN steering %s)\n",
            num_workers, g_ncpu,
            (pin_cpus && num_workers <= g_ncpu) ? "yes" : "no", steering ? "yes" : "no");
    fprintf(stdout,"\e[0;93mconnections: \e[92m%ld\e[0m max (%d per worker; fd limit %ld%s)\n",
            cap, workers[0].max_live, fd_limit,
            fd_limit < 65536 ? " -- raise with `ulimit -n 1048576` or LimitNOFILE= for more" : "");
    fprintf(stdout,"\e[0;93mkeep-alive: \e[92m%ds\e[0m  request log: %s  kTLS: %s\n",
            keepalive_secs, log_requests ? "on" : "off",
            ktls_available() ? "on" : "off (run `modprobe tls` to enable)");
    fprintf(stdout,"\e[0;93mtcp: \e[92mreuseport, nodelay, defer-accept, fastopen%s\e[0m\n",
            busy_poll_us ? ", busy-poll" : "");
    fprintf(stdout,"\e[0;93mtls: \e[92mTLS1.2+, AEAD, X25519, ALPN http/1.1, tickets, release-buffers\e[0m\n");

    /* No acceptor loop any more -- the workers accept for themselves.
       The main thread just waits for Ctrl-C / SIGTERM. */
    int sig = 0;
    sigwait(&sigs, &sig);
    fprintf(stdout, "\nsignal %d -- stopping workers\n", sig);

    uint64_t one = 1;
    for (int i = 0; i < num_workers; i++)
        if (write(workers[i].evfd, &one, sizeof(one)) < 0) { /* ignore */ }
    for (int i = 0; i < num_workers; i++)
        pthread_join(workers[i].tid, NULL);

    for (int i = 0; i < num_workers; i++)
        fprintf(stdout, "worker %2d: accepted %-9lu peak open %-7d refused %lu\n",
                i, workers[i].accepted, workers[i].peak, workers[i].shed);

    SSL_CTX_free(ctx);
    return 0;
}




/* ==================================================================== *
 *  Section 0 -- working out where we are on disk
 * ==================================================================== */

/* strdup(p) with exactly one trailing '/'. NULL on empty input or OOM. */
static char * dir_with_slash(const char *p) {
    if (!p || !*p) { errno = EINVAL; return NULL; }

    size_t len = strlen(p);
    while (len > 1 && p[len-1] == '/') len--;   /* collapse "a///" -> "a/" */

    char *out = malloc(len + 2);
    if (!out) return NULL;
    memcpy(out, p, len);
    if (out[len-1] != '/') out[len++] = '/';
    out[len] = '\0';
    return out;
}

/* `sub` (e.g. "certs/") in `start`, or in the closest parent directory
   that has it -- so a binary in a subfolder still finds the shared
   certs/ one or two levels up. Falls back to start/sub.
   Result is malloc'd and keeps a trailing '/'. */
static char *find_up(const char *start, const char *sub) {
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", start);
    for (int level = 0; level < 4; level++) {
        char cand[PATH_MAX];
        struct stat st;
        int len = snprintf(cand, sizeof(cand), "%s%s", dir, sub);
        if (len > 0 && len < (int)sizeof(cand) &&
            stat(cand, &st) == 0 && S_ISDIR(st.st_mode)) return strdup(cand);
        size_t n = strlen(dir);
        if (n <= 1) break;
        dir[n - 1] = '\0';                          /* drop trailing '/' */
        char *slash = strrchr(dir, '/');
        if (!slash) break;
        slash[1] = '\0';                            /* parent, with '/' */
    }
    char *out = malloc(strlen(start) + strlen(sub) + 1);
    if (out) sprintf(out, "%s%s", start, sub);
    return out;
}

/* Fill in `home` (the directory this binary lives in) and `workspace`
   (the folder above it, where the per-domain folders live). /proc/self/exe is the authoritative answer on Linux --
   it survives a relative invocation, a PATH lookup, and a changed cwd,
   all of which make argv[0] unreliable. argv[0] via realpath() is only
   the fallback for a kernel without /proc mounted. */
static int resolve_paths(const char *argv0) {
    char exe[PATH_MAX];

    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        exe[n] = '\0';
    } else if (!argv0 || !realpath(argv0, exe)) {
        fprintf(stderr, "cannot resolve the server's own path: %s\n",
                strerror(errno));
        return -1;
    }

    char *slash = strrchr(exe, '/');
    if (!slash) {
        fprintf(stderr, "unexpected executable path: %s\n", exe);
        return -1;
    }

    *slash = '\0';                       /* the binary's folder */
    home = dir_with_slash(*exe ? exe : "/");
    if (!home) { perror("malloc home"); return -1; }

    /* site root = one folder up: .../BACKEND_EPOLL/Backend_Vanila/itl_server_epoll
       serves .../BACKEND_EPOLL/<host>/ */
    slash = strrchr(exe, '/');
    if (slash) *slash = '\0';
    workspace = dir_with_slash(*exe ? exe : "/");
    if (!workspace) { perror("malloc workspace"); return -1; }

    return 0;
}

/* List the (sub)domain folders in the site root -- every directory whose
   name is a valid hostname (letters, digits, '-', '.', at least one dot).
   Only these are ever served; anything else there (source folders,
   certs, ...) is not reachable through the Host header. */
static void print_sites(void) {
    DIR *d = opendir(workspace);
    if (!d) {
        fprintf(stdout, "\e[1;31mwarning\e[0m: site root %s cannot be opened: %s\n",
                workspace, strerror(errno));
        return;
    }
    int n = 0, have_fallback = 0;
    struct dirent *de;
    fprintf(stdout, "\e[0;93msites       \e[92m");
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.' || !is_known_host(de->d_name)) continue;
        fprintf(stdout, "%s%s", n++ ? ", " : "", de->d_name);
        if (strcasecmp(de->d_name, domain) == 0) have_fallback = 1;
    }
    closedir(d);
    fprintf(stdout, "%s\e[0m\n", n ? "" : "(none)");
    if (!have_fallback)
        fprintf(stdout, "\e[1;33mwarning\e[0m: no folder for the fallback domain %s in %s"
                        " -- unknown Hosts will 404\n", domain, workspace);
}

/* cert_dir + the two filenames, after -c has had its say. */
static void build_cert_paths(void) {
    snprintf(cert_file, sizeof(cert_file), "%s%s", cert_dir, CERT_NAME);
    snprintf(key_file,  sizeof(key_file),  "%s%s", cert_dir, KEY_NAME);
}

/* strtol with the checks atoi() silently skips: no digits at all, trailing
   junk ("8443x"), overflow, and out-of-range. 0 on success. */
static int parse_int_arg(const char *s, int lo, int hi, int *out) {
    if (!s || !*s) return -1;

    errno = 0;
    char *end = NULL;
    long v = strtol(s, &end, 10);

    if (errno != 0)   return -1;      /* ERANGE */
    if (end == s)     return -1;      /* no digits */
    if (*end != '\0') return -1;      /* trailing junk */
    if (v < lo || v > hi) return -1;

    *out = (int)v;
    return 0;
}

/* The help page. Prints the live defaults and the paths resolve_paths()
   just worked out, so it doubles as "what would this binary actually do". */
static void usage(const char *prog) {
    const char *name = "itl_server_epoll";
    if (prog && *prog) {
        const char *slash = strrchr(prog, '/');
        name = slash ? slash + 1 : prog;
    }

    printf(
"ITL server (epoll edition) -- HTTPS on one port, an HTTP->HTTPS redirect\n"
"on another, served by a pool of epoll worker threads.\n"
"\n"
"Usage: %s [options]\n"
"       %s                       run with the defaults below\n"
"       %s --help                show this page\n"
"\n"
"Options:\n"
"  -b <ipv4>   address to bind both listeners to   (default %s)\n"
"  -p <port>   HTTPS port,  1..65535               (default %d)\n"
"  -P <port>   plain HTTP port, 1..65535           (default %d)\n"
"  -d <name>   domain used when a request's Host is missing or unknown\n"
"                                                  (default %s)\n"
"  -w <n>      epoll worker threads, 1..%d         (default: one per CPU)\n"
"  -m <n>      max open connections, all workers   (default: what `ulimit -n` allows)\n"
"  -k <secs>   keep-alive idle timeout, 0 = off    (default %d)\n"
"  -a 0|1      pin workers to CPUs + SYN steering  (default 1)\n"
"  -l 0|1      one log line per request            (default 1)\n"
"  -B <usec>   busy-poll the NIC, 0 = off          (default 0; lower latency, more CPU)\n"
"  -r <dir>    site root: sites are served from <dir>/<host>/  (default: folder above the binary)\n"
"  -c <dir>    directory holding %s and %s  (default: nearest certs/)\n"
"              plus optional <name>.<tag> pairs, e.g. fullchain.pem.opaq +\n"
"              privkey.pem.opaq -- one RSA and one ECDSA chain side by side\n"
"  -h, --help, -help, -?, ?   show this page and exit\n"
"\n"
"Paths for this binary (worked out at startup from /proc/self/exe;\n"
"-r and -c override them):\n"
"  binary dir  %s\n"
"  site root   %s\n"
"  certs       %s\n"
"\n"
"Examples:\n"
"  %s -w 8\n"
"  %s -b 0.0.0.0 -p 8443 -P 8080 -w 8\n"
"  %s -r /srv/sites -c /etc/letsencrypt/live/%s\n",
        name, name, name,
        BIND_ADDR, PORT, HTTP_PORT, DOMAIN,
        MAX_WORKERS, DEFAULT_KEEPALIVE,
        CERT_NAME, KEY_NAME,
        home      ? home      : "(unresolved)",
        workspace ? workspace : "(unresolved)",
        cert_dir  ? cert_dir  : "(unresolved)",
        name, name, name, DOMAIN);
}


/* The engine and the routes. Both are textually included (not separate
   translation units), so they see every type, global and prototype
   declared above main() -- and neither belongs on the gcc line. */
#include "epoll_helpers.c"      /* TCP/TLS engine -- no need to touch   */
#include "handlers.c"           /* routes -- add your entries here      */

/* return 1 if s contains "..", else 0 */
static int contains_dotdot(const char *s) {
    if (!s) return 1;
    for (const char *p = s; *p; ++p) {
        if (p[0] == '.' && p[1] == '.') return 1;
    }
    return 0;
}

/* Simple allowed-file check using stat + access only.
 * home should be like "/var/www/" (prefer trailing slash).
 * host is the site folder (e.g., "example.com").
 * uri is the request path (e.g., "/index.html" or "index.html").
 * Returns 1 if file exists, is regular, and readable; otherwise 0.
 */
int is_file_allowed(const char *home, const char *host, const char *uri) {
    if (!home || !host || !uri) return 0;

    if (contains_dotdot(host) || contains_dotdot(uri)) return 0;

    /* normalize uri: skip leading slash */
    const char *u = uri;
    if (u[0] == '/') u++;

    char candidate[PATH_MAX];
    int n = snprintf(candidate, sizeof(candidate), "%s%s/%s", home, host, u);
    if (n < 0 || n >= (int)sizeof(candidate)) return 0;

    struct stat st;
    if (stat(candidate, &st) != 0) return 0;        /* not exists or stat error */
    if (!S_ISREG(st.st_mode)) return 0;             /* not a regular file */
    if (access(candidate, R_OK) != 0) return 0;     /* not readable */

    return 1;
}

FileInfo get_file(const char* host, const char* filename) {
    FileInfo result;
    result.data = NULL;
    result.size = 0;
    char path[PATH_MAX];
    if (!host || !filename) return result;

    /* FIX: was strcpy + two strcat into char[1024]. Harmless while HOME was
       a fixed literal; with a runtime site root it needs a bound. */
    int n = snprintf(path, sizeof(path), "%s%s%s", workspace, host, filename);
    if (n < 0 || n >= (int)sizeof(path)) {
        fprintf(stderr, "path too long: %s%s%s\n", workspace, host, filename);
        return result;
    }

    FILE* file = fopen(path, "r");
    if (!file) {
        perror("Failed to open file");
        return result;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        perror("fseek failed");
        fclose(file);
        return result;
    }

    long size = ftell(file);
    if (size < 0) {
        perror("ftell failed");
        fclose(file);
        return result;
    }
    rewind(file);

    char* buffer = (char*)calloc((size_t)size + 1, sizeof(char));
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(file);
        return result;
    }

    size_t read = fread(buffer, 1, size, file);
    fclose(file);

    if (read != (size_t)size) {
        fprintf(stderr, "Only read %zu of %ld bytes\n", read, size);
        free(buffer);
        return result;
    }

    result.data = buffer;
    result.size = read;
    return result;
}

void print_signal_error(int sig_num) {
    const char *sig_name;

    switch (sig_num) {
        case SIGHUP:    sig_name = "SIGHUP (Hangup detected)"; break;
        case SIGINT:    sig_name = "SIGINT (Interrupt from keyboard)"; break;
        case SIGQUIT:   sig_name = "SIGQUIT (Quit from keyboard)"; break;
        case SIGILL:    sig_name = "SIGILL (Illegal instruction)"; break;
        case SIGTRAP:   sig_name = "SIGTRAP (Trace/breakpoint trap)"; break;
        case SIGABRT:   sig_name = "SIGABRT (Abort signal)"; break;
        case SIGBUS:    sig_name = "SIGBUS (Bus error)"; break;
        case SIGFPE:    sig_name = "SIGFPE (Floating point exception)"; break;
        case SIGKILL:   sig_name = "SIGKILL (Kill signal)"; break;
        case SIGUSR1:   sig_name = "SIGUSR1 (User-defined signal 1)"; break;
        case SIGSEGV:   sig_name = "SIGSEGV (Segmentation fault)"; break;
        case SIGUSR2:   sig_name = "SIGUSR2 (User-defined signal 2)"; break;
        case SIGPIPE:   sig_name = "SIGPIPE (Broken pipe)"; break;
        case SIGALRM:   sig_name = "SIGALRM (Timer signal)"; break;
        case SIGTERM:   sig_name = "SIGTERM (Termination signal)"; break;
        case SIGSTKFLT: sig_name = "SIGSTKFLT (Stack fault on coprocessor)"; break;
        case SIGCHLD:   sig_name = "SIGCHLD (Child stopped or terminated)"; break;
        case SIGCONT:   sig_name = "SIGCONT (Continue if stopped)"; break;
        case SIGSTOP:   sig_name = "SIGSTOP (Stop process)"; break;
        case SIGTSTP:   sig_name = "SIGTSTP (Stop typed at terminal)"; break;
        case SIGTTIN:   sig_name = "SIGTTIN (Terminal input for background process)"; break;
        case SIGTTOU:   sig_name = "SIGTTOU (Terminal output for background process)"; break;
        case SIGURG:    sig_name = "SIGURG (Urgent condition on socket)"; break;
        case SIGXCPU:   sig_name = "SIGXCPU (CPU time limit exceeded)"; break;
        case SIGXFSZ:   sig_name = "SIGXFSZ (File size limit exceeded)"; break;
        case SIGVTALRM: sig_name = "SIGVTALRM (Virtual alarm clock)"; break;
        case SIGPROF:   sig_name = "SIGPROF (Profiling timer expired)"; break;
        case SIGWINCH:  sig_name = "SIGWINCH (Window size change)"; break;
        case SIGIO:     sig_name = "SIGIO (I/O now possible)"; break;
        case SIGPWR:    sig_name = "SIGPWR (Power failure)"; break;
        case SIGSYS:    sig_name = "SIGSYS (Bad system call)"; break;
        default:        sig_name = "Unknown signal"; break;
    }

    fprintf(stdout, "Received signal %d: %s\n", sig_num, sig_name);
}

void handler(int sig) {
    print_signal_error(sig);
}

void bind_signal_handlers(){
    signal(SIGHUP, handler);
//    signal(SIGINT, handler);
//    signal(SIGQUIT, handler);
    signal(SIGILL, handler);
    signal(SIGTRAP, handler);
    signal(SIGABRT, handler);
#ifdef SIGIOT
    signal(SIGIOT, handler);
#endif
    signal(SIGBUS, handler);
    signal(SIGFPE, handler);
//    signal(SIGKILL, handler); // Cannot be caught or ignored
    signal(SIGUSR1, handler);
    signal(SIGSEGV, handler);
    signal(SIGUSR2, handler);
//    signal(SIGPIPE, handler); // ignored in main() instead
    signal(SIGALRM, handler);
//    signal(SIGTERM, handler);
    signal(SIGCHLD, handler);
    signal(SIGCONT, handler);
  //  signal(SIGSTOP, handler); // Cannot be caught or ignored
    signal(SIGTSTP, handler);
    signal(SIGTTIN, handler);
    signal(SIGTTOU, handler);
    signal(SIGURG, handler);
    signal(SIGXCPU, handler);
    signal(SIGXFSZ, handler);
    signal(SIGVTALRM, handler);
    signal(SIGPROF, handler);
    signal(SIGWINCH, handler);
    signal(SIGPOLL, handler);
#ifdef SIGPWR
    signal(SIGPWR, handler);
#endif
#ifdef SIGSYS
    signal(SIGSYS, handler);
#endif
}

/* Server-side ALPN. SSL_CTX_set_alpn_protos() is the CLIENT API -- on a
   server it has no effect, so http/1.1 was never actually negotiated. */
static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl; (void)arg;
    static const unsigned char h11[] = "\x08http/1.1";
    unsigned char *sel = NULL;
    if (SSL_select_next_proto(&sel, outlen, h11, sizeof(h11) - 1, in, inlen)
            == OPENSSL_NPN_NEGOTIATED) {
        *out = sel;
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

#ifndef SSL_OP_ENABLE_KTLS
#define SSL_OP_ENABLE_KTLS 0
#endif

/* "tls" listed in tcp_available_ulp == the kernel TLS module is loaded */
static int ktls_available(void) {
    FILE *f = fopen("/proc/sys/net/ipv4/tcp_available_ulp", "r");
    if (!f) return 0;
    char buf[256] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    for (char *t = strtok(buf, " \n"); t; t = strtok(NULL, " \n"))
        if (strcmp(t, "tls") == 0) return 1;
    return 0;
}

SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Failed to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    /* SSL_OP_ENABLE_KTLS: once the handshake is done OpenSSL hands the keys
       to the kernel (if `modprobe tls` is loaded) and SSL_write becomes a
       plain write that the kernel encrypts. Harmless when unavailable. */
    /* IGNORE_UNEXPECTED_EOF: a client that just closes (most browsers do,
       without close_notify) is treated as a normal EOF instead of an error
       that fills OpenSSL's error queue on every connection. */
    long opts = SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION |
                SSL_OP_CIPHER_SERVER_PREFERENCE;
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    opts |= SSL_OP_IGNORE_UNEXPECTED_EOF;
#endif
    /* only ask for kTLS when the kernel has it -- otherwise OpenSSL makes
       two failing setsockopt(TCP_ULP) calls on every connection */
    if (ktls_available()) opts |= SSL_OP_ENABLE_KTLS;
    SSL_CTX_set_options(ctx, opts);

    /* AEAD only, X25519 first: fastest key exchange, and the suites the
       kernel can offload */
    SSL_CTX_set_ciphersuites(ctx,
        "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384");
    SSL_CTX_set_cipher_list(ctx,
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");
    SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384");

    SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);

    /* Stateless session tickets instead of the server-side cache: the
       cache is one table behind one lock shared by every worker. */
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_num_tickets(ctx, 1);

    /* one recv() per TLS record instead of a 5-byte header read + body */
    SSL_CTX_set_read_ahead(ctx, 1);

    /* Non-blocking sockets: let SSL_write report a partial write instead of
       insisting the whole record go out in one call, and tolerate the buffer
       address moving between retries. */
    /* RELEASE_BUFFERS: OpenSSL frees its ~17 KB read and ~17 KB write
       record buffers whenever they are empty, instead of keeping both for
       the life of the connection. Idle keep-alive connections then cost a
       few KB each -- the single biggest lever for holding many at once. */
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                          SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
                          SSL_MODE_RELEASE_BUFFERS);
    return ctx;
}

/* Load one certificate CHAIN + key.

   SSL_CTX_use_certificate_chain_file() -- not SSL_CTX_use_certificate_file()
   -- so the leaf AND every intermediate go out in the handshake. OpenSSL
   keeps one chain per key type, so an RSA and an ECDSA chain can be loaded
   side by side: modern clients get ECDSA (a much cheaper handshake), old
   RSA-only clients still connect.

   Returns 0 loaded, 1 skipped (that key type is already loaded), -1 fatal. */
static int load_cert_pair(SSL_CTX *ctx, const char *chain, const char *key,
                          int *have_rsa, int *have_ec) {
    FILE *f = fopen(chain, "r");
    if (!f) { fprintf(stderr, "cannot open %s: %s\n", chain, strerror(errno)); return -1; }
    int ncerts = 0;
    X509 *leaf = NULL, *x;
    while ((x = PEM_read_X509(f, NULL, NULL, NULL))) {
        if (!leaf) leaf = x; else X509_free(x);
        ncerts++;
    }
    fclose(f);
    ERR_clear_error();                          /* PEM EOF leaves an error */
    if (!leaf) { fprintf(stderr, "no certificate in %s\n", chain); return -1; }

    int type  = EVP_PKEY_get_base_id(X509_get0_pubkey(leaf));
    int is_ec = (type == EVP_PKEY_EC);
    int *slot = is_ec ? have_ec : have_rsa;
    const char *tname = is_ec ? "ECDSA" : (type == EVP_PKEY_RSA ? "RSA" : "other");

    char cn[256] = "?";
    X509_NAME_get_text_by_NID(X509_get_subject_name(leaf), NID_commonName, cn, sizeof(cn));
    int days = 0, secs = 0;
    ASN1_TIME_diff(&days, &secs, NULL, X509_get0_notAfter(leaf));
    X509_free(leaf);

    if (*slot) {
        fprintf(stdout, "\e[1;33mwarning\e[0m: %s is a second %s chain -- skipped\n", chain, tname);
        return 1;
    }
    if (SSL_CTX_use_certificate_chain_file(ctx, chain) <= 0) {
        fprintf(stderr, "Failed to load certificate chain %s\n", chain);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "Private key %s does not load or does not match %s\n", key, chain);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    *slot = 1;

    fprintf(stdout, "\e[0;93mcert         \e[92m%-5s\e[0m %s  CN=%s  chain=%d  expires in %d days\n",
            tname, chain, cn, ncerts, days);
    if (ncerts < 2)
        fprintf(stdout, "\e[1;31mwarning\e[0m: %s holds only the leaf certificate -- use the "
                        "FULL chain (fullchain.pem) or many clients will reject it\n", chain);
    if (days < 0)
        fprintf(stdout, "\e[1;31mwarning\e[0m: %s has EXPIRED\n", chain);
    else if (days < 14)
        fprintf(stdout, "\e[1;33mwarning\e[0m: %s expires in %d days -- renew it\n", chain, days);
    return 0;
}

void configure_ssl_context(SSL_CTX *ctx) {
    int have_rsa = 0, have_ec = 0;

    /* primary pair: certs/fullchain.pem + certs/privkey.pem (required) */
    if (load_cert_pair(ctx, cert_file, key_file, &have_rsa, &have_ec) != 0) {
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    /* extra pairs: certs/fullchain.pem.<tag> + certs/privkey.pem.<tag> */
    DIR *d = opendir(cert_dir);
    if (!d) return;
    const char *pfx = CERT_NAME ".";
    size_t pl = strlen(pfx);
    struct dirent *de;
    while ((de = readdir(d))) {
        if (strncmp(de->d_name, pfx, pl) != 0 || !de->d_name[pl]) continue;
        char chain[PATH_MAX], key[PATH_MAX];
        snprintf(chain, sizeof(chain), "%s%s", cert_dir, de->d_name);
        snprintf(key, sizeof(key), "%s" KEY_NAME ".%s", cert_dir, de->d_name + pl);
        if (access(key, R_OK) != 0) {
            fprintf(stdout, "\e[1;33mwarning\e[0m: %s has no matching %s -- skipped\n", chain, key);
            continue;
        }
        if (load_cert_pair(ctx, chain, key, &have_rsa, &have_ec) < 0) {
            closedir(d);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
    }
    closedir(d);
}

char * method_to_str(Method method){
  switch(method){
    case M_OPTIONS: return "OPTIONS";
    case M_DELETE:  return "DELETE";
    case M_CONNECT: return "CONNECT";
    case M_GET:     return "GET";
    case M_PUT:     return "PUT";
    case M_PATCH:   return "PATCH";
    case M_TRACE:   return "TRACE";
    case M_HEAD:    return "HEAD";
    case M_POST:    return "POST";
    default:      return "UNSUPPORTED_METHOD";
  }
}

const char *get_mime_type(const char *filename) {
    const char *dot = strrchr(filename, '.');
    if (!dot) return "text/html";
    const char *ext = dot + 1;

    for (int i = 0; mime_map[i].extension != NULL; ++i) {
        if (strcasecmp(ext, mime_map[i].extension) == 0) {
            return mime_map[i].mime_type;
        }
    }
    return "application/octet-stream";
}
