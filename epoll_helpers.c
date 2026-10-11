/* ====================================================================
 *  epoll_helpers.c
 *
 *  The TCP engine: listeners, worker threads, the per-connection state
 *  machine, non-blocking TLS/TCP I/O and HTTP framing. Routes live in
 *  handlers.c -- nothing in this file needs touching to add one.
 *
 *  NOT a separate translation unit -- main.c #includes it textually, the
 *  same way it includes ../Backend/gilat.c. It relies on the types,
 *  globals and prototypes declared above main.c's #include of this file,
 *  and must NOT be added to the gcc line in ./compile.
 *
 *  ---- what changed (the TCP path, handlers untouched) ----------------
 *
 *  Still the kernel's TCP, but the server now drives it with far fewer
 *  syscalls, no locks and no cross-CPU traffic:
 *
 *   - No acceptor thread / eventfd handoff / mutex. Every worker owns its
 *     own SO_REUSEPORT listener on each port and accepts for itself; the
 *     kernel spreads new connections across workers.
 *   - Optional cBPF steering + CPU pinning (-a 1, default when workers ==
 *     CPUs): a connection is accepted by the worker pinned to the CPU that
 *     received its SYN, so packet processing, TLS and the handler share
 *     one core's cache.
 *   - accept4(SOCK_NONBLOCK): no fcntl pair per connection. TCP_NODELAY is
 *     set once on the listener and inherited by every accepted socket.
 *   - TCP_DEFER_ACCEPT: the worker is only woken once the ClientHello /
 *     request line has arrived, and the handshake starts immediately.
 *   - Edge-triggered epoll, registered ONCE per connection for
 *     IN|OUT|RDHUP. The old conn_arm() did an epoll_ctl(MOD) on every
 *     WANT_READ <-> WANT_WRITE flip; now there are zero epoll_ctl calls
 *     after accept. rd_ready / wr_ready remember what the socket can do,
 *     so no read or write is attempted that would only return EAGAIN.
 *   - close() drops the fd from epoll by itself -- no EPOLL_CTL_DEL.
 *   - O(1) timer lists instead of walking every live connection once a
 *     second.
 *   - conn_t + its buffers are pooled per worker instead of
 *     calloc/malloc/free per connection.
 *   - Keep-alive + pipelining when a response allows it (Content-Length
 *     present, no "Connection: close"). handle_request() answers with
 *     "Connection: close" today, so it keeps closing exactly as before;
 *     drop that header from a route and it gets connection reuse for free.
 *   - Request log lines are batched per worker and written once per epoll
 *     batch instead of one unbuffered write(2) per line under stdio's
 *     global lock.
 *   - Clean close: close_notify, FIN, then drain until the peer's FIN, so
 *     unread input never turns our close into a RST that eats the reply.
 * ==================================================================== */
#ifndef EPOLL_HELPERS_C_INCLUDED
#define EPOLL_HELPERS_C_INCLUDED

#ifndef SO_ATTACH_REUSEPORT_CBPF
#define SO_ATTACH_REUSEPORT_CBPF 51
#endif
#ifndef SO_BUSY_POLL
#define SO_BUSY_POLL 46
#endif
#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL 69
#endif

/* epoll busy-poll parameters (Linux >= 6.9); defined here for older headers */
#ifndef EPIOCSPARAMS
struct epoll_params {
    uint32_t busy_poll_usecs;
    uint16_t busy_poll_budget;
    uint8_t  prefer_busy_poll;
    uint8_t  __pad;
};
#define EPIOCSPARAMS _IOW(0x8A, 0x01, struct epoll_params)
#endif

static inline uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);     /* vDSO, no syscall */
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* ==================================================================== *
 *  Section 1 -- listeners
 * ==================================================================== */

/* Kept for anything else that wants it; the engine itself no longer
   needs it (socket() and accept4() take SOCK_NONBLOCK directly). */
static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* One listening socket. Called once per worker per port: all of them
   bind the same addr:port thanks to SO_REUSEPORT and the kernel
   load-balances incoming connections between them. Options set here are
   copied onto every socket accept4() returns. */
static int make_listener(const char *addr, int port) {
    int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (s < 0) { perror("Socket creation failed"); return -1; }

    int one = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0 ||
        setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) {
        perror("setsockopt SO_REUSEADDR/SO_REUSEPORT");
        close(s);
        return -1;
    }
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    int defer = DEFER_ACCEPT_SECS;
    setsockopt(s, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer, sizeof(defer));

    int tfo = FASTOPEN_QLEN;
    setsockopt(s, IPPROTO_TCP, TCP_FASTOPEN, &tfo, sizeof(tfo));

    /* -B: spin on the NIC queue for up to N microseconds instead of
       sleeping until the interrupt -- lower latency, costs CPU. Inherited
       by every accepted socket. Off by default. */
    if (busy_poll_us > 0) {
        setsockopt(s, SOL_SOCKET, SO_BUSY_POLL, &busy_poll_us, sizeof(busy_poll_us));
        setsockopt(s, SOL_SOCKET, SO_PREFER_BUSY_POLL, &one, sizeof(one));
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
        fprintf(stderr, "bad bind address %s\n", addr);
        close(s);
        return -1;
    }
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "Bind %s:%d failed: %s\n", addr, port, strerror(errno));
        close(s);
        return -1;
    }
    if (listen(s, BACKLOG) < 0) {
        perror("Listen failed");
        close(s);
        return -1;
    }
    return s;
}

/* reuseport group member index = CPU that processed the SYN (mod n).
   Worker i owns member i and is pinned to CPU i. */
static int attach_cpu_steering(int fd, int n) {
    struct sock_filter code[] = {
        { BPF_LD  | BPF_W | BPF_ABS, 0, 0, (uint32_t)(SKF_AD_OFF + SKF_AD_CPU) },
        { BPF_ALU | BPF_MOD | BPF_K, 0, 0, (uint32_t)n },
        { BPF_RET | BPF_A,           0, 0, 0 },
    };
    struct sock_fprog prog = { .len = 3, .filter = code };
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &prog, sizeof(prog)) < 0) {
        fprintf(stderr, "cBPF steering unavailable: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/* ==================================================================== *
 *  Section 2 -- connections: pool, timers, close
 * ==================================================================== */

static void conn_timer_unlink(conn_t *c) {
    if (c->tlist < 0) return;
    tlist_t *l = &c->w->tl[c->tlist];
    if (c->prev) c->prev->next = c->next; else l->head = c->next;
    if (c->next) c->next->prev = c->prev; else l->tail = c->prev;
    c->prev = c->next = NULL;
    c->tlist = -1;
}

/* Every list has one fixed timeout, so appending at the tail keeps each
   list sorted by deadline -- the sweep only ever looks at the head. */
static void conn_timer(conn_t *c, int list) {
    worker_t *w = c->w;
    uint64_t deadline = w->now_ms + w->tl[list].timeout_ms;
    if (c->tlist == list && w->tl[list].tail == c) { c->deadline = deadline; return; }
    conn_timer_unlink(c);
    tlist_t *l = &w->tl[list];
    c->tlist = list;
    c->deadline = deadline;
    c->next = NULL;
    c->prev = l->tail;
    if (l->tail) l->tail->next = c; else l->head = c;
    l->tail = c;
}

/* Same name and meaning as before: "this connection just made progress". */
static void conn_touch(conn_t *c) {
    c->last_active = time(NULL);
    if (c->tlist >= 0) conn_timer(c, c->tlist);
}

static conn_t *conn_new(worker_t *w, int fd, struct sockaddr_in *addr,
                        SSL_CTX *ctx, int is_tls) {
    conn_t *c = w->free_list;
    if (c) {
        w->free_list = c->next_pending;
        w->nfree--;
    } else {
        /* buffers are allocated lazily by in_reserve()/out_append() */
        c = calloc(1, sizeof(conn_t));
        if (!c) { perror("calloc conn"); return NULL; }
    }

    c->kind        = EP_CONN;
    c->fd          = fd;
    c->is_tls      = is_tls;
    c->ctx         = ctx;
    c->ssl         = NULL;
    c->address     = *addr;
    c->state       = is_tls ? CS_HANDSHAKE : CS_READ;
    c->want        = IO_OK;
    c->rd_ready    = 1;          /* TCP_DEFER_ACCEPT: data is already here */
    c->wr_ready    = 1;
    c->keepalive   = 0;
    c->close_after = 0;
    c->http10      = 0;
    c->rdhup       = 0;
    c->requests    = 0;
    c->shutdown_tries = 0;
    c->in_epoll    = 0;
    c->armed       = 0;
    c->last_active = time(NULL);
    c->in_len      = 0;
    if (c->in) c->in[0] = '\0';
    c->scan_from   = 0;
    c->headers_end = -1;
    c->need        = -1;
    c->out_len     = 0;
    c->out_sent    = 0;
    c->tlist       = -1;
    c->prev = c->next = NULL;
    c->next_pending = NULL;
    c->w           = w;
    inet_ntop(AF_INET, &c->address.sin_addr, c->ip, INET_ADDRSTRLEN);

    if (is_tls) {
        c->ssl = SSL_new(ctx);
        if (!c->ssl || SSL_set_fd(c->ssl, fd) != 1) {
            ERR_print_errors_fp(stderr);
            if (c->ssl) SSL_free(c->ssl);
            c->ssl = NULL;
            c->next_pending = w->free_list;      /* straight back to the pool */
            w->free_list = c;
            w->nfree++;
            return NULL;
        }
        SSL_set_accept_state(c->ssl);
    }
    return c;
}

/* Give both buffers back. An idle keep-alive connection then costs only
   its conn_t and the (buffer-less, see SSL_MODE_RELEASE_BUFFERS) SSL
   object -- a few KB instead of ~45 KB -- which is what lets one worker
   hold tens of thousands of open connections. */
static void conn_drop_buffers(conn_t *c) {
    free(c->in);  c->in  = NULL; c->in_cap  = 0;
    free(c->out); c->out = NULL; c->out_cap = 0;
    c->in_len = 0;
    c->out_len = c->out_sent = 0;
}

/* Close now; the conn_t itself is recycled at the end of the epoll batch
   so a later event in the same batch can never land on a reused object. */
static void conn_destroy(conn_t *c) {
    if (!c || c->state == CS_DEAD) return;
    worker_t *w = c->w;

    conn_timer_unlink(c);
    if (c->ssl) { SSL_free(c->ssl); c->ssl = NULL; }  /* also drops the BIO */
    if (c->fd >= 0) { close(c->fd); c->fd = -1; }     /* also leaves epoll  */

    c->state = CS_DEAD;
    c->next_pending = w->grave;
    w->grave = c;
    w->nlive--;
}

static void worker_reap(worker_t *w) {
    while (w->grave) {
        conn_t *c = w->grave;
        w->grave = c->next_pending;
        if (w->nfree >= POOL_KEEP_FREE) {
            free(c->in); free(c->out); free(c);
            continue;
        }
        /* free + malloc, not realloc-to-shrink: shrinking a large (mmap'd)
           block and growing it again next request makes the kernel map and
           zero fresh pages every time; a plain free() lets malloc reuse
           the memory instead */
        if (c->in_cap > POOL_BUF_MAX)  conn_drop_buffers(c);
        if (c->out_cap > POOL_BUF_MAX) conn_drop_buffers(c);
        c->next_pending = w->free_list;
        w->free_list = c;
        w->nfree++;
    }
}

/* Close connections whose deadline passed. Touches only expired ones. */
static void worker_sweep_idle(worker_t *w) {
    for (int i = 0; i < TL_COUNT; i++)
        while (w->tl[i].head && w->tl[i].head->deadline <= w->now_ms)
            conn_destroy(w->tl[i].head);
}

/* ==================================================================== *
 *  Section 3 -- non-blocking I/O
 * ==================================================================== */

static io_state tls_err(conn_t *c, int r, int writing) {
    switch (SSL_get_error(c->ssl, r)) {
      case SSL_ERROR_WANT_READ:   return IO_WANT_READ;
      case SSL_ERROR_WANT_WRITE:  return IO_WANT_WRITE;
      case SSL_ERROR_ZERO_RETURN: return IO_EOF;
      case SSL_ERROR_SYSCALL:
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return writing ? IO_WANT_WRITE : IO_WANT_READ;
        return (errno == 0) ? IO_EOF : IO_ERR;
      case SSL_ERROR_SSL:
#ifdef SSL_R_UNEXPECTED_EOF_WHILE_READING
        if (ERR_GET_REASON(ERR_peek_last_error()) == SSL_R_UNEXPECTED_EOF_WHILE_READING)
            return IO_EOF;              /* OpenSSL 3.x unclean close */
#endif
        return IO_ERR;
      default:
        return IO_ERR;
    }
}

/* One non-blocking read. Same contract as before. */
static io_state conn_recv(conn_t *c, void *buf, size_t len, size_t *got) {
    *got = 0;
    if (len == 0) return IO_OK;

    if (!c->is_tls) {
        for (;;) {
            ssize_t n = recv(c->fd, buf, len, 0);
            if (n > 0) {
                *got = (size_t)n;
                /* short read: the receive queue is empty; the next data
                   to arrive raises a fresh edge */
                if ((size_t)n < len) c->rd_ready = 0;
                return IO_OK;
            }
            if (n == 0) return IO_EOF;
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return IO_WANT_READ;
            return IO_ERR;
        }
    }

    size_t n = 0;
    ERR_clear_error();
    if (SSL_read_ex(c->ssl, buf, len, &n) == 1) { *got = n; return IO_OK; }
    return tls_err(c, 0, 0);
}

/* One non-blocking write. Same contract as before. */
static io_state conn_send(conn_t *c, const void *buf, size_t len, size_t *sent) {
    *sent = 0;
    if (len == 0) return IO_OK;

    if (!c->is_tls) {
        for (;;) {
            ssize_t n = send(c->fd, buf, len, MSG_NOSIGNAL);
            if (n >= 0) {
                *sent = (size_t)n;
                if ((size_t)n < len) c->wr_ready = 0;
                return IO_OK;
            }
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return IO_WANT_WRITE;
            return IO_ERR;
        }
    }

    size_t n = 0;
    ERR_clear_error();
    if (SSL_write_ex(c->ssl, buf, len, &n) == 1) { *sent = n; return IO_OK; }
    return tls_err(c, 0, 1);
}

/* Remember what the socket is waiting for; the next edge clears it. */
static drive_r conn_wait(conn_t *c, io_state st) {
    if (st == IO_WANT_READ) { c->rd_ready = 0; c->want = IO_WANT_READ;  }
    else                    { c->wr_ready = 0; c->want = IO_WANT_WRITE; }
    return DR_WAIT;
}

/* Make sure at least `extra` bytes (plus the NUL) fit in c->in. */
static int in_reserve(conn_t *c, size_t extra) {
    if (c->in_len + extra + 1 <= c->in_cap) return 0;

    size_t cap = c->in_cap ? c->in_cap : BUFFER_SIZE;
    while (cap < c->in_len + extra + 1) {
        if (cap > MAX_REQUEST_SIZE) return -1;
        cap *= 2;
    }
    if (cap > MAX_REQUEST_SIZE + BUFFER_SIZE) return -1;

    char *tmp = realloc(c->in, cap);
    if (!tmp) { perror("realloc request buffer"); return -1; }
    c->in     = tmp;
    c->in_cap = cap;
    return 0;
}

/* Append to the response buffer -- unchanged contract (still keeps
   c->out NUL-terminated). */
static int out_append(conn_t *c, const void *data, size_t len) {
    if (!data || len == 0) return 0;

    if (c->out_len + len + 1 > c->out_cap) {
        size_t cap = c->out_cap ? c->out_cap : BUFFER_SIZE;
        while (cap < c->out_len + len + 1) cap *= 2;
        char *tmp = realloc(c->out, cap);
        if (!tmp) { perror("realloc response buffer"); return -1; }
        c->out     = tmp;
        c->out_cap = cap;
    }

    memcpy(c->out + c->out_len, data, len);
    c->out_len += len;
    c->out[c->out_len] = '\0';
    return 0;
}

/* ==================================================================== *
 *  Section 4 -- HTTP framing (where a request ends, may we reuse the
 *               connection). parse_request() still does the real parse.
 * ==================================================================== */

static int name_is(const char *p, size_t n, const char *lower) {
    size_t l = strlen(lower);
    return n == l && strncasecmp(p, lower, l) == 0;
}

static int has_token(const char *v, size_t n, const char *tok) {
    size_t tl = strlen(tok), i = 0;
    while (i < n) {
        while (i < n && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) i++;
        size_t s = i;
        while (i < n && v[i] != ',') i++;
        size_t e = i;
        while (e > s && (v[e-1] == ' ' || v[e-1] == '\t')) e--;
        if (e - s == tl && strncasecmp(v + s, tok, tl) == 0) return 1;
    }
    return 0;
}

typedef struct {
    long cl;            /* Content-Length, -1 = none               */
    int  bad;           /* HTTP status to fail with, 0 = fine      */
    int  te, conn_close, conn_ka, have_len;
} frame_t;

/* Walk "Name: value" lines in [p, end) without modifying them. */
static void scan_headers(const char *p, const char *end, frame_t *f, int is_request) {
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl) break;
        const char *le = (nl > p && nl[-1] == '\r') ? nl - 1 : nl;
        if (le == p) break;
        const char *colon = memchr(p, ':', (size_t)(le - p));
        if (colon) {
            const char *v = colon + 1;
            while (v < le && (*v == ' ' || *v == '\t')) v++;
            const char *ve = le;
            while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
            size_t nlen = (size_t)(colon - p), vl = (size_t)(ve - v);

            if (name_is(p, nlen, "content-length")) {
                f->have_len = 1;
                if (is_request) {
                    long x = 0;
                    if (vl == 0 || vl > 10) f->bad = vl ? 413 : 400;
                    for (size_t i = 0; i < vl && !f->bad; i++) {
                        if (v[i] < '0' || v[i] > '9') f->bad = 400;
                        else x = x * 10 + (v[i] - '0');
                    }
                    if (!f->bad && f->cl >= 0 && f->cl != x) f->bad = 400;  /* smuggling */
                    if (!f->bad) f->cl = x;
                }
            } else if (name_is(p, nlen, "transfer-encoding")) {
                f->te = 1;
                f->have_len = 1;
            } else if (name_is(p, nlen, "connection")) {
                if (has_token(v, vl, "close"))      f->conn_close = 1;
                if (has_token(v, vl, "keep-alive")) f->conn_ka = 1;
            }
        }
        p = nl + 1;
    }
}

/* 1 = whole request in c->in[0 .. need), 0 = need more, <0 = -(status) */
static int request_complete(conn_t *c) {
    if (c->headers_end < 0) {
        if (c->in_len < 4) return 0;
        char *p = memmem(c->in + c->scan_from, c->in_len - c->scan_from, "\r\n\r\n", 4);
        if (!p) {
            if (c->in_len > MAX_HEADER_BLOCK) return -431;      /* header flood */
            c->scan_from = c->in_len - 3;
            return 0;
        }
        size_t he = (size_t)(p - c->in) + 4;
        if (he > MAX_HEADER_BLOCK) return -431;

        const char *rl_nl = memchr(c->in, '\n', he);
        const char *rl_e  = (rl_nl > c->in && rl_nl[-1] == '\r') ? rl_nl - 1 : rl_nl;
        if (rl_e - c->in < 14) return -400;
        if      (!memcmp(rl_e - 8, "HTTP/1.1", 8)) c->http10 = 0;
        else if (!memcmp(rl_e - 8, "HTTP/1.0", 8)) c->http10 = 1;
        else return -505;

        frame_t f = { .cl = -1 };
        scan_headers(rl_nl + 1, c->in + he, &f, 1);
        if (f.bad) return -f.bad;
        if (f.te)  return -501;                 /* chunked uploads unsupported */

        long body = f.cl < 0 ? 0 : f.cl;
        if (body > (long)MAX_REQUEST_SIZE - (long)he) return -413;

        c->headers_end = (long)he;
        c->need        = (long)he + body;
        c->keepalive   = c->http10 ? f.conn_ka : !f.conn_close;
    }
    return ((long)c->in_len >= c->need) ? 1 : 0;
}

/* Reuse the connection only if the handler's response is self-delimiting
   and doesn't ask to close. */
static int response_wants_close(conn_t *c) {
    char *he = memmem(c->out, c->out_len, "\r\n\r\n", 4);
    if (!he || c->out_len < 12) return 1;
    const char *nl = memchr(c->out, '\n', (size_t)(he - c->out) + 2);
    frame_t f = { .cl = -1 };
    scan_headers(nl + 1, he + 4, &f, 0);
    if (f.conn_close) return 1;
    if (c->http10 && !f.conn_ka) return 1;
    if (!f.have_len) {
        int code = atoi(c->out + 9);
        if (code != 204 && code != 304) return 1;
    }
    return 0;
}

/* What a handler should put in its "Connection:" header. The engine
   then keeps the connection open only if the response says keep-alive
   and carries a Content-Length (see response_wants_close()). */
static const char *conn_keepalive_hdr(conn_t *c) {
    int ka = c->keepalive && keepalive_secs > 0 && !c->rdhup &&
             c->requests + 1 < MAX_KEEPALIVE_REQS;
    return ka ? "keep-alive" : "close";
}

static void send_error_close(conn_t *c, int status) {
    const char *txt =
        status == 400 ? "Bad Request" :
        status == 413 ? "Content Too Large" :
        status == 431 ? "Request Header Fields Too Large" :
        status == 501 ? "Not Implemented" :
        status == 505 ? "HTTP Version Not Supported" : "Internal Server Error";
    char buf[160];
    int n = snprintf(buf, sizeof(buf),
        "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, txt);
    c->out_len = c->out_sent = 0;
    out_append(c, buf, (size_t)n);
    c->close_after = 1;
}

/* Per-worker log buffer: one write(2) per epoll batch, not per request. */
static void worker_log_flush(worker_t *w) {
    size_t off = 0;
    while (off < w->log_len) {
        ssize_t n = write(STDOUT_FILENO, w->log + off, w->log_len - off);
        if (n <= 0) { if (n < 0 && errno == EINTR) continue; break; }
        off += (size_t)n;
    }
    w->log_len = 0;
}

static void log_request(conn_t *c, Request *req) {
    if (!log_requests) return;
    worker_t *w = c->w;
    if (w->log_len > LOG_BUF_SIZE - 1024) worker_log_flush(w);
    int n = snprintf(w->log + w->log_len, LOG_BUF_SIZE - w->log_len,
        "%s%s%s: %s%s%s uri=%s%s%s version=%s%s%s host=%s%s%s [%s%s%s]\n",
        ANSI_MAGENTA, req->ip, ANSI_RESET,
        ANSI_GREEN, method_to_str(req->method), ANSI_RESET,
        ANSI_CYAN, req->uri ? req->uri : "(null)", ANSI_RESET,
        ANSI_YELLOW, req->version ? req->version : "(null)", ANSI_RESET,
        ANSI_BOLD_RED, get_header_default(req, "Host", "(none)"), ANSI_RESET,
        ANSI_DIM_GRAY, req->is_tls ? "https" : "http", ANSI_RESET);
    if (n > 0) {
        size_t room = LOG_BUF_SIZE - w->log_len;
        w->log_len += ((size_t)n < room) ? (size_t)n : room - 1;
    }
}

/* ==================================================================== *
 *  Section 5 -- the state machine
 *
 *    CS_HANDSHAKE -> CS_READ -> CS_HANDLE -> CS_WRITE -+-> CS_READ (keep-alive)
 *                                                      +-> CS_SHUTDOWN -> CS_LINGER
 * ==================================================================== */

static drive_r do_handshake(conn_t *c) {
    if (!c->is_tls) { c->state = CS_READ; return DR_AGAIN; }

    ERR_clear_error();
    int r = SSL_do_handshake(c->ssl);
    if (r == 1) {
        c->state = CS_READ;
        conn_timer(c, TL_IDLE);
        return DR_AGAIN;
    }
    io_state st = tls_err(c, r, 0);
    if (st == IO_WANT_READ || st == IO_WANT_WRITE) return conn_wait(c, st);

    /* handshake failed -- drop it quietly, as before */
    ERR_clear_error();
    conn_destroy(c);
    return DR_DEAD;
}

static drive_r do_read(conn_t *c) {
    for (;;) {
        int done = request_complete(c);          /* pipelined bytes first */
        if (done > 0) { c->state = CS_HANDLE; return DR_AGAIN; }
        if (done < 0) {
            send_error_close(c, -done);
            c->state = CS_WRITE;
            conn_timer(c, TL_IO);
            return DR_AGAIN;
        }

        /* Idle TLS connection (between requests): ask the kernel whether
           anything arrived before calling SSL_read(). SSL_read() allocates
           OpenSSL's ~17 KB record buffer and then sits on it until data
           comes -- FIONREAD costs the same one syscall as the EAGAIN it
           replaces and keeps an idle connection buffer-free. Bytes that
           arrive after this check raise a new edge, so nothing is missed. */
        if (c->rd_ready && c->is_tls && c->in_len == 0 && !SSL_has_pending(c->ssl)) {
            int avail = 0;
            if (ioctl(c->fd, FIONREAD, &avail) == 0 && avail == 0 && !c->rdhup)
                c->rd_ready = 0;
        }

        if (!c->rd_ready) {
            if (c->rdhup) { conn_destroy(c); return DR_DEAD; }  /* peer gone */
            c->want = IO_WANT_READ;
            return DR_WAIT;
        }

        size_t want = BUFFER_SIZE;
        if (c->need > 0 && (size_t)c->need > c->in_len && (size_t)c->need - c->in_len > want)
            want = (size_t)c->need - c->in_len;
        if (in_reserve(c, want) < 0) {
            send_error_close(c, 413);
            c->state = CS_WRITE;
            return DR_AGAIN;
        }

        size_t got = 0, before = c->in_len;
        io_state st = conn_recv(c, c->in + c->in_len, c->in_cap - c->in_len - 1, &got);

        if (st == IO_OK) {
            c->in_len += got;
            c->in[c->in_len] = '\0';
            c->last_active = time(NULL);
            /* a new request starts its deadline on its first byte; body
               bytes keep refreshing it, a header drip does not */
            if (before == 0 || c->headers_end >= 0) conn_timer(c, TL_IO);
            continue;
        }
        if (st == IO_WANT_READ || st == IO_WANT_WRITE) return conn_wait(c, st);

        if (st == IO_EOF && c->headers_end > 0) {
            /* peer closed mid-body: serve what we have, as before */
            c->need = (long)c->in_len;
            c->keepalive = 0;
            c->state = CS_HANDLE;
            return DR_AGAIN;
        }
        conn_destroy(c);
        return DR_DEAD;
    }
}

/* One parse for both listeners, then the handler that fits the port. */
static drive_r do_handle(conn_t *c) {
    size_t req_len  = (size_t)c->need;
    size_t full_len = c->in_len;

    /* hide pipelined bytes from parse_request(), which treats everything
       after the header block as the body */
    char saved = c->in[req_len];
    c->in[req_len] = '\0';
    c->in_len = req_len;
    c->out_len = c->out_sent = 0;

    Request req = parse_request(c);
    if (!req.parsed) {
        free_headers(&req);          /* a partial table may have been built */
        conn_destroy(c);
        return DR_DEAD;
    }

    log_request(c, &req);

    if (c->is_tls) handle_request(c, &req);          /* the real routes */
    else           handle_http_redirect(c, &req);    /* 302 to https    */

    free_headers(&req);

    /* keep whatever was pipelined behind this request */
    c->in[req_len] = saved;
    size_t rest = full_len - req_len;
    if (rest) memmove(c->in, c->in + req_len, rest);
    c->in_len = rest;
    c->in[rest] = '\0';
    c->headers_end = -1;
    c->need = -1;
    c->scan_from = 0;
    c->requests++;

    if (c->out_len == 0)
        send_error_close(c, 500);
    else if (!c->keepalive || keepalive_secs == 0 || c->rdhup ||
             c->requests >= MAX_KEEPALIVE_REQS || response_wants_close(c))
        c->close_after = 1;

    c->state = CS_WRITE;
    conn_timer(c, TL_IO);
    return DR_AGAIN;
}

static drive_r do_write(conn_t *c) {
    int progressed = 0;
    while (c->out_sent < c->out_len) {
        if (!c->wr_ready) { c->want = IO_WANT_WRITE; goto wait; }
        size_t sent = 0;
        io_state st = conn_send(c, c->out + c->out_sent, c->out_len - c->out_sent, &sent);
        if (st == IO_OK) { c->out_sent += sent; progressed = 1; continue; }
        if (st == IO_WANT_WRITE || st == IO_WANT_READ) { conn_wait(c, st); goto wait; }

        /* IO_EOF or IO_ERR: peer is gone, nothing left to say */
        ERR_clear_error();
        conn_destroy(c);
        return DR_DEAD;
    }

    c->out_len = c->out_sent = 0;
    c->last_active = time(NULL);

    if (c->close_after) { c->state = CS_SHUTDOWN; return DR_AGAIN; }
    c->state = CS_READ;
    if (c->in_len == 0) conn_drop_buffers(c);       /* idle: hold no buffers */
    conn_timer(c, c->in_len ? TL_IO : TL_IDLE);
    return DR_AGAIN;

wait:
    if (progressed) { c->last_active = time(NULL); conn_timer(c, TL_IO); }
    return DR_WAIT;
}

/* close_notify (one-way -- we don't wait for theirs), then FIN, then
   drain input until the peer's FIN so the close is never a RST. */
static drive_r do_shutdown(conn_t *c) {
    if (c->is_tls && c->ssl) {
        ERR_clear_error();
        SSL_shutdown(c->ssl);
        c->shutdown_tries++;
    }
    shutdown(c->fd, SHUT_WR);
    c->state = CS_LINGER;
    c->rd_ready = 1;
    conn_timer(c, TL_LINGER);
    return DR_AGAIN;
}

static drive_r do_linger(conn_t *c) {
    char sink[4096];
    for (;;) {
        if (!c->rd_ready) { c->want = IO_WANT_READ; return DR_WAIT; }
        ssize_t n = recv(c->fd, sink, sizeof(sink), 0);
        if (n > 0) continue;
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            c->rd_ready = 0;
            c->want = IO_WANT_READ;
            return DR_WAIT;
        }
        conn_destroy(c);                        /* FIN or error */
        return DR_DEAD;
    }
}

/* Run the state machine until it finishes or needs to wait. Never makes
   a syscall that the readiness flags say would return EAGAIN. */
static void conn_drive(conn_t *c) {
    for (;;) {
        if (c->want == IO_WANT_READ  && !c->rd_ready) return;
        if (c->want == IO_WANT_WRITE && !c->wr_ready) return;
        c->want = IO_OK;

        drive_r r;
        switch (c->state) {
            case CS_HANDSHAKE: r = do_handshake(c); break;
            case CS_READ:      r = do_read(c);      break;
            case CS_HANDLE:    r = do_handle(c);    break;
            case CS_WRITE:     r = do_write(c);     break;
            case CS_SHUTDOWN:  r = do_shutdown(c);  break;
            case CS_LINGER:    r = do_linger(c);    break;
            default:           return;
        }
        if (r != DR_AGAIN) return;
    }
}

/* ==================================================================== *
 *  Section 6 -- workers
 * ==================================================================== */

/* Out of file descriptors: the pending connection would sit in the
   (level-triggered) listen queue and wake us in a busy loop. Spend the
   spare fd kept for exactly this, accept it, close it, take the spare back. */
static void worker_shed_one(worker_t *w, int lfd) {
    if (w->spare_fd >= 0) { close(w->spare_fd); w->spare_fd = -1; }
    int fd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
    if (fd >= 0) close(fd);
    w->spare_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    w->shed++;
}

static void worker_accept(worker_t *w, int lfd, int is_tls) {
    for (int k = 0; k < ACCEPT_BATCH; k++) {
        /* at this worker's share of -m: refuse politely instead of
           running the process out of memory or descriptors */
        if (w->max_live && w->nlive >= w->max_live) {
            int fd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
            if (fd < 0) return;
            close(fd);
            w->shed++;
            continue;
        }

        struct sockaddr_in addr;
        socklen_t alen = sizeof(addr);
        int cfd = accept4(lfd, (struct sockaddr *)&addr, &alen, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            if (errno == EMFILE || errno == ENFILE) {
                if (w->now_ms - w->last_emfile_log > 1000) {
                    fprintf(stderr, "worker %d: out of file descriptors at %d connections"
                                    " -- raise `ulimit -n` or lower -m\n", w->id, w->nlive);
                    w->last_emfile_log = w->now_ms;
                }
                worker_shed_one(w, lfd);
                continue;
            }
            if (errno != EAGAIN && errno != EWOULDBLOCK) perror("accept failed");
            return;
        }

        conn_t *c = conn_new(w, cfd, &addr, w->ctx, is_tls);
        if (!c) { close(cfd); continue; }

        struct epoll_event ev;
        ev.events   = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;
        ev.data.ptr = c;
        if (epoll_ctl(w->epfd, EPOLL_CTL_ADD, cfd, &ev) < 0) {
            perror("epoll_ctl add");
            w->nlive++;              /* conn_destroy() decrements */
            conn_destroy(c);
            continue;
        }
        c->in_epoll = 1;
        c->armed    = ev.events;
        w->nlive++;
        w->accepted++;
        if (w->nlive > w->peak) w->peak = w->nlive;
        conn_timer(c, is_tls ? TL_HANDSHAKE : TL_IO);

        conn_drive(c);               /* first flight is already queued */
    }
}

static void *worker_main(void *arg) {
    worker_t *w = (worker_t *)arg;
    struct epoll_event events[MAX_EVENTS];

    if (w->cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(w->cpu, &set);
        pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    }

    w->spare_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);   /* see worker_shed_one() */
    w->tl[TL_HANDSHAKE].timeout_ms = TMO_HANDSHAKE_MS;
    w->tl[TL_IDLE].timeout_ms      = (uint64_t)(keepalive_secs ? keepalive_secs : IDLE_TIMEOUT_SECS) * 1000u;
    w->tl[TL_IO].timeout_ms        = (uint64_t)IDLE_TIMEOUT_SECS * 1000u;
    w->tl[TL_LINGER].timeout_ms    = TMO_LINGER_MS;

    if (busy_poll_us > 0) {                       /* epoll busy-poll, Linux >= 6.9 */
        struct epoll_params bp = { .busy_poll_usecs = (uint32_t)busy_poll_us,
                                   .busy_poll_budget = 64, .prefer_busy_poll = 1 };
        ioctl(w->epfd, EPIOCSPARAMS, &bp);        /* best effort */
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;                          /* listeners: level-triggered */
    ev.data.ptr = &w->tag_tls;
    epoll_ctl(w->epfd, EPOLL_CTL_ADD, w->lfd_tls, &ev);
    ev.data.ptr = &w->tag_plain;
    epoll_ctl(w->epfd, EPOLL_CTL_ADD, w->lfd_plain, &ev);
    ev.data.ptr = &w->tag_stop;
    epoll_ctl(w->epfd, EPOLL_CTL_ADD, w->evfd, &ev);

    w->now_ms = mono_ms();
    uint64_t next_sweep = w->now_ms + SWEEP_INTERVAL_MS;
    int running = 1;

    while (running) {
        int n = epoll_wait(w->epfd, events, MAX_EVENTS, SWEEP_INTERVAL_MS);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }
        w->now_ms = mono_ms();

        for (int i = 0; i < n; i++) {
            int kind = *(int *)events[i].data.ptr;
            if (kind == EP_CONN) {
                conn_t *c = events[i].data.ptr;
                if (c->state == CS_DEAD) continue;      /* closed earlier this batch */
                uint32_t e = events[i].events;
                if (e & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) c->rd_ready = 1;
                if (e & (EPOLLOUT | EPOLLHUP | EPOLLERR))              c->wr_ready = 1;
                if (e & (EPOLLRDHUP | EPOLLHUP))                      c->rdhup = 1;
                conn_drive(c);
            } else if (kind == EP_LISTEN_TLS) {
                worker_accept(w, w->lfd_tls, 1);
            } else if (kind == EP_LISTEN_PLAIN) {
                worker_accept(w, w->lfd_plain, 0);
            } else if (kind == EP_STOP) {
                running = 0;
            }
        }

        if (w->now_ms >= next_sweep) {
            worker_sweep_idle(w);
            next_sweep = w->now_ms + SWEEP_INTERVAL_MS;
        }
        worker_reap(w);
        if (w->log_len) worker_log_flush(w);
    }

    /* shutting down: close everything this worker owns */
    close(w->lfd_tls);
    close(w->lfd_plain);
    for (int i = 0; i < TL_COUNT; i++)
        while (w->tl[i].head) conn_destroy(w->tl[i].head);
    worker_reap(w);
    while (w->free_list) {
        conn_t *c = w->free_list;
        w->free_list = c->next_pending;
        free(c->in); free(c->out); free(c);
    }
    if (w->log_len) worker_log_flush(w);
    if (w->spare_fd >= 0) close(w->spare_fd);
    return NULL;
}

#endif /* EPOLL_HELPERS_C_INCLUDED */
