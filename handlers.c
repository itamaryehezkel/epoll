/* ====================================================================
 *  handlers.c -- the routes
 *
 *  This is the only file you need to touch to add a page or an API
 *  endpoint. Scroll down to "THE ROUTE TABLE": write a function, add one
 *  line to the table, rebuild with ./compile. That's it.
 *
 *  What is in here, top to bottom:
 *
 *    1. parse_request()     bytes -> Request (method, uri, query, headers,
 *                           body). Allocates nothing: every string points
 *                           into the connection's input buffer.
 *    2. header lookups      get_header(), get_header_default()
 *    3. response helpers    send_response(), serve_file()
 *    4. YOUR ROUTES         route functions + THE ROUTE TABLE
 *    5. handle_request()    looks the request up in the table; anything
 *                           not listed is served as a static file
 *    6. the :80 redirect    handle_http_redirect()
 *
 *  NOT a separate translation unit -- main.c #includes it, so it sees
 *  every type and helper declared there. Don't add it to the gcc line.
 * ==================================================================== */
#ifndef HANDLERS_C_INCLUDED
#define HANDLERS_C_INCLUDED

/* ==================================================================== *
 *  1. Request parsing
 * ==================================================================== */

#define MAX_HEADERS 100

/* The header table lives in per-thread storage instead of being
   calloc'd for every request: a Request is only ever used by the worker
   thread that parsed it, and only until its handler returns. */
static __thread char  *hdr_rows[MAX_HEADERS][3];
static __thread char **hdr_table[MAX_HEADERS + 1];

static char *trim_inplace(char *s) {
    if (!s) return NULL;
    while (*s == ' ' || *s == '\t') s++;
    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'))
        *--end = '\0';
    return s;
}

static Method method_of(const char *m) {
    if (!strcmp(m, "GET"))     return M_GET;
    if (!strcmp(m, "POST"))    return M_POST;
    if (!strcmp(m, "HEAD"))    return M_HEAD;
    if (!strcmp(m, "PUT"))     return M_PUT;
    if (!strcmp(m, "DELETE"))  return M_DELETE;
    if (!strcmp(m, "PATCH"))   return M_PATCH;
    if (!strcmp(m, "OPTIONS")) return M_OPTIONS;
    if (!strcmp(m, "TRACE"))   return M_TRACE;
    if (!strcmp(m, "CONNECT")) return M_CONNECT;
    return M_UNSUPPORTED;
}

/* The engine calls this once a whole request (headers + Content-Length
   body) is in c->in. Check .parsed: 1 = usable, 0 = malformed (the
   engine drops the connection). Always followed by free_headers(). */
Request parse_request(conn_t *c) {
    Request r;
    memset(&r, 0, sizeof(r));
    r.c           = c;
    r.is_tls      = c->is_tls;
    r.buffer      = c->in;
    r.buffer_size = (int)c->in_cap;
    r.total_read  = (int)c->in_len;
    memcpy(r.ip, c->ip, INET_ADDRSTRLEN);

    if (c->headers_end < 0) return r;
    char *buf  = c->in;
    char *hend = buf + c->headers_end;

    /* request line: METHOD SP URI SP VERSION CRLF */
    char *nl = memchr(buf, '\n', (size_t)c->headers_end);
    if (!nl || nl == buf || nl[-1] != '\r') return r;
    nl[-1] = '\0';

    char *sp1 = strchr(buf, ' ');
    if (!sp1) return r;
    *sp1 = '\0';
    char *uri = sp1 + 1;
    char *sp2 = strchr(uri, ' ');
    if (!sp2) return r;
    *sp2 = '\0';

    r.method  = method_of(buf);
    r.version = sp2 + 1;
    char *q = strchr(uri, '?');
    if (q) { *q = '\0'; r.query = q + 1; }
    r.uri = uri;

    /* headers: "Name: value" lines up to the blank line */
    int n = 0;
    char *p = nl + 1;
    while (p < hend) {
        char *e = memchr(p, '\n', (size_t)(hend - p));
        if (!e) break;
        char *le = (e > p && e[-1] == '\r') ? e - 1 : e;
        if (le == p) break;                         /* blank line */
        *le = '\0';
        char *colon = strchr(p, ':');
        if (colon && n < MAX_HEADERS) {
            *colon = '\0';
            char *name = trim_inplace(p);
            if (*name) {
                hdr_rows[n][0] = name;
                hdr_rows[n][1] = trim_inplace(colon + 1);
                hdr_rows[n][2] = NULL;
                hdr_table[n] = hdr_rows[n];
                n++;
            }
        }
        p = e + 1;
    }
    hdr_table[n]    = NULL;
    r.headers       = hdr_table;
    r.headers_count = n;

    if (c->in_len > (size_t)c->headers_end) {
        r.body     = hend;
        r.body_len = c->in_len - (size_t)c->headers_end;
    }
    r.parsed = 1;
    return r;
}

/* Nothing to free any more (the table is per-thread); kept so callers
   don't change. */
void free_headers(Request *req) {
    if (!req) return;
    req->headers = NULL;
    req->headers_count = 0;
}

/* ==================================================================== *
 *  2. Header lookups
 * ==================================================================== */

/* Case-insensitive. Returns the trimmed value, or NULL if absent. */
char *get_header(Request *req, const char *name) {
    if (!req || !req->headers || !name) return NULL;
    for (int i = 0; req->headers[i]; i++)
        if (strcasecmp(req->headers[i][0], name) == 0)
            return req->headers[i][1];
    return NULL;
}

char *get_header_default(Request *req, const char *name, char *fallback) {
    char *v = get_header(req, name);
    return v ? v : fallback;
}

/* ==================================================================== *
 *  3. Response helpers -- use these from your routes
 * ==================================================================== */

/* Queue a complete response. Adds Content-Length and the right
   Connection header (so the browser can reuse the connection for its
   next request), and leaves the body out for HEAD requests. */
static void send_response(conn_t *c, Request *req, int status, const char *reason,
                          const char *content_type, const void *body, size_t len) {
    char hdr[512];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "\r\n",
        status, reason, content_type, len, conn_keepalive_hdr(c));
    out_append(c, hdr, (size_t)n);
    if (req->method != M_HEAD && len) out_append(c, body, len);
}

/* Serve <site root>/<host><path>, or a 404 if it isn't an allowed file. */
static void serve_file(conn_t *c, Request *req, const char *host, const char *path) {
    FileInfo f = { 0, NULL };
    if (is_file_allowed(workspace, host, path))
        f = get_file(host, path);

    if (!f.data) {
        send_response(c, req, 404, "Not Found", "text/plain; charset=utf-8", "not found\n", 10);
        return;
    }
    char ctype[128];
    snprintf(ctype, sizeof(ctype), "%s; charset=utf-8", get_mime_type(path));
    send_response(c, req, 200, "OK", ctype, f.data, f.size);
    free(f.data);
}

/* ==================================================================== *
 *  4. YOUR ROUTES
 *
 *  A route is a function with this signature:
 *
 *      static void route_name(conn_t *c, Request *req, const char *host)
 *
 *  What you get in `req`:
 *      req->method     M_GET, M_POST, M_PUT, M_DELETE, ...
 *      req->uri        path without the query, e.g. "/api/data"
 *      req->query      text after '?', or NULL
 *      req->body       request body (req->body_len bytes), or NULL
 *      req->ip         client IPv4 address as text
 *      get_header(req, "Cookie")   any request header, or NULL
 *
 *  `host` is the site being served (the Host header, already checked and
 *  without ":port") -- its files live in <site root>/<host>/.
 *
 *  To answer, call send_response() or serve_file() exactly once.
 * ==================================================================== */

/* "/" and "/index.html" -> the site's index.html */
static void route_index(conn_t *c, Request *req, const char *host) {
    serve_file(c, req, host, "/index.html");
}

/* Example -- uncomment it and its line in the table to try it:

static void route_hello(conn_t *c, Request *req, const char *host) {
    static const char body[] = "{\"hello\":\"world\"}";
    send_response(c, req, 200, "OK", "application/json", body, sizeof(body) - 1);
}
*/

typedef void (*route_fn)(conn_t *c, Request *req, const char *host);

/* ---------------------------------------------------------------------
 *  THE ROUTE TABLE -- add one line per endpoint.
 *
 *  Matching is exact on the path. An M_GET entry also answers HEAD.
 *  Anything not listed here falls through to static files from
 *  <site root>/<host>/ (GET/HEAD only), then 404.
 * --------------------------------------------------------------------- */
static const struct { Method method; const char *path; route_fn fn; } routes[] = {
    { M_GET,  "/",             route_index },
    { M_GET,  "/index.html",   route_index },
 /* { M_GET,  "/api/hello",    route_hello }, */
 /* { M_POST, "/api/login",    route_login }, */
};

/* ==================================================================== *
 *  5. Dispatch -- normally no need to edit below this line
 * ==================================================================== */

static void handle_request(conn_t *c, Request *req) {

    /* The Host header names the site folder. Strip ":port" and only
       accept a host we have a folder for -- anything else is served from
       DOMAIN's folder. is_known_host() also rejects "..", "/" and CR/LF. */
    char host[256];
    const char *h = get_header_default(req, "Host", domain);
    size_t i = 0;
    while (h[i] && h[i] != ':' && i + 1 < sizeof(host)) { host[i] = h[i]; i++; }
    host[i] = '\0';
    if (!is_known_host(host)) snprintf(host, sizeof(host), "%s", domain);

    for (size_t r = 0; r < sizeof(routes) / sizeof(routes[0]); r++) {
        int method_ok = routes[r].method == req->method ||
                        (routes[r].method == M_GET && req->method == M_HEAD);
        if (method_ok && strcmp(routes[r].path, req->uri) == 0) {
            routes[r].fn(c, req, host);
            return;
        }
    }

    if (req->method == M_GET || req->method == M_HEAD) {
        serve_file(c, req, host, req->uri);         /* css, js, images, ... */
        return;
    }
    send_response(c, req, 404, "Not Found", "text/plain; charset=utf-8", "not found\n", 10);
}

/* ==================================================================== *
 *  6. The plain-HTTP port: 302 up to https://<host>/
 * ==================================================================== */

/* Does this server serve `host`? True when `host` looks like a hostname
   and <site root>/<host> is a directory. Also the trust boundary for the
   redirect: a Host we don't serve is never reflected into a Location. */
static int is_known_host(const char *host) {
    if (!host || !*host || contains_dotdot(host)) return 0;
    int dots = 0;
    for (const char *p = host; *p; ++p) {
        if (*p == '.') dots++;
        else if (!(isalnum((unsigned char)*p) || *p == '-')) return 0;
    }
    /* A real hostname has a dot. The site root is the folder ABOVE the
       binary, so this is what stops "Host: certs" or "Host: src" from
       serving a sibling folder that isn't a website. */
    if (dots == 0 || host[0] == '.') return 0;

    char candidate[PATH_MAX];
    int n = snprintf(candidate, sizeof(candidate), "%s%s", workspace, host);
    if (n < 0 || n >= (int)sizeof(candidate)) return 0;
    struct stat st;
    return stat(candidate, &st) == 0 && S_ISDIR(st.st_mode);
}

static const char *redirect_host(Request *req, char *buf, size_t buflen) {
    const char *h = get_header(req, "Host");
    if (!h || !*h) return domain;
    size_t n = 0;
    while (h[n] && h[n] != ':' && n + 1 < buflen) n++;
    if (h[n] && h[n] != ':') return domain;
    memcpy(buf, h, n);
    buf[n] = '\0';
    return is_known_host(buf) ? buf : domain;
}

static void handle_http_redirect(conn_t *c, Request *req) {
    char hostbuf[256];
    const char *host = redirect_host(req, hostbuf, sizeof(hostbuf));
    char response[512];
    int n = snprintf(response, sizeof(response),
                     "HTTP/1.1 302 Found\r\n"
                     "Location: https://%s/\r\n"
                     "Content-Length: 0\r\n"
                     "Connection: close\r\n\r\n", host);
    if (n > 0 && n < (int)sizeof(response))
        out_append(c, response, (size_t)n);
}

#endif /* HANDLERS_C_INCLUDED */
