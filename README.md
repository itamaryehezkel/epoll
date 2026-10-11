# Backend_Vanila -- opaq.co.il static-file HTTPS server

A static-file HTTPS server with a plain-HTTP port that redirects to HTTPS. It uses the kernel's TCP stack, driven by a pool of epoll worker threads tuned for as few system calls, locks, copies and bytes of memory per connection as possible. The only dependency is OpenSSL.

## Files

```
Backend_Vanila/
├── compile            build script -- only main.c goes on the gcc line
├── main.c             types, globals, arguments, TLS setup, certificates, helpers
├── epoll_helpers.c    TCP engine: listeners, workers, connection state machine (no need to touch)
├── handlers.c         ROUTES: request parser, route table, static files, :80 redirect
└── README.md
```

**Sites live in the folder above the binary**, one folder per domain or subdomain:

```
BACKEND_EPOLL/                 <- site root (found automatically)
├── opaq.co.il/index.html      <- https://opaq.co.il/  (also the fallback for unknown Hosts)
├── tv.opaq.co.il/index.html   <- https://tv.opaq.co.il/
└── Backend_Vanila/            <- the server
```

At startup the server prints the site root and every domain folder it found (`sites  opaq.co.il, tv.opaq.co.il`). It warns if the fallback domain's folder is missing.

Only folders named like a hostname (letters, digits, `-`, `.`, with at least one dot) are ever served. Sibling folders such as `Backend_Vanila/` or `certs/` can't be reached through the Host header.

`certs/` is looked for next to the binary first, then in the nearest parent folder that has it (up to 3 levels). From `Backend_Vanila/` that is the shared `TCP HTTPS/certs/`. `-r` / `-c` override both.

## Adding a route

Open `handlers.c` and go to section 4:

1. Write a function `static void route_x(conn_t *c, Request *req, const char *host)` that answers with `send_response(...)` or `serve_file(...)`.
2. Add one line to **THE ROUTE TABLE**, for example `{ M_GET, "/api/x", route_x },`.
3. Run `./compile`.

A commented-out example (`route_hello`) is already in the file. Paths not in the table are served as static files from `<site root>/<host>/`.

## Build and run (Linux)

```sh
chmod +x compile
./compile                  # -> ./itl_server_epoll         (needs libssl-dev)
./compile debug            # -> ./itl_server_epoll_debug   (AddressSanitizer + UBSan)

ulimit -n 1048576          # allow many connections (or LimitNOFILE=1048576 in systemd)
sudo modprobe tls          # optional: kernel TLS offload
sudo ./itl_server_epoll    # 10.0.0.2 :443 (https) + :80 (redirect), one worker per CPU
```

| flag | meaning | default |
|---|---|---|
| `-b` | IPv4 bind address | 10.0.0.2 |
| `-p` / `-P` | HTTPS / plain HTTP port | 443 / 80 |
| `-d` | fallback site for unknown Hosts and redirects | opaq.co.il |
| `-w` | worker threads | one per CPU |
| `-m` | max open connections, all workers together | as many as `ulimit -n` allows |
| `-r` / `-c` | site root / certificate folder | folder above the binary / nearest `certs/` |
| `-k` | keep-alive idle seconds, 0 = off | 15 |
| `-a 0/1` | pin workers to CPUs + steer each connection to the CPU that received it | 1 |
| `-l 0/1` | one log line per request | 1 |
| `-B usec` | busy-poll the network card instead of waiting for interrupts (lower latency, more CPU) | 0 (off) |

## How it scales

**Threads and descriptors.** Every worker thread has its own epoll instance, its own `SO_REUSEPORT` listening sockets, and thousands of connection descriptors. The kernel spreads new connections across the workers, and a worker never shares a connection, lock or queue with another. Running more threads than CPUs doesn't add capacity, so the default is one worker per CPU.

**What limits the connection count:**

| limit | what the server does |
|---|---|
| file descriptors (`ulimit -n`, often 1024 by default) | raises its soft limit to the hard limit at startup, splits it across workers, and prints the result |
| memory per connection | about 12 KB per idle TLS connection (was about 35 KB) |
| hitting the cap (`-m`, or fd limit) | refuses the extra connections cleanly and keeps serving the ones it has |
| running out of fds anyway (`EMFILE`) | a spare descriptor is kept to accept and close the pending connection, so the listener doesn't spin |

Memory per connection dropped because of three changes:
- `SSL_MODE_RELEASE_BUFFERS` frees OpenSSL's record buffers when they're empty.
- The server checks the socket (`FIONREAD`) before calling `SSL_read` on an idle connection, so OpenSSL doesn't allocate a buffer just to find nothing there.
- Request and response buffers are allocated on demand and freed when a connection goes idle.

At about 12 KB per connection, 1 GB of RAM holds around 80,000 idle TLS connections. Tested here: **18,000 simultaneous TLS connections** (the test machine's fd limit is 20,000) on 2 workers at 207 MB RSS, with new requests still answered in 5 ms.

**Server settings for large connection counts:**

```sh
sysctl -w net.core.somaxconn=65535
sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sysctl -w fs.file-max=2097152
```

Add `LimitNOFILE=1048576` in the systemd unit.

## HTTPS

* ALPN always negotiates **http/1.1**, including when the client offers h2 first. A client that only offers h2 connects without ALPN.
* Keep-alive is on: `send_response()` sends `Content-Length` and `Connection: keep-alive`, so a browser loads a page and all its files over one TLS handshake.
* Stateless session tickets (no locked session cache), `read_ahead`, AEAD suites with X25519, and kTLS when the kernel has it.
* A client that closes without close_notify (most browsers) is treated as a normal close, not an error (`SSL_OP_IGNORE_UNEXPECTED_EOF`).
* Both chains in `certs/` (RSA + ECDSA) are served; clients get the best one they support. Chains are loaded in full and checked at startup.

Benchmark on 2 vCPUs (wrk on the same machine):

| test | previous build | this build |
|---|---|---|
| `index.html`, 100 clients | about 3,400 req/s | **about 90,000 req/s** |
| 1 MB file, 20 clients | about 945 req/s | about 1,100–1,800 req/s |
| forced new connection per request | about 3,400 req/s | about 3,500 req/s (unchanged) |

Most of the gain comes from connections being reused instead of paying a TLS handshake per request.

## Serving

* The Host header, with any `:port` removed (`opaq.co.il:443` becomes `opaq.co.il`), picks `<site root>/<host>/`. An unknown or invalid Host is served from `<site root>/opaq.co.il/`.
* `..` in the path or the host is rejected, and anything not found gets a 404.
