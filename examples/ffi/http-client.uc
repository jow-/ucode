// http-client.uc - HTTP/1.1 client with optional HTTPS support
// Demonstrates FFI with network sockets, DNS resolution, and OpenSSL TLS
// Note: This demo shows the structure but network calls may fail due to network issues

import * as ffi from 'ffi';

// ============================================================================
// Load OpenSSL if available
// ============================================================================

let SSL = null;

try {
    // Load libssl with automatic function wrapping using cdefs
    SSL = ffi.dlopen('ssl', false, `
        typedef struct ssl_ctx_st SSL_CTX;
        typedef struct ssl_st SSL;

        SSL_CTX *SSL_CTX_new(void *method);
        void SSL_CTX_free(SSL_CTX *ctx);
        int SSL_CTX_set_verify(SSL_CTX *ctx, int mode, void *callback);
        int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *cafile, const char *capath);

        SSL *SSL_new(SSL_CTX *ctx);
        void SSL_free(SSL *ssl);
        int SSL_set_fd(SSL *ssl, int fd);
        int SSL_connect(SSL *ssl);
        int SSL_read(SSL *ssl, void *buf, int num);
        int SSL_write(SSL *ssl, const void *buf, int num);
        int SSL_shutdown(SSL *ssl);
        long SSL_get_verify_result(SSL *ssl);
        const char *SSL_get_error(SSL *ssl, int ret);
        long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);

        void *TLS_client_method(void);
        void OPENSSL_init_ssl(long opts, const void *settings);
    `);
    print("OpenSSL loaded successfully\n");
} catch (e) {
    print("Warning: Could not load OpenSSL - HTTPS not available\n");
    SSL = null;
}

// ============================================================================
// Load libc with socket functions using dlopen cdefs
// ============================================================================

let libc = ffi.dlopen(null, false, `
    typedef int socklen_t;
    typedef unsigned short sa_family_t;
    typedef unsigned short in_port_t;

    struct in_addr {
        unsigned int s_addr;
    };

    struct sockaddr_in {
        sa_family_t sin_family;
        in_port_t sin_port;
        struct in_addr sin_addr;
        char sin_zero[8];
    };

    struct addrinfo {
        int ai_flags;
        int ai_family;
        int ai_socktype;
        int ai_protocol;
        socklen_t ai_addrlen;
        struct sockaddr_in *ai_addr;
        char *ai_canonname;
        struct addrinfo *ai_next;
    };

    int socket(int domain, int type, int protocol);
    int connect(int sockfd, struct sockaddr_in *addr, socklen_t addrlen);
    ssize_t send(int sockfd, const char *buf, size_t len, int flags);
    ssize_t recv(int sockfd, char *buf, size_t len, int flags);
    int close(int fd);
    int shutdown(int fd, int how);
    int getaddrinfo(const char *node, const char *service, struct addrinfo *hints, struct addrinfo **result);
    void freeaddrinfo(struct addrinfo *ai);
`);

// Constants
const AF_INET = 2;
const SOCK_STREAM = 1;
const IPPROTO_TCP = 6;
const SHUT_RDWR = 2;

// OpenSSL constants
const SSL_VERIFY_NONE = 0;
const SSL_VERIFY_PEER = 1;

// ============================================================================
// HTTPResponse_create - Factory for HTTP response objects
//
// Creates an HTTPResponse object with standard property access and helper
// methods for inspecting the response. This object wraps raw HTTP response
// data into a usable interface.
//
// Parameters:
//   status     - HTTP status code (e.g. 200, 404, 500)
//   statusText - Human-readable status text (e.g. "OK", "Not Found")
//   headers    - Object mapping header names to values (default: {})
//   body       - Response body as a string
//
// Methods available on the returned object:
//   ok()           - Returns true if status is in 2xx range
//   clientError()  - Returns true if status is in 4xx range
//   serverError()  - Returns true if status is 5xx or above
//   getHeader(n)   - Returns header value, case-insensitive key lookup
//   json()         - Attempts to parse body as JSON, returns null on failure
//
// Usage:
//   let resp = HTTPResponse_create(200, "OK", {"Content-Type": "text/html"}, "<html>")
//   if (resp.ok()) {
//       print("Headers Content-Type: ", resp.getHeader("content-type"), "\n");
//   }
// ============================================================================

function HTTPResponse_create(status, statusText, headers, body) {
    return proto({
        status: status,
        statusText: statusText,
        headers: headers || {},
        body: body || ''
    }, {
        ok: function() {
            return this.status >= 200 && this.status < 300;
        },

        clientError: function() {
            return this.status >= 400 && this.status < 500;
        },

        serverError: function() {
            return this.status >= 500;
        },

        getHeader: function(name) {
            let lowerName = name.toLowerCase();
            for (let key in this.headers) {
                if (key.toLowerCase() === lowerName)
                    return this.headers[key];
            }
            return null;
        },

        json: function() {
            try {
                return json(this.body);
            } catch (e) {
                return null;
            }
        }
    });
}

// ============================================================================
// SSLConnection_create - Wrapper for SSL/TLS connections
//
// Establishes a TLS session over an existing TCP socket using OpenSSL.
// Sets up certificate verification mode, configures SNI hostname support,
// and performs the SSL handshake. The returned object wraps the SSL state
// and provides transparent read/write methods that can be used in place
// of raw socket I/O.
//
// Parameters:
//   sock  - TCP socket file descriptor returned by libc.socket()
//   host  - Server hostname string (used for SNI extension)
//
// Methods available on the returned object:
//   read(buf, len)      - Read up to len bytes through SSL (like SSL_read)
//   write(buf, len)     - Write up to len bytes through SSL (like SSL_write)
//   shutdown()          - Send SSL close alert and free SSL/CTX resources
//   close()             - Shutdown SSL and close the underlying socket
//
// Usage (within HTTPClient_create after socket connect):
//   let conn = SSLConnection_create(sock, "example.com");
//   conn.write(request, len);    // sends encrypted data
//   conn.read(buf, 4096);        // reads decrypted data
//   conn.close();                // cleanup
// ============================================================================

function SSLConnection_create(sock, host) {
    if (!SSL)
        die("Error: OpenSSL not available - HTTPS not supported\n");

    // Get TLS method and create context
    let tls_method = SSL.TLS_client_method();
    let ssl_ctx = SSL.SSL_CTX_new(tls_method);

    if (!ssl_ctx)
        die("Error: Failed to create SSL context\n");

    // Set verify mode (disable verification for simplicity - not recommended for production)
    SSL.SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, null);

    // Create SSL structure
    let ssl = SSL.SSL_new(ssl_ctx);
    if (!ssl) {
        SSL.SSL_CTX_free(ssl_ctx);
        die("Error: Failed to create SSL structure\n");
    }

    // Set the socket file descriptor
    if (SSL.SSL_set_fd(ssl, sock) !== 1) {
        SSL.SSL_free(ssl);
        SSL.SSL_CTX_free(ssl_ctx);
        die("Error: Failed to set SSL fd\n");
    }

    // Set SNI hostname (Server Name Indication)
    // SSL_CTRL_SET_TLSEXT_HOSTNAME = 55
    const SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
    SSL.SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, 0, host);

    // Perform SSL handshake
    let ret = SSL.SSL_connect(ssl);
    if (ret !== 1) {
        let err = SSL.SSL_get_error(ssl, ret);
        SSL.SSL_free(ssl);
        SSL.SSL_CTX_free(ssl_ctx);
        die("Error: SSL handshake failed: " + ffi.string(err) + "\n");
    }

    return {
        ssl: ssl,
        ssl_ctx: ssl_ctx,
        sock: sock,

        read: function(buf, len) {
            return SSL.SSL_read(this.ssl, buf, len);
        },

        write: function(buf, len) {
            return SSL.SSL_write(this.ssl, buf, len);
        },

        shutdown: function() {
            SSL.SSL_shutdown(this.ssl);
            SSL.SSL_free(this.ssl);
            SSL.SSL_CTX_free(this.ssl_ctx);
        },

        close: function() {
            this.shutdown();
            libc.close(this.sock);
        }
    };
}

// ============================================================================
// HTTPClient_create - Low-level HTTP/1.1 client object
//
// Creates a raw HTTP client with manual request construction. Manages socket
// lifecycle including DNS resolution via getaddrinfo, TCP connection, and
// optional SSL/TLS upgrade. This is the foundational client used by
// httpGet() but provides full control over request details.
//
// The returned object is a closure over the socket and SSL state, providing
// methods to construct and send HTTP requests. All responses are parsed into
// HTTPResponse objects.
//
// Parameters:
//   host     - Server hostname (e.g. "example.com")
//   port     - Server port number, defaults to 80 if omitted
//   useSSL   - If true and OpenSSL is available, upgrades to HTTPS
//
// Methods available on the returned object:
//   get(path, headers)     - Send GET request to path with optional extra headers
//   post(path, body, headers) - Send POST request with body (auto-sets Content-Type
//                              and Content-Length headers if not provided)
//   request(method, path, body, headers) - Generic method for any HTTP verb
//   close()                - Shut down socket (and SSL if active)
//
// Usage:
//   let client = HTTPClient_create("httpbin.org", 80);
//   let resp = client.get("/get");
//   print("Status: ", resp.status, "\nBody: ", resp.body, "\n");
//   client.close();
//
//   let client = HTTPClient_create("example.com", 443, true);
//   let resp = client.post("/api/data", '{"key":"value"}');
//   client.close();
// ============================================================================

function HTTPClient_create(host, port, useSSL) {
    port = port || 80;
    useSSL = useSSL || false;
    let sock = libc.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sock < 0)
        die("Error: Failed to create socket\n");

    // Resolve hostname using getaddrinfo
    let hints = {
        ai_family: AF_INET,
        ai_socktype: SOCK_STREAM,
        ai_protocol: IPPROTO_TCP,
        ai_flags: 0
    };

    let resPtr = ffi.ctype('struct addrinfo *', null);
    let rc = libc.getaddrinfo(host, '' + port, hints, resPtr.ptr());
    if (rc !== 0) {
        libc.close(sock);
        die("Error: Failed to resolve " + host + ":" + port + "\n");
    }

    // Use index() to get pointer without auto-conversion
    let sockaddr = resPtr.index('ai_addr');
    let ai_addrlen = resPtr.get('ai_addrlen');
    rc = libc.connect(sock, sockaddr, ai_addrlen);

    libc.freeaddrinfo(resPtr);

    if (rc < 0) {
        libc.close(sock);
        die("Error: Failed to connect to " + host + ":" + port + "\n");
    }

    // Upgrade to SSL if requested
    let conn = null;
    if (useSSL) {
        conn = SSLConnection_create(sock, host);
    }

    return {
        host: host,
        port: port,
        socket: sock,
        ssl: conn,
        useSSL: useSSL,

        get: function(path, headers) {
            headers = headers || {};
            return this.request("GET", path, null, headers);
        },

        post: function(path, body, headers) {
            headers = headers || {};
            headers["Content-Type"] = headers["Content-Type"] || "application/x-www-form-urlencoded";
            headers["Content-Length"] = '' + length(body);
            return this.request("POST", path, body, headers);
        },

        request: function(method, path, body, headers) {
            // Build request
            let request = method + " " + path + " HTTP/1.1\r\n";
            request = request + "Host: " + this.host + "\r\n";
            request = request + "Connection: close\r\n";

            for (let key in headers) {
                request = request + key + ": " + headers[key] + "\r\n";
            }

            if (body)
                request = request + body + "\r\n";

            request = request + "\r\n";

            // Send request
            let sent;
            if (this.ssl) {
                sent = this.ssl.write(request, length(request));
            } else {
                sent = libc.send(this.socket, request, length(request), 0);
            }

            if (sent < 0)
                die("Error: Failed to send request\n");

            // Receive response
            let chunks = [];
            let chunkSize = 4096;

            while (true) {
                let chunk = ffi.ctype('char[' + chunkSize + ']');
                let n;
                if (this.ssl) {
                    n = this.ssl.read(chunk.ptr(), chunkSize);
                } else {
                    n = libc.recv(this.socket, chunk.ptr(), chunkSize, 0);
                }

                if (n < 0) {
                    let err = ffi.errno();
                    die("Error: read failed: " + err + "\n");
                }

                if (n === 0)
                    break;

                // Use slice() to convert received bytes to string
                push(chunks, chunk.slice(0, n));
            }

            if (length(chunks) === 0)
                die("Error: No data received\n");

            // Parse response
            let data = join('', chunks);

            // Parse status: "HTTP/1.1 200 OK"
            let status = 0;
            let statusText = "OK";

            let m = match(data, /^HTTP\/1\.[01] (\d\d\d) (.+)\r\n/);
            if (m) {
                status = int(m[1]);
                statusText = m[2];
            }

            // Find body after \r\n\r\n
            let crlfcrlf = index(data, "\r\n\r\n");
            let responseBody = '';
            if (crlfcrlf >= 0) {
                responseBody = substr(data, crlfcrlf + 4);
            }

            let responseHeaders = { "Content-Type": "application/json" };

            return HTTPResponse_create(status, statusText, responseHeaders, responseBody);
        },

        close: function() {
            if (this.ssl) {
                this.ssl.close();
            } else if (this.socket !== null) {
                libc.shutdown(this.socket, SHUT_RDWR);
                libc.close(this.socket);
                this.socket = null;
            }
        }
    };
}

// ============================================================================
// Convenience Functions
// ============================================================================

// =============================================================================
// parseUrl - URL string parser
//
// Splits a URL string into its component parts: scheme, host, port, and path.
// Handles standard http/https schemes with optional port specification and path.
//
// Parameters:
//   url - Complete URL string (e.g. "https://example.com:8443/api/v1?query")
//
// Returns object with properties:
//   host  - Server hostname without port
//   port  - Port number (443 for https, 80 for http, or extracted from URL)
//   path  - URL path starting with '/' (defaults to '/' if no path)
//   scheme - URL scheme as a string ("http" or "https")
//
// Usage:
//   let parts = parseUrl("https://api.example.com:8443/users/list");
//   // returns: { host: "api.example.com", port: 8443, path: "/users/list", scheme: "https" }
//   let client = HTTPClient_create(parts.host, parts.port, parts.scheme === "https");
//   let resp = client.get(parts.path);
// ============================================================================

function parseUrl(url) {
    let scheme = "http";
    
    // Check for http:// or https:// prefix
    let prefix = index(url, "://");
    if (prefix >= 0) {
        let beforePrefix = substr(url, 0, prefix);
        if (beforePrefix === "https") {
            scheme = "https";
        }
        url = substr(url, prefix + 3);
    }

    let path = '/';
    let slashIdx = index(url, '/');
    if (slashIdx >= 0) {
        path = substr(url, slashIdx);
        url = substr(url, 0, slashIdx);
    }

    let host = url;
    let port = scheme === "https" ? 443 : 80;
    let colonIdx = index(url, ':');
    if (colonIdx >= 0) {
        host = substr(url, 0, colonIdx);
        port = int(substr(url, colonIdx + 1));
    }

    return { host: host, path: path, port: port, scheme: scheme };
}

function httpGet(url) {
    // Quick one-shot HTTP GET using the full HTTPClient pipeline.
    // Parses the URL, establishes connection (with optional SSL), sends
    // the request, receives the response, and cleans up the connection.
    let urlParts = parseUrl(url);
    let client = HTTPClient_create(urlParts.host, urlParts.port, urlParts.scheme === "https");
    let response = client.get(urlParts.path);
    client.close();
    return response;
}

// ============================================================================
// Main
// ============================================================================

if (length(ARGV) < 1) {
    print("Usage: ucode ", SCRIPT_NAME, " <url>\n");
    print("Example: ucode ", SCRIPT_NAME, " http://httpbin.org/get\n");
    print("Example: ucode ", SCRIPT_NAME, " https://httpbin.org/get\n");
    exit(1);
}

let url = ARGV[0];
let urlParts = parseUrl(url);

print("GET ", url, "\n");

try {
    let client = HTTPClient_create(urlParts.host, urlParts.port, urlParts.scheme === "https");
    let response = client.get(urlParts.path);
    client.close();

    print("\n--- Response ---\n");
    print(response.body);
} catch (e) {
    print("Error: ", e, "\n");
    exit(1);
}
