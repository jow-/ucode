// http-client.uc - Simple HTTP/1.1 client using libc socket primitives
// Demonstrates FFI with network sockets, DNS resolution, and binary data handling
// Note: This demo shows the structure but network calls may fail due to network issues

import * as ffi from 'ffi';

// ============================================================================
// C Declarations
// ============================================================================

ffi.cdef(`
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

// ============================================================================
// Helper Functions
// ============================================================================

function stringToBytes(str) {
    let arr = ffi.ctype('char[' + (length(str) + 1) + ']');
    ffi.copy(arr.ptr(), str, length(str) + 1);
    return arr;
}

function createBuffer(size) {
    let buf = ffi.ctype('char[' + size + ']');
    ffi.fill(buf, size, 0);
    return buf;
}

function die(msg) {
    print("Error: ", msg, "\n");
    exit(1);
}

// ============================================================================
// HTTP Response Object
// ============================================================================

function HTTPResponse_create(status, statusText, headers, body) {
    return {
        status: status,
        statusText: statusText,
        headers: headers || {},
        body: body || '',

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
                return parse_json(this.body);
            } catch (e) {
                return null;
            }
        }
    };
}

// ============================================================================
// HTTP Client Object
// ============================================================================

function HTTPClient_create(host, port) {
    port = port || 80;

    let socket_fn = ffi.C.wrap('socket');
    let sock = socket_fn(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sock < 0)
        die("Failed to create socket");

    // Resolve hostname using getaddrinfo
    let getaddrinfo_fn = ffi.C.wrap('getaddrinfo');
    let freeaddrinfo_fn = ffi.C.wrap('freeaddrinfo');

    let hints = {
        ai_family: AF_INET,
        ai_socktype: SOCK_STREAM,
        ai_protocol: IPPROTO_TCP,
        ai_flags: 0
    };

    let resPtr = ffi.ctype('struct addrinfo *', null);
    let rc = getaddrinfo_fn(host, '' + port, hints, resPtr.ptr());
    if (rc !== 0) {
        let close_fn = ffi.C.wrap('close');
        close_fn(sock);
        die("Failed to resolve " + host + ": " + rc);
    }

    // Use index() to get pointer without auto-conversion
    let sockaddr = resPtr.index('ai_addr');
    let ai_addrlen = resPtr.get('ai_addrlen');

    let connect_fn = ffi.C.wrap('connect');
    rc = connect_fn(sock, sockaddr, ai_addrlen);

    freeaddrinfo_fn(resPtr);

    if (rc < 0) {
        let close_fn = ffi.C.wrap('close');
        close_fn(sock);
        die("Failed to connect to " + host + ":" + port);
    }

    return {
        host: host,
        port: port,
        socket: sock,

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
            let reqBytes = stringToBytes(request);
            let send_fn = ffi.C.wrap('send');
            let sent = send_fn(
                this.socket, reqBytes.ptr(), reqBytes.length(), 0
            );

            if (sent < 0)
                die("Failed to send request");

            // Receive response
            let chunks = [];
            let chunkSize = 4096;

            while (true) {
                let chunk = ffi.ctype('char[' + chunkSize + ']');
                let recv_fn = ffi.C.wrap('recv');
                let n = recv_fn(
                    this.socket, chunk.ptr(), chunkSize, 0
                );

                if (n < 0) {
                    let err = ffi.errno();
                    die("recv failed: " + err);
                }

                if (n === 0)
                    break;

                // Use slice() to convert received bytes to string
                push(chunks, chunk.slice(0, n));
            }

            if (length(chunks) === 0)
                die("No data received");

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
            if (this.socket !== null) {
                let shutdown_fn = ffi.C.wrap('shutdown');
                shutdown_fn(this.socket, SHUT_RDWR);
                let close_fn = ffi.C.wrap('close');
                close_fn(this.socket);
                this.socket = null;
            }
        }
    };
}

// ============================================================================
// Convenience Functions
// ============================================================================

function parseUrl(url) {
    // Remove http:// or https:// prefix
    let prefix = index(url, "://");
    if (prefix >= 0) {
        url = substr(url, prefix + 3);
    }

    let path = '/';
    let slashIdx = index(url, '/');
    if (slashIdx >= 0) {
        path = substr(url, slashIdx);
        url = substr(url, 0, slashIdx);
    }

    let host = url;
    let port = 80;
    let colonIdx = index(url, ':');
    if (colonIdx >= 0) {
        host = substr(url, 0, colonIdx);
        port = int(substr(url, colonIdx + 1));
    }

    return { host: host, path: path, port: port };
}

function httpGet(url) {
    let urlParts = parseUrl(url);
    let client = HTTPClient_create(urlParts.host, urlParts.port);
    let response = client.get(urlParts.path);
    client.close();
    return response;
}

// ============================================================================
// Main
// ============================================================================

if (length(ARGV) < 1) {
    print("Usage: ", SCRIPT_NAME, " <url>\n");
    print("Example: ", SCRIPT_NAME, " http://httpbin.org/get\n");
    exit(1);
}

let url = ARGV[0];
let urlParts = parseUrl(url);

print("GET ", url, "\n");

try {
    let client = HTTPClient_create(urlParts.host, urlParts.port);
    let response = client.get(urlParts.path);
    client.close();

    print(response.body);
} catch (e) {
    print("Error: ", e, "\n");
    exit(1);
}
