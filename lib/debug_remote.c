/*
 * Copyright (C) 2026 Jo-Philipp Wich <jo@mein.io>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ANY IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * @module debug
 */
/*
 *
 * Remote debugger attachment functionality.
 *
 * This module provides the `listen()` function which allows a running ucode
 * script to accept debugger connections from a separate `udbg` process.
 *
 *   ```
 *   import * as debug from 'debug';
 *
 *   // Start listening for debugger connections on a Unix socket
 *   debug.listen('/tmp/ucode-debug.sock');
 *
 *   // Script will pause here waiting for debugger connection
 *   ```
 *
 * Then connect with:
 *
 *   ```
 *   udbg /tmp/ucode-debug.sock
 *   ```
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "ucode/lib.h"
#include "ucode/util.h"
#include "ucode/vm.h"
#include "debug_remote.h"

/* Forward declaration from debug.c */
extern void uc_module_init_remote(uc_vm_t *vm, uc_value_t *scope);
#include "ucode/platform.h"
#include "ucode/compiler.h"
#include "ucode/vm.h"

#ifdef HAVE_ULOOP
#include <libubox/uloop.h>
#endif

/* External declarations for functions used by debug.c */
extern int debug_remote_create_attach_socket(void);
extern const char *debug_remote_get_socket_path(void);
extern void debug_remote_cleanup_attach_socket(void);
extern uc_value_t *uc_debug_listen(uc_vm_t *vm, size_t nargs);

bool debug_remote_loop(uc_vm_t *vm, int fd);
int debug_remote_handle_break(uc_vm_t *vm);
bool debug_remote_has_active_connection(void);

static int remote_debug_fd = -1;
static uc_vm_t *remote_debug_vm = NULL;
static char remote_socket_path[1024] = { 0 };
static bool run_program = true;


static void
debug_remote_cleanup_socket(void)
{
	if (remote_socket_path[0] != '\0') {
		unlink(remote_socket_path);
		remote_socket_path[0] = '\0';
	}
}


static void
debug_remote_close(void)
{
	debug_remote_cleanup_socket();
	debug_remote_cleanup_attach_socket();
	if (remote_debug_fd >= 0) {
		close(remote_debug_fd);
		remote_debug_fd = -1;
	}
}


/* Per-connection state for uloop-based line reading */
struct debug_remote_client_state {
	char buf[1024];
	size_t len;
};

static struct debug_remote_client_state client_state;

/* Read one line from fd into buf. Returns NULL on EAGAIN (need more data)
 * or on real EOF/error. On EAGAIN, partial data is preserved in client_state
 * and will be resumed on the next callback invocation. */
static char *
debug_read_line(int fd, char *buf, size_t buflen)
{
	ssize_t n;

	/* Copy any buffered partial line first */
	if (client_state.len > 0) {
		if (client_state.len >= buflen)
			client_state.len = buflen - 1;
		memcpy(buf, client_state.buf, client_state.len);
	}

	size_t len = client_state.len;

	while (len < buflen - 1) {
		n = read(fd, buf + len, 1);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/* Save partial line for next callback */
				memcpy(client_state.buf, buf, len);
				client_state.buf[len] = '\0';
				client_state.len = len;
				return NULL;
			}
			return NULL;
		}
		if (n == 0)
			return NULL;
		if (buf[len] == '\n') {
			buf[len] = '\0';
			client_state.len = 0;
			return buf;
		}
		len++;
	}

	buf[len] = '\0';
	client_state.len = 0;
	return buf;
}

/* Reset client read state (e.g., on new connection) */
static void
debug_remote_reset_client_state(void)
{
	client_state.len = 0;
	client_state.buf[0] = '\0';
}

/* Non-uloop version: blocking read_line for the fallback path */
static char *
debug_read_line_blocking(int fd, char *buf, size_t buflen)
{
	size_t len = 0;
	ssize_t n;

	while (len < buflen - 1) {
		n = read(fd, buf + len, 1);
		if (n <= 0)
			return NULL;
		if (buf[len] == '\n') {
			buf[len] = '\0';
			return buf;
		}
		len++;
	}

	buf[len] = '\0';
	return buf;
}


static void
debug_write_response(int fd, const char *fmt, ...)
{
	va_list ap;
	char buf[4096];
	ssize_t len;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (len > 0 && (size_t)len < sizeof(buf))
		write(fd, buf, len);
}


static void
debug_write_json_string(int fd, const char *str)
{
	size_t len = strlen(str);
	size_t i;

	write(fd, "\"", 1);
	for (i = 0; i < len; i++) {
		switch (str[i]) {
		case '"':  write(fd, "\\\"", 2); break;
		case '\\': write(fd, "\\\\", 2); break;
		case '\n': write(fd, "\\n", 2); break;
		case '\r': write(fd, "\\r", 2); break;
		case '\t': write(fd, "\\t", 2); break;
		default:
			if ((unsigned char)str[i] < 32) {
				char hexbuf[8];
				int hlen = sprintf(hexbuf, "\\u%04x", (unsigned char)str[i]);
				write(fd, hexbuf, hlen);
			} else
				write(fd, str + i, 1);
		}
	}
	write(fd, "\"", 1);
}


static void
debug_handle_command(uc_vm_t *vm, int fd, char *cmd)
{
	uc_value_t *scope = uc_vm_scope_get(vm);
	uc_value_t *result = NULL;

	if (strcmp(cmd, "continue") == 0 || strcmp(cmd, "c") == 0) {
		debug_write_response(fd, "Resuming execution...\n");
		run_program = true;
		return;
	}

	if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "q") == 0) {
		debug_write_response(fd, "OK\n");
		debug_remote_close();
		return;
	}

	if (strcmp(cmd, "help") == 0 || strcmp(cmd, "h") == 0) {
		debug_write_response(fd, "Commands: continue, quit, print <expr>, list, backtrace, help\n");
		return;
	}

	if (strncmp(cmd, "print ", 6) == 0 || strncmp(cmd, "p ", 2) == 0) {
		const char *expr = (cmd[0] == 'p' && cmd[1] == ' ') ? cmd + 2 : cmd + 6;
		uc_value_t *func = ucv_object_get(scope, "print", NULL);

		if (ucv_type(func) == UC_CLOSURE) {
			uc_vm_stack_push(vm, ucv_get(func));
			uc_vm_stack_push(vm, ucv_string_new(expr));

			if (uc_vm_call(vm, false, 1) == EXCEPTION_NONE) {
				result = uc_vm_stack_pop(vm);
				if (ucv_type(result) == UC_STRING) {
					debug_write_response(fd, "Result: ");
					debug_write_json_string(fd, ucv_string_get(result));
					debug_write_response(fd, "\n");
				}
				ucv_put(result);
			} else {
				debug_write_response(fd, "Exception\n");
			}
		} else {
			debug_write_response(fd, "Error: print function not available\n");
		}
		return;
	}

	if (strcmp(cmd, "list") == 0 || strcmp(cmd, "l") == 0) {
		debug_write_response(fd, "Listing not available in remote mode\n");
		return;
	}

	if (strcmp(cmd, "backtrace") == 0 || strcmp(cmd, "bt") == 0) {
		debug_write_response(fd, "Backtrace not available in remote mode\n");
		return;
	}

	debug_write_response(fd, "Unknown command: %s\n", cmd);
}


bool
debug_remote_loop(uc_vm_t *vm, int fd)
{
	char buf[1024];
	char *line;

	while ((line = debug_read_line_blocking(fd, buf, sizeof(buf))) != NULL) {
		if (strlen(line) == 0)
			continue;

		debug_handle_command(vm, fd, line);

		if (remote_debug_fd < 0)
			break;
	}

	return (remote_debug_fd < 0);
}

#ifdef HAVE_ULOOP
static struct uloop_fd listen_uloop_fd;
static struct uloop_fd client_uloop_fd;
static struct uloop_timeout connect_timeout;
static uc_vm_t *uloop_vm = NULL;
static int uloop_result = -1;

static void
debug_remote_uloop_client_cb(struct uloop_fd *u, unsigned int events)
{
	if (events & ULOOP_READ) {
		char buf[1024];
		char *line;
		int fd = u->fd;

		line = debug_read_line(fd, buf, sizeof(buf));

		if (line == NULL) {
			/* If we have partial data buffered, EAGAIN — keep waiting */
			if (client_state.len > 0)
				return;
			/* Connection closed or real error */
			uloop_fd_delete(u);
			debug_remote_close();
			uloop_result = 0;
			return;
		}

		if (strlen(line) == 0)
			return;

		debug_handle_command(uloop_vm, fd, line);

		if (remote_debug_fd < 0) {
			uloop_fd_delete(u);
			uloop_result = 0;
		}
	}
}

static void
debug_remote_uloop_accept_cb(struct uloop_fd *u, unsigned int events)
{
	if (events & ULOOP_READ) {
		int listen_fd = u->fd;
		int client_fd = accept(listen_fd, NULL, NULL);

		if (client_fd < 0) {
			debug_remote_cleanup_attach_socket();
			uloop_fd_delete(u);
			uloop_result = 1;
			return;
		}

		/* Remove listen fd from uloop */
		uloop_fd_delete(u);
		close(listen_fd);

		remote_debug_fd = client_fd;
		remote_debug_vm = uloop_vm;

		debug_write_response(client_fd,
			"Connected to ucode debugger. Type 'help' for commands.\n");

		/* Reset client read state for new connection */
		debug_remote_reset_client_state();

		/* Register client fd with uloop */
		client_uloop_fd.cb = debug_remote_uloop_client_cb;
		client_uloop_fd.fd = client_fd;
		uloop_fd_add(&client_uloop_fd, ULOOP_READ);

		/* Cancel connect timeout */
		uloop_timeout_cancel(&connect_timeout);

		/* Stop program execution - wait for client commands */
		run_program = false;
	}
}

static void
debug_remote_uloop_timeout_cb(struct uloop_timeout *t)
{
	fprintf(stderr, "Timeout waiting for debugger connection - continuing execution\n");
	uloop_result = 0;
}
#endif

/* Called by debug.c when STATUS_BREAK is returned in -X mode.
 * Becomes the main execution loop: handles VM execution and client commands.
 * Returns 0 if execution should resume, 1 if the program should exit. */
int
debug_remote_handle_break(uc_vm_t *vm)
{
	int listen_fd = debug_remote_create_attach_socket();

	if (listen_fd < 0) {
		fprintf(stderr, "Failed to create attach socket: %s\n", strerror(errno));
		return 1;
	}

	fprintf(stderr, "Debugger socket ready, waiting for connection...\n");

#ifdef HAVE_ULOOP
	uloop_vm = vm;
	uloop_result = -1;
	run_program = true;

	/* Register listen fd with uloop */
	listen_uloop_fd.cb = debug_remote_uloop_accept_cb;
	listen_uloop_fd.fd = listen_fd;
	uloop_fd_add(&listen_uloop_fd, ULOOP_READ);

	/* Install 30s connect timeout */
	connect_timeout.cb = debug_remote_uloop_timeout_cb;
	uloop_timeout_set(&connect_timeout, 30000);

	/* Main loop: handle VM execution and client commands */
	for (;;) {
		/* Process uloop events (client commands, listen socket) */
		uloop_run_timeout(0);

		/* If timeout expired without client, resume execution */
		if (uloop_result == 0 && remote_debug_fd < 0) {
			uloop_fd_delete(&listen_uloop_fd);
			return 0;
		}

		/* If client connected, handle commands and VM execution */
		if (remote_debug_fd >= 0) {
			if (run_program) {
				int rc = uc_vm_resume(vm);

				if (rc == STATUS_BREAK) {
					/* VM hit a breakpoint - stop and wait for commands */
					run_program = false;
					debug_write_response(remote_debug_fd,
						"Program paused at breakpoint. Type 'help' for commands.\n");
				} else if (rc == STATUS_EXIT) {
					/* Program exited */
					debug_write_response(remote_debug_fd, "Program exited.\n");
					debug_remote_close();
					uloop_fd_delete(&listen_uloop_fd);
					return 1;
				} else if (rc == STATUS_OK) {
					/* Program completed normally */
					debug_write_response(remote_debug_fd, "Program completed.\n");
					debug_remote_close();
					uloop_fd_delete(&listen_uloop_fd);
					return 1;
				} else {
					/* Uncaught exception (ERROR_RUNTIME/ERROR_COMPILE) - the
					 * exception notification was already pushed to the client
					 * via the VM's exception handler chain; just terminate. */
					debug_remote_close();
					uloop_fd_delete(&listen_uloop_fd);
					return 1;
				}
			}
		} else if (uloop_result == 0) {
			/* Client disconnected or continue - resume execution */
			uloop_fd_delete(&listen_uloop_fd);
			debug_remote_close();
			return 0;
		} else if (uloop_result < 0) {
			/* No client yet and no timeout - keep waiting */
			continue;
		} else {
			/* Error or quit */
			uloop_fd_delete(&listen_uloop_fd);
			debug_remote_close();
			return 1;
		}
	}
#else
	/* Fallback: wait for client connection with 30s timeout, retry on EINTR */
	{
		fd_set readfds;
		struct timeval tv;
		int ret;

		for (;;) {
			FD_ZERO(&readfds);
			FD_SET(listen_fd, &readfds);
			tv.tv_sec = 30;
			tv.tv_usec = 0;

			ret = select(listen_fd + 1, &readfds, NULL, NULL, &tv);

			if (ret < 0 && errno == EINTR)
				continue;

			break;
		}

		if (ret > 0) {
			int client_fd = accept(listen_fd, NULL, NULL);
			close(listen_fd);
			if (client_fd < 0) {
				debug_remote_cleanup_attach_socket();
				return 1;
			}

			remote_debug_fd = client_fd;
			remote_debug_vm = vm;

			debug_write_response(client_fd,
				"Connected to ucode debugger. Type 'help' for commands.\n");

			debug_remote_loop(vm, client_fd);

			debug_remote_close();

			return 0;
		}

		close(listen_fd);
		debug_remote_cleanup_attach_socket();

		if (ret == 0) {
			fprintf(stderr, "Timeout waiting for debugger connection - continuing execution\n");
			return 0;
		}

		fprintf(stderr, "Error waiting for debugger connection: %s\n", strerror(errno));

		return 1;
	}
#endif
}


/* Global socket path for SIGUSR1-triggered attach */
static char attach_socket_path[1024] = { 0 };

int
debug_remote_create_attach_socket(void)
{
	struct sockaddr_un addr = { 0 };
	int listen_fd;
	socklen_t addrlen;
	mode_t old_umask;
	pid_t pid = getpid();

	/* Create socket path */
	snprintf(attach_socket_path, sizeof(attach_socket_path),
		 "/tmp/ucode-debug-%d.sock", pid);

	/* Create socket */
	listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_fd < 0)
		return -1;

	/* Set up address */
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, attach_socket_path, sizeof(addr.sun_path) - 1);
	addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';
	addrlen = sizeof(sa_family_t) + strlen(attach_socket_path) + 1;

	/* Remove existing socket file */
	unlink(attach_socket_path);

	/* Set umask for socket permissions */
	old_umask = umask(077);

	/* Bind */
	if (bind(listen_fd, (struct sockaddr *)&addr, addrlen) < 0) {
		umask(old_umask);
		close(listen_fd);
		return -1;
	}

	umask(old_umask);

	/* Listen */
	if (listen(listen_fd, 1) < 0) {
		close(listen_fd);
		return -1;
	}

	return listen_fd;
}

const char *
debug_remote_get_socket_path(void)
{
	return attach_socket_path[0] ? attach_socket_path : NULL;
}

void
debug_remote_cleanup_attach_socket(void)
{
	if (attach_socket_path[0] != '\0') {
		unlink(attach_socket_path);
		attach_socket_path[0] = '\0';
	}
}

/**
 * Listen for debugger connection.
 *
 * This function creates a Unix domain socket at the specified path and waits
 * for a debugger client (like `udbg`) to connect. Once connected, the script
 * will pause and handle debugger commands until the connection is closed or
 * a "continue" command is received.
 *
 * The socket file will be created with permissions 0600 and removed on
 * cleanup.
 *
 * @param {string} path
 * The Unix domain socket path to listen on (e.g., "/tmp/ucode-debug.sock")
 *
 * @returns {boolean}
 * `true` if the listener was set up successfully, `false` on error.
 *
 * @example
 * import * as debug from 'debug';
 *
 * debug.listen("/tmp/ucode-debug.sock");
 *
 * // Script is now paused, waiting for debugger connection
 * // Connect with: udbg /tmp/ucode-debug.sock
 */
uc_value_t *
uc_debug_listen(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path_val = uc_fn_arg(0);
	struct sockaddr_un addr = { 0 };
	int listen_fd, client_fd;
	socklen_t addrlen;
	char *path;
	mode_t old_umask;

	if (ucv_type(path_val) != UC_STRING)
		return ucv_boolean_new(false);

	path = (char *)ucv_string_get(path_val);

	/* Create socket */
	listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_fd < 0)
		return ucv_boolean_new(false);

	/* Set up address */
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
	addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';
	addrlen = sizeof(sa_family_t) + strlen(path) + 1;

	/* Remove existing socket file */
	unlink(path);

	/* Set umask for socket permissions */
	old_umask = umask(077);

	/* Bind */
	if (bind(listen_fd, (struct sockaddr *)&addr, addrlen) < 0) {
		umask(old_umask);
		close(listen_fd);
		return ucv_boolean_new(false);
	}

	umask(old_umask);

	/* Listen */
	if (listen(listen_fd, 1) < 0) {
		close(listen_fd);
		return ucv_boolean_new(false);
	}

	/* Accept connection (blocking) */
	client_fd = accept(listen_fd, NULL, NULL);
	close(listen_fd);

	if (client_fd < 0)
		return ucv_boolean_new(false);

	remote_debug_fd = client_fd;
	remote_debug_vm = vm;

	/* Send welcome message */
	debug_write_response(client_fd, "Connected to ucode debugger. Type 'help' for commands.\n");

	/* Run command loop - this will block until continue/quit */
	debug_remote_loop(vm, client_fd);

	debug_remote_close();

	return ucv_boolean_new(true);
}

bool
debug_remote_has_active_connection(void)
{
	return remote_debug_fd >= 0;
}


static const char *exception_type_names[] = {
	[EXCEPTION_NONE]      = "None",
	[EXCEPTION_SYNTAX]    = "SyntaxError",
	[EXCEPTION_RUNTIME]   = "RuntimeError",
	[EXCEPTION_TYPE]      = "TypeError",
	[EXCEPTION_REFERENCE] = "ReferenceError",
	[EXCEPTION_USER]      = "Error",
	[EXCEPTION_EXIT]      = "Exit",
};

/* Push an unsolicited exception notification to the connected debugger
 * client, if any. Safe to call unconditionally from the VM's exception
 * handler chain; a no-op when nobody is attached. */
void
debug_remote_notify_exception(uc_vm_t *vm, uc_exception_t *ex)
{
	const char *typenam;

	if (remote_debug_fd < 0)
		return;

	typenam = (ex->type >= 0 && (size_t)ex->type < ARRAY_SIZE(exception_type_names) &&
			exception_type_names[ex->type])
		? exception_type_names[ex->type] : "Error";

	debug_write_response(remote_debug_fd, "EVENT exception %s: %s\n",
		typenam, ex->message ? ex->message : "");
}

/* Push an unsolicited signal notification to the connected debugger client.
 * Called from the SIGUSR1 signal handler when a debugger is already
 * attached, so this must stay async-signal-safe: no vsnprintf, no malloc,
 * just a raw write() of a fixed message. */
void
debug_remote_notify_signal(int signum)
{
	static const char msg[] = "EVENT signal SIGUSR1 received (already attached, ignoring)\n";

	(void)signum;

	if (remote_debug_fd >= 0) {
		if (write(remote_debug_fd, msg, sizeof(msg) - 1) == -1) {}
	}
}


static const uc_function_list_t debug_remote_fns[] = {
	{ "listen",	uc_debug_listen },
};


void uc_module_init_remote(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, debug_remote_fns);
}
