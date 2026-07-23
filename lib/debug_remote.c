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
 * This file only deals with the socket transport: creating the Unix domain
 * socket(s), accepting a `udbg` client connection (with a timeout for the
 * SIGUSR1 attach flow), and pushing asynchronous "EVENT " notifications to
 * an attached client. The actual interactive command session - which reuses
 * the exact same command set, tab completion and readline-style editing as
 * the local terminal debugger - is driven by debug_cli_run_remote_session()
 * in debug.c, once a client fd has been accepted here.
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

static int remote_debug_fd = -1;
static char remote_socket_path[1024] = { 0 };


static void
debug_remote_cleanup_socket(void)
{
	if (remote_socket_path[0] != '\0') {
		unlink(remote_socket_path);
		remote_socket_path[0] = '\0';
	}
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

	if (len > 0 && (size_t)len < sizeof(buf)) {
		if (write(fd, buf, len) == -1) {}
	}
}


void
debug_remote_set_active_fd(int fd)
{
	remote_debug_fd = fd;
}

bool
debug_remote_has_active_connection(void)
{
	return remote_debug_fd >= 0;
}


/* Wait for a udbg client to connect to the SIGUSR1 attach socket, with a
 * 30s timeout. Returns the accepted client fd on success, -1 on timeout
 * (caller should resume execution unattended), or -2 on a fatal error. */
int
debug_remote_handle_break(uc_vm_t *vm)
{
	int listen_fd = debug_remote_create_attach_socket();
	fd_set readfds;
	struct timeval tv;
	int ret, client_fd;

	if (listen_fd < 0) {
		fprintf(stderr, "Failed to create attach socket: %s\n", strerror(errno));
		return -2;
	}

	fprintf(stderr, "Debugger socket ready, waiting for connection...\n");

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

	if (ret <= 0) {
		close(listen_fd);
		debug_remote_cleanup_attach_socket();

		if (ret == 0)
			fprintf(stderr, "Timeout waiting for debugger connection - continuing execution\n");
		else
			fprintf(stderr, "Error waiting for debugger connection: %s\n", strerror(errno));

		return -1;
	}

	client_fd = accept(listen_fd, NULL, NULL);
	close(listen_fd);

	if (client_fd < 0) {
		debug_remote_cleanup_attach_socket();
		return -1;
	}

	return client_fd;
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
 * pauses and hands control to the same interactive command-line debugger
 * used for local sessions (breakpoints, stepping, variable inspection, etc.)
 * until the connection is closed or the `quit` command is issued.
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

	strncpy(remote_socket_path, path, sizeof(remote_socket_path) - 1);

	/* Run the full interactive debugger CLI session over this connection;
	 * takes ownership of client_fd and resumes script execution before
	 * returning. */
	debug_cli_run_remote_session(vm, client_fd);

	debug_remote_cleanup_socket();

	return ucv_boolean_new(true);
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
