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

/*
 * Remote debugger socket transport.
 *
 * This file only deals with the socket transport: creating Unix domain
 * sockets (both the PID-derived SIGUSR1 attach socket and arbitrary
 * caller-supplied paths for debug.listen()), accepting a `udbg` client
 * connection, and pushing asynchronous "EVENT " notifications to an
 * attached client. The script-facing debug.listen() API and the actual
 * interactive command session - which reuses the exact same command set,
 * tab completion and readline-style editing as the local terminal debugger
 * - live in debug.c (see uc_debug_listen() / debug_cli_run_remote_session()),
 * once a client fd has been accepted here.
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

static int remote_debug_fd = -1;


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


/* Create, bind (mode 0600) and listen on a Unix domain socket at the given
 * path, removing any stale socket file first. Shared by both the
 * SIGUSR1-triggered attach socket (fixed, PID-derived path) and
 * debug.listen() (arbitrary caller-supplied path). Returns the listening
 * fd, or -1 on error. */
static int
debug_remote_bind_and_listen(const char *path)
{
	struct sockaddr_un addr = { 0 };
	int listen_fd;
	socklen_t addrlen;
	mode_t old_umask;

	listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_fd < 0)
		return -1;

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
	addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';
	addrlen = sizeof(sa_family_t) + strlen(path) + 1;

	unlink(path);

	old_umask = umask(077);

	if (bind(listen_fd, (struct sockaddr *)&addr, addrlen) < 0) {
		umask(old_umask);
		close(listen_fd);
		return -1;
	}

	umask(old_umask);

	if (listen(listen_fd, 1) < 0) {
		close(listen_fd);
		return -1;
	}

	return listen_fd;
}


/* Global socket path for SIGUSR1-triggered attach */
static char attach_socket_path[1024] = { 0 };

int
debug_remote_create_attach_socket(void)
{
	pid_t pid = getpid();

	snprintf(attach_socket_path, sizeof(attach_socket_path),
		 "/tmp/ucode-debug-%d.sock", pid);

	return debug_remote_bind_and_listen(attach_socket_path);
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

/* Bind, listen on and accept a single connection on an arbitrary,
 * caller-supplied Unix domain socket path, blocking indefinitely. Returns
 * the accepted client fd, or -1 on error. Used by debug.listen(path) (see
 * debug.c) for the explicit-path case, as opposed to the PID-derived attach
 * socket used for the SIGUSR1/-X flow above. */
int
debug_remote_accept_on_path(const char *path)
{
	int listen_fd, client_fd;

	listen_fd = debug_remote_bind_and_listen(path);
	if (listen_fd < 0)
		return -1;

	client_fd = accept(listen_fd, NULL, NULL);
	close(listen_fd);

	/* The socket file is no longer needed once accepted (or on error) -
	 * the connection itself doesn't depend on the path persisting. */
	unlink(path);

	return client_fd;
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
