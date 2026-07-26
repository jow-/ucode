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
#include "debug_proto.h"

static int remote_debug_fd = -1;


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

int
debug_remote_get_active_fd(void)
{
	return remote_debug_fd;
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


/* Shallow-copy a plain object's own keys into a fresh object with no
 * prototype - values are shared (ucv_get()'d, not deep-cloned).
 *
 * Used to defuse uc_vm_exception_object()'s tostring() prototype method
 * (attached for script-facing try/catch ergonomics, so `catch (e) {
 * print(e) }` prints the message) before JSON-serializing it: ucv_to_json
 * string() invokes tostring() if present instead of serializing the
 * object's own fields, which would collapse the whole thing down to just
 * the message string. Worse, invoking it runs through the VM's own call
 * machinery, which calls uc_vm_clear_exception() as a side effect - wiping
 * out vm->exception (including freeing ->message) out from under whatever
 * runs next. Copying rather than mutating the prototype in place on the
 * original object avoids surprising a caller who still holds a reference
 * to it for other purposes. */
static uc_value_t *
object_shallow_copy_no_proto(uc_vm_t *vm, uc_value_t *obj)
{
	uc_value_t *copy = ucv_object_new(vm);

	ucv_object_foreach(obj, k, v)
		ucv_object_add(copy, k, ucv_get(v));

	return copy;
}

/* Push an unsolicited exception notification to the connected debugger
 * client, if any, as the same JSON exception object shape script code sees
 * via try/catch ({type, message, stacktrace} - see uc_vm_exception_object()
 * in vm.c) - safe to call unconditionally from the VM's exception handler
 * chain; a no-op when nobody is attached. `ex` is expected to still be
 * `&vm->exception` at this point (true for the exception handler chain,
 * which runs synchronously before anything gets cleared), since the actual
 * object is built from vm->exception directly. */
void
debug_remote_notify_exception(uc_vm_t *vm, uc_exception_t *ex)
{
	uc_value_t *exo, *plain, *evo;

	(void)ex;

	if (remote_debug_fd < 0)
		return;

	exo = uc_vm_exception_object(vm);
	plain = object_shallow_copy_no_proto(vm, exo);
	ucv_put(exo);

	evo = ucv_object_new(vm);
	ucv_object_add(evo, "event", ucv_string_new("exception"));
	ucv_object_add(evo, "exception", plain);

	debug_proto_write(remote_debug_fd, vm, "EVENT", evo);
	ucv_put(evo);
}

static const char *
vm_status_name(uc_vm_status_t status)
{
	switch (status) {
	case STATUS_OK:      return "OK";
	case STATUS_EXIT:    return "EXIT";
	case STATUS_BREAK:   return "BREAK";
	case ERROR_COMPILE:  return "ERROR_COMPILE";
	case ERROR_RUNTIME:  return "ERROR_RUNTIME";
	default:             return "UNKNOWN";
	}
}

/* Push a final "the target is going away" notification to the connected
 * debugger client, if any, as a JSON object describing the full final VM
 * state - {status}, plus {code} for STATUS_EXIT or the same {type, message,
 * stacktrace} exception object shape used above for ERROR_COMPILE/
 * ERROR_RUNTIME. Called from main.c right after uc_vm_execute() returns,
 * before the process actually exits and the connection drops - without
 * this, a client only finds out the target is gone once the socket EOFs,
 * with no indication of why.
 *
 * Takes the raw uc_vm_status_t rather than main.c's own CLI exit-code
 * translation (which flattens both ERROR_COMPILE and ERROR_RUNTIME to the
 * same -2 and loses the actual exception), plus exit_code and a
 * pre-built exception object (or NULL). Both must be supplied by the
 * caller rather than read off the vm here: by the time this runs
 * (dispatched through a ucode-level call), uc_vm_call() has already
 * cleared vm->exception as its own first action, so main.c has to
 * snapshot vm->arg.s32 / call uc_vm_exception_object() *before* making
 * this call. */
void
debug_remote_notify_exit(uc_vm_t *vm, uc_vm_status_t status, int32_t exit_code,
                          uc_value_t *exception_obj)
{
	uc_value_t *evo;

	if (remote_debug_fd < 0)
		return;

	evo = ucv_object_new(vm);

	ucv_object_add(evo, "event", ucv_string_new("exit"));
	ucv_object_add(evo, "status", ucv_string_new(vm_status_name(status)));

	if (status == STATUS_EXIT)
		ucv_object_add(evo, "code", ucv_int64_new(exit_code));
	else if (exception_obj) {
		/* Copy without the tostring() prototype uc_vm_exception_object()
		 * attaches (for script-facing try/catch ergonomics) before nesting
		 * it - see the comment on object_shallow_copy_no_proto() above:
		 * otherwise ucv_to_jsonstring() below would invoke it and collapse
		 * this down to just the message string instead of serializing
		 * {type, message, stacktrace}. */
		uc_value_t *plain = object_shallow_copy_no_proto(vm, exception_obj);

		ucv_object_add(evo, "exception", plain);
	}

	debug_proto_write(remote_debug_fd, vm, "EVENT", evo);
	ucv_put(evo);
}
