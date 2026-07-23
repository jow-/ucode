#ifndef _UCODE_DEBUG_REMOTE_H
#define _UCODE_DEBUG_REMOTE_H

#include <ucode/types.h>

int debug_remote_create_attach_socket(void);
const char *debug_remote_get_socket_path(void);
void debug_remote_cleanup_attach_socket(void);

uc_value_t *uc_debug_listen(uc_vm_t *vm, size_t nargs);

/* Push unsolicited notifications to a connected debugger client, if any. */
void debug_remote_notify_exception(uc_vm_t *vm, uc_exception_t *ex);
void debug_remote_notify_signal(int signum);

/* Mark the given fd as the currently attached remote debugger connection
 * (or -1 for none), used by debug_remote_has_active_connection() and the
 * notify helpers above. Owned by whoever is currently driving the session
 * (either uc_debug_listen() or debug_cli_run_remote_session()). */
void debug_remote_set_active_fd(int fd);
bool debug_remote_has_active_connection(void);

/* Wait for a udbg client to connect to the SIGUSR1 attach socket, with a
 * 30s timeout. Returns the accepted client fd on success, -1 on timeout or
 * disconnect (caller should resume execution unattended), or -2 on a fatal
 * socket error (caller should give up). */
int debug_remote_handle_break(uc_vm_t *vm);

/* Provided by debug.c: run a full interactive debugger CLI session over an
 * already-connected client socket, reusing the local terminal debugger's
 * command set and readline-style editing. Takes ownership of client_fd
 * (closes it) and resumes script execution before returning. */
void debug_cli_run_remote_session(uc_vm_t *vm, int client_fd);

#endif
