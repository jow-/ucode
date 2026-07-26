#ifndef _UCODE_DEBUG_REMOTE_H
#define _UCODE_DEBUG_REMOTE_H

#include <ucode/types.h>
#include <ucode/vm.h>

int debug_remote_create_attach_socket(void);
const char *debug_remote_get_socket_path(void);
void debug_remote_cleanup_attach_socket(void);

/* Accept a single connection on an arbitrary, caller-supplied Unix domain
 * socket path, blocking indefinitely. Returns the accepted client fd, or -1
 * on error. Used by debug.listen(path) for the explicit-path case. */
int debug_remote_accept_on_path(const char *path);

/* Push unsolicited notifications to a connected debugger client, if any, as
 * "EVENT {json}" protocol messages (see debug_proto.h) - the JSON payload
 * always carries a discriminating "event" field ("exception"/"exit"). */
void debug_remote_notify_exception(uc_vm_t *vm, uc_exception_t *ex);
void debug_remote_notify_exit(uc_vm_t *vm, uc_vm_status_t status, int32_t exit_code,
                               uc_value_t *exception_obj);

/* Mark the given fd as the currently attached debugger session connection
 * (or -1 for none), used by debug_remote_has_active_connection() and the
 * notify helpers above - shared by both the remote and local (-x) cases,
 * since both ultimately just hand a connected fd to bk_enter_session().
 * Owned by whoever is currently driving the session (debug_run_session()). */
void debug_remote_set_active_fd(int fd);
bool debug_remote_has_active_connection(void);
int debug_remote_get_active_fd(void);

/* Wait for a udbg client to connect to the SIGUSR1 attach socket, with a
 * 30s timeout. Returns the accepted client fd on success, -1 on timeout or
 * disconnect (caller should resume execution unattended), or -2 on a fatal
 * socket error (caller should give up). */
int debug_remote_handle_break(uc_vm_t *vm);

/* Provided by debug.c: run a full interactive debugger session over an
 * already-connected client socket, speaking the line-based debug protocol
 * (see debug_proto.h). Takes ownership of client_fd (closes it) and resumes
 * script execution before returning. */
void debug_run_session(uc_vm_t *vm, int client_fd);

#endif
