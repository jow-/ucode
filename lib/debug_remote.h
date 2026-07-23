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

#endif
