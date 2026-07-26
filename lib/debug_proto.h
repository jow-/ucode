#ifndef _UCODE_DEBUG_PROTO_H
#define _UCODE_DEBUG_PROTO_H

#include <stddef.h>

#include <ucode/types.h>
#include <ucode/vm.h>

/*
 * Line-based debug protocol framing.
 *
 * One message per line: an uppercase VERB, optionally followed by a single
 * space and a JSON-encoded object payload, terminated by '\n'. Used for both
 * directions of traffic (client commands and server responses/events), and
 * by every transport (local socketpair, remote Unix domain socket).
 */

/* Incremental read buffer, one per connection. Zero-initialize (or use
 * debug_proto_buf_init()) before first use; release with
 * debug_proto_buf_free() once the connection is done. */
typedef struct {
	char *data;
	size_t len;
	size_t cap;
} debug_proto_buf_t;

void debug_proto_buf_init(debug_proto_buf_t *buf);
void debug_proto_buf_free(debug_proto_buf_t *buf);

/* Write a single "VERB json\n" (or "VERB\n" if payload is NULL) message to
 * fd. Best-effort: I/O errors are silently swallowed, matching the previous
 * debug_write_response() semantics - a dead/blocked peer must never be fatal
 * to the caller. payload is not consumed/freed. */
void debug_proto_write(int fd, uc_vm_t *vm, const char *verb, uc_value_t *payload);

/* Read a single message from fd, using buf to hold data already read from
 * fd but not yet consumed as a full line (refilled from fd as needed).
 * Blocks until a full line is available, EOF, or an I/O error occurs.
 *
 * On success (return 1), *verb_out is set to a newly heap-allocated,
 * NUL-terminated verb string (caller must free()) and *payload_out to the
 * parsed JSON payload, or NULL if the line carried no payload.
 *
 * Returns 0 on clean EOF, -1 on I/O error, -2 if the line's payload could
 * not be parsed as JSON (verb/payload are left untouched in both error
 * cases).
 */
int debug_proto_read(int fd, debug_proto_buf_t *buf, uc_vm_t *vm,
                      char **verb_out, uc_value_t **payload_out);

#endif
