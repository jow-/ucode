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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "ucode/util.h"
#include "debug_proto.h"

#define DEBUG_PROTO_READ_CHUNK 1024

void
debug_proto_buf_init(debug_proto_buf_t *buf)
{
	buf->data = NULL;
	buf->len = 0;
	buf->cap = 0;
}

void
debug_proto_buf_free(debug_proto_buf_t *buf)
{
	free(buf->data);
	buf->data = NULL;
	buf->len = 0;
	buf->cap = 0;
}

void
debug_proto_write(int fd, uc_vm_t *vm, const char *verb, uc_value_t *payload)
{
	uc_stringbuf_t *sb = xprintbuf_new();
	const char *p;
	size_t remaining;
	ssize_t n;
	char *json;

	printbuf_memappend_fast(sb, verb, (int)strlen(verb));

	if (payload) {
		json = ucv_to_jsonstring(vm, payload);

		if (json) {
			printbuf_memappend_fast(sb, " ", 1);
			printbuf_memappend_fast(sb, json, (int)strlen(json));
			free(json);
		}
	}

	printbuf_memappend_fast(sb, "\n", 1);

	p = sb->buf;
	remaining = (size_t)printbuf_length(sb);

	while (remaining > 0) {
		n = write(fd, p, remaining);

		if (n < 0) {
			if (errno == EINTR)
				continue;

			break;
		}

		p += n;
		remaining -= (size_t)n;
	}

	printbuf_free(sb);
}

/* Append `len` bytes to the tail of buf, growing its backing storage as
 * needed. Returns false on allocation failure (buf is left unchanged). */
static bool
buf_append(debug_proto_buf_t *buf, const char *data, size_t len)
{
	char *newdata;
	size_t newcap;

	if (buf->len + len > buf->cap) {
		newcap = buf->cap ? buf->cap : DEBUG_PROTO_READ_CHUNK;

		while (newcap < buf->len + len)
			newcap *= 2;

		newdata = realloc(buf->data, newcap);

		if (!newdata)
			return false;

		buf->data = newdata;
		buf->cap = newcap;
	}

	memcpy(buf->data + buf->len, data, len);
	buf->len += len;

	return true;
}

/* Drop the first `n` bytes already consumed as a message from the front of
 * buf, shifting any remaining buffered bytes down. */
static void
buf_consume(debug_proto_buf_t *buf, size_t n)
{
	memmove(buf->data, buf->data + n, buf->len - n);
	buf->len -= n;
}

int
debug_proto_read(int fd, debug_proto_buf_t *buf, uc_vm_t *vm,
                  char **verb_out, uc_value_t **payload_out)
{
	char chunk[DEBUG_PROTO_READ_CHUNK];
	char *line, *sp, *verb;
	struct json_tokener *tok;
	json_object *jso;
	size_t line_len, verb_len, json_len;
	ssize_t n;

	*verb_out = NULL;
	*payload_out = NULL;

	for (;;) {
		char *nl = memchr(buf->data, '\n', buf->len);

		if (nl) {
			line_len = (size_t)(nl - buf->data);
			break;
		}

		n = read(fd, chunk, sizeof(chunk));

		if (n < 0) {
			if (errno == EINTR)
				continue;

			return -1;
		}

		if (n == 0)
			return 0;

		if (!buf_append(buf, chunk, (size_t)n))
			return -1;
	}

	line = malloc(line_len + 1);

	if (!line)
		return -1;

	memcpy(line, buf->data, line_len);
	line[line_len] = '\0';
	buf_consume(buf, line_len + 1);

	if (line_len > 0 && line[line_len - 1] == '\r')
		line[--line_len] = '\0';

	sp = memchr(line, ' ', line_len);
	verb_len = sp ? (size_t)(sp - line) : line_len;

	verb = malloc(verb_len + 1);

	if (!verb) {
		free(line);

		return -1;
	}

	memcpy(verb, line, verb_len);
	verb[verb_len] = '\0';

	json_len = sp ? line_len - verb_len - 1 : 0;

	if (json_len > 0) {
		tok = xjs_new_tokener();

		/* len + 1 to include the trailing NUL: works around json-c
		 * treating a lone atomic value (e.g. `true`) as incomplete
		 * without a following delimiter, see json-c issue #681. */
		jso = json_tokener_parse_ex(tok, sp + 1, (int)json_len + 1);

		if (json_tokener_get_error(tok) != json_tokener_success) {
			json_tokener_free(tok);
			json_object_put(jso);
			free(verb);
			free(line);

			return -2;
		}

		*payload_out = ucv_from_json(vm, jso);

		json_tokener_free(tok);
		json_object_put(jso);
	}

	free(line);
	*verb_out = verb;

	return 1;
}
