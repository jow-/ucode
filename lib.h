/*
 * Copyright (C) 2020 Jo-Philipp Wich <jo@mein.io>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __LIB_H_
#define __LIB_H_

#include "ast.h"
#include "lexer.h"

typedef struct json_object *(ut_c_fn)(struct ut_state *, struct ut_opcode *, struct json_object *);

static inline int
ut_c_fn_to_string(struct json_object *v, struct printbuf *pb, int level, int flags)
{
	return sprintbuf(pb, "%sfunction(...) { [native code] }%s",
		level ? "\"" : "", level ? "\"" : "");
}

static inline bool
ut_add_function(struct ut_state *state, struct json_object *scope, const char *name, ut_c_fn *fn)
{
	struct ut_opcode *op = ut_new_op(state, T_CFUNC,
		json_object_new_boolean(0), (struct ut_opcode *)fn, (void *)1);

	json_object_set_serializer(op->val, ut_c_fn_to_string, op, NULL);

	return json_object_object_add(scope, name, json_object_get(op->val));
}

void ut_lib_init(struct ut_state *state, struct json_object *scope);

char *ut_format_error(struct ut_state *state, const char *expr);

#endif /* __LIB_H_ */
