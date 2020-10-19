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

#ifndef __MODULE_H_
#define __MODULE_H_

#include "ast.h"
#include "lib.h"

struct ut_ops {
	bool (*register_function)(struct ut_state *, struct json_object *, const char *, ut_c_fn *);
	bool (*register_type)(const char *, struct json_object *, void (*)(void *));
	struct json_object *(*set_type)(struct json_object *, const char *, void *);
	void **(*get_type)(struct json_object *, const char *);
	struct json_object *(*new_object)(struct json_object *);
	struct json_object *(*new_double)(double);
	struct json_object *(*invoke)(struct ut_state *, uint32_t, struct json_object *, struct json_object *, struct json_object *);
	enum json_type (*cast_number)(struct json_object *, int64_t *, double *);
};

extern const struct ut_ops ut;

#define register_functions(state, ops, functions, scope) \
	if (scope) \
		for (int i = 0; i < ARRAY_SIZE(functions); i++) \
			ops->register_function(state, scope, functions[i].name, functions[i].func)

void ut_module_init(const struct ut_ops *, struct ut_state *, struct json_object *);

#endif /* __MODULE_H_ */
