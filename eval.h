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

#ifndef __MATCHER_H_
#define __MATCHER_H_

#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <regex.h>

#include "ast.h"

bool
ut_cmp(int how, struct json_object *v1, struct json_object *v2);

bool
ut_val_is_truish(struct json_object *val);

enum json_type
ut_cast_number(struct json_object *v, int64_t *n, double *d);

struct json_object *
ut_invoke(struct ut_state *, uint32_t, struct json_object *, struct json_object *, struct json_object *);

enum ut_error_type
ut_run(struct ut_state *state, struct json_object *env, struct json_object *modules);

#endif
