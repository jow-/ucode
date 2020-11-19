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

typedef struct json_object *(uc_c_fn)(struct uc_state *, uint32_t, struct json_object *);

void uc_lib_init(struct uc_state *state, struct json_object *scope);

struct json_object *uc_execute_source(struct uc_state *s, struct uc_source *src, struct uc_scope *scope);

struct json_object *uc_parse_error(struct uc_state *s, uint32_t off, uint64_t *tokens, int max_token);

char *uc_format_error(struct uc_state *state, FILE *fp);

#endif /* __LIB_H_ */
