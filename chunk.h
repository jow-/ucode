/*
 * Copyright (C) 2020-2021 Jo-Philipp Wich <jo@mein.io>
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

#ifndef __CHUNK_H_
#define __CHUNK_H_

#include <stdint.h>
#include <stddef.h>

#include "value.h"
#include "util.h"


typedef struct {
	size_t from, to, target, slot;
} uc_ehrange;

typedef struct {
	size_t from, to, slot, nameidx;
} uc_varrange;

uc_declare_vector(uc_ehranges, uc_ehrange);
uc_declare_vector(uc_variables, uc_varrange);
uc_declare_vector(uc_offsetinfo, uint8_t);

typedef struct {
	size_t count;
	uint8_t *entries;
	uc_value_list constants;
	uc_ehranges ehranges;
	struct {
		uc_variables variables;
		uc_value_list varnames;
		uc_offsetinfo offsets;
	} debuginfo;
} uc_chunk;

void uc_chunk_init(uc_chunk *chunk);
void uc_chunk_free(uc_chunk *chunk);
size_t uc_chunk_add(uc_chunk *chunk, uint8_t byte, size_t line);

typedef struct uc_value_t uc_value_t;

ssize_t uc_chunk_add_constant(uc_chunk *chunk, uc_value_t *value);
uc_value_t *uc_chunk_get_constant(uc_chunk *chunk, size_t idx);
void uc_chunk_pop(uc_chunk *chunk);

size_t uc_chunk_debug_get_srcpos(uc_chunk *chunk, size_t off);
void uc_chunk_debug_add_variable(uc_chunk *chunk, size_t from, size_t to, size_t slot, bool upval, uc_value_t *name);
uc_value_t *uc_chunk_debug_get_variable(uc_chunk *chunk, size_t off, size_t slot, bool upval);

#endif /* __CHUNK_H_ */
