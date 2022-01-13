/*
 * Copyright (C) 2022 Jo-Philipp Wich <jo@mein.io>
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

#ifndef __PROGRAM_H_
#define __PROGRAM_H_

#include "types.h"


uc_program_t *uc_program_new(uc_source_t *);

void uc_program_free(uc_program_t *);

uc_value_t *uc_program_function_new(uc_program_t *, const char *, size_t);
size_t uc_program_function_id(uc_program_t *, uc_value_t *);
uc_value_t *uc_program_function_load(uc_program_t *, size_t);

uc_value_t *uc_program_get_constant(uc_program_t *, size_t);
ssize_t uc_program_add_constant(uc_program_t *, uc_value_t *);

#endif /* __PROGRAM_H_ */
