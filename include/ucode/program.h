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

#ifndef UCODE_PROGRAM_H
#define UCODE_PROGRAM_H

#include "types.h"


uc_program_t *uc_program_new(uc_source_t *);

static inline uc_program_t *
uc_program_get(uc_program_t *prog) {
	return (uc_program_t *)ucv_get(prog ? &prog->header : NULL);
}

static inline void
uc_program_put(uc_program_t *prog) {
	ucv_put(prog ? &prog->header : NULL);
}

#define uc_program_function_foreach(prog, fn)			\
	uc_function_t *fn;									\
	for (fn = (uc_function_t *)prog->functions.prev;	\
	     fn != (uc_function_t *)&prog->functions; 		\
	     fn = (uc_function_t *)fn->progref.prev)

#define uc_program_function_foreach_safe(prog, fn)		\
	uc_function_t *fn, *fn##_tmp;						\
	for (fn = (uc_function_t *)prog->functions.prev, 	\
	     fn##_tmp = (uc_function_t *)fn->progref.prev;	\
	     fn != (uc_function_t *)&prog->functions; 		\
	     fn = fn##_tmp, 								\
	     fn##_tmp = (uc_function_t *)fn##_tmp->progref.prev)

uc_function_t *uc_program_function_new(uc_program_t *, const char *, size_t);
size_t uc_program_function_id(uc_program_t *, uc_function_t *);
uc_function_t *uc_program_function_load(uc_program_t *, size_t);
size_t uc_program_function_srcpos(uc_function_t *, size_t);
void uc_program_function_free(uc_function_t *);


uc_value_t *uc_program_get_constant(uc_program_t *, size_t);
ssize_t uc_program_add_constant(uc_program_t *, uc_value_t *);

void uc_program_write(uc_program_t *, FILE *, bool);
uc_program_t *uc_program_load(uc_source_t *, char **);

uc_function_t *uc_program_entry(uc_program_t *);

#endif /* UCODE_PROGRAM_H */
