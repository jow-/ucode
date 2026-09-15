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

#include <stdio.h>

#include <ucode/types.h>

/* Serialized bytecode format version. */
#define UCODE_BYTECODE_VERSION 0x02

/* Create a new, empty program. */
uc_program_t *uc_program_new(void);

/* Reference counting. uc_program_t is an opaque refcounted value; these are
 * the only ways downstream should acquire/release a program. */
uc_program_t *uc_program_get(uc_program_t *prog);
void uc_program_put(uc_program_t *prog);

/* Serialize a program to a stream, or load one (plain or precompiled) from a
 * source. uc_program_load takes ownership of the source. */
void uc_program_write(uc_program_t *prog, FILE *fp, bool compressed);
uc_program_t *uc_program_load(uc_source_t *source, char **errp);

/* Return the program's top-level entry function, or NULL if the program is
 * empty. The returned function is owned by the program. */
uc_function_t *uc_program_entry(uc_program_t *prog);

#endif /* UCODE_PROGRAM_H */
