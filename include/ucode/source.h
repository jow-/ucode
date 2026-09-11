/*
 * Copyright (C) 2021 Jo-Philipp Wich <jo@mein.io>
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

#ifndef UCODE_SOURCE_H
#define UCODE_SOURCE_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include <ucode/util.h>
#include <ucode/types.h>


#define UC_PRECOMPILED_BYTECODE_MAGIC 0x1b756362  /* <esc> 'u' 'c' 'b' */

typedef enum {
	UC_SOURCE_TYPE_PLAIN = 0,
	UC_SOURCE_TYPE_PRECOMPILED = 1,
} uc_source_type_t;

/* Create a source from a file or an in-memory buffer. The buffer variant
 * takes ownership of `buf` (it is freed when the source is released). */
uc_source_t *uc_source_new_file(const char *path);
uc_source_t *uc_source_new_buffer(const char *name, char *buf, size_t len);

/* Fetch the line containing the given byte offset; *offset is set to the
 * offset of the first character of that line. Returns the 1-based line number. */
size_t uc_source_get_line(uc_source_t *source, size_t *offset);

/* Reference counting. uc_source_t is an opaque refcounted value; these are
 * the only ways downstream should acquire/release a source. */
uc_source_t *uc_source_get(uc_source_t *source);
void uc_source_put(uc_source_t *source);

#endif /* UCODE_SOURCE_H */
