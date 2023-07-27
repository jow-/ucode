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

#include "util.h"
#include "types.h"


#define UC_PRECOMPILED_BYTECODE_MAGIC 0x1b756362  /* <esc> 'u' 'c' 'b' */

typedef enum {
	UC_SOURCE_TYPE_PLAIN = 0,
	UC_SOURCE_TYPE_PRECOMPILED = 1,
} uc_source_type_t;

uc_source_t *uc_source_new_file(const char *path);
uc_source_t *uc_source_new_buffer(const char *name, char *buf, size_t len);

size_t uc_source_get_line(uc_source_t *source, size_t *offset);

static inline uc_source_t *
uc_source_get(uc_source_t *source) {
	return (uc_source_t *)ucv_get(source ? &source->header : NULL);
}

static inline void
uc_source_put(uc_source_t *source) {
	ucv_put(source ? &source->header : NULL);
}

__hidden uc_source_type_t uc_source_type_test(uc_source_t *source);

__hidden void uc_source_line_next(uc_source_t *source);
__hidden void uc_source_line_update(uc_source_t *source, size_t off);

__hidden void uc_source_runpath_set(uc_source_t *source, const char *runpath);

__hidden bool uc_source_export_add(uc_source_t *source, uc_value_t *name);
__hidden ssize_t uc_source_export_lookup(uc_source_t *source, uc_value_t *name);

#endif /* UCODE_SOURCE_H */
