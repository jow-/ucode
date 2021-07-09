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

#ifndef __SOURCE_H_
#define __SOURCE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "util.h"
#include "types.h"


uc_source_t *uc_source_new_file(const char *path);
uc_source_t *uc_source_new_buffer(const char *name, char *buf, size_t len);

size_t uc_source_get_line(uc_source_t *source, size_t *offset);

uc_source_t *uc_source_get(uc_source_t *source);
void uc_source_put(uc_source_t *source);

#endif /* __SOURCE_H_ */
