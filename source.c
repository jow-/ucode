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

#include <string.h>

#include "source.h"


uc_source_t *
uc_source_new_file(const char *path)
{
	FILE *fp = fopen(path, "rb");
	uc_source_t *src;

	if (!fp)
		return NULL;

	src = xalloc(ALIGN(sizeof(*src)) + strlen(path) + 1);
	src->fp = fp;
	src->buffer = NULL;
	src->filename = strcpy((char *)src + ALIGN(sizeof(*src)), path);

	src->usecount = 1;

	src->lineinfo.count = 0;
	src->lineinfo.entries = NULL;

	return src;
}

uc_source_t *
uc_source_new_buffer(const char *name, char *buf, size_t len)
{
	FILE *fp = fmemopen(buf, len, "rb");
	uc_source_t *src;

	if (!fp)
		return NULL;

	src = xalloc(ALIGN(sizeof(*src)) + strlen(name) + 1);
	src->fp = fp;
	src->buffer = buf;
	src->filename = strcpy((char *)src + ALIGN(sizeof(*src)), name);

	src->usecount = 1;

	src->lineinfo.count = 0;
	src->lineinfo.entries = NULL;

	return src;
}

size_t
uc_source_get_line(uc_source_t *source, size_t *offset)
{
	uc_lineinfo_t *lines = &source->lineinfo;
	size_t i, pos = 0, line = 0, lastoff = 0;

	for (i = 0; i < lines->count; i++) {
		if (lines->entries[i] & 0x80) {
			lastoff = pos;
			line++;
			pos++;
		}

		pos += (lines->entries[i] & 0x7f);

		if (pos >= *offset) {
			*offset -= lastoff - 1;

			return line;
		}
	}

	return 0;
}

uc_source_t *
uc_source_get(uc_source_t *source)
{
	if (!source)
		return NULL;

	source->usecount++;

	return source;
}

void
uc_source_put(uc_source_t *source)
{
	if (!source)
		return;

	if (source->usecount > 1) {
		source->usecount--;

		return;
	}

	uc_vector_clear(&source->lineinfo);
	fclose(source->fp);
	free(source->buffer);
	free(source);
}
