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
#include <errno.h>
#if defined(__APPLE__)
  #include <machine/endian.h>
  #include "macos_endian.h"
#else
  #include <endian.h>
#endif

#include "ucode/source.h"


uc_source_t *
uc_source_new_file(const char *path)
{
	FILE *fp = fopen(path, "rb");
	uc_source_t *src;

	if (!fp)
		return NULL;

	src = xalloc(ALIGN(sizeof(*src)) + strlen(path) + 1);

	src->header.type = UC_SOURCE;
	src->header.refcount = 1;

	src->fp = fp;
	src->buffer = NULL;
	src->filename = strcpy((char *)src + ALIGN(sizeof(*src)), path);
	src->runpath = src->filename;

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

	src->header.type = UC_SOURCE;
	src->header.refcount = 1;

	src->fp = fp;
	src->buffer = buf;
	src->filename = strcpy((char *)src + ALIGN(sizeof(*src)), name);

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

uc_source_type_t
uc_source_type_test(uc_source_t *source)
{
	union { char s[sizeof(uint32_t)]; uint32_t n; } buf = { 0 };
	uc_source_type_t type = UC_SOURCE_TYPE_PLAIN;
	FILE *fp = source->fp;
	size_t rlen;
	int c = 0;

	if (fread(buf.s, 1, 2, fp) == 2 && !strncmp(buf.s, "#!", 2)) {
		source->off += 2;

		while ((c = fgetc(fp)) != EOF) {
			source->off++;

			if (c == '\n')
				break;
		}
	}
	else {
		if (fseek(fp, 0L, SEEK_SET) == -1)
			fprintf(stderr, "Failed to rewind source buffer: %s\n", strerror(errno));
	}

	rlen = fread(buf.s, 1, 4, fp);

	if (rlen == 4 && buf.n == htobe32(UC_PRECOMPILED_BYTECODE_MAGIC)) {
		type = UC_SOURCE_TYPE_PRECOMPILED;
	}
	else {
		uc_source_line_update(source, source->off);

		if (c == '\n')
			uc_source_line_next(source);
	}

	if (fseek(fp, -(long)rlen, SEEK_CUR) == -1)
		fprintf(stderr, "Failed to rewind source buffer: %s\n", strerror(errno));

	return type;
}

/* lineinfo is encoded in bytes: the most significant bit specifies whether
 * to advance the line count by one or not, while the remaining 7 bits encode
 * the amounts of bytes on the current line.
 *
 * If a line has more than 127 characters, the first byte will be set to
 * 0xff (1 1111111) and subsequent bytes will encode the remaining characters
 * in bits 1..7 while setting bit 8 to 0. A line with 400 characters will thus
 * be encoded as 0xff 0x7f 0x7f 0x13 (1:1111111 + 0:1111111 + 0:1111111 + 0:1111111).
 *
 * The newline character itself is not counted, so an empty line is encoded as
 * 0x80 (1:0000000).
 */

void
uc_source_line_next(uc_source_t *source)
{
	uc_lineinfo_t *lines = &source->lineinfo;

	uc_vector_grow(lines);
	lines->entries[lines->count++] = 0x80;
}

void
uc_source_line_update(uc_source_t *source, size_t off)
{
	uc_lineinfo_t *lines = &source->lineinfo;
	uint8_t *entry, n;

	if (!lines->count)
		uc_source_line_next(source);

	entry = uc_vector_last(lines);

	if ((entry[0] & 0x7f) + off <= 0x7f) {
		entry[0] += off;
	}
	else {
		off -= (0x7f - (entry[0] & 0x7f));
		entry[0] |= 0x7f;

		while (off > 0) {
			n = (off > 0x7f) ? 0x7f : off;
			uc_vector_grow(lines);
			entry = uc_vector_last(lines);
			entry[1] = n;
			off -= n;
			lines->count++;
		}
	}
}

void
uc_source_runpath_set(uc_source_t *source, const char *runpath)
{
	if (source->runpath != source->filename)
		free(source->runpath);

	source->runpath = xstrdup(runpath);
}
