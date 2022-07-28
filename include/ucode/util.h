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

#ifndef UCODE_UTIL_H
#define UCODE_UTIL_H

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h> /* va_start(), va_end(), va_list */
#include <string.h> /* strdup() */
#include <json-c/json.h>


#ifndef __hidden
#define __hidden __attribute__((visibility("hidden")))
#endif


/* alignment & array size */

#ifndef ALIGN
#define ALIGN(x) (((x) + sizeof(size_t) - 1) & -sizeof(size_t))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif


/* vector macros */

#define UC_VECTOR_CHUNK_SIZE 8

#define uc_declare_vector(name, type) \
	typedef struct { \
		size_t count; \
		type *entries; \
	} name

#define uc_vector_grow(vec) \
	do { \
		if (((vec)->count % UC_VECTOR_CHUNK_SIZE) == 0) { \
			(vec)->entries = xrealloc((vec)->entries, sizeof((vec)->entries[0]) * ((vec)->count + UC_VECTOR_CHUNK_SIZE)); \
			memset(&(vec)->entries[(vec)->count], 0, sizeof((vec)->entries[0]) * UC_VECTOR_CHUNK_SIZE); \
		} \
	} while(0)

#define uc_vector_clear(vec) \
	do { \
		free((vec)->entries); \
		(vec)->entries = NULL; \
		(vec)->count = 0; \
	} while(0)

#define uc_vector_first(vec) \
	(&((vec)->entries[0]))

#define uc_vector_last(vec) \
	(&((vec)->entries[(vec)->count - 1]))

#define uc_vector_push(vec, val) do { \
	uc_vector_grow(vec); \
	(vec)->entries[(vec)->count++] = (val); \
} while(0)


/* "failsafe" utility functions */

static inline void *xcalloc(size_t size, size_t nmemb) {
	void *ptr = calloc(size, nmemb);

	if (!ptr) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return ptr;
}

static inline void *xalloc(size_t size) {
	return xcalloc(1, size);
}

static inline void *xrealloc(void *ptr, size_t size) {
	ptr = realloc(ptr, size);

	if (!ptr) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return ptr;
}

static inline char *xstrdup(const char *s) {
	char *ptr = strdup(s);

	if (!ptr) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return ptr;
}

static inline struct json_tokener *xjs_new_tokener(void) {
	struct json_tokener *tok = json_tokener_new();

	if (!tok) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return tok;
}

__attribute__((format(printf, 2, 0)))
static inline int xasprintf(char **strp, const char *fmt, ...) {
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vasprintf(strp, fmt, ap);
	va_end(ap);

	if (len == -1) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return len;
}

__attribute__((format(printf, 2, 0)))
static inline int xvasprintf(char **strp, const char *fmt, va_list ap) {
	int len = vasprintf(strp, fmt, ap);

	if (len == -1) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return len;
}

static inline struct printbuf *xprintbuf_new(void) {
	struct printbuf *pb = printbuf_new();

	if (!pb) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return pb;
}

#endif /* UCODE_UTIL_H */
