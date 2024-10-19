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

#ifndef localfunc
# if defined(__GNUC__) || defined(__clang__)
#  define localfunc static __attribute__((noinline,unused))
# else
#  define localfunc static inline
# endif
#endif


/* alignment & array size */

#ifndef ALIGN
#define ALIGN(x) (((x) + sizeof(size_t) - 1) & -sizeof(size_t))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif


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


/* linked lists */

typedef struct uc_list {
	struct uc_list *prev;
	struct uc_list *next;
} uc_list_t;

static inline void uc_list_insert(uc_list_t *list, uc_list_t *item)
{
	list->next->prev = item;
	item->next = list->next;
	item->prev = list;
	list->next = item;
}

static inline void uc_list_remove(uc_list_t *item)
{
	item->next->prev = item->prev;
	item->prev->next = item->next;
	item->prev = item->next = item;
}

#define uc_list_foreach(item, list) \
	for (uc_list_t *item = (list)->next; item != (list); item = item->next)


/* vector macros */

#define UC_VECTOR_INIT_SIZE 8

#define uc_declare_vector(name, type) \
	typedef struct { \
		size_t count; \
		type *entries; \
	} name

localfunc size_t
uc_vector_capacity(size_t init, size_t count)
{
	if (count == 0)
		return init;

	size_t capacity = init;

	while (capacity <= count)
		capacity += (capacity >> 1);

	return capacity;
}

localfunc void
uc_vector_reduce_(char **base, size_t itemsize, size_t count, size_t remove)
{
	if (*base == NULL)
		return;

	if (remove > count)
		remove = count;

	size_t next_capacity = uc_vector_capacity(UC_VECTOR_INIT_SIZE, count - remove);

	if (uc_vector_capacity(next_capacity, count) != next_capacity)
		*base = (__typeof__(*base))xrealloc(*base, itemsize * next_capacity);
}

localfunc void *
uc_vector_extend_(char **base, size_t itemsize, size_t count, size_t add)
{
	size_t curr_capacity = uc_vector_capacity(UC_VECTOR_INIT_SIZE, count);

	if (*base == NULL || count + add >= curr_capacity) {
		size_t next_capacity = uc_vector_capacity(curr_capacity, count + add);

		*base = (__typeof__(*base))xrealloc(*base, itemsize * next_capacity);

		memset(*base + itemsize * count, 0,
			itemsize * (next_capacity - count));
	}

	return *base + itemsize * count;
}

#define uc_vector_reduce(vec, remove) \
	uc_vector_reduce_((char **)&(vec)->entries, sizeof((vec)->entries[0]), (vec)->count, (remove))

#define uc_vector_extend(vec, add) \
	(__typeof__((vec)->entries + 0)) uc_vector_extend_( \
		(char **)&(vec)->entries, \
		sizeof((vec)->entries[0]), \
		(vec)->count, (add))

#define uc_vector_grow(vec) \
	uc_vector_extend_((char **)&(vec)->entries, sizeof((vec)->entries[0]), (vec)->count, 1)

#define uc_vector_clear(vec) \
	do { \
		free((vec)->entries); \
		(vec)->entries = NULL; \
		(vec)->count = 0; \
	} while(0)

#define uc_vector_first(vec) \
	(&((vec)->entries[0]))

#define uc_vector_last(vec) \
	((vec)->count ? &((vec)->entries[(vec)->count - 1]) : NULL)

#define uc_vector_push(vec, ...) ({ \
	*uc_vector_extend((vec), 1) = ((__typeof__((vec)->entries[0]))__VA_ARGS__); \
	&(vec)->entries[(vec)->count++]; \
})

#define uc_vector_pop(vec) \
	((vec)->count ? &(vec)->entries[--(vec)->count] : NULL)

#define uc_vector_foreach(vec, iter) \
	for (__typeof__((vec)->entries + 0) iter = (vec)->entries; \
	     iter < (vec)->entries + (vec)->count; \
	     iter++)

#define uc_vector_foreach_reverse(vec, iter) \
	for (__typeof__((vec)->entries + 0) iter = (vec)->count \
	         ? (vec)->entries + (vec)->count - 1 : NULL; \
	     iter != NULL && iter >= (vec)->entries; \
	     iter--)

#endif /* UCODE_UTIL_H */
