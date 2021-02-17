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

#ifndef __VALUE_H_
#define __VALUE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef JSONC
	#include <json.h>
#else
	#include <json-c/json.h>
#endif

#include <stdio.h>

typedef enum {
	TAG_INVAL = 0,
	TAG_NUM = 1,
	TAG_LNUM = 2,
	TAG_DBL = 3,
	TAG_STR = 4,
	TAG_LSTR = 5,
	TAG_PTR = 6
} uc_value_type_t;

typedef struct {
	size_t isize;
	size_t dsize;
	uint64_t *index;
	char *data;
} uc_value_list;

json_object *uc_double_new(double v);

bool uc_eq(json_object *v1, json_object *v2);
bool uc_cmp(int how, json_object *v1, json_object *v2);
bool uc_val_is_truish(json_object *val);

enum json_type uc_cast_number(json_object *v, int64_t *n, double *d);

json_object *uc_getval(json_object *scope, json_object *key);
json_object *uc_setval(json_object *scope, json_object *key, json_object *val);

void uc_vallist_init(uc_value_list *list);
void uc_vallist_free(uc_value_list *list);

ssize_t uc_vallist_add(uc_value_list *list, json_object *value);
uc_value_type_t uc_vallist_type(uc_value_list *list, size_t idx);
struct json_object *uc_vallist_get(uc_value_list *list, size_t idx);

#define uc_value_get(val) \
	({ \
		struct json_object *__o = val; \
		/*fprintf(stderr, "get(%p // %s) [%d + 1] @ %s:%d\n", __o, json_object_to_json_string(__o), getrefcnt(__o), __FILE__, __LINE__);*/ \
		json_object_get(__o); \
	})

#define uc_value_put(val) \
	({ \
		struct json_object *__o = val; \
		/*fprintf(stderr, "put(%p // %s) [%d - 1] @ %s:%d\n", __o, json_object_to_json_string(__o), getrefcnt(__o), __FILE__, __LINE__);*/ \
		json_object_put(__o); \
	})

#endif /* __VALUE_H_ */
