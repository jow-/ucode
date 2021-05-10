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

#ifndef __TYPES_H_
#define __TYPES_H_

#include <stdbool.h>
#include <stdint.h>
#include <regex.h>
#include <json-c/json.h>

#include "util.h"


/* Value types and generic value header */

typedef enum uc_type_t {
	UC_NULL,
	UC_INTEGER,
	UC_BOOLEAN,
	UC_STRING,
	UC_DOUBLE,
	UC_ARRAY,
	UC_OBJECT,
	UC_REGEXP,
	UC_FUNCTION,
	UC_CFUNCTION,
	UC_CLOSURE,
	UC_UPVALUE,
	UC_RESSOURCE
} uc_type_t;

typedef struct uc_value_t {
	uint32_t type:4;
	uint32_t mark:1;
	uint32_t u64:1;
	uint32_t refcount:26;
} uc_value_t;


/* Constant list defintions */

typedef struct {
	size_t isize;
	size_t dsize;
	uint64_t *index;
	char *data;
} uc_value_list;


/* Source buffer defintions */

uc_declare_vector(uc_lineinfo, uint8_t);

typedef struct {
	char *filename, *buffer;
	FILE *fp;
	size_t usecount, off;
	uc_lineinfo lineinfo;
} uc_source;


/* Bytecode chunk defintions */

typedef struct {
	size_t from, to, target, slot;
} uc_ehrange;

typedef struct {
	size_t from, to, slot, nameidx;
} uc_varrange;

uc_declare_vector(uc_ehranges, uc_ehrange);
uc_declare_vector(uc_variables, uc_varrange);
uc_declare_vector(uc_offsetinfo, uint8_t);

typedef struct {
	size_t count;
	uint8_t *entries;
	uc_value_list constants;
	uc_ehranges ehranges;
	struct {
		uc_variables variables;
		uc_value_list varnames;
		uc_offsetinfo offsets;
	} debuginfo;
} uc_chunk;


/* Value type structures */

typedef struct uc_weakref_t {
	struct uc_weakref_t *prev;
	struct uc_weakref_t *next;
} uc_weakref_t;

typedef struct {
	uc_value_t header;
	double dbl;
} uc_double_t;

typedef struct {
	uc_value_t header;
	union {
		int64_t s64;
		uint64_t u64;
	} i;
} uc_integer_t;

typedef struct {
	uc_value_t header;
	size_t length;
	char str[];
} uc_string_t;

typedef struct {
	uc_value_t header;
	uc_weakref_t ref;
	size_t count;
	uc_value_t *proto;
	uc_value_t **entries;
} uc_array_t;

typedef struct {
	uc_value_t header;
	uc_weakref_t ref;
	uc_value_t *proto;
	struct lh_table *table;
} uc_object_t;

typedef struct {
	uc_value_t header;
	regex_t regexp;
	bool icase, newline, global;
	char source[];
} uc_regexp_t;

typedef struct {
	uc_value_t header;
	bool arrow, vararg, strict;
	size_t nargs;
	size_t nupvals;
	size_t srcpos;
	uc_chunk chunk;
	uc_source *source;
	char name[];
} uc_function_t;

typedef struct uc_upvalref_t {
	uc_value_t header;
	size_t slot;
	bool closed;
	uc_value_t *value;
	struct uc_upvalref_t *next;
} uc_upvalref_t;

typedef struct {
	uc_value_t header;
	uc_weakref_t ref;
	bool is_arrow;
	uc_function_t *function;
	uc_upvalref_t **upvals;
} uc_closure_t;

typedef struct uc_vm uc_vm;
typedef uc_value_t *(*uc_cfn_ptr_t)(uc_vm *, size_t);

typedef struct {
	uc_value_t header;
	uc_cfn_ptr_t cfn;
	char name[];
} uc_cfunction_t;

typedef struct {
	uc_value_t header;
	size_t type;
	void *data;
} uc_ressource_t;

typedef struct {
	const char *name;
	uc_value_t *proto;
	void (*free)(void *);
} uc_ressource_type_t;

uc_declare_vector(uc_ressource_types_t, uc_ressource_type_t);


/* Parser definitions */

typedef struct {
	bool lstrip_blocks;
	bool trim_blocks;
	bool strict_declarations;
} uc_parse_config;


/* VM definitions */

typedef enum {
	EXCEPTION_NONE,
	EXCEPTION_SYNTAX,
	EXCEPTION_RUNTIME,
	EXCEPTION_TYPE,
	EXCEPTION_REFERENCE,
	EXCEPTION_USER
} uc_exception_type_t;

typedef struct {
	uc_exception_type_t type;
	uc_value_t *stacktrace;
	char *message;
} uc_exception;

typedef struct {
	uint8_t *ip;
	uc_closure_t *closure;
	uc_cfunction_t *cfunction;
	size_t stackframe;
	uc_value_t *ctx;
	bool mcall, strict;
} uc_callframe;

uc_declare_vector(uc_callframes, uc_callframe);
uc_declare_vector(uc_stack, uc_value_t *);

typedef struct printbuf uc_stringbuf_t;

struct uc_vm {
	uc_stack stack;
	uc_exception exception;
	uc_callframes callframes;
	uc_upvalref_t *open_upvals;
	uc_parse_config *config;
	uc_value_t *globals;
	uc_source *sources;
	uc_weakref_t values;
	union {
		uint32_t u32;
		int32_t s32;
		uint16_t u16;
		int16_t s16;
		uint8_t u8;
		int8_t s8;
	} arg;
	size_t spread_values;
	uint8_t trace;
	uc_stringbuf_t *strbuf;
	FILE *output;
};


/* Value API */

void ucv_free(uc_value_t *, bool);
void ucv_put(uc_value_t *);

uc_value_t *ucv_get(uc_value_t *uv);

uc_type_t ucv_type(uc_value_t *);
const char *ucv_typename(uc_value_t *);

uc_value_t *ucv_boolean_new(bool);
bool ucv_boolean_get(uc_value_t *);

uc_value_t *ucv_string_new(const char *);
uc_value_t *ucv_string_new_length(const char *, size_t);
size_t ucv_string_length(uc_value_t *);

char *_ucv_string_get(uc_value_t **);
#define ucv_string_get(uv) _ucv_string_get((uc_value_t **)&uv)

uc_stringbuf_t *ucv_stringbuf_new(void);
uc_value_t *ucv_stringbuf_finish(uc_stringbuf_t *);

void _ucv_stringbuf_append(uc_stringbuf_t *, const char *, size_t);

#define _ucv_is_literal(str) ("" str)
#define ucv_stringbuf_append(buf, str) _ucv_stringbuf_append(buf, _ucv_is_literal(str), sizeof(str) - 1)
#define ucv_stringbuf_addstr(buf, str, len) _ucv_stringbuf_append(buf, str, len)
#define ucv_stringbuf_printf(buf, fmt, ...) sprintbuf(buf, fmt, __VA_ARGS__)

uc_value_t *ucv_int64_new(int64_t);
uc_value_t *ucv_uint64_new(uint64_t);
int64_t ucv_int64_get(uc_value_t *);
uint64_t ucv_uint64_get(uc_value_t *);

uc_value_t *ucv_double_new(double);
double ucv_double_get(uc_value_t *);

uc_value_t *ucv_array_new(uc_vm *);
uc_value_t *ucv_array_new_length(uc_vm *, size_t);
uc_value_t *ucv_array_get(uc_value_t *, size_t);
uc_value_t *ucv_array_pop(uc_value_t *);
uc_value_t *ucv_array_push(uc_value_t *, uc_value_t *);
uc_value_t *ucv_array_shift(uc_value_t *);
uc_value_t *ucv_array_unshift(uc_value_t *, uc_value_t *);
void ucv_array_sort(uc_value_t *, int (*)(const void *, const void *));
bool ucv_array_delete(uc_value_t *, size_t, size_t);
bool ucv_array_set(uc_value_t *, size_t, uc_value_t *);
size_t ucv_array_length(uc_value_t *);

uc_value_t *ucv_object_new(uc_vm *);
uc_value_t *ucv_object_get(uc_value_t *, const char *, bool *);
bool ucv_object_add(uc_value_t *, const char *, uc_value_t *);
bool ucv_object_delete(uc_value_t *, const char *);
size_t ucv_object_length(uc_value_t *);

#define ucv_object_foreach(obj, key, val)														\
	char *key = NULL;																			\
	uc_value_t *val = NULL;																		\
	struct lh_entry *entry##key;																\
	struct lh_entry *entry_next##key = NULL;													\
	for (entry##key = (ucv_type(obj) == UC_OBJECT) ? ((uc_object_t *)obj)->table->head : NULL;	\
	     (entry##key ? (key = (char *)lh_entry_k(entry##key),									\
	                    val = (uc_value_t *)lh_entry_v(entry##key),								\
	                    entry_next##key = entry##key->next, entry##key)							\
	                 : 0);																		\
	     entry##key = entry_next##key)

uc_value_t *ucv_function_new(const char *, size_t, uc_source *);
size_t ucv_function_srcpos(uc_value_t *, size_t);

uc_value_t *ucv_cfunction_new(const char *, uc_cfn_ptr_t);

uc_value_t *ucv_closure_new(uc_vm *, uc_function_t *, bool);

uc_ressource_type_t *ucv_ressource_type_add(const char *, uc_value_t *, void (*)(void *));
uc_ressource_type_t *ucv_ressource_type_lookup(const char *);

uc_value_t *ucv_ressource_new(uc_ressource_type_t *, void *);
void **ucv_ressource_dataptr(uc_value_t *, const char *);

uc_value_t *ucv_regexp_new(const char *, bool, bool, bool, char **);

uc_value_t *ucv_upvalref_new(size_t);

uc_value_t *ucv_prototype_get(uc_value_t *);
bool ucv_prototype_set(uc_value_t *, uc_value_t *);

uc_value_t *ucv_property_get(uc_value_t *, const char *);

uc_value_t *ucv_from_json(uc_vm *, json_object *);
json_object *ucv_to_json(uc_value_t *);

char *ucv_to_string(uc_vm *, uc_value_t *);
char *ucv_to_jsonstring_formatted(uc_vm *, uc_value_t *, char, size_t);
void ucv_to_stringbuf_formatted(uc_vm *, uc_stringbuf_t *, uc_value_t *, size_t, char, size_t);

#define ucv_to_jsonstring(vm, val) ucv_to_jsonstring_formatted(vm, val, '\1', 0)
#define ucv_to_stringbuf(vm, buf, val, json) ucv_to_stringbuf_formatted(vm, buf, val, 0, json ? '\1' : '\0', 0)

static inline bool
ucv_is_callable(uc_value_t *uv)
{
	switch (ucv_type(uv)) {
	case UC_CLOSURE:
	case UC_CFUNCTION:
		return true;

	default:
		return false;
	}
}

static inline bool
ucv_is_arrowfn(uc_value_t *uv)
{
	uc_closure_t *closure = (uc_closure_t *)uv;

	return (ucv_type(uv) == UC_CLOSURE && closure->is_arrow);
}

static inline bool
ucv_is_u64(uc_value_t *uv)
{
	return (((uintptr_t)uv & 3) == 0 && uv != NULL && uv->u64 == true);
}

static inline bool
ucv_is_scalar(uc_value_t *uv)
{
	switch (ucv_type(uv)) {
	case UC_NULL:
	case UC_BOOLEAN:
	case UC_DOUBLE:
	case UC_INTEGER:
	case UC_STRING:
		return true;

	default:
		return false;
	}
}

static inline bool
ucv_is_marked(uc_value_t *uv)
{
	return (((uintptr_t)uv & 3) == 0 && uv != NULL && uv->mark == true);
}

static inline void
ucv_set_mark(uc_value_t *uv)
{
	if (((uintptr_t)uv & 3) == 0 && uv != NULL)
		uv->mark = true;
}

static inline void
ucv_clear_mark(uc_value_t *uv)
{
	if (((uintptr_t)uv & 3) == 0 && uv != NULL)
		uv->mark = false;
}

bool ucv_equal(uc_value_t *, uc_value_t *);

void ucv_gc(uc_vm *, bool);

#endif /* __TYPES_H_ */
