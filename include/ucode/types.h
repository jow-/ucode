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

#ifndef UCODE_TYPES_H
#define UCODE_TYPES_H

#include <stdbool.h>
#include <stdint.h>
#include <regex.h>
#include <signal.h>
#include <json-c/json.h>

#include "util.h"
#include "platform.h"


/* Value types and generic value header */

typedef enum uc_type {
	UC_NULL,
	UC_INTEGER,
	UC_BOOLEAN,
	UC_STRING,
	UC_DOUBLE,
	UC_ARRAY,
	UC_OBJECT,
	UC_REGEXP,
	UC_CFUNCTION,
	UC_CLOSURE,
	UC_UPVALUE,
	UC_RESOURCE,
	UC_PROGRAM,
	UC_SOURCE
} uc_type_t;

typedef struct uc_value {
	uint32_t type:4;
	uint32_t mark:1;
	uint32_t u64_or_constant:1;
	uint32_t refcount:26;
} uc_value_t;


/* Constant list defintions */

typedef struct {
	size_t isize;
	size_t dsize;
	uint64_t *index;
	char *data;
} uc_value_list_t;


/* Source buffer defintions */

uc_declare_vector(uc_lineinfo_t, uint8_t);

typedef struct {
	uc_value_t header;
	char *filename, *runpath, *buffer;
	FILE *fp;
	size_t off;
	uc_lineinfo_t lineinfo;
	struct {
		size_t count, offset;
		uc_value_t **entries;
	} exports;
} uc_source_t;


/* Bytecode chunk defintions */

typedef struct {
	size_t from, to, target, slot;
} uc_ehrange_t;

typedef struct {
	size_t from, to, slot, nameidx;
} uc_varrange_t;

uc_declare_vector(uc_ehranges_t, uc_ehrange_t);
uc_declare_vector(uc_variables_t, uc_varrange_t);
uc_declare_vector(uc_offsetinfo_t, uint8_t);

typedef struct {
	size_t count;
	uint8_t *entries;
	uc_ehranges_t ehranges;
	struct {
		uc_variables_t variables;
		uc_value_list_t varnames;
		uc_offsetinfo_t offsets;
	} debuginfo;
} uc_chunk_t;


/* Value type structures */

typedef struct uc_weakref {
	struct uc_weakref *prev;
	struct uc_weakref *next;
} uc_weakref_t;

typedef struct uc_function {
	uc_weakref_t progref;
	bool arrow, vararg, strict, module;
	size_t nargs;
	size_t nupvals;
	size_t srcidx;
	size_t srcpos;
	uc_chunk_t chunk;
	struct uc_program *program;
	char name[];
} uc_function_t;

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

typedef struct uc_upval_tref {
	uc_value_t header;
	size_t slot;
	bool closed;
	uc_value_t *value;
	struct uc_upval_tref *next;
} uc_upvalref_t;

typedef struct {
	uc_value_t header;
	uc_weakref_t ref;
	bool is_arrow;
	uc_function_t *function;
	uc_upvalref_t **upvals;
} uc_closure_t;

typedef struct uc_vm uc_vm_t;
typedef uc_value_t *(*uc_cfn_ptr_t)(uc_vm_t *, size_t);

typedef struct {
	uc_value_t header;
	uc_cfn_ptr_t cfn;
	char name[];
} uc_cfunction_t;

typedef struct {
	const char *name;
	uc_value_t *proto;
	void (*free)(void *);
} uc_resource_type_t;

typedef struct {
	uc_value_t header;
	uc_resource_type_t *type;
	void *data;
} uc_resource_t;

uc_declare_vector(uc_resource_types_t, uc_resource_type_t *);

typedef struct {
	uc_list_t list;
	struct lh_table *table;
	union {
		struct lh_entry *pos;
		struct {
			const void *k;
			unsigned long hash;
		} kh;
	} u;
} uc_object_iterator_t;


/* Program structure definitions */

uc_declare_vector(uc_sources_t, uc_source_t *);
uc_declare_vector(uc_modexports_t, uc_upvalref_t *);

typedef struct uc_program {
	uc_value_t header;
	uc_value_list_t constants;
	uc_weakref_t functions;
	uc_sources_t sources;
	uc_modexports_t exports;
} uc_program_t;


/* Parser definitions */

uc_declare_vector(uc_search_path_t, char *);

typedef struct {
	bool lstrip_blocks;
	bool trim_blocks;
	bool strict_declarations;
	bool raw_mode;
	uc_search_path_t module_search_path;
	uc_search_path_t force_dynlink_list;
	bool setup_signal_handlers;
} uc_parse_config_t;

extern uc_parse_config_t uc_default_parse_config;

void uc_search_path_init(uc_search_path_t *search_path);

static inline void
uc_search_path_add(uc_search_path_t *search_path, char *path) {
	uc_vector_push(search_path, xstrdup(path));
}

static inline void
uc_search_path_free(uc_search_path_t *search_path) {
	while (search_path->count > 0)
		free(search_path->entries[--search_path->count]);

	uc_vector_clear(search_path);
}


/* TLS data */

typedef struct {
	/* VM owning installed signal handlers */
	uc_vm_t *signal_handler_vm;

	/* Object iteration */
	uc_list_t object_iterators;
} uc_thread_context_t;

__hidden uc_thread_context_t *uc_thread_context_get(void);


/* VM definitions */

typedef enum {
	EXCEPTION_NONE,
	EXCEPTION_SYNTAX,
	EXCEPTION_RUNTIME,
	EXCEPTION_TYPE,
	EXCEPTION_REFERENCE,
	EXCEPTION_USER,
	EXCEPTION_EXIT
} uc_exception_type_t;

typedef struct {
	uc_exception_type_t type;
	uc_value_t *stacktrace;
	char *message;
} uc_exception_t;

typedef struct {
	uint8_t *ip;
	uc_closure_t *closure;
	uc_cfunction_t *cfunction;
	size_t stackframe;
	uc_value_t *ctx;
	bool mcall, strict;
} uc_callframe_t;

uc_declare_vector(uc_callframes_t, uc_callframe_t);
uc_declare_vector(uc_stack_t, uc_value_t *);

typedef struct printbuf uc_stringbuf_t;

typedef void (uc_exception_handler_t)(uc_vm_t *, uc_exception_t *);

struct uc_vm {
	uc_stack_t stack;
	uc_exception_t exception;
	uc_callframes_t callframes;
	uc_upvalref_t *open_upvals;
	uc_parse_config_t *config;
	uc_value_t *globals;
	uc_value_t *registry;
	uc_source_t *sources;
	uc_weakref_t values;
	uc_resource_types_t restypes;
	char _reserved[sizeof(uc_modexports_t)];
	union {
		uint32_t u32;
		int32_t s32;
		uint16_t u16;
		int16_t s16;
		uint8_t u8;
		int8_t s8;
	} arg;
	size_t alloc_refs;
	uint8_t trace;
	uint8_t gc_flags;
	uint16_t gc_interval;
	uc_stringbuf_t *strbuf;
	uc_exception_handler_t *exhandler;
	FILE *output;
	struct {
		uint64_t raised[((UC_SYSTEM_SIGNAL_COUNT + 63) & ~63) / 64];
		uc_value_t *handler;
		struct sigaction sa;
		int sigpipe[2];
	} signal;
};


/* Value API */

__hidden void ucv_free(uc_value_t *, bool);
__hidden void ucv_unref(uc_weakref_t *);
__hidden void ucv_ref(uc_weakref_t *, uc_weakref_t *);

uc_value_t *ucv_get(uc_value_t *uv);
void ucv_put(uc_value_t *);

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

uc_value_t *ucv_array_new(uc_vm_t *);
uc_value_t *ucv_array_new_length(uc_vm_t *, size_t);
uc_value_t *ucv_array_get(uc_value_t *, size_t);
uc_value_t *ucv_array_pop(uc_value_t *);
uc_value_t *ucv_array_push(uc_value_t *, uc_value_t *);
uc_value_t *ucv_array_shift(uc_value_t *);
uc_value_t *ucv_array_unshift(uc_value_t *, uc_value_t *);
void ucv_array_sort(uc_value_t *, int (*)(const void *, const void *));
void ucv_array_sort_r(uc_value_t *, int (*)(uc_value_t *, uc_value_t *, void *), void *);
bool ucv_array_delete(uc_value_t *, size_t, size_t);
bool ucv_array_set(uc_value_t *, size_t, uc_value_t *);
size_t ucv_array_length(uc_value_t *);

uc_value_t *ucv_object_new(uc_vm_t *);
uc_value_t *ucv_object_get(uc_value_t *, const char *, bool *);
bool ucv_object_add(uc_value_t *, const char *, uc_value_t *);
void ucv_object_sort(uc_value_t *, int (*)(const void *, const void *));
void ucv_object_sort_r(uc_value_t *, int (*)(const char *, uc_value_t *, const char *, uc_value_t *, void *), void *);
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

uc_value_t *ucv_cfunction_new(const char *, uc_cfn_ptr_t);

uc_value_t *ucv_closure_new(uc_vm_t *, uc_function_t *, bool);

uc_resource_type_t *ucv_resource_type_add(uc_vm_t *, const char *, uc_value_t *, void (*)(void *));
uc_resource_type_t *ucv_resource_type_lookup(uc_vm_t *, const char *);

uc_value_t *ucv_resource_new(uc_resource_type_t *, void *);
void *ucv_resource_data(uc_value_t *uv, const char *);
void **ucv_resource_dataptr(uc_value_t *, const char *);

static inline uc_value_t *
ucv_resource_create(uc_vm_t *vm, const char *type, void *value)
{
    uc_resource_type_t *t = NULL;

    if (type && (t = ucv_resource_type_lookup(vm, type)) == NULL)
        return NULL;

    return ucv_resource_new(t, value);
}

uc_value_t *ucv_regexp_new(const char *, bool, bool, bool, char **);

uc_value_t *ucv_upvalref_new(size_t);

uc_value_t *ucv_prototype_get(uc_value_t *);
bool ucv_prototype_set(uc_value_t *, uc_value_t *);

uc_value_t *ucv_property_get(uc_value_t *, const char *);

uc_value_t *ucv_from_json(uc_vm_t *, json_object *);
json_object *ucv_to_json(uc_value_t *);

char *ucv_to_string(uc_vm_t *, uc_value_t *);
char *ucv_to_jsonstring_formatted(uc_vm_t *, uc_value_t *, char, size_t);
void ucv_to_stringbuf_formatted(uc_vm_t *, uc_stringbuf_t *, uc_value_t *, size_t, char, size_t);

#define ucv_to_jsonstring(vm, val) ucv_to_jsonstring_formatted(vm, val, '\1', 0)
#define ucv_to_stringbuf(vm, buf, val, json) ucv_to_stringbuf_formatted(vm, buf, val, 0, json ? '\1' : '\0', 0)

uc_type_t ucv_cast_number(uc_value_t *, int64_t *, double *);

uc_value_t *ucv_to_number(uc_value_t *);

static inline double
ucv_to_double(uc_value_t *v)
{
	uc_value_t *nv;
	double d;

	nv = ucv_to_number(v);
	d = ucv_double_get(nv);
	ucv_put(nv);

	return d;
}

static inline int64_t
ucv_to_integer(uc_value_t *v)
{
	uc_value_t *nv;
	int64_t n;

	nv = ucv_to_number(v);
	n = ucv_int64_get(nv);
	ucv_put(nv);

	return n;
}

static inline uint64_t
ucv_to_unsigned(uc_value_t *v)
{
	uc_value_t *nv;
	uint64_t u;

	nv = ucv_to_number(v);
	u = ucv_uint64_get(nv);
	ucv_put(nv);

	return u;
}

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
	return (((uintptr_t)uv & 3) == 0 && uv != NULL && uv->u64_or_constant == true &&
		    uv->type == UC_INTEGER);
}

static inline bool
ucv_is_constant(uc_value_t *uv)
{
	return (((uintptr_t)uv & 3) == 0 && uv != NULL && uv->u64_or_constant == true &&
	        (uv->type == UC_ARRAY || uv->type == UC_OBJECT));
}

static inline bool
ucv_set_constant(uc_value_t *uv, bool constant)
{
	if (((uintptr_t)uv & 3) == 0 && uv != NULL && uv->u64_or_constant != constant &&
	    (uv->type == UC_ARRAY || uv->type == UC_OBJECT)) {
		uv->u64_or_constant = constant;

		return true;
	}

	return false;
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

bool ucv_is_equal(uc_value_t *, uc_value_t *);
bool ucv_is_truish(uc_value_t *);

bool ucv_compare(int, uc_value_t *, uc_value_t *, int *);

uc_value_t *ucv_key_get(uc_vm_t *, uc_value_t *, uc_value_t *);
uc_value_t *ucv_key_set(uc_vm_t *, uc_value_t *, uc_value_t *, uc_value_t *);
bool ucv_key_delete(uc_vm_t *, uc_value_t *, uc_value_t *);


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

void ucv_gc(uc_vm_t *);

__hidden void ucv_freeall(uc_vm_t *);

#endif /* UCODE_TYPES_H */
