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

#ifndef __OBJECT_H_
#define __OBJECT_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <regex.h>

#ifdef JSONC
	#include <json.h>
#else
	#include <json-c/json.h>
#endif

#include "source.h"
#include "chunk.h"
#include "util.h"

typedef enum {
	UC_OBJ_INVAL,
	UC_OBJ_UPVAL,
	UC_OBJ_FUNCTION,
	UC_OBJ_CLOSURE,
	UC_OBJ_CFUNCTION,
	UC_OBJ_REGEXP,
	UC_OBJ_PROTOTYPE,
	UC_OBJ_RESSOURCE
} uc_objtype_t;

typedef struct {
	uc_objtype_t type;
	json_object *jso;
} uc_objhdr;

typedef struct uc_upvalref {
	uc_objhdr header;
	size_t slot;
	bool closed;
	json_object *value;
	struct uc_upvalref *next;
} uc_upvalref;

typedef struct {
	uc_objhdr header;
	char *name;
	bool arrow, vararg;
	size_t nargs;
	size_t nupvals;
	size_t srcpos;
	uc_chunk chunk;
	uc_source *source;
} uc_function;

typedef struct {
	uc_objhdr header;
	uc_function *function;
	uc_upvalref **upvals;
	bool is_arrow;
} uc_closure;

struct uc_vm;
typedef json_object *(*uc_cfn_ptr)(struct uc_vm *, size_t);

typedef struct {
	uc_objhdr header;
	char *name;
	uc_cfn_ptr cfn;
} uc_cfunction;

typedef struct {
	uc_objhdr header;
	regex_t re;
	char *pattern;
	bool icase, newline, global;
} uc_regexp;

struct uc_prototype {
	uc_objhdr header;
	struct uc_prototype *parent;
};

typedef struct uc_prototype uc_prototype;

typedef struct {
	uc_objhdr header;
	uc_prototype *proto;
	size_t type;
	void *data;
} uc_ressource;

typedef struct {
	const char *name;
	uc_prototype *proto;
	void (*free)(void *);
} uc_ressource_type;

uc_declare_vector(uc_ressource_types, uc_ressource_type);

uc_upvalref *uc_upvalref_new(size_t slot);
uc_function *uc_function_new(const char *name, size_t line, uc_source *source);
uc_closure *uc_closure_new(uc_function *function, bool arrow_fn);
uc_cfunction *uc_cfunction_new(const char *name, uc_cfn_ptr cfn);
uc_regexp *uc_regexp_new(const char *pattern, bool icase, bool newline, bool global, char **err);
uc_prototype *uc_prototype_new(uc_prototype *parent);
uc_prototype *uc_protoref_new(json_object *value, uc_prototype *proto);

uc_ressource_type *uc_ressource_type_add(const char *name, uc_prototype *proto, void (*freefn)(void *));
uc_ressource_type *uc_ressource_type_lookup(const char *name);

uc_ressource *uc_ressource_new(json_object *jso, uc_ressource_type *type, void *data);
uc_prototype *uc_ressource_prototype(json_object *jso);
void **uc_ressource_dataptr(json_object *jso, const char *name);

size_t uc_function_get_srcpos(uc_function *function, size_t off);

static inline uc_objtype_t
uc_object_type(json_object *jso)
{
	uc_objhdr *hdr = json_object_get_userdata(jso);

	return hdr ? hdr->type : UC_OBJ_INVAL;
}

static inline bool
uc_object_is_type(json_object *jso, uc_objtype_t type)
{
	return uc_object_type(jso) == type;
}

static inline uc_upvalref *
uc_object_as_upvalref(json_object *jso)
{
	return json_object_get_userdata(jso);
}

static inline uc_function *
uc_object_as_function(json_object *jso)
{
	return json_object_get_userdata(jso);
}

static inline uc_closure *
uc_object_as_closure(json_object *jso)
{
	return json_object_get_userdata(jso);
}

static inline uc_cfunction *
uc_object_as_cfunction(json_object *jso)
{
	return json_object_get_userdata(jso);
}

static inline uc_regexp *
uc_object_as_regexp(json_object *jso)
{
	return json_object_get_userdata(jso);
}

static inline uc_prototype *
uc_object_as_prototype(json_object *jso)
{
	return json_object_get_userdata(jso);
}

static inline uc_ressource *
uc_object_as_ressource(json_object *jso)
{
	return json_object_get_userdata(jso);
}

static inline bool
uc_object_is_callable(json_object *jso)
{
	switch (uc_object_type(jso)) {
	case UC_OBJ_CLOSURE:
	case UC_OBJ_CFUNCTION:
		return true;

	default:
		return false;
	}
}

#endif /* __OBJECT_H_ */
