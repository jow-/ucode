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

#include <string.h>
#include <assert.h>

#include "object.h"

static void *
uc_object_new(uc_objtype_t type, size_t size, json_object_to_json_string_fn *tostring, json_object_delete_fn *gc)
{
	uc_objhdr *hdr = xalloc(size);

	hdr->type = type;
	hdr->jso = xjs_new_object();

	json_object_set_serializer(hdr->jso, tostring, hdr, gc);

	return hdr;
}

static int
uc_upvalref_tostring(json_object *jso, struct printbuf *pb, int level, int flags)
{
	return sprintbuf(pb, "<upvalref %p>", jso);
}

static void
uc_upvalref_gc(json_object *jso, void *userdata)
{
	uc_upvalref *up = userdata;

	uc_value_put(up->value);
	free(up);
}

uc_upvalref *
uc_upvalref_new(size_t slot)
{
	uc_upvalref *up;

	up = uc_object_new(UC_OBJ_UPVAL, sizeof(*up), uc_upvalref_tostring, uc_upvalref_gc);
	up->slot = slot;

	return up;
}

static int
uc_function_tostring(json_object *jso, struct printbuf *pb, int level, int flags)
{
	return sprintbuf(pb, "<function %p>", jso);
}

static void
uc_function_gc(json_object *jso, void *userdata)
{
	uc_function *fn = userdata;

	uc_chunk_free(&fn->chunk);
	uc_source_put(fn->source);

	free(fn);
}

uc_function *
uc_function_new(const char *name, size_t srcpos, uc_source *source)
{
	size_t namelen = 0;
	uc_function *fn;

	if (name)
		namelen = strlen(name) + 1;

	fn = uc_object_new(UC_OBJ_FUNCTION, ALIGN(sizeof(*fn)) + namelen, uc_function_tostring, uc_function_gc);
	fn->name = name ? strcpy((char *)fn + ALIGN(sizeof(*fn)), name) : NULL;
	fn->nargs = 0;
	fn->nupvals = 0;
	fn->srcpos = srcpos;
	fn->source = uc_source_get(source);
	fn->vararg = false;

	uc_chunk_init(&fn->chunk);

	return fn;
}

size_t
uc_function_get_srcpos(uc_function *fn, size_t off)
{
	size_t pos = uc_chunk_debug_get_srcpos(&fn->chunk, off);

	return pos ? fn->srcpos + pos : 0;
}

static int
uc_closure_tostring(json_object *jso, struct printbuf *pb, int level, int flags)
{
	bool strict = (level > 0) || (flags & JSON_C_TO_STRING_STRICT);
	uc_closure *closure = json_object_get_userdata(jso);
	uc_function *function = closure->function;
	json_object *argname;
	size_t i;

	sprintbuf(pb, "%s%s",
		strict ? "\"" : "",
		closure->is_arrow ? "" : "function");

	if (function->name)
		sprintbuf(pb, " %s", function->name);

	sprintbuf(pb, "(");

	for (i = 1; i <= function->nargs; i++) {
		argname = uc_chunk_debug_get_variable(&function->chunk, i - 1, i, false);

		if (i > 1)
			sprintbuf(pb, ", ");

		if (i == function->nargs && function->vararg)
			sprintbuf(pb, "...");

		if (argname)
			sprintbuf(pb, "%s", json_object_get_string(argname));
		else
			sprintbuf(pb, "[arg%zu]", i);

		uc_value_put(argname);
	}

	return sprintbuf(pb, ")%s { ... }%s",
		closure->is_arrow ? " =>" : "",
		strict ? "\"" : "");
}

static void
uc_closure_gc(json_object *jso, void *userdata)
{
	uc_closure *closure = userdata;
	uc_function *function = closure->function;
	size_t i;

	for (i = 0; i < function->nupvals; i++)
		uc_value_put(closure->upvals[i]->header.jso);

	uc_value_put(function->header.jso);

	free(closure);
}

uc_closure *
uc_closure_new(uc_function *function, bool arrow_fn)
{
	uc_closure *closure;

	closure = uc_object_new(UC_OBJ_CLOSURE,
		ALIGN(sizeof(*closure)) + (sizeof(uc_upvalref *) * function->nupvals),
		uc_closure_tostring, uc_closure_gc);

	closure->function = function;
	closure->is_arrow = arrow_fn;
	closure->upvals = function->nupvals ? ((void *)closure + ALIGN(sizeof(*closure))) : NULL;

	return closure;
}

static int
uc_cfunction_tostring(json_object *jso, struct printbuf *pb, int level, int flags)
{
	bool strict = (level > 0) || (flags & JSON_C_TO_STRING_STRICT);
	uc_cfunction *cfn = json_object_get_userdata(jso);

	return sprintbuf(pb, "%sfunction%s%s(...) { [native code] }%s",
		strict ? "\"" : "",
		cfn->name ? " " : "",
		cfn->name ? cfn->name : "",
		strict ? "\"" : "");
}

static void
uc_cfunction_gc(json_object *jso, void *userdata)
{
	free(userdata);
}

uc_cfunction *
uc_cfunction_new(const char *name, uc_cfn_ptr fptr)
{
	size_t namelen = 0;
	uc_cfunction *cfn;

	if (name)
		namelen = strlen(name) + 1;

	cfn = uc_object_new(UC_OBJ_CFUNCTION, ALIGN(sizeof(*cfn)) + namelen, uc_cfunction_tostring, uc_cfunction_gc);
	cfn->name = name ? strcpy((char *)cfn + ALIGN(sizeof(*cfn)), name) : NULL;
	cfn->cfn = fptr;

	return cfn;
}

static int
uc_regexp_tostring(json_object *jso, struct printbuf *pb, int level, int flags)
{
	bool strict = (level > 0) || (flags & JSON_C_TO_STRING_STRICT);
	uc_regexp *re = json_object_get_userdata(jso);
	json_object *s;
	const char *p;
	size_t len;

	sprintbuf(pb, "%s/", strict ? "\"" : "");

	s = xjs_new_string(re->pattern);

	if (strict)
		for (p = json_object_to_json_string(s) + 1, len = strlen(p) - 1; len > 0; len--, p++)
			sprintbuf(pb, "%c", *p);
	else
		sprintbuf(pb, "%s", json_object_get_string(s));

	uc_value_put(s);

	return sprintbuf(pb, "/%s%s%s%s",
		             re->global  ? "g" : "",
		             re->icase   ? "i" : "",
		             re->newline ? "s" : "",
		             strict ? "\"" : "");
}

static void
uc_regexp_gc(json_object *jso, void *userdata)
{
	uc_regexp *re = userdata;

	regfree(&re->re);
	free(re);
}

uc_regexp *
uc_regexp_new(const char *pattern, bool icase, bool newline, bool global, char **err)
{
	int cflags = REG_EXTENDED, res;
	uc_regexp *re;
	size_t len;

	re = uc_object_new(UC_OBJ_REGEXP, ALIGN(sizeof(*re)) + strlen(pattern) + 1, uc_regexp_tostring, uc_regexp_gc);
	re->icase = icase;
	re->global = global;
	re->newline = newline;
	re->pattern = strcpy((char *)re + ALIGN(sizeof(*re)), pattern);

	if (icase)
		cflags |= REG_ICASE;

	if (newline)
		cflags |= REG_NEWLINE;

	res = regcomp(&re->re, pattern, cflags);

	if (res != 0) {
		if (err) {
			len = regerror(res, &re->re, NULL, 0);
			*err = xalloc(len);

			regerror(res, &re->re, *err, len);
		}

		uc_value_put(re->header.jso);

		return NULL;
	}

	json_object_object_add(re->header.jso, "source", xjs_new_string(pattern));
	json_object_object_add(re->header.jso, "i", xjs_new_boolean(icase));
	json_object_object_add(re->header.jso, "g", xjs_new_boolean(global));
	json_object_object_add(re->header.jso, "s", xjs_new_boolean(newline));

	return re;
}

static void
uc_prototype_gc(json_object *jso, void *userdata)
{
	uc_prototype *proto = userdata;

	if (proto->parent)
		uc_value_put(proto->parent->header.jso);

	free(proto);
}

uc_prototype *
uc_prototype_new(uc_prototype *parent)
{
	uc_prototype *proto;

	proto = uc_object_new(UC_OBJ_PROTOTYPE, sizeof(*proto), NULL, uc_prototype_gc);

	if (parent) {
		proto->parent = parent;
		uc_value_get(parent->header.jso);
	}

	return proto;
}

json_object *
uc_prototype_lookup(uc_prototype *proto, const char *key)
{
	json_object *val;

	for (; proto; proto = proto->parent)
		if (json_object_object_get_ex(proto->header.jso, key, &val))
			return val;

	return NULL;
}

uc_prototype *
uc_protoref_new(json_object *value, uc_prototype *proto)
{
	uc_prototype *ref;

	if (!json_object_is_type(value, json_type_object) &&
	    !json_object_is_type(value, json_type_array))
		return NULL;

	ref = xalloc(sizeof(*ref));
	ref->header.type = UC_OBJ_PROTOTYPE;
	ref->header.jso = value;

	if (proto) {
		ref->parent = proto;
		uc_value_get(proto->header.jso);
	}

	json_object_set_serializer(ref->header.jso, NULL, ref, uc_prototype_gc);

	return ref;
}


static uc_ressource_types res_types;

uc_ressource_type *
uc_ressource_type_add(const char *name, uc_prototype *proto, void (*freefn)(void *))
{
	uc_vector_grow(&res_types);

	res_types.entries[res_types.count].name = name;
	res_types.entries[res_types.count].proto = proto;
	res_types.entries[res_types.count].free = freefn;

	return &res_types.entries[res_types.count++];
}

static uc_ressource_type *
uc_ressource_type_get(size_t type)
{
	return (type < res_types.count) ? &res_types.entries[type] : NULL;
}

uc_ressource_type *
uc_ressource_type_lookup(const char *name)
{
	size_t i;

	for (i = 0; i < res_types.count; i++)
		if (!strcmp(res_types.entries[i].name, name))
			return &res_types.entries[i];

	return NULL;
}

static int
uc_ressource_tostring(json_object *jso, struct printbuf *pb, int level, int flags)
{
	bool strict = (level > 0) || (flags & JSON_C_TO_STRING_STRICT);
	uc_ressource *res = json_object_get_userdata(jso);
	uc_ressource_type *type = uc_ressource_type_get(res->type);

	return sprintbuf(pb, "%s<%s %p>%s",
		strict ? "\"" : "",
		type ? type->name : "ressource",
		res->data,
		strict ? "\"" : "");
}

static void
uc_ressource_gc(json_object *jso, void *userdata)
{
	uc_ressource *res = userdata;
	uc_ressource_type *type = uc_ressource_type_get(res->type);

	if (type && type->free)
		type->free(res->data);

	free(res);
}

uc_ressource *
uc_ressource_new(json_object *jso, uc_ressource_type *type, void *data)
{
	uc_ressource *res;

	if (!jso)
		return NULL;

	res = xalloc(sizeof(*res));
	res->header.type = UC_OBJ_RESSOURCE;
	res->header.jso = jso;

	res->type = type - res_types.entries;
	res->data = data;

	json_object_set_serializer(res->header.jso, uc_ressource_tostring, res, uc_ressource_gc);

	return res;
}

void **
uc_ressource_dataptr(json_object *jso, const char *name)
{
	uc_ressource_type *type;
	uc_ressource *res;

	if (!uc_object_is_type(jso, UC_OBJ_RESSOURCE))
		return NULL;

	res = uc_object_as_ressource(jso);

	if (name) {
		type = uc_ressource_type_lookup(name);

		if (!type || type != uc_ressource_type_get(res->type))
			return NULL;
	}

	return &res->data;
}

uc_prototype *
uc_ressource_prototype(json_object *jso)
{
	uc_ressource_type *type;
	uc_ressource *res;

	if (!uc_object_is_type(jso, UC_OBJ_RESSOURCE))
		return NULL;

	res = uc_object_as_ressource(jso);
	type = uc_ressource_type_get(res->type);

	return type ? type->proto : NULL;
}
