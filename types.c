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

#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <math.h>
#include <ctype.h>
#include <float.h>

#include "json-c-compat.h"

#include "ucode/types.h"
#include "ucode/util.h"
#include "ucode/vm.h"
#include "ucode/program.h"

__thread struct uc_threadlocal *uc_threadlocal_data;

static char *uc_default_search_path[] = { LIB_SEARCH_PATH };

uc_parse_config_t uc_default_parse_config = {
	.module_search_path = {
		.count = ARRAY_SIZE(uc_default_search_path),
		.entries = uc_default_search_path
	}
};

uc_type_t
ucv_type(uc_value_t *uv)
{
	uc_type_t type = ((uintptr_t)uv & 3);

	if (type == UC_NULL && uv != NULL)
		type = uv->type;

	return type;
}

const char *
ucv_typename(uc_value_t *uv)
{
	switch (ucv_type(uv)) {
	case UC_NULL:      return "null";
	case UC_INTEGER:   return "integer";
	case UC_BOOLEAN:   return "boolean";
	case UC_STRING:    return "string";
	case UC_DOUBLE:    return "double";
	case UC_ARRAY:     return "array";
	case UC_OBJECT:    return "object";
	case UC_REGEXP:    return "regexp";
	case UC_CFUNCTION: return "cfunction";
	case UC_CLOSURE:   return "closure";
	case UC_UPVALUE:   return "upvalue";
	case UC_RESOURCE:  return "resource";
	case UC_PROGRAM:   return "program";
	case UC_SOURCE:    return "source";
	}

	return "unknown";
}

void
ucv_unref(uc_weakref_t *ref)
{
	ref->prev->next = ref->next;
	ref->next->prev = ref->prev;
}

void
ucv_ref(uc_weakref_t *head, uc_weakref_t *item)
{
	item->next = head->next;
	item->prev = head;
	head->next->prev = item;
	head->next = item;
}

#if 0
static uc_weakref_t *
ucv_get_weakref(uc_value_t *uv)
{
	switch (ucv_type(uv)) {
	case UC_ARRAY:
		return &((uc_array_t *)uv)->ref;

	case UC_OBJECT:
		return &((uc_object_t *)uv)->ref;

	case UC_CLOSURE:
		return &((uc_closure_t *)uv)->ref;

	default:
		return NULL;
	}
}
#endif

static void
ucv_put_value(uc_value_t *uv, bool retain)
{
	if (uv == NULL || (uintptr_t)uv & 3)
		return;

	assert(uv->type == UC_NULL || uv->refcount > 0);

	if (uv->refcount > 0)
		uv->refcount--;

	if (uv->refcount == 0)
		ucv_free(uv, retain);
}

static void
ucv_gc_mark(uc_value_t *uv);

static void
ucv_gc_mark(uc_value_t *uv)
{
	uc_function_t *function;
	uc_closure_t *closure;
	uc_upvalref_t *upval;
	uc_object_t *object;
	uc_array_t *array;
	uc_resource_t *resource;
	uc_program_t *program;
	struct lh_entry *entry;
	size_t i;

	if (ucv_is_marked(uv))
		return;

	switch (ucv_type(uv)) {
	case UC_ARRAY:
		array = (uc_array_t *)uv;

		if (array->ref.next)
			ucv_set_mark(uv);

		ucv_gc_mark(array->proto);

		for (i = 0; i < array->count; i++)
			ucv_gc_mark(array->entries[i]);

		break;

	case UC_OBJECT:
		object = (uc_object_t *)uv;

		if (object->ref.next)
			ucv_set_mark(uv);

		ucv_gc_mark(object->proto);

		lh_foreach(object->table, entry)
			ucv_gc_mark((uc_value_t *)lh_entry_v(entry));

		break;

	case UC_CLOSURE:
		closure = (uc_closure_t *)uv;
		function = closure->function;

		if (closure->ref.next)
			ucv_set_mark(uv);

		for (i = 0; i < function->nupvals; i++)
			ucv_gc_mark(&closure->upvals[i]->header);

		ucv_gc_mark(&function->program->header);

		break;

	case UC_UPVALUE:
		upval = (uc_upvalref_t *)uv;
		ucv_gc_mark(upval->value);
		break;

	case UC_RESOURCE:
		resource = (uc_resource_t *)uv;

		if (resource->type)
			ucv_gc_mark(resource->type->proto);

		break;

	case UC_PROGRAM:
		program = (uc_program_t *)uv;

		for (i = 0; i < program->sources.count; i++)
			ucv_gc_mark(&program->sources.entries[i]->header);

		for (i = 0; i < program->exports.count; i++)
			ucv_gc_mark(&program->exports.entries[i]->header);

		break;

	default:
		break;
	}
}

void
ucv_free(uc_value_t *uv, bool retain)
{
	uc_resource_type_t *restype;
	uc_resource_t *resource;
	uc_function_t *function;
	uc_closure_t *closure;
	uc_program_t *program;
	uc_upvalref_t *upval;
	uc_source_t *source;
	uc_regexp_t *regexp;
	uc_object_t *object;
	uc_array_t *array;
	uc_weakref_t *ref;
	size_t i;

	if (uv == NULL || (uintptr_t)uv & 3)
		return;

	if (uv->mark)
		return;

	uv->mark = true;

	ref = NULL;

	switch (uv->type) {
	case UC_ARRAY:
		array = (uc_array_t *)uv;
		ref = &array->ref;
		ucv_put_value(array->proto, retain);

		for (i = 0; i < array->count; i++)
			ucv_put_value(array->entries[i], retain);

		uc_vector_clear(array);
		break;

	case UC_OBJECT:
		object = (uc_object_t *)uv;
		ref = &object->ref;
		ucv_put_value(object->proto, retain);
		lh_table_free(object->table);
		break;

	case UC_REGEXP:
		regexp = (uc_regexp_t *)uv;
		regfree(&regexp->regexp);
		break;

	case UC_CLOSURE:
		closure = (uc_closure_t *)uv;
		function = closure->function;
		ref = &closure->ref;

		for (i = 0; i < function->nupvals; i++)
			if (closure->upvals[i])
				ucv_put_value(&closure->upvals[i]->header, retain);

		ucv_put_value(&function->program->header, retain);
		break;

	case UC_RESOURCE:
		resource = (uc_resource_t *)uv;
		restype = resource->type;

		if (restype && restype->free)
			restype->free(resource->data);

		break;

	case UC_UPVALUE:
		upval = (uc_upvalref_t *)uv;
		ucv_put_value(upval->value, retain);
		break;

	case UC_PROGRAM:
		program = (uc_program_t *)uv;

		uc_program_function_foreach_safe(program, func)
			uc_program_function_free(func);

		uc_vallist_free(&program->constants);

		for (i = 0; i < program->sources.count; i++)
			ucv_put_value(&program->sources.entries[i]->header, retain);

		for (i = 0; i < program->exports.count; i++)
			ucv_put_value(&program->exports.entries[i]->header, retain);

		uc_vector_clear(&program->sources);
		uc_vector_clear(&program->exports);
		break;

	case UC_SOURCE:
		source = (uc_source_t *)uv;

		if (source->runpath != source->filename)
			free(source->runpath);

		for (i = 0; i < source->exports.count; i++)
			ucv_put(source->exports.entries[i]);

		uc_vector_clear(&source->lineinfo);
		uc_vector_clear(&source->exports);
		fclose(source->fp);
		free(source->buffer);
		break;
	}

	if (!ref || !retain) {
		if (ref && ref->prev && ref->next)
			ucv_unref(ref);

		free(uv);
	}
	else {
		uv->type = UC_NULL;
	}
}

void
ucv_put(uc_value_t *uv)
{
	ucv_put_value(uv, false);
}

uc_value_t *
ucv_get(uc_value_t *uv)
{
	if (uv == NULL || (uintptr_t)uv & 3)
		return uv;

	assert(uv->refcount < 0x03ffffff);

	uv->refcount++;

	return uv;
}

uc_value_t *
ucv_boolean_new(bool val)
{
	uintptr_t pv = UC_BOOLEAN | (val << 2);

	return (uc_value_t *)pv;
}

bool
ucv_boolean_get(uc_value_t *uv)
{
	uintptr_t pv = (uintptr_t)uv;

	if ((pv & 3) == UC_BOOLEAN)
		return (pv >> 2) & 1;

	return false;
}


uc_value_t *
ucv_string_new(const char *str)
{
	return ucv_string_new_length(str, strlen(str));
}

uc_value_t *
ucv_string_new_length(const char *str, size_t length)
{
	uc_string_t *ustr;
	uintptr_t pv;
	size_t i;
	char *s;

	if ((length + 1) < sizeof(void *)) {
		pv = UC_STRING | (length << 2);

#if __BYTE_ORDER == __LITTLE_ENDIAN
		s = (char *)&pv + 1;
#else
		s = (char *)&pv;
#endif

		for (i = 0; i < length; i++)
			s[i] = str[i];

		return (uc_value_t *)pv;
	}

	ustr = xalloc(sizeof(*ustr) + length + 1);
	ustr->header.type = UC_STRING;
	ustr->header.refcount = 1;
	ustr->length = length;
	memcpy(ustr->str, str, length);

	return &ustr->header;
}

uc_stringbuf_t *
ucv_stringbuf_new(void)
{
	uc_stringbuf_t *sb = xprintbuf_new();
	uc_string_t ustr = {
		.header = {
			.type = UC_STRING,
			.refcount = 1
		}
	};

	printbuf_memappend_fast(sb, (char *)&ustr, (int)sizeof(ustr));

	return sb;
}

uc_value_t *
ucv_stringbuf_finish(uc_stringbuf_t *sb)
{
	uc_string_t *ustr = (uc_string_t *)sb->buf;

	ustr->length = printbuf_length(sb) - offsetof(uc_string_t, str);

	free(sb);

	return &ustr->header;
}

char *
_ucv_string_get(uc_value_t **uv)
{
	uc_string_t *str;

	switch ((uintptr_t)*uv & 3) {
	case UC_STRING:
#if __BYTE_ORDER == __LITTLE_ENDIAN
		return (char *)uv + 1;
#else
		return (char *)uv;
#endif

	case UC_NULL:
		if (*uv != NULL && (*uv)->type == UC_STRING) {
			str = (uc_string_t *)*uv;

			return str->str;
		}
	}

	return NULL;
}

size_t
ucv_string_length(uc_value_t *uv)
{
	uc_string_t *str = (uc_string_t *)uv;
	uintptr_t pv = (uintptr_t)uv;

	if ((pv & 3) == UC_STRING)
		return (pv & 0xff) >> 2;
	else if (uv != NULL && uv->type == UC_STRING)
		return str->length;

	return 0;
}


uc_value_t *
ucv_int64_new(int64_t n)
{
	uint64_t uval = (n < 0) ? ((n > INT64_MIN) ? (~n + 1) : INT64_MAX) : n;
	uint64_t max = (1ULL << ((sizeof(void *) * 8) - 3)) - 1;
	uc_integer_t *integer;
	uintptr_t pv;

	if (uval <= max) {
		pv = UC_INTEGER | ((n < 0) << 2) | (uval << 3);

		return (uc_value_t *)pv;
	}

	integer = xalloc(sizeof(*integer));
	integer->header.type = UC_INTEGER;
	integer->header.refcount = 1;
	integer->header.u64_or_constant = 0;
	integer->i.s64 = n;

	return &integer->header;
}

uc_value_t *
ucv_uint64_new(uint64_t n)
{
	uint64_t max = (1ULL << ((sizeof(void *) * 8) - 3)) - 1;
	uc_integer_t *integer;
	uintptr_t pv;

	if (n <= max) {
		pv = UC_INTEGER | (n << 3);

		return (uc_value_t *)pv;
	}

	integer = xalloc(sizeof(*integer));
	integer->header.type = UC_INTEGER;
	integer->header.refcount = 1;
	integer->header.u64_or_constant = 1;
	integer->i.u64 = n;

	return &integer->header;
}

uint64_t
ucv_uint64_get(uc_value_t *uv)
{
	uintptr_t pv = (uintptr_t)uv;
	uc_integer_t *integer;
	double d;

	errno = 0;

	if ((pv & 3) == UC_INTEGER) {
		if (((pv >> 2) & 1) == 0)
			return (uint64_t)(pv >> 3);

		errno = ERANGE;

		return 0;
	}

	switch (ucv_type(uv)) {
	case UC_INTEGER:
		integer = (uc_integer_t *)uv;

		if (integer->header.u64_or_constant)
			return integer->i.u64;

		if (integer->i.s64 >= 0)
			return (uint64_t)integer->i.s64;

		errno = ERANGE;

		return 0;

	case UC_DOUBLE:
		d = ucv_double_get(uv);

		if (d < 0.0) {
			errno = ERANGE;

			return 0;
		}

		if (d >= ldexp(1.0, 64)) {
			errno = ERANGE;

			return UINT64_MAX;
		}

		return (uint64_t)d;

	default:
		errno = EINVAL;

		return 0;
	}
}

int64_t
ucv_int64_get(uc_value_t *uv)
{
	uintptr_t pv = (uintptr_t)uv;
	uc_integer_t *integer;
	double d;

	errno = 0;

	if ((pv & 3) == UC_INTEGER) {
		if (((pv >> 2) & 1) == 0)
			return (int64_t)(pv >> 3);

		return -(int64_t)(pv >> 3);
	}

	switch (ucv_type(uv)) {
	case UC_INTEGER:
		integer = (uc_integer_t *)uv;

		if (integer->header.u64_or_constant && integer->i.u64 <= (uint64_t)INT64_MAX)
			return (int64_t)integer->i.u64;

		if (!integer->header.u64_or_constant)
			return integer->i.s64;

		errno = ERANGE;

		return INT64_MAX;

	case UC_DOUBLE:
		d = ucv_double_get(uv);

		if (d < ldexp(-1.0, 63)) {
			errno = ERANGE;

			return INT64_MIN;
		}

		if (d >= ldexp(1.0, 63)) {
			errno = ERANGE;

			return INT64_MAX;
		}

		return (int64_t)d;

	default:
		errno = EINVAL;

		return 0;
	}
}


uc_value_t *
ucv_double_new(double d)
{
	uc_double_t *dbl;

	dbl = xalloc(sizeof(*dbl));
	dbl->header.type = UC_DOUBLE;
	dbl->header.refcount = 1;
	dbl->dbl = d;

	return &dbl->header;
}

double
ucv_double_get(uc_value_t *uv)
{
	uint64_t max_int = (2ULL << (DBL_MANT_DIG - 1));
	uc_double_t *dbl;
	uint64_t u;
	int64_t n;

	errno = 0;

	switch (ucv_type(uv)) {
	case UC_DOUBLE:
		dbl = (uc_double_t *)uv;

		return dbl->dbl;

	case UC_INTEGER:
		n = ucv_int64_get(uv);

		if (errno == ERANGE) {
			u = ucv_uint64_get(uv);

			/* signal precision loss for integral values >2^53 */
			if (u > max_int)
				errno = ERANGE;

			return (double)u;
		}

		/* signal precision loss for integral values <-2^53 or >2^53 */
		if (n < -(int64_t)max_int || n > (int64_t)max_int)
			errno = ERANGE;

		return (double)n;

	default:
		errno = EINVAL;

		return NAN;
	}
}


uc_value_t *
ucv_array_new(uc_vm_t *vm)
{
	return ucv_array_new_length(vm, 0);
}

uc_value_t *
ucv_array_new_length(uc_vm_t *vm, size_t length)
{
	uc_array_t *array;

	array = xalloc(sizeof(*array));
	array->header.type = UC_ARRAY;
	array->header.refcount = 1;

	/* preallocate memory */
	if (length)
		uc_vector_extend(array, length);

	if (vm) {
		ucv_ref(&vm->values, &array->ref);
		vm->alloc_refs++;
	}

	return &array->header;
}

uc_value_t *
ucv_array_pop(uc_value_t *uv)
{
	uc_array_t *array = (uc_array_t *)uv;
	uc_value_t *item;

	if (ucv_type(uv) != UC_ARRAY || array->count == 0)
		return NULL;

	item = ucv_get(array->entries[array->count - 1]);

	ucv_array_delete(uv, array->count - 1, 1);

	return item;
}

uc_value_t *
ucv_array_push(uc_value_t *uv, uc_value_t *item)
{
	uc_array_t *array = (uc_array_t *)uv;

	if (ucv_type(uv) != UC_ARRAY || uv->u64_or_constant)
		return NULL;

	ucv_array_set(uv, array->count, item);

	return item;
}

uc_value_t *
ucv_array_shift(uc_value_t *uv)
{
	uc_array_t *array = (uc_array_t *)uv;
	uc_value_t *item;

	if (ucv_type(uv) != UC_ARRAY || array->count == 0)
		return NULL;

	item = ucv_get(array->entries[0]);

	ucv_array_delete(uv, 0, 1);

	return item;
}

uc_value_t *
ucv_array_unshift(uc_value_t *uv, uc_value_t *item)
{
	uc_array_t *array = (uc_array_t *)uv;
	size_t i;

	if (ucv_type(uv) != UC_ARRAY)
		return NULL;

	uc_vector_extend(array, 1);

	for (i = ++array->count; i > 1; i--)
		array->entries[i - 1] = array->entries[i - 2];

	array->entries[0] = item;

	return item;
}

void
ucv_array_sort(uc_value_t *uv, int (*cmp)(uc_value_t * const *,uc_value_t * const *,void *),void *ctx)
{
	uc_array_t *array = (uc_array_t *)uv;

	if (ucv_type(uv) != UC_ARRAY || array->count <= 1)
		return;

	qsort_r(array->entries, array->count, sizeof(array->entries[0]), 
		(int (*)(const void *,const void *,void *))cmp, 
		ctx);
}

bool
ucv_array_delete(uc_value_t *uv, size_t offset, size_t count)
{
	uc_array_t *array = (uc_array_t *)uv;
	size_t i;

	if (ucv_type(uv) != UC_ARRAY || array->count == 0)
		return false;

	if (offset >= array->count)
		return false;

	if ((offset + count) < offset)
		return false;

	if ((offset + count) > array->count)
		count = array->count - offset;

	for (i = 0; i < count; i++)
		ucv_put(array->entries[offset + i]);

	memmove(&array->entries[offset],
	        &array->entries[offset + count],
	        (array->count - (offset + count)) * sizeof(array->entries[0]));

	uc_vector_reduce(array, count);
	array->count -= count;

	return true;
}

bool
ucv_array_set(uc_value_t *uv, size_t index, uc_value_t *item)
{
	uc_array_t *array = (uc_array_t *)uv;

	if (ucv_type(uv) != UC_ARRAY)
		return false;

	if (index >= array->count) {
		uc_vector_extend(array, index + 1 - array->count);
		array->count = index + 1;
	}
	else {
		ucv_put(array->entries[index]);
	}

	array->entries[index] = item;

	return true;
}

uc_value_t *
ucv_array_get(uc_value_t *uv, size_t index)
{
	uc_array_t *array = (uc_array_t *)uv;

	if (ucv_type(uv) != UC_ARRAY)
		return NULL;

	if (index >= array->count)
		return NULL;

	return array->entries[index];
}
size_t
ucv_array_length(uc_value_t *uv)
{
	uc_array_t *array = (uc_array_t *)uv;

	if (ucv_type(uv) != UC_ARRAY)
		return 0;

	return array->count;
}


static void
ucv_free_object_entry(struct lh_entry *entry)
{
	uc_list_foreach(item, &uc_threadlocal_data->object_iterators) {
		uc_object_iterator_t *iter = (uc_object_iterator_t *)item;

		if (iter->u.pos == entry)
			iter->u.pos = entry->next;
	}

	free(lh_entry_k(entry));
	ucv_put(lh_entry_v(entry));
}

uc_value_t *
ucv_object_new(uc_vm_t *vm)
{
	struct lh_table *table;
	uc_object_t *object;

	table = lh_kchar_table_new(16, ucv_free_object_entry);

	if (!table) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	object = xalloc(sizeof(*object));
	object->header.type = UC_OBJECT;
	object->header.refcount = 1;
	object->table = table;

	if (vm) {
		ucv_ref(&vm->values, &object->ref);
		vm->alloc_refs++;
	}

	return &object->header;
}

bool
ucv_object_add(uc_value_t *uv, const char *key, uc_value_t *val)
{
	uc_object_t *object = (uc_object_t *)uv;
	struct lh_entry *existing_entry;
	uc_value_t *existing_value;
	unsigned long hash;
	void *k;

	if (ucv_type(uv) != UC_OBJECT || uv->u64_or_constant)
		return false;

	hash = lh_get_hash(object->table, (const void *)key);
	existing_entry = lh_table_lookup_entry_w_hash(object->table, (const void *)key, hash);

	if (existing_entry == NULL) {
		bool rehash = (object->table->count >= object->table->size * LH_LOAD_FACTOR);

		/* insert will rehash table, backup affected iterator states */
		if (rehash) {
			uc_list_foreach(item, &uc_threadlocal_data->object_iterators) {
				uc_object_iterator_t *iter = (uc_object_iterator_t *)item;

				if (iter->table != object->table)
					continue;

				if (iter->u.pos == NULL)
					continue;

				iter->u.kh.k = iter->u.pos->k;
				iter->u.kh.hash = lh_get_hash(iter->table, iter->u.kh.k);
			}
		}

		k = xstrdup(key);

		if (lh_table_insert_w_hash(object->table, k, val, hash, 0) != 0) {
			free(k);

			return false;
		}

		/* restore affected iterator state pointer after rehash */
		if (rehash) {
			uc_list_foreach(item, &uc_threadlocal_data->object_iterators) {
				uc_object_iterator_t *iter = (uc_object_iterator_t *)item;

				if (iter->table != object->table)
					continue;

				if (iter->u.kh.k == NULL)
					continue;

				iter->u.pos = lh_table_lookup_entry_w_hash(iter->table,
				                                           iter->u.kh.k,
				                                           iter->u.kh.hash);
			}
		}

		return true;
	}

	existing_value = (uc_value_t *)lh_entry_v(existing_entry);

	if (existing_value)
		ucv_put(existing_value);

	existing_entry->v = val;

	return true;
}

void
ucv_object_sort(uc_value_t *uv, 
	int (*cmp)(struct lh_entry * const *, struct lh_entry * const *, void *), void *ctx )
{
	uc_object_t *object = (uc_object_t *)uv;
	struct lh_table *t;
	struct lh_entry *e;
	size_t i;

	struct {
		struct lh_entry **entries;
		size_t count;
	} keys = { 0 };

	if (ucv_type(uv) != UC_OBJECT || lh_table_length(object->table) <= 1)
		return;

	for (t = object->table, e = t->head; e; e = e->next)
		uc_vector_push(&keys, e);

	if (!keys.entries)
		return;

	qsort_r(keys.entries, keys.count, sizeof(keys.entries[0]), 
		(int (*)(const void *,const void *,void *))cmp, 
		ctx);

	for (i = 0; i < keys.count; i++) {
		e = keys.entries[i];

		if (i == 0) {
			t->head = t->tail = e;
			e->next = e->prev = NULL;
		}
		else {
			t->tail->next = e;
			e->prev = t->tail;
			e->next = NULL;
			t->tail = e;
		}
	}

	uc_vector_clear(&keys);
}

bool
ucv_object_delete(uc_value_t *uv, const char *key)
{
	uc_object_t *object = (uc_object_t *)uv;

	if (ucv_type(uv) != UC_OBJECT || uv->u64_or_constant)
		return false;

	return (lh_table_delete(object->table, key) == 0);
}

uc_value_t *
ucv_object_get(uc_value_t *uv, const char *key, bool *found)
{
	uc_object_t *object = (uc_object_t *)uv;
	uc_value_t *val = NULL;
	bool rv;

	if (found != NULL)
		*found = false;

	if (ucv_type(uv) != UC_OBJECT)
		return NULL;

	rv = lh_table_lookup_ex(object->table, (const void *)key, (void **)&val);

	if (found != NULL)
		*found = rv;

	return val;
}

size_t
ucv_object_length(uc_value_t *uv)
{
	uc_object_t *object = (uc_object_t *)uv;

	if (ucv_type(uv) != UC_OBJECT)
		return 0;

	return lh_table_length(object->table);
}


uc_value_t *
ucv_cfunction_new(const char *name, uc_cfn_ptr_t fptr)
{
	uc_cfunction_t *cfn;
	size_t namelen = 0;

	if (name)
		namelen = strlen(name);

	cfn = xalloc(sizeof(*cfn) + namelen + 1);
	cfn->header.type = UC_CFUNCTION;
	cfn->header.refcount = 1;

	if (name)
		strcpy(cfn->name, name);

	cfn->cfn = fptr;

	return &cfn->header;
}


uc_value_t *
ucv_closure_new(uc_vm_t *vm, uc_function_t *function, bool arrow_fn)
{
	uc_closure_t *closure;

	closure = xalloc(sizeof(*closure) + (sizeof(uc_upvalref_t *) * function->nupvals));
	closure->header.type = UC_CLOSURE;
	closure->header.refcount = 1;
	closure->function = function;
	closure->is_arrow = arrow_fn;
	closure->upvals = function->nupvals ? (uc_upvalref_t **)((uintptr_t)closure + ALIGN(sizeof(*closure))) : NULL;

	if (vm) {
		ucv_ref(&vm->values, &closure->ref);
		vm->alloc_refs++;
	}

	uc_program_get(function->program);

	return &closure->header;
}


uc_resource_type_t *
ucv_resource_type_add(uc_vm_t *vm, const char *name, uc_value_t *proto, void (*freefn)(void *))
{
	uc_resource_type_t *type;

	type = ucv_resource_type_lookup(vm, name);

	if (type) {
		ucv_put(proto);

		return type;
	}

	type = xalloc(sizeof(*type));
	type->name = name;
	type->proto = proto;
	type->free = freefn;

	uc_vector_push(&vm->restypes, type);

	return type;
}

uc_resource_type_t *
ucv_resource_type_lookup(uc_vm_t *vm, const char *name)
{
	size_t i;

	for (i = 0; i < vm->restypes.count; i++)
		if (!strcmp(vm->restypes.entries[i]->name, name))
			return vm->restypes.entries[i];

	return NULL;
}


uc_value_t *
ucv_resource_new(uc_resource_type_t *type, void *data)
{
	uc_resource_t *res;

	res = xalloc(sizeof(*res));
	res->header.type = UC_RESOURCE;
	res->header.refcount = 1;
	res->type = type;
	res->data = data;

	return &res->header;
}

static uc_resource_t *
ucv_resource_check(uc_value_t *uv, const char *name)
{
	uc_resource_t *res = (uc_resource_t *)uv;

	if (ucv_type(uv) != UC_RESOURCE)
		return NULL;

	if (name) {
		if (!res->type || strcmp(res->type->name, name))
			return NULL;
	}

	return res;
}

void *
ucv_resource_data(uc_value_t *uv, const char *name)
{
	uc_resource_t *res = ucv_resource_check(uv, name);

	return res ? res->data : NULL;
}

void **
ucv_resource_dataptr(uc_value_t *uv, const char *name)
{
	uc_resource_t *res = ucv_resource_check(uv, name);

	return res ? &res->data : NULL;
}


uc_value_t *
ucv_regexp_new(const char *pattern, bool icase, bool newline, bool global, char **error)
{
	int cflags = REG_EXTENDED, res;
	uc_regexp_t *re;
	size_t len;

	re = xalloc(sizeof(*re) + strlen(pattern) + 1);
	re->header.type = UC_REGEXP;
	re->header.refcount = 1;
	re->icase = icase;
	re->global = global;
	re->newline = newline;
	strcpy(re->source, pattern);

	if (icase)
		cflags |= REG_ICASE;

	if (newline)
		cflags |= REG_NEWLINE;

	res = regcomp(&re->regexp, pattern, cflags);

	if (res != 0) {
		if (error) {
			len = regerror(res, &re->regexp, NULL, 0);
			*error = xalloc(len);

			regerror(res, &re->regexp, *error, len);
		}

		free(re);

		return NULL;
	}

	return &re->header;
}


uc_value_t *
ucv_upvalref_new(size_t slot)
{
	uc_upvalref_t *up;

	up = xalloc(sizeof(*up));
	up->header.type = UC_UPVALUE;
	up->header.refcount = 1;
	up->slot = slot;

	return &up->header;
}


uc_value_t *
ucv_prototype_get(uc_value_t *uv)
{
	uc_resource_type_t *restype;
	uc_resource_t *resource;
	uc_object_t *object;
	uc_array_t *array;

	switch (ucv_type(uv)) {
	case UC_ARRAY:
		array = (uc_array_t *)uv;

		return array->proto;

	case UC_OBJECT:
		object = (uc_object_t *)uv;

		return object->proto;

	case UC_RESOURCE:
		resource = (uc_resource_t *)uv;
		restype = resource->type;

		return restype ? restype->proto : NULL;

	default:
		return NULL;
	}
}

bool
ucv_prototype_set(uc_value_t *uv, uc_value_t *proto)
{
	uc_object_t *object;
	uc_array_t *array;

	if (ucv_type(proto) != UC_OBJECT)
		return false;

	switch (ucv_type(uv)) {
	case UC_ARRAY:
		array = (uc_array_t *)uv;
		array->proto = proto;

		return true;

	case UC_OBJECT:
		object = (uc_object_t *)uv;
		object->proto = proto;

		return true;

	default:
		return false;
	}
}

uc_value_t *
ucv_property_get(uc_value_t *uv, const char *key)
{
	uc_value_t *val;
	bool found;

	for (; uv; uv = ucv_prototype_get(uv)) {
		val = ucv_object_get(uv, key, &found);

		if (found)
			return val;
	}

	return NULL;
}


uc_value_t *
ucv_from_json(uc_vm_t *vm, json_object *jso)
{
	//uc_array_t *arr;
	uc_value_t *uv, *item;
	int64_t n;
	size_t i;

	switch (json_object_get_type(jso)) {
	case json_type_null:
		return NULL;

	case json_type_boolean:
		return ucv_boolean_new(json_object_get_boolean(jso));

	case json_type_double:
		return ucv_double_new(json_object_get_double(jso));

	case json_type_int:
		n = json_object_get_int64(jso);

		if (n == INT64_MAX)
			return ucv_uint64_new(json_object_get_uint64(jso));

		return ucv_int64_new(n);

	case json_type_object:
		uv = ucv_object_new(vm);

		json_object_object_foreach(jso, key, val) {
			item = ucv_from_json(vm, val);

			if (!ucv_object_add(uv, key, item))
				ucv_put(item);

#ifdef __clang_analyzer__
			/* Clang static analyzer does not understand that the object retains
			 * our item so pretend to free it here to suppress the false positive
			 * memory leak warning. */
			ucv_put(item);
#endif
		}

		return uv;

	case json_type_array:
		/* XXX
		arr = (uc_array_t *)ucv_array_new_length(vm, json_object_array_length(jso));

		for (i = 0; i < arr->count; i++)
			arr->entries[i] = ucv_from_json(vm, json_object_array_get_idx(jso, i));

		return &arr->header;
		*/
		uv = ucv_array_new(vm);

		for (i = 0; i < json_object_array_length(jso); i++) {
			item = ucv_from_json(vm, json_object_array_get_idx(jso, i));

			if (!ucv_array_push(uv, item))
				ucv_put(item);

#ifdef __clang_analyzer__
			/* Clang static analyzer does not understand that the array retains
			 * our item so pretend to free it here to suppress the false positive
			 * memory leak warning. */
			ucv_put(item);
#endif
		}

		return uv;

	case json_type_string:
		return ucv_string_new_length(json_object_get_string(jso), json_object_get_string_len(jso));
	}

	return NULL;
}

json_object *
ucv_to_json(uc_value_t *uv)
{
	uc_regexp_t *regexp;
	uc_array_t *array;
	json_object *jso;
	size_t i;
	char *s;

	switch (ucv_type(uv)) {
	case UC_BOOLEAN:
		return json_object_new_boolean(ucv_boolean_get(uv));

	case UC_INTEGER:
		if (ucv_is_u64(uv))
			return json_object_new_uint64(ucv_uint64_get(uv));

		return json_object_new_int64(ucv_int64_get(uv));

	case UC_DOUBLE:
		return json_object_new_double(ucv_double_get(uv));

	case UC_STRING:
		return json_object_new_string_len(ucv_string_get(uv), ucv_string_length(uv));

	case UC_ARRAY:
		array = (uc_array_t *)uv;
		jso = json_object_new_array_ext(array->count);

		for (i = 0; i < array->count; i++)
			json_object_array_put_idx(jso, i, ucv_to_json(array->entries[i]));

		return jso;

	case UC_OBJECT:
		jso = json_object_new_object();

		ucv_object_foreach(uv, key, val)
			json_object_object_add(jso, key, ucv_to_json(val));

		return jso;

	case UC_REGEXP:
		regexp = (uc_regexp_t *)uv;
		i = asprintf(&s, "/%s/%s%s%s",
			regexp->source,
			regexp->global ? "g" : "",
			regexp->icase ? "i" : "",
			regexp->newline ? "s" : "");

		if (i <= 0)
			return NULL;

		jso = json_object_new_string_len(s, i);

		free(s);

		return jso;

	case UC_CLOSURE:
	case UC_CFUNCTION:
	case UC_RESOURCE:
	case UC_UPVALUE:
	case UC_PROGRAM:
	case UC_SOURCE:
	case UC_NULL:
		return NULL;
	}

	return NULL;
}

static void
ucv_to_string_json_encoded(uc_stringbuf_t *pb, const char *s, size_t len, bool regexp)
{
	size_t i;

	if (!regexp)
		ucv_stringbuf_append(pb, "\"");

	for (i = 0; s != NULL && i < len; i++, s++) {
		switch (*s) {
		case '"':
			ucv_stringbuf_append(pb, "\\\"");
			break;

		case '\\':
			ucv_stringbuf_append(pb, "\\\\");
			break;

		case '\b':
			ucv_stringbuf_append(pb, "\\b");
			break;

		case '\f':
			ucv_stringbuf_append(pb, "\\f");
			break;

		case '\n':
			ucv_stringbuf_append(pb, "\\n");
			break;

		case '\r':
			ucv_stringbuf_append(pb, "\\r");
			break;

		case '\t':
			ucv_stringbuf_append(pb, "\\t");
			break;

		case '/':
			ucv_stringbuf_append(pb, "/");
			break;

		default:
			if ((unsigned char)*s < 0x20)
				ucv_stringbuf_printf(pb, "\\u%04x", (unsigned char)*s);
			else
				ucv_stringbuf_addstr(pb, s, 1);

			break;
		}
	}

	if (!regexp)
		ucv_stringbuf_append(pb, "\"");
}

static bool
ucv_call_tostring(uc_vm_t *vm, uc_stringbuf_t *pb, uc_value_t *uv, bool json)
{
	uc_value_t *proto = ucv_prototype_get(uv);
	uc_value_t *tostr = ucv_object_get(proto, "tostring", NULL);
	uc_value_t *str;
	size_t l;
	char *s;

	if (!ucv_is_callable(tostr))
		return false;

	uc_vm_stack_push(vm, ucv_get(uv));
	uc_vm_stack_push(vm, ucv_get(tostr));

	if (uc_vm_call(vm, true, 0) != EXCEPTION_NONE)
		return false;

	str = uc_vm_stack_pop(vm);

	if (ucv_type(str) == UC_STRING) {
		s = ucv_string_get(str);
		l = ucv_string_length(str);

		if (json)
			ucv_to_string_json_encoded(pb, s, l, false);
		else if (s)
			ucv_stringbuf_addstr(pb, s, l);
	}
	else if (json) {
		ucv_stringbuf_append(pb, "\"\"");
	}

	ucv_put(str);

	return true;
}

void
_ucv_stringbuf_append(uc_stringbuf_t *pb, const char *str, size_t len)
{
	printbuf_memappend_fast(pb, str, (int)len);
}

static void
ucv_to_stringbuf_add_padding(uc_stringbuf_t *pb, char pad_char, size_t pad_size)
{
	if (pad_char != '\0' && pad_char != '\1') {
		ucv_stringbuf_append(pb, "\n");
		printbuf_memset(pb, -1, pad_char, pad_size);
	}
	else {
		ucv_stringbuf_append(pb, " ");
	}
}

static void
ucv_to_stringbuf_add_double(uc_stringbuf_t *pb, double val, bool json)
{
	int len = ucv_stringbuf_printf(pb, "%.14g", val);

	if (!json)
		return;

	for (char *p = pb->buf + pb->bpos - len; len > 0; len--, p++)
		if (*p == '.' || *p == 'e')
			return;

	ucv_stringbuf_append(pb, ".0");
}

void
ucv_to_stringbuf_formatted(uc_vm_t *vm, uc_stringbuf_t *pb, uc_value_t *uv, size_t depth, char pad_char, size_t pad_size)
{
	bool json = (pad_char != '\0');
	uc_resource_type_t *restype;
	uc_resource_t *resource;
	uc_cfunction_t *cfunction;
	uc_function_t *function;
	uc_closure_t *closure;
	uc_regexp_t *regexp;
	uc_value_t *argname;
	uc_upvalref_t *ref;
	uc_array_t *array;
	size_t i, l;
	double d;
	char *s;

	if (ucv_is_marked(uv)) {
		ucv_stringbuf_append(pb, "null");

		return;
	}

	if (vm != NULL && ucv_call_tostring(vm, pb, uv, json))
		return;

	ucv_set_mark(uv);

	switch (ucv_type(uv)) {
	case UC_NULL:
		ucv_stringbuf_append(pb, "null");
		break;

	case UC_BOOLEAN:
		if (ucv_boolean_get(uv))
			ucv_stringbuf_append(pb, "true");
		else
			ucv_stringbuf_append(pb, "false");
		break;

	case UC_INTEGER:
		if (ucv_is_u64(uv))
			ucv_stringbuf_printf(pb, "%" PRIu64, ucv_uint64_get(uv));
		else
			ucv_stringbuf_printf(pb, "%" PRId64, ucv_int64_get(uv));
		break;

	case UC_DOUBLE:
		d = ucv_double_get(uv);

		if (json && isnan(d))
			ucv_stringbuf_append(pb, "\"NaN\"");
		else if (json && d == INFINITY)
			ucv_stringbuf_append(pb, "1e309");
		else if (json && d == -INFINITY)
			ucv_stringbuf_append(pb, "-1e309");
		else if (isnan(d))
			ucv_stringbuf_append(pb, "NaN");
		else if (d == INFINITY)
			ucv_stringbuf_append(pb, "Infinity");
		else if (d == -INFINITY)
			ucv_stringbuf_append(pb, "-Infinity");
		else
			ucv_to_stringbuf_add_double(pb, d, json);

		break;

	case UC_STRING:
		s = ucv_string_get(uv);
		l = ucv_string_length(uv);

		if (s) {
			if (json)
				ucv_to_string_json_encoded(pb, s, l, false);
			else
				ucv_stringbuf_addstr(pb, s, l);
		}

		break;

	case UC_ARRAY:
		array = (uc_array_t *)uv;

		ucv_stringbuf_append(pb, "[");

		for (i = 0; i < array->count; i++) {
			if (i)
				ucv_stringbuf_append(pb, ",");

			ucv_to_stringbuf_add_padding(pb, pad_char, (depth + 1) * pad_size);
			ucv_to_stringbuf_formatted(vm, pb, array->entries[i], depth + 1, pad_char ? pad_char : '\1', pad_size);
		}

		ucv_to_stringbuf_add_padding(pb, pad_char, depth * pad_size);
		ucv_stringbuf_append(pb, "]");
		break;

	case UC_OBJECT:
		ucv_stringbuf_append(pb, "{");

		i = 0;
		ucv_object_foreach(uv, key, val) {
			if (i++)
				ucv_stringbuf_append(pb, ",");

			ucv_to_stringbuf_add_padding(pb, pad_char, (depth + 1) * pad_size);
			ucv_to_string_json_encoded(pb, key, strlen(key), false);
			ucv_stringbuf_append(pb, ": ");
			ucv_to_stringbuf_formatted(vm, pb, val, depth + 1, pad_char ? pad_char : '\1', pad_size);
		}

		ucv_to_stringbuf_add_padding(pb, pad_char, depth * pad_size);
		ucv_stringbuf_append(pb, "}");
		break;

	case UC_REGEXP:
		regexp = (uc_regexp_t *)uv;

		if (json)
			ucv_stringbuf_append(pb, "\"");

		ucv_stringbuf_append(pb, "/");
		ucv_to_string_json_encoded(pb, regexp->source, strlen(regexp->source), true);
		ucv_stringbuf_append(pb, "/");

		if (regexp->global)
			ucv_stringbuf_append(pb, "g");

		if (regexp->icase)
			ucv_stringbuf_append(pb, "i");

		if (regexp->newline)
			ucv_stringbuf_append(pb, "s");

		if (json)
			ucv_stringbuf_append(pb, "\"");

		break;

	case UC_CLOSURE:
		closure = (uc_closure_t *)uv;
		function = closure->function;

		if (json)
			ucv_stringbuf_append(pb, "\"");

		if (!closure->is_arrow) {
			ucv_stringbuf_append(pb, "function");

			if (function->name[0]) {
				ucv_stringbuf_append(pb, " ");
				ucv_stringbuf_addstr(pb, function->name, strlen(function->name));
			}
		}

		ucv_stringbuf_append(pb, "(");

		for (i = 1; i <= function->nargs; i++) {
			argname = uc_chunk_debug_get_variable(&function->chunk, i - 1, i, false);

			if (i > 1)
				ucv_stringbuf_append(pb, ", ");

			if (i == function->nargs && function->vararg)
				ucv_stringbuf_append(pb, "...");

			if (argname) {
				s = ucv_string_get(argname);
				l = ucv_string_length(argname);

				if (s)
					ucv_stringbuf_addstr(pb, s, l);

				ucv_put(argname);

				continue;
			}

			ucv_stringbuf_printf(pb, "[arg%zu]", i);
		}

		ucv_stringbuf_printf(pb, ")%s { ... }%s",
			closure->is_arrow ? " =>" : "",
			json ? "\"" : "");

		break;

	case UC_CFUNCTION:
		cfunction = (uc_cfunction_t *)uv;

		ucv_stringbuf_printf(pb, "%sfunction%s%s(...) { [native code] }%s",
			json ? "\"" : "",
			cfunction->name[0] ? " " : "",
			cfunction->name[0] ? cfunction->name : "",
			json ? "\"" : "");

		break;

	case UC_RESOURCE:
		resource = (uc_resource_t *)uv;
		restype = resource->type;

		ucv_stringbuf_printf(pb, "%s<%s %p>%s",
			json ? "\"" : "",
			restype ? restype->name : "resource",
			resource->data,
			json ? "\"" : "");

		break;

	case UC_UPVALUE:
		ref = (uc_upvalref_t *)uv;

		if (ref->closed)
			ucv_to_stringbuf_formatted(vm, pb, ref->value, depth, pad_char, pad_size);
		else if (vm != NULL && ref->slot < vm->stack.count)
			ucv_to_stringbuf_formatted(vm, pb, vm->stack.entries[ref->slot], depth, pad_char, pad_size);
		else
			ucv_stringbuf_printf(pb, "%s<upvalref %p>%s",
				json ? "\"" : "",
				uv,
				json ? "\"" : "");

		break;

	case UC_PROGRAM:
		ucv_stringbuf_printf(pb, "%s<program %p>%s",
			json ? "\"" : "",
			uv,
			json ? "\"" : "");

		break;

	case UC_SOURCE:
		ucv_stringbuf_printf(pb, "%s<source %p>%s",
			json ? "\"" : "",
			uv,
			json ? "\"" : "");
	}

	ucv_clear_mark(uv);
}

static char *
ucv_to_string_any(uc_vm_t *vm, uc_value_t *uv, char pad_char, size_t pad_size)
{
	uc_stringbuf_t *pb = xprintbuf_new();
	char *rv;

	ucv_to_stringbuf_formatted(vm, pb, uv, 0, pad_char, pad_size);

	rv = pb->buf;

	free(pb);

	return rv;
}

char *
ucv_to_string(uc_vm_t *vm, uc_value_t *uv)
{
	return ucv_to_string_any(vm, uv, '\0', 0);
}

char *
ucv_to_jsonstring_formatted(uc_vm_t *vm, uc_value_t *uv, char pad_char, size_t pad_size)
{
	return ucv_to_string_any(vm, uv, pad_char ? pad_char : '\1', pad_size);
}


bool
ucv_is_equal(uc_value_t *uv1, uc_value_t *uv2)
{
	uc_type_t t1 = ucv_type(uv1);
	uc_type_t t2 = ucv_type(uv2);
	const char *s1, *s2;
	uint64_t u1, u2;
	int64_t n1, n2;
	bool b1, b2;

	if (t1 != t2)
		return false;

	if (t1 != UC_DOUBLE && uv1 == uv2)
		return true;

	switch (t1) {
	case UC_NULL:
		return true;

	case UC_BOOLEAN:
		return ucv_boolean_get(uv1) == ucv_boolean_get(uv2);

	case UC_DOUBLE:
		return ucv_double_get(uv1) == ucv_double_get(uv2);

	case UC_INTEGER:
		n1 = ucv_int64_get(uv1);
		b1 = (errno == 0);

		n2 = ucv_int64_get(uv2);
		b2 = (errno == 0);

		if (b1 && b2)
			return (n1 == n2);

		u1 = ucv_uint64_get(uv1);
		b1 = (errno == 0);

		u2 = ucv_uint64_get(uv2);
		b2 = (errno == 0);

		if (b1 && b2)
			return (u1 == u2);

		return false;

	case UC_STRING:
		s1 = ucv_string_get(uv1);
		s2 = ucv_string_get(uv2);
		u1 = ucv_string_length(uv1);
		u2 = ucv_string_length(uv2);

		if (s1 == NULL || s2 == NULL || u1 != u2)
			return false;

		return (memcmp(s1, s2, u1) == 0);

	case UC_ARRAY:
		u1 = ucv_array_length(uv1);
		u2 = ucv_array_length(uv2);

		if (u1 != u2)
			return false;

		for (u1 = 0; u1 < u2; u1++)
			if (!ucv_is_equal(ucv_array_get(uv1, u1), ucv_array_get(uv2, u1)))
				return false;

		return true;

	case UC_OBJECT:
		u1 = ucv_object_length(uv1);
		u2 = ucv_object_length(uv2);

		if (u1 != u2)
			return false;

		ucv_object_foreach(uv1, key, val) {
			if (!ucv_is_equal(val, ucv_object_get(uv2, key, NULL)))
				return false;
		}

		ucv_object_foreach(uv2, key2, val2) {
			(void)val2;
			ucv_object_get(uv1, key2, &b1);

			if (!b1)
				return false;
		}

		return true;

	default:
		return false;
	}
}

bool
ucv_is_truish(uc_value_t *val)
{
	double d;

	switch (ucv_type(val)) {
	case UC_INTEGER:
		if (ucv_is_u64(val))
			return (ucv_uint64_get(val) != 0);

		return (ucv_int64_get(val) != 0);

	case UC_DOUBLE:
		d = ucv_double_get(val);

		return (d != 0 && !isnan(d));

	case UC_BOOLEAN:
		return ucv_boolean_get(val);

	case UC_STRING:
		return (ucv_string_length(val) > 0);

	case UC_NULL:
		return false;

	default:
		return true;
	}
}

uc_value_t *
ucv_to_number(uc_value_t *v)
{
	switch (ucv_type(v)) {
	case UC_NULL:
		return ucv_uint64_new(0);

	case UC_BOOLEAN:
		return ucv_uint64_new(ucv_boolean_get(v));

	case UC_INTEGER:
		return ucv_get(v);

	case UC_DOUBLE:
		if (isnan(ucv_double_get(v)))
			return NULL;

		return ucv_get(v);

	case UC_STRING:
		return uc_number_parse(ucv_string_get(v), NULL);

	default:
		return NULL;
	}
}

bool
ucv_compare(int how, uc_value_t *v1, uc_value_t *v2, int *deltap)
{
	uc_type_t t1 = ucv_type(v1);
	uc_type_t t2 = ucv_type(v2);
	uc_value_t *nv1, *nv2;
	uint64_t u1, u2;
	int64_t n1, n2;
	double d1, d2;
	int delta;

	/* at least one operand is null and we compare for equality or inequality ... */
	if ((!v1 || !v2) && (how == I_EQ || how == I_NE)) {
		delta = (v1 != v2);
	}

	/* ... otherwise if both operands are strings, compare bytewise ... */
	else if (t1 == UC_STRING && t2 == UC_STRING) {
		u1 = ucv_string_length(v1);
		u2 = ucv_string_length(v2);

		delta = memcmp(ucv_string_get(v1), ucv_string_get(v2),
			(u1 < u2) ? u1 : u2);

		if (delta == 0 && u1 < u2)
			delta = -1;
		else if (delta == 0 && u1 > u2)
			delta = 1;
	}

	/* handle non-string cases... */
	else {
		/* ... both operands are of the same, non-scalar type... */
		if (t1 == t2 && !ucv_is_scalar(v1)) {
			/* ... compare memory addrs */
			if ((uintptr_t)v1 == (uintptr_t)v2)
				delta = 0;
			else if ((uintptr_t)v1 < (uintptr_t)v2)
				delta = -1;
			else
				delta = 1;
		}

		/* ... operands are of different type or at least one is scalar... */
		else {
			nv1 = ucv_to_number(v1);
			nv2 = ucv_to_number(v2);

			/* ... at least one of them is NaN (not convertible)... */
			if (!nv1 || !nv2) {
				ucv_put(nv1);
				ucv_put(nv2);

				if (deltap)
					*deltap = 2;

				/* ... all comparison results except `!=` involving NaN are false */
				return (how == I_NE);
			}

			/* ... either of them is a double, compare both as double */
			if (ucv_type(nv1) == UC_DOUBLE || ucv_type(nv2) == UC_DOUBLE) {
				d1 = ucv_double_get(nv1);
				d2 = ucv_double_get(nv2);

				if (d1 == d2)
					delta = 0;
				else if (d1 < d2)
					delta = -1;
				else
					delta = 1;
			}

			/* ... both are integers... */
			else {
				n1 = ucv_int64_get(nv1);

				/* ... left operand is large positive... */
				if (errno == ERANGE) {
					ucv_int64_get(nv2);

					/* ... right operand is large positive too... */
					if (errno == ERANGE) {
						/* ... compare both as unsigned */
						u1 = ucv_uint64_get(nv1);
						u2 = ucv_uint64_get(nv2);

						if (u1 == u2)
							delta = 0;
						else if (u1 < u2)
							delta = -1;
						else
							delta = 1;
					}

					/* ... right operand is within int64_t range... */
					else {
						/* ... left > right by definition */
						delta = 1;
					}
				}

				/* ... left operand is within int64_t range... */
				else {
					n2 = ucv_int64_get(nv2);

					/* ... right operand is large positive... */
					if (errno == ERANGE) {
						/* ... left < right by definition */
						delta = -1;
					}

					/* ... right operand is within int64_t range... */
					else {
						/* ... compare both as signed */
						if (n1 == n2)
							delta = 0;
						else if (n1 < n2)
							delta = -1;
						else
							delta = 1;
					}
				}
			}

			ucv_put(nv1);
			ucv_put(nv2);
		}
	}

	if (deltap)
		*deltap = delta;

	switch (how) {
	case I_LT:
		return (delta < 0);

	case I_LE:
		return (delta <= 0);

	case I_GT:
		return (delta > 0);

	case I_GE:
		return (delta >= 0);

	case I_EQ:
		return (delta == 0);

	case I_NE:
		return (delta != 0);

	default:
		return false;
	}
}


static char *
ucv_key_to_string(uc_vm_t *vm, uc_value_t *val)
{
	if (ucv_type(val) != UC_STRING)
		return ucv_to_string(vm, val);

	return NULL;
}

static int64_t
ucv_key_to_index(uc_value_t *val)
{
	const char *k;
	int64_t idx;
	double d;
	char *e;

	/* only consider doubles with integer values as array keys */
	if (ucv_type(val) == UC_DOUBLE) {
		d = ucv_double_get(val);

		if (trunc(d) != d)
			return INT64_MIN;

		return (int64_t)d;
	}
	else if (ucv_type(val) == UC_INTEGER) {
		return ucv_int64_get(val);
	}
	else if (ucv_type(val) == UC_STRING) {
		errno = 0;
		k = ucv_string_get(val);
		idx = strtoll(k, &e, 0);

		if (errno != 0 || e == k || *e != 0)
			return INT64_MIN;

		return idx;
	}

	return INT64_MIN;
}

uc_value_t *
ucv_key_get(uc_vm_t *vm, uc_value_t *scope, uc_value_t *key)
{
	uc_value_t *o, *v = NULL;
	int64_t idx;
	bool found;
	char *k;

	if (ucv_type(scope) == UC_ARRAY) {
		idx = ucv_key_to_index(key);

		if (idx < 0 && idx > INT64_MIN && (uint64_t)llabs(idx) <= ucv_array_length(scope))
			idx += ucv_array_length(scope);

		if (idx >= 0 && (uint64_t)idx < ucv_array_length(scope))
			return ucv_get(ucv_array_get(scope, idx));
	}

	k = ucv_key_to_string(vm, key);

	for (o = scope; o; o = ucv_prototype_get(o)) {
		if (ucv_type(o) != UC_OBJECT)
			continue;

		v = ucv_object_get(o, k ? k : ucv_string_get(key), &found);

		if (found)
			break;
	}

	free(k);

	return ucv_get(v);
}

uc_value_t *
ucv_key_set(uc_vm_t *vm, uc_value_t *scope, uc_value_t *key, uc_value_t *val)
{
	int64_t idx;
	char *s;
	bool rv;

	if (!key)
		return NULL;

	if (ucv_type(scope) == UC_ARRAY) {
		idx = ucv_key_to_index(key);

		if (idx < 0 && idx > INT64_MIN && (uint64_t)llabs(idx) <= ucv_array_length(scope))
			idx += ucv_array_length(scope);

		if (idx < 0 || !ucv_array_set(scope, idx, val))
			return NULL;

		return ucv_get(val);
	}

	s = ucv_key_to_string(vm, key);
	rv = ucv_object_add(scope, s ? s : ucv_string_get(key), val);
	free(s);

	return rv ? ucv_get(val) : NULL;
}

bool
ucv_key_delete(uc_vm_t *vm, uc_value_t *scope, uc_value_t *key)
{
	char *s;
	bool rv;

	if (!key)
		return NULL;

	s = ucv_key_to_string(vm, key);
	rv = ucv_object_delete(scope, s ? s : ucv_string_get(key));
	free(s);

	return rv;
}


static void
ucv_gc_common(uc_vm_t *vm, bool final)
{
	uc_weakref_t *ref, *tmp;
	uc_value_t *val;
	size_t i;

	vm->alloc_refs = 0;

	/* back out early if value list is uninitialized */
	if (!vm->values.prev || !vm->values.next)
		return;

	if (!final) {
		/* mark reachable objects */
		ucv_gc_mark(vm->globals);
		ucv_gc_mark(vm->registry);
		ucv_gc_mark(vm->signal.handler);
		ucv_gc_mark(vm->exception.stacktrace);

		for (i = 0; i < vm->callframes.count; i++) {
			ucv_gc_mark(vm->callframes.entries[i].ctx);

			if (vm->callframes.entries[i].closure)
				ucv_gc_mark(&vm->callframes.entries[i].closure->header);

			if (vm->callframes.entries[i].cfunction)
				ucv_gc_mark(&vm->callframes.entries[i].cfunction->header);
		}

		for (i = 0; i < vm->stack.count; i++)
			ucv_gc_mark(vm->stack.entries[i]);

		for (i = 0; i < vm->restypes.count; i++)
			ucv_gc_mark(vm->restypes.entries[i]->proto);
	}

	/* unref unreachable objects */
	for (ref = vm->values.next; ref != &vm->values; ref = ref->next) {
		val = (uc_value_t *)((uintptr_t)ref - offsetof(uc_array_t, ref));

		if (ucv_is_marked(val))
			ucv_clear_mark(val);
		else
			ucv_free(val, true);
	}

	/* free destroyed objects */
	for (ref = vm->values.next, tmp = ref->next; ref != &vm->values; ref = tmp, tmp = tmp->next) {
		val = (uc_value_t *)((uintptr_t)ref - offsetof(uc_array_t, ref));

		if (val->type == UC_NULL) {
			ucv_unref(ref);
			free(val);
		}
	}
}

void
ucv_gc(uc_vm_t *vm)
{
	ucv_gc_common(vm, false);
}

void
ucv_freeall(uc_vm_t *vm)
{
	ucv_gc_common(vm, true);
}

void
uc_search_path_init(uc_search_path_t *search_path)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(uc_default_search_path); i++)
		uc_vector_push(search_path, xstrdup(uc_default_search_path[i]));
}
