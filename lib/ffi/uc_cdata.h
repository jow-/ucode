/*
** C data management.
** Copyright (C) 2005-2025 Mike Pall. See Copyright Notice below.
**
** This header contains derived work from LuaJIT's FFI C data objects.
**
** Modifications:
** - Adapted for ucode VM integration (uc_cdata_new, uc_cdata_dataptr, etc.)
** - Removed JIT-specific dependencies
**
** See NOTICE and ATTRIBUTION.md for complete attribution details.
*/

#ifndef _UC_CDATA_H
#define _UC_CDATA_H

#include "uc_ctype.h"

/* Get C data pointer. */
static UC_AINLINE void *cdata_getptr(void *p, CTSize sz)
{
	if (UC_64 && sz == 4)
	{ /* Support 32 bit pointers on 64 bit targets. */
		return ((void *)(uintptr_t) * (uint32_t *)p);
	}
	else
	{
		uc_assertX(sz == CTSIZE_PTR, "bad pointer size %d", sz);
		return *(void **)p;
	}
}

/* Set C data pointer. */
static UC_AINLINE void cdata_setptr(void *p, CTSize sz, const void *v)
{
	if (UC_64 && sz == 4)
	{ /* Support 32 bit pointers on 64 bit targets. */
		*(uint32_t *)p = (uint32_t)(uintptr_t)v;
	}
	else
	{
		uc_assertX(sz == CTSIZE_PTR, "bad pointer size %d", sz);
		*(void **)p = (void *)v;
	}
}

/* Allocate fixed-size C data object. */
static inline uc_value_t *
uc_cdata_new(uc_vm_t *vm, CTypeID id, CTSize sz)
{
	CTState *cts = ctype_cts(vm);
	uc_resource_t *res;
	GCcdata *cd;

#ifdef LUA_USE_ASSERT
	CType *ct = ctype_raw(cts, id);
	uc_assertCTS((ctype_hassize(ct->info) ? ct->size : CTSIZE_PTR) == sz,
				 "inconsistent size of fixed-size cdata alloc");
#endif

	res = xalloc(ALIGN(sizeof(*res)) + sizeof(*cd) + sz);
	res->header.type = UC_RESOURCE;
	res->header.refcount = 1;
	res->type = ucv_resource_type_lookup(vm, "ffi.ctype");
	res->data = (char *)res + ALIGN(sizeof(*res));

	cd = res->data;
	cd->ctypeid = ctype_check(cts, id);
	cd->isvla = 0;
	cd->refs = NULL;

	return &res->header;
}

/* Variant which works without a valid CTState. */
static UC_AINLINE uc_value_t *uc_cdata_new_(uc_vm_t *vm, CTypeID id, CTSize sz)
{
	GCcdata *cd;

	cd = xalloc(sizeof(*cd) + sz);
	cd->ctypeid = id;
	cd->isvla = 0;
	cd->refs = NULL;

	return ucv_resource_new(ucv_resource_type_lookup(vm, "ffi.ctype"), cd);
}

UC_NOAPI uc_value_t *uc_cdata_newref(uc_vm_t *vm, const void *pp, CTypeID id);
UC_NOAPI uc_value_t *uc_cdata_newv(uc_vm_t *vm, CTypeID id, CTSize sz,
                                  CTSize align);
UC_NOAPI uc_value_t *uc_cdata_newx(uc_vm_t *vm, CTypeID id, CTSize sz,
                                  CTInfo info);

static inline void *
uc_cdata_dataptr(uc_value_t *val)
{
	if (ucv_type(val) != UC_RESOURCE)
		return NULL;

	uc_resource_t *res = (uc_resource_t *)val;

	if (!res->type || strcmp(res->type->name, "ffi.ctype") != 0)
		return NULL;

	return cdataptr((GCcdata *)res->data);
}

#define uc_cdataptr(res) cdataptr(((uc_resource_t *)res)->data)


UC_NOAPI CType *uc_cdata_index(CTState *cts, GCcdata *cd, uc_value_t *key,
							  uint8_t **pp, CTInfo *qual);
UC_NOAPI int uc_cdata_get(CTState *cts, CType *s, uc_value_t **uv, uint8_t *sp);
UC_NOAPI void uc_cdata_set(CTState *cts, CType *d, uint8_t *dp, uc_value_t *uv,
						  CTInfo qual, uc_value_t **refs);

#endif
