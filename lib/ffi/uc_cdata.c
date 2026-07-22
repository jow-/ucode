/*
** C data management.
** Copyright (C) 2005-2025 Mike Pall. See Copyright Notice below.
**
** This file contains derived work from LuaJIT's FFI C data objects (lj_cdata.c).
**
** Modifications:
** - Adapted VM interactions to use ucode's API (uc_vm_t, uc_value_t, etc.)
** - Adapted C data allocation to use ucode resource system (uc_cdata_new, etc.)
** - Removed JIT-specific code and dependencies
**
** See NOTICE and ATTRIBUTION.md for complete attribution details.
*/


#include "uc_ctype.h"
#include "uc_cconv.h"
#include "uc_cdata.h"

/* -- C data allocation --------------------------------------------------- */

/* Allocate a new C data object holding a reference to another object. */
uc_value_t *uc_cdata_newref(uc_vm_t *vm, const void *p, CTypeID id)
{
	CTypeID refid = uc_ctype_intern(ctype_cts(vm), CTINFO_REF(id), CTSIZE_PTR);
	uc_value_t *res = uc_cdata_new(vm, refid, CTSIZE_PTR);

	*(const void **)uc_cdata_dataptr(res) = p;

	return res;
}

/* Allocate variable-sized or specially aligned C data object. */
uc_value_t *uc_cdata_newv(uc_vm_t *vm, CTypeID id, CTSize sz, CTSize align)
{
	// global_State *g;
	// FIXME: non-power-of-two alignments?
	if (align < 1) align = 1;  // Ensure minimum alignment
	size_t hdrsize = (sizeof(uc_resource_t) + align - 1) & -align;
	size_t extra = sizeof(GCcdataVar) + sizeof(GCcdata)
	    + (align > CT_MEMALIGN ? (1u << align) - (1u << CT_MEMALIGN) : 0);

	uc_resource_t *res = xalloc(hdrsize + sz + extra);
	res->header.type = UC_RESOURCE;
	res->header.refcount = 1;
	res->type = ucv_resource_type_lookup(vm, "ffi.ctype");

	char *p = (char *)res + hdrsize;
	uintptr_t adata = (uintptr_t)p + sizeof(GCcdataVar) + sizeof(GCcdata);
	uintptr_t almask = (1u << align) - 1u;
	GCcdata *cd = (GCcdata *)(((adata + almask) & ~almask) - sizeof(GCcdata));
	cdatav(cd)->offset = (uint16_t)((char *)cd - p);
	cdatav(cd)->extra = extra;
	cdatav(cd)->len = sz;
	cd->ctypeid = id;
	cd->isvla = 1;
	cd->refs = NULL;

	res->data = cd;

	return &res->header;
}

/* Allocate arbitrary C data object. */
uc_value_t *uc_cdata_newx(uc_vm_t *vm, CTypeID id, CTSize sz, CTInfo info)
{
	if (!(info & CTF_VLA) && ctype_align(info) <= CT_MEMALIGN)
		return uc_cdata_new(vm, id, sz);
	else
		return uc_cdata_newv(vm, id, sz, ctype_align(info));
}

/* -- C data indexing ----------------------------------------------------- */

/* Index C data by a TValue. Return CType and pointer. */
CType *uc_cdata_index(CTState *cts, GCcdata *cd, uc_value_t *key, uint8_t **pp,
					  CTInfo *qual)
{
	uint8_t *p = (uint8_t *)cdataptr(cd);
	CType *ct = ctype_get(cts, cd->ctypeid);
	ptrdiff_t idx;
	uc_type_t ut = ucv_type(key);
	GCcdata *cdk = (ut == UC_RESOURCE) ? ucv_resource_data(key, "ffi.ctype") : NULL;

	/* Skip extern and attribute wrappers */
	while (ctype_isextern(ct->info) || ctype_isattrib(ct->info))
		ct = ctype_child(cts, ct);

	/* Resolve reference for cdata object. */
	if (ctype_isref(ct->info))
	{
		uc_assertCTS(ct->size == CTSIZE_PTR, "ref is not pointer-sized");
		p = *(uint8_t **)p;
		ct = ctype_child(cts, ct);
	}

collect_attrib:
	/* Skip any remaining attributes and collect qualifiers. */
	while (ctype_isattrib(ct->info))
	{
		if (ctype_attrib(ct->info) == CTA_QUAL)
			*qual |= ct->size;
		ct = ctype_child(cts, ct);
	}
	/* Interning rejects refs to refs. */
	uc_assertCTS(!ctype_isref(ct->info), "bad ref of ref");

	if (ut == UC_INTEGER)
	{
		idx = (ptrdiff_t)ucv_int64_get(key);
		goto integer_key;
	}
	else if (ut == UC_DOUBLE)
	{ /* Numeric key. */
		double d = ucv_double_get(key);
		idx = UC_64 ? (ptrdiff_t)d : (ptrdiff_t)uc_num2int(d);
	integer_key:
		if (ctype_ispointer(ct->info) || ctype_isrefarray(ct->info))
		{
			CTSize sz = uc_ctype_size(cts, ctype_cid(ct->info)); /* Element size. */
			if (sz == CTSIZE_INVALID) {
				uc_vm_raise_exception(cts->vm, EXCEPTION_TYPE,
					"size of C type is unknown or too large");

				return NULL;
			}
			if (ctype_isptr(ct->info))
			{
				p = (uint8_t *)cdata_getptr(p, ct->size);
			}
			else if ((ct->info & (CTF_VECTOR | CTF_COMPLEX)))
			{
				if ((ct->info & CTF_COMPLEX))
					idx &= 1;
				*qual |= CTF_CONST; /* Valarray elements are constant. */
			}
			*pp = p + idx * (int32_t)sz;
			return ct;
		}
	}
	else if (cdk)
	{ /* Integer cdata key. */
		CType *ctk = ctype_raw(cts, cdk->ctypeid);
		if (ctype_isenum(ctk->info))
			ctk = ctype_child(cts, ctk);
		if (ctype_isinteger(ctk->info))
		{
			uc_cconv_ct_ct(cts, ctype_get(cts, CTID_INT_PSZ), ctk,
						   (uint8_t *)&idx, cdataptr(cdk), 0);
			goto integer_key;
		}
	}
	else if (ut == UC_STRING)
	{ /* String key. */
		if (ctype_isstruct(ct->info))
		{
			CTSize ofs;
			CType *fct = uc_ctype_getfieldq(cts, ct, key, &ofs, qual);
			if (fct)
			{
				*pp = p + ofs;
				return fct;
			}
		}
		else if (ctype_iscomplex(ct->info))
		{
			if (ucv_string_length(key) == 2)
			{
				char *name = ucv_string_get(key);

				*qual |= CTF_CONST; /* Complex fields are constant. */
				if (name[0] == 'r' && name[1] == 'e')
				{
					*pp = p;
					return ct;
				}
				else if (name[0] == 'i' && name[1] == 'm')
				{
					*pp = p + (ct->size >> 1);
					return ct;
				}
			}
		}
		else if (cd->ctypeid == CTID_CTYPEID)
		{
			/* Allow indexing a (pointer to) struct constructor to get constants. */
			CType *sct = ctype_raw(cts, *(CTypeID *)p);
			if (ctype_isptr(sct->info))
				sct = ctype_rawchild(cts, sct);
			if (ctype_isstruct(sct->info))
			{
				CTSize ofs;
				CType *fct = uc_ctype_getfield(cts, sct, key, &ofs);
				if (fct && ctype_isconstval(fct->info))
					return fct;
			}
			ct = sct; /* Allow resolving metamethods for constructors, too. */
		}
	}
	if (ctype_isptr(ct->info))
	{ /* Automatically perform '->'. */
		if (ctype_isstruct(ctype_rawchild(cts, ct)->info))
		{
			p = (uint8_t *)cdata_getptr(p, ct->size);
			ct = ctype_child(cts, ct);
			goto collect_attrib;
		}
	}
	*qual |= 1; /* Lookup failed. */
	return ct;	/* But return the resolved raw type. */
}

/* -- C data getters ------------------------------------------------------ */

/* Get constant value and convert to TValue. */
static void cdata_getconst(CTState *cts, uc_value_t **uv, CType *ct)
{
	CType *ctt = ctype_child(cts, ct);
	uc_assertCTS(ctype_isinteger(ctt->info) && ctt->size <= 4,
				 "only 32 bit const supported"); /* NYI */

	ucv_put(*uv);

	/* Constants are already zero-extended/sign-extended to 32 bits. */
	if ((ctt->info & CTF_UNSIGNED) && (int32_t)ct->size < 0)
		*uv = ucv_int64_new((int64_t)(uint32_t)ct->size);
	else
		*uv = ucv_int64_new((int64_t)(int32_t)ct->size);
}

/* Get C data value and convert to TValue. */
int uc_cdata_get(CTState *cts, CType *s, uc_value_t **uv, uint8_t *sp)
{
	CTypeID sid;

	if (ctype_isconstval(s->info))
	{
		cdata_getconst(cts, uv, s);
		return 0; /* No GC step needed. */
	}
	else if (ctype_isbitfield(s->info))
	{
		return uc_cconv_tv_bf(cts, s, uv, sp);
	}

	/* Get child type of pointer/array/field. */
	uc_assertCTS(ctype_ispointer(s->info) || ctype_isfield(s->info),
				 "pointer or field expected");
	sid = ctype_cid(s->info);
	s = ctype_get(cts, sid);

	/* Resolve reference for field. */
	if (ctype_isref(s->info))
	{
		uc_assertCTS(s->size == CTSIZE_PTR, "ref is not pointer-sized");
		sp = *(uint8_t **)sp;
		sid = ctype_cid(s->info);
		s = ctype_get(cts, sid);
	}

	/* Skip attributes. */
	while (ctype_isattrib(s->info))
		s = ctype_child(cts, s);

	return uc_cconv_tv_ct(cts, s, sid, uv, sp);
}

/* -- C data setters ------------------------------------------------------ */

/* Convert TValue and set C data value. */
void uc_cdata_set(CTState *cts, CType *d, uint8_t *dp, uc_value_t *uv, CTInfo qual, uc_value_t **refs)
{
	if (ctype_isconstval(d->info))
	{
		goto err_const;
	}
	else if (ctype_isbitfield(d->info))
	{
		if (((d->info | qual) & CTF_CONST))
			goto err_const;
		uc_cconv_bf_tv(cts, d, dp, uv, refs);
		return;
	}

	/* Get child type of pointer/array/field. */
	uc_assertCTS(ctype_ispointer(d->info) || ctype_isfield(d->info),
				 "pointer or field expected");
	d = ctype_child(cts, d);

	/* Resolve reference for field. */
	if (ctype_isref(d->info))
	{
		uc_assertCTS(d->size == CTSIZE_PTR, "ref is not pointer-sized");
		dp = *(uint8_t **)dp;
		d = ctype_child(cts, d);
	}

	/* Skip attributes and collect qualifiers. */
	for (;;)
	{
		if (ctype_isattrib(d->info))
		{
			if (ctype_attrib(d->info) == CTA_QUAL)
				qual |= d->size;
		}
		else
		{
			break;
		}
		d = ctype_child(cts, d);
	}

	uc_assertCTS(ctype_hassize(d->info), "store to ctype without size");
	uc_assertCTS(!ctype_isvoid(d->info), "store to void type");

	if (((d->info | qual) & CTF_CONST))
	{
	err_const:
		uc_vm_raise_exception(cts->vm, EXCEPTION_REFERENCE,
			"attempt to write to constant location");

		return;
	}

	uc_cconv_ct_tv(cts, d, dp, uv, 0, refs);
}
