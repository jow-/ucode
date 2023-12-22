/*
** C type conversions.
** Copyright (C) 2005-2025 Mike Pall. See Copyright Notice below.
**
** This file contains derived work from LuaJIT's FFI conversion machinery (lj_cconv.c).
**
** Modifications:
** - Adapted VM interactions to use ucode's API (uc_vm_t, uc_value_t, etc.)
** - Replaced LuaJIT's parallel call infrastructure with libffi
** - Adapted value marshaling between ucode and C types
** - Removed JIT-specific code and dependencies
**
** See NOTICE and ATTRIBUTION.md for complete attribution details.
*/


#include "uc_ctype.h"
#include "uc_cdata.h"
#include "uc_cconv.h"

#include <ffi.h>

/* -- Conversion errors --------------------------------------------------- */

/* Bad conversion. */
static bool
cconv_err_conv(CTState *cts, CType *d, CType *s, CTInfo flags)
{
	uc_value_t *dst_repr = uc_ctype_repr(cts->vm, ctype_typeid(cts, d), NULL);
	uc_value_t *src_repr = NULL;
	const char *dst = ucv_string_get(dst_repr);
	const char *src;

	if ((flags & CCF_FROMTV))
	{
		src = ctype_isnum(s->info)
			? "number"
			: ctype_isarray(s->info)
				? "string"
				: "null";
	}
	else
	{
		src_repr = uc_ctype_repr(cts->vm, ctype_typeid(cts, s), NULL);
		src = ucv_string_get(src_repr);
	}

	if (CCF_GETARG(flags)) {
		uc_vm_raise_exception(cts->vm, EXCEPTION_TYPE,
		                      "cannot convert argument #%d from '%s' to '%s'",
		                      CCF_GETARG(flags), src, dst);
	}
	// lj_err_argv(cts->L, CCF_GETARG(flags), LJ_ERR_FFI_BADCONV, src, dst);
	else {
		uc_vm_raise_exception(cts->vm, EXCEPTION_TYPE,
		                      "cannot convert from '%s' to '%s'",
		                      src, dst);
	}

	// lj_err_callerv(cts->L, LJ_ERR_FFI_BADCONV, src, dst);
	ucv_put(dst_repr);
	ucv_put(src_repr);

	return false;
}

/* Bad conversion from TValue. */
static bool
cconv_err_convtv(CTState *cts, CType *d, uc_value_t *uv, CTInfo flags)
{
	uc_value_t *dst_repr = uc_ctype_repr(cts->vm, ctype_typeid(cts, d), NULL);
	const char *dst = ucv_string_get(dst_repr);
	const char *src = ucv_typename(uv);

	if (CCF_GETARG(flags)) {
		uc_vm_raise_exception(cts->vm, EXCEPTION_TYPE,
		                      "cannot convert argument #%d from '%s' to '%s'",
		                      CCF_GETARG(flags), src, dst);
	}
	// lj_err_argv(cts->L, CCF_GETARG(flags), LJ_ERR_FFI_BADCONV, src, dst);
	else {
		uc_vm_raise_exception(cts->vm, EXCEPTION_TYPE,
		                      "cannot convert from '%s' to '%s'",
		                      src, dst);
	}

	// lj_err_callerv(cts->L, LJ_ERR_FFI_BADCONV, src, dst);
	ucv_put(dst_repr);

	return false;
}

/* Initializer overflow. */
static bool
cconv_err_initov(CTState *cts, CType *d)
{
	uc_value_t *repr = uc_ctype_repr(cts->vm, ctype_typeid(cts, d), NULL);

	uc_vm_raise_exception(cts->vm, EXCEPTION_REFERENCE,
	                      "too many initializers for '%s'",
	                      ucv_string_get(repr));

	ucv_put(repr);

	return false;
}

/* -- C type compatibility checks ----------------------------------------- */

/* Get raw type and qualifiers for a child type. Resolves enums, too. */
static CType *cconv_childqual(CTState *cts, CType *ct, CTInfo *qual)
{
	ct = ctype_child(cts, ct);
	for (;;)
	{
		if (ctype_isattrib(ct->info))
		{
			if (ctype_attrib(ct->info) == CTA_QUAL)
				*qual |= ct->size;
		}
		else if (!ctype_isenum(ct->info))
		{
			break;
		}
		ct = ctype_child(cts, ct);
	}
	*qual |= (ct->info & CTF_QUAL);
	return ct;
}

/* Check for compatible types when converting to a pointer.
** Note: these checks are more relaxed than what C99 mandates.
*/
int uc_cconv_compatptr(CTState *cts, CType *d, CType *s, CTInfo flags)
{
	if (!((flags & CCF_CAST) || d == s))
	{
		CTInfo dqual = 0, squal = 0;
		d = cconv_childqual(cts, d, &dqual);
		if (!ctype_isstruct(s->info))
			s = cconv_childqual(cts, s, &squal);
		if ((flags & CCF_SAME))
		{
			if (dqual != squal)
				return 0; /* Different qualifiers. */
		}
		else if (!(flags & CCF_IGNQUAL))
		{
			if ((dqual & squal) != squal)
				return 0; /* Discarded qualifiers. */
			if (ctype_isvoid(d->info) || ctype_isvoid(s->info))
				return 1; /* Converting to/from void * is always ok. */
		}
		if (ctype_type(d->info) != ctype_type(s->info) ||
			d->size != s->size)
			return 0; /* Different type or different size. */
		if (ctype_isnum(d->info))
		{
			if (((d->info ^ s->info) & (CTF_BOOL | CTF_FP)))
				return 0; /* Different numeric types. */
		}
		else if (ctype_ispointer(d->info))
		{
			/* Check child types for compatibility. */
			return uc_cconv_compatptr(cts, d, s, flags | CCF_SAME);
		}
		else if (ctype_isstruct(d->info))
		{
			if (d != s)
				return 0; /* Must be exact same type for struct/union. */
		}
		else if (ctype_isfunc(d->info))
		{
			/* NYI: structural equality of functions. */
		}
	}
	return 1; /* Types are compatible. */
}

/* -- C type to C type conversion ----------------------------------------- */

/* Convert C type to C type. Caveat: expects to get the raw CType!
**
** Note: This is only used by the interpreter and not optimized at all.
** The JIT compiler will do a much better job specializing for each case.
*/
bool uc_cconv_ct_ct(CTState *cts, CType *d, CType *s,
					uint8_t *dp, uint8_t *sp, CTInfo flags)
{
	CTSize dsize = d->size, ssize = s->size;
	CTInfo dinfo = d->info, sinfo = s->info;
	void *tmpptr;

	uc_assertCTS(!ctype_isenum(dinfo) && !ctype_isenum(sinfo),
				 "unresolved enum");
	uc_assertCTS(!ctype_isattrib(dinfo) && !ctype_isattrib(sinfo),
				 "unstripped attribute");

	if (ctype_type(dinfo) > CT_MAYCONVERT || ctype_type(sinfo) > CT_MAYCONVERT)
		goto err_conv;

	/* Some basic sanity checks. */
	uc_assertCTS(!ctype_isnum(dinfo) || dsize > 0, "bad size for number type");
	uc_assertCTS(!ctype_isnum(sinfo) || ssize > 0, "bad size for number type");
	uc_assertCTS(!ctype_isbool(dinfo) || dsize == 1 || dsize == 4,
				 "bad size for bool type");
	uc_assertCTS(!ctype_isbool(sinfo) || ssize == 1 || ssize == 4,
				 "bad size for bool type");
	uc_assertCTS(!ctype_isinteger(dinfo) || (1u << uc_fls(dsize)) == dsize,
				 "bad size for integer type");
	uc_assertCTS(!ctype_isinteger(sinfo) || (1u << uc_fls(ssize)) == ssize,
				 "bad size for integer type");

	switch (cconv_idx2(dinfo, sinfo))
	{
	/* Destination is a bool. */
	case CCX(B, B):
		/* Source operand is already normalized. */
		if (dsize == 1)
			*dp = *sp;
		else
			*(int *)dp = *sp;
		break;
	case CCX(B, I):
	{
		size_t i;
		uint8_t b = 0;
		for (i = 0; i < ssize; i++)
			b |= sp[i];
		b = (b != 0);
		if (dsize == 1)
			*dp = b;
		else
			*(int *)dp = b;
		break;
	}
	case CCX(B, F):
	{
		uint8_t b;
		if (ssize == sizeof(double))
			b = (*(double *)sp != 0);
		else if (ssize == sizeof(float))
			b = (*(float *)sp != 0);
		else
			goto err_conv; /* NYI: long double. */
		if (dsize == 1)
			*dp = b;
		else
			*(int *)dp = b;
		break;
	}

	/* Destination is an integer. */
	case CCX(I, B):
	case CCX(I, I):
	conv_I_I:
		if (dsize > ssize)
		{ /* Zero-extend or sign-extend LSB. */
#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t fill = (!(sinfo & CTF_UNSIGNED) && (sp[ssize - 1] & 0x80)) ? 0xff : 0;
			memcpy(dp, sp, ssize);
			memset(dp + ssize, fill, dsize - ssize);
#else
			uint8_t fill = (!(sinfo & CTF_UNSIGNED) && (sp[0] & 0x80)) ? 0xff : 0;
			memset(dp, fill, dsize - ssize);
			memcpy(dp + (dsize - ssize), sp, ssize);
#endif
		}
		else
		{ /* Copy LSB. */
#if __BYTE_ORDER == __LITTLE_ENDIAN
			memcpy(dp, sp, dsize);
#else
			memcpy(dp, sp + (ssize - dsize), dsize);
#endif
		}
		break;
	case CCX(I, F):
	{
		double n; /* Always convert via double. */
	conv_I_F:
		/* Convert source to double. */
		if (ssize == sizeof(double))
			n = *(double *)sp;
		else if (ssize == sizeof(float))
			n = (double)*(float *)sp;
		else
			goto err_conv; /* NYI: long double. */
		/* Then convert double to integer. */
		/* The conversion must exactly match the semantics of JIT-compiled code! */
		if (dsize < 4 || (dsize == 4 && !(dinfo & CTF_UNSIGNED)))
		{
			int32_t i = (int32_t)n;
			if (dsize == 4)
				*(int32_t *)dp = i;
			else if (dsize == 2)
				*(int16_t *)dp = (int16_t)i;
			else
				*(int8_t *)dp = (int8_t)i;
		}
		else if (dsize == 4)
		{
			*(uint32_t *)dp = (uint32_t)n;
		}
		else if (dsize == 8)
		{
			if (!(dinfo & CTF_UNSIGNED))
				*(int64_t *)dp = (int64_t)n;
			else
				*(uint64_t *)dp = uc_num2u64(n);
		}
		else
		{
			goto err_conv; /* NYI: conversion to >64 bit integers. */
		}
		break;
	}
	case CCX(I, C):
		s = ctype_child(cts, s);
		ssize = s->size;
		goto conv_I_F; /* Just convert re. */
	case CCX(I, P):
		if (!(flags & CCF_CAST))
			goto err_conv;
		sinfo = CTINFO(CT_NUM, CTF_UNSIGNED);
		goto conv_I_I;
	case CCX(I, A):
		if (!(flags & CCF_CAST))
			goto err_conv;
		sinfo = CTINFO(CT_NUM, CTF_UNSIGNED);
		ssize = CTSIZE_PTR;
		tmpptr = sp;
		sp = (uint8_t *)&tmpptr;
		goto conv_I_I;

	/* Destination is a floating-point number. */
	case CCX(F, B):
	case CCX(F, I):
	{
		double n; /* Always convert via double. */
	conv_F_I:
		/* First convert source to double. */
		/* The conversion must exactly match the semantics of JIT-compiled code! */
		if (ssize < 4 || (ssize == 4 && !(sinfo & CTF_UNSIGNED)))
		{
			int32_t i;
			if (ssize == 4)
			{
				i = *(int32_t *)sp;
			}
			else if (!(sinfo & CTF_UNSIGNED))
			{
				if (ssize == 2)
					i = *(int16_t *)sp;
				else
					i = *(int8_t *)sp;
			}
			else
			{
				if (ssize == 2)
					i = *(uint16_t *)sp;
				else
					i = *(uint8_t *)sp;
			}
			n = (double)i;
		}
		else if (ssize == 4)
		{
			n = (double)*(uint32_t *)sp;
		}
		else if (ssize == 8)
		{
			if (!(sinfo & CTF_UNSIGNED))
				n = (double)*(int64_t *)sp;
			else
				n = (double)*(uint64_t *)sp;
		}
		else
		{
			goto err_conv; /* NYI: conversion from >64 bit integers. */
		}
		/* Convert double to destination. */
		if (dsize == sizeof(double))
			*(double *)dp = n;
		else if (dsize == sizeof(float))
			*(float *)dp = (float)n;
		else
			goto err_conv; /* NYI: long double. */
		break;
	}
	case CCX(F, F):
	{
		double n; /* Always convert via double. */
	conv_F_F:
		if (ssize == dsize)
			goto copyval;
		/* Convert source to double. */
		if (ssize == sizeof(double))
			n = *(double *)sp;
		else if (ssize == sizeof(float))
			n = (double)*(float *)sp;
		else
			goto err_conv; /* NYI: long double. */
		/* Convert double to destination. */
		if (dsize == sizeof(double))
			*(double *)dp = n;
		else if (dsize == sizeof(float))
			*(float *)dp = (float)n;
		else
			goto err_conv; /* NYI: long double. */
		break;
	}
	case CCX(F, C):
		s = ctype_child(cts, s);
		ssize = s->size;
		goto conv_F_F; /* Ignore im, and convert from re. */

	/* Destination is a complex number. */
	case CCX(C, I):
		d = ctype_child(cts, d);
		dsize = d->size;
		memset(dp + dsize, 0, dsize); /* Clear im. */
		goto conv_F_I;				  /* Convert to re. */
	case CCX(C, F):
		d = ctype_child(cts, d);
		dsize = d->size;
		memset(dp + dsize, 0, dsize); /* Clear im. */
		goto conv_F_F;				  /* Convert to re. */

	case CCX(C, C):
		if (dsize != ssize)
		{ /* Different types: convert re/im separately. */
			CType *dc = ctype_child(cts, d);
			CType *sc = ctype_child(cts, s);
			return uc_cconv_ct_ct(cts, dc, sc, dp, sp, flags) &&
			       uc_cconv_ct_ct(cts, dc, sc, dp + dc->size, sp + sc->size, flags);
		}
		goto copyval; /* Otherwise this is easy. */

	/* Destination is a vector. */
	case CCX(V, I):
	case CCX(V, F):
	case CCX(V, C):
	{
		CType *dc = ctype_child(cts, d);
		CTSize esize;
		/* First convert the scalar to the first element. */
		if (!uc_cconv_ct_ct(cts, dc, s, dp, sp, flags))
			return false;
		/* Then replicate it to the other elements (splat). */
		for (sp = dp, esize = dc->size; dsize > esize; dsize -= esize)
		{
			dp += esize;
			memcpy(dp, sp, esize);
		}
		break;
	}

	case CCX(V, V):
		/* Copy same-sized vectors, even for different lengths/element-types. */
		if (dsize != ssize)
			goto err_conv;
		goto copyval;

	/* Destination is a pointer. */
	case CCX(P, I):
		if (!(flags & CCF_CAST))
			goto err_conv;
		goto conv_I_I;

	case CCX(P, F):
		if (!(flags & CCF_CAST) || !(flags & CCF_FROMTV))
			goto err_conv;
		/* The signed conversion is cheaper. x64 really has 47 bit pointers. */
		dinfo = CTINFO(CT_NUM, (UC_64 && dsize == 8) ? 0 : CTF_UNSIGNED);
		goto conv_I_F;

	case CCX(P, P):
		if (!uc_cconv_compatptr(cts, d, s, flags))
			goto err_conv;
		cdata_setptr(dp, dsize, cdata_getptr(sp, ssize));
		break;

	case CCX(P, A):
	case CCX(P, S):
		if (!uc_cconv_compatptr(cts, d, s, flags)) {
			goto err_conv;
		}
		cdata_setptr(dp, dsize, sp);
		break;

	/* Destination is an array. */
	case CCX(A, A):
		if ((flags & CCF_CAST) || (d->info & CTF_VLA) || dsize != ssize ||
			d->size == CTSIZE_INVALID || !uc_cconv_compatptr(cts, d, s, flags))
			goto err_conv;
		goto copyval;

	/* Destination is a struct/union. */
	case CCX(S, S):
		if ((flags & CCF_CAST) || (d->info & CTF_VLA) || d != s)
			goto err_conv; /* Must be exact same type. */
	copyval:			   /* Copy value. */
		uc_assertCTS(dsize == ssize, "value copy with different sizes");
		memcpy(dp, sp, dsize);
		break;

	default:
	err_conv:
		return cconv_err_conv(cts, d, s, flags);
	}

	return true;
}

/* -- C type to TValue conversion ----------------------------------------- */

/* Convert C type to TValue. Caveat: expects to get the raw CType! */
int uc_cconv_tv_ct(CTState *cts, CType *s, CTypeID sid,
				   uc_value_t **uv, uint8_t *sp)
{
	CTInfo sinfo = s->info;
	if (ctype_isnum(sinfo))
	{
		ucv_put(*uv);

		if (!ctype_isbool(sinfo))
		{
			if (ctype_isinteger(sinfo)) {
				if (sinfo & CTF_UNSIGNED) {
					uint64_t u;
					uc_cconv_ct_ct(cts, ctype_get(cts, CTID_UINT64), s,
					               (uint8_t *)&u, sp, 0);
					*uv = ucv_uint64_new(u);
				}
				else {
					int64_t n;
					uc_cconv_ct_ct(cts, ctype_get(cts, CTID_INT64), s,
					               (uint8_t *)&n, sp, 0);
					*uv = ucv_int64_new(n);
				}
			}
			else {
				double d;
				uc_cconv_ct_ct(cts, ctype_get(cts, CTID_DOUBLE), s,
				               (uint8_t *)&d, sp, 0);
				*uv = ucv_double_new(d);
			}
		}
		else
		{
			uint32_t b = s->size == 1 ? (*sp != 0) : (*(int *)sp != 0);
			*uv = ucv_boolean_new(b);
			//setboolV(o, b);
			//setboolV(&cts->g->tmptv2, b); /* Remember for trace recorder. */
		}
		return 0;
	}
	else if (ctype_isrefarray(sinfo) || ctype_isstruct(sinfo))
	{
		/* Create reference. */
		ucv_put(*uv);
		*uv = uc_cdata_newref(cts->vm, sp, sid);

		//setcdataV(cts->L, o, lj_cdata_newref(cts, sp, sid));
		return 1; /* Need GC step. */
	}
	else
	{
		CTSize sz = s->size;
		uc_assertCTS(sz != CTSIZE_INVALID, "value copy with invalid size");

		/* Attributes are stripped, qualifiers are kept (but mostly ignored). */
		uc_value_t *res = uc_cdata_new(cts->vm, ctype_typeid(cts, s), sz);
		memcpy(uc_cdata_dataptr(res), sp, sz);

		ucv_put(*uv);
		*uv = res;

		return 1; /* Need GC step. */
	}
}

/* Convert bitfield to TValue. */
int uc_cconv_tv_bf(CTState *cts, CType *s, uc_value_t **uv, uint8_t *sp)
{
	CTInfo info = s->info;
	CTSize pos, bsz;
	uint32_t val;
	uc_assertCTS(ctype_isbitfield(info), "bitfield expected");
	/* NYI: packed bitfields may cause misaligned reads. */
	switch (ctype_bitcsz(info))
	{
	case 4:
		val = *(uint32_t *)sp;
		break;
	case 2:
		val = *(uint16_t *)sp;
		break;
	case 1:
		val = *(uint8_t *)sp;
		break;
	default:
		uc_assertCTS(0, "bad bitfield container size %d", ctype_bitcsz(info));
		val = 0;
		break;
	}
	/* Check if a packed bitfield crosses a container boundary. */
	pos = ctype_bitpos(info);
	bsz = ctype_bitbsz(info);
	uc_assertCTS(pos < 8 * ctype_bitcsz(info), "bad bitfield position");
	uc_assertCTS(bsz > 0 && bsz <= 8 * ctype_bitcsz(info), "bad bitfield size");
	if (pos + bsz > 8 * ctype_bitcsz(info)) {
		uc_vm_raise_exception(cts->vm, EXCEPTION_TYPE,
			"packed bit fields are not implemented yet");
		return 0;
	}
	if (!(info & CTF_BOOL))
	{
		CTSize shift = 32 - bsz;
		if (!(info & CTF_UNSIGNED))
		{
			ucv_put(*uv);
			*uv = ucv_int64_new((int32_t)(val << (shift - pos)) >> shift);
			//setintV(o, (int32_t)(val << (shift - pos)) >> shift);
		}
		else
		{
			val = (val << (shift - pos)) >> shift;
			ucv_put(*uv);
			*uv = ucv_uint64_new(val);
			//if (!LJ_DUALNUM || (int32_t)val < 0)
			//	setnumV(o, (lua_Number)(uint32_t)val);
			//else
			//	setintV(o, (int32_t)val);
		}
	}
	else
	{
		uint32_t b = (val >> pos) & 1;
		uc_assertCTS(bsz == 1, "bad bool bitfield size");
		ucv_put(*uv);
		*uv = ucv_boolean_new(b);
		//setboolV(o, b);
		//setboolV(&cts->g->tmptv2, b); /* Remember for trace recorder. */
	}
	return 0; /* No GC step needed. */
}

/* -- TValue to C type conversion ----------------------------------------- */

/* Convert ucode array to C array. */
static bool cconv_array_tab(CTState *cts, CType *d,
							uint8_t *dp, uc_value_t *arr, CTInfo flags,
							uc_value_t **refs)
{
	size_t arrlen = ucv_array_length(arr);
	size_t i;
	CType *dc = ctype_rawchild(cts, d); /* Array element type. */
	CTSize size = d->size, esize = dc->size, ofs = 0;
	for (i = 0; i < arrlen; i++)
	{
		if (ofs >= size)
			cconv_err_initov(cts, d);
		uc_cconv_ct_tv(cts, dc, dp + ofs, ucv_array_get(arr, i), flags, refs);
		ofs += esize;
	}
	if (size != CTSIZE_INVALID)
	{ /* Only fill up arrays with known size. */
		if (ofs == esize)
		{ /* Replicate a single element. */
			for (; ofs < size; ofs += esize)
				memcpy(dp + ofs, dp, esize);
		}
		else
		{ /* Otherwise fill the remainder with zero. */
			memset(dp + ofs, 0, size - ofs);
		}
	}

	return true;
}

/* Convert ucode array to sub-struct/union. */
static bool cconv_substruct_tab(CTState *cts, CType *d, uint8_t *dp,
								uc_value_t *tab, int32_t *ip, CTInfo flags,
								uc_value_t **refs)
{
	CTypeID id = d->sib;

	while (id)
	{
		CType *df = ctype_get(cts, id);
		id = df->sib;

		if (ctype_isfield(df->info) || ctype_isbitfield(df->info))
		{
			uc_value_t *uv;

			if (!df->uv_name)
				continue; /* Ignore unnamed fields. */

			if (ucv_type(tab) == UC_ARRAY)
			{
				int32_t i = *ip;

				uv = ucv_array_get(tab, i);

				if (!uv)
					break; /* Stop at first nil. */

				*ip = i + 1;
			}
			else if (ucv_type(tab) == UC_OBJECT)
			{
				uv = ucv_object_get(tab, ucv_string_get(df->uv_name), NULL);

				if (!uv)
					continue;
			}
			else {
				uc_vm_raise_exception(cts->vm, EXCEPTION_TYPE,
					"array or object initializer value expected, got %s",
					ucv_typename(tab));

				return false;
			}

			if (ctype_isfield(df->info))
				uc_cconv_ct_tv(cts, ctype_rawchild(cts, df), dp + df->size,
				               uv, flags, refs);
			else
				uc_cconv_bf_tv(cts, df, dp + df->size, uv, refs);

			if ((d->info & CTF_UNION))
				break;
		}
		else if (ctype_isxattrib(df->info, CTA_SUBTYPE))
		{
			if (!cconv_substruct_tab(cts, ctype_rawchild(cts, df),
			                         dp + df->size, tab, ip, flags, refs))
				return false;
		} /* Ignore all other entries in the chain. */
	}

	return true;
}

/* Convert table to struct/union. */
static bool cconv_struct_tab(CTState *cts, CType *d,
                             uint8_t *dp, uc_value_t *tab, CTInfo flags,
							 uc_value_t **refs)
{
	int32_t i = 0;

	memset(dp, 0, d->size); /* Much simpler to clear the struct first. */

	return cconv_substruct_tab(cts, d, dp, tab, &i, flags, refs);
}

/* Convert TValue to C type. Caveat: expects to get the raw CType! */
bool uc_cconv_ct_tv(CTState *cts, CType *d,
					uint8_t *dp, uc_value_t *uv, CTInfo flags,
					uc_value_t **refs)
{
	uintptr_t pv = (uintptr_t)uv;
	CTypeID sid = CTID_P_VOID;
	CType *s;
	void *tmpptr;
	uint8_t tmpbool, *sp = (uint8_t *)&tmpptr;
	GCcdata *cd;
	uc_type_t utt = pv & 3;
	uc_type_t ut = (!utt && uv) ? uv->type : utt;

	/* optimized case: fast tagged integer read */
	if (UC_LIKELY(utt == UC_INTEGER)) {
		/* unsigned */
		if (((pv >> 2) & 1) == 0) {
			tmpptr = (void *)(pv >> 3);
			sid = (sizeof(tmpptr) == sizeof(uint64_t)) ? CTID_UINT64 : CTID_UINT32;
		}
		else {
			tmpptr = (void *)(uintptr_t)-(pv >> 3);
			sid = (sizeof(tmpptr) == sizeof(int64_t)) ? CTID_INT64 : CTID_INT32;
		}

		flags |= CCF_FROMTV;
	}
	/* optimized case: fast bool read */
	else if (UC_LIKELY(utt == UC_BOOLEAN))
	{
		tmpbool = (pv >> 2) & 1;
		sp = &tmpbool;
		sid = CTID_BOOL;
	}
	else if (UC_LIKELY(ut == UC_INTEGER))
	{
		uc_integer_t *ui = (uc_integer_t *)uv;

		/* unsigned */
		if (ui->header.ext_flag) {
			sp = (uint8_t *)&ui->i.u64;
			sid = CTID_UINT64;
		}
		else {
			sp = (uint8_t *)&ui->i.s64;
			sid = CTID_INT64;
		}

		flags |= CCF_FROMTV;
	}
	else if (UC_LIKELY(ut == UC_DOUBLE))
	{
		uc_double_t *ud = (uc_double_t *)uv;

		sp = (uint8_t *)&ud->dbl;
		sid = CTID_DOUBLE;
		flags |= CCF_FROMTV;
	}
	else if (ut == UC_RESOURCE && (cd = ucv_resource_data(uv, "ffi.ctype")) != NULL)
	{
		sp = cdataptr(cd);
		sid = cd->ctypeid;
		s = ctype_get(cts, sid);
		if (ctype_isref(s->info))
		{ /* Resolve reference for value. */
			uc_assertCTS(s->size == CTSIZE_PTR, "ref is not pointer-sized");
			sp = *(void **)sp;
			sid = ctype_cid(s->info);
		}
		s = ctype_raw(cts, sid);
		if (ctype_isfunc(s->info))
		{
			CTypeID did = ctype_typeid(cts, d);
			sid = uc_ctype_intern(cts, CTINFO(CT_PTR, CTALIGN_PTR | sid), CTSIZE_PTR);
			d = ctype_get(cts, did); /* cts->tab may have been reallocated. */
		}
		else
		{
			if (ctype_isenum(s->info))
				s = ctype_child(cts, s);
			goto doconv;
		}
	}
	else if (ut == UC_STRING)
	{
		if (ctype_isenum(d->info))
		{ /* Match string against enum constant. */
			CTSize ofs;
			CType *cct = uc_ctype_getfield(cts, d, uv, &ofs);
			if (!cct || !ctype_isconstval(cct->info))
				goto err_conv;
			uc_assertCTS(d->size == 4, "only 32 bit enum supported"); /* NYI */
			sp = (uint8_t *)&cct->size;
			sid = ctype_cid(cct->info);
		}
		else if (ctype_isrefarray(d->info))
		{ /* Copy string to array. */
			CType *dc = ctype_rawchild(cts, d);
			CTSize sz = ucv_string_length(uv) + 1;
			if (!ctype_isinteger(dc->info) || dc->size != 1)
				goto err_conv;
			if (d->size != 0 && d->size < sz)
				sz = d->size;
			return memcpy(dp, ucv_string_get(uv), sz);
		}
		else
		{ /* Otherwise pass it as a const char[]. */
			uc_value_t *us = uc_cconv_addref(refs, uv);
			sp = (uint8_t *)ucv_string_get(us);
			sid = CTID_A_CCHAR;
			flags |= CCF_FROMTV;
		}
	}
	else if (ut == UC_ARRAY)
	{
		if (ctype_isarray(d->info))
		{
			return cconv_array_tab(cts, d, dp, uv, flags, refs);
		}
		else if (ctype_isstruct(d->info))
		{
			return cconv_struct_tab(cts, d, dp, uv, flags, refs);
		}
		else
		{
			goto err_conv;
		}
	}
	else if (ut == UC_OBJECT)
	{
		if (ctype_isstruct(d->info))
		{
			return cconv_struct_tab(cts, d, dp, uv, flags, refs);
		}
		else
		{
			goto err_conv;
		}
	}
	else if (ut == UC_NULL)
	{
		tmpptr = (void *)0;
		flags |= CCF_FROMTV;
	}
	else if (ut == UC_RESOURCE)
	{
		tmpptr = ucv_resource_data(uv, NULL);
	}
	else
	{
	err_conv:
		return cconv_err_convtv(cts, d, uv, flags);
	}
	s = ctype_get(cts, sid);
doconv:
	if (ctype_isenum(d->info))
		d = ctype_child(cts, d);
	return uc_cconv_ct_ct(cts, d, s, dp, sp, flags);
}

/* Convert TValue to bitfield. */
bool uc_cconv_bf_tv(CTState *cts, CType *d, uint8_t *dp, uc_value_t *uv,
                    uc_value_t **refs)
{
	CTInfo info = d->info;
	CTSize pos, bsz;
	uint32_t val = 0, mask;
	uc_assertCTS(ctype_isbitfield(info), "bitfield expected");
	if ((info & CTF_BOOL))
	{
		uint8_t tmpbool = 0;
		uc_assertCTS(ctype_bitbsz(info) == 1, "bad bool bitfield size");
		if (!uc_cconv_ct_tv(cts, ctype_get(cts, CTID_BOOL), &tmpbool, uv, 0, refs))
			return false;
		val = tmpbool;
	}
	else
	{
		CTypeID did = (info & CTF_UNSIGNED) ? CTID_UINT32 : CTID_INT32;
		if (!uc_cconv_ct_tv(cts, ctype_get(cts, did), (uint8_t *)&val, uv, 0, refs))
			return false;
	}
	pos = ctype_bitpos(info);
	bsz = ctype_bitbsz(info);
	uc_assertCTS(pos < 8 * ctype_bitcsz(info), "bad bitfield position");
	uc_assertCTS(bsz > 0 && bsz <= 8 * ctype_bitcsz(info), "bad bitfield size");
	/* Check if a packed bitfield crosses a container boundary. */
	if (pos + bsz > 8 * ctype_bitcsz(info)) {
		//lj_err_caller(cts->L, LJ_ERR_FFI_NYIPACKBIT);
		uc_vm_raise_exception(cts->vm, EXCEPTION_TYPE,
		                      "packed bit fields are not implemented yet");

		return false;
	}
	mask = ((1u << bsz) - 1u) << pos;
	val = (val << pos) & mask;
	/* NYI: packed bitfields may cause misaligned reads/writes. */
	switch (ctype_bitcsz(info))
	{
	case 4:
		*(uint32_t *)dp = (*(uint32_t *)dp & ~mask) | (uint32_t)val;
		break;
	case 2:
		*(uint16_t *)dp = (*(uint16_t *)dp & ~mask) | (uint16_t)val;
		break;
	case 1:
		*(uint8_t *)dp = (*(uint8_t *)dp & ~mask) | (uint8_t)val;
		break;
	default:
		uc_assertCTS(0, "bad bitfield container size %d", ctype_bitcsz(info));
		break;
	}

	return true;
}

/* -- Initialize C type with TValues -------------------------------------- */

/* Initialize an array with TValues. */
static bool cconv_array_init(CTState *cts, CType *d, CTSize sz, uint8_t *dp,
							 uc_value_t **uv, size_t len, uc_value_t **refs)
{
	CType *dc = ctype_rawchild(cts, d); /* Array element type. */
	CTSize ofs, esize = dc->size;
	size_t i;
	if (len * esize > sz)
		return cconv_err_initov(cts, d);
	for (i = 0, ofs = 0; i < len; i++, ofs += esize)
		if (!uc_cconv_ct_tv(cts, dc, dp + ofs, uv[i], 0, refs))
			return false;
	if (ofs == esize)
	{ /* Replicate a single element. */
		for (; ofs < sz; ofs += esize)
			memcpy(dp + ofs, dp, esize);
	}
	else
	{ /* Otherwise fill the remainder with zero. */
		memset(dp + ofs, 0, sz - ofs);
	}

	return true;
}

/* Initialize a sub-struct/union with TValues. */
static bool cconv_substruct_init(CTState *cts, CType *d, uint8_t *dp,
								 uc_value_t **uv, size_t len, size_t *ip,
								 uc_value_t **refs)
{
	CTypeID id = d->sib;
	while (id)
	{
		CType *df = ctype_get(cts, id);
		id = df->sib;
		if (ctype_isfield(df->info) || ctype_isbitfield(df->info))
		{
			size_t i = *ip;
			if (!df->uv_name)
				continue; /* Ignore unnamed fields. */
			if (i >= len)
				break;
			*ip = i + 1;

			if (ctype_isfield(df->info)) {
				if (!uc_cconv_ct_tv(cts, ctype_rawchild(cts, df),
				                    dp + df->size, uv[i], 0, refs))
					return false;
			}
			else {
				if (!uc_cconv_bf_tv(cts, df, dp + df->size, uv[i], refs))
					return false;
			}

			if ((d->info & CTF_UNION))
				break;
		}
		else if (ctype_isxattrib(df->info, CTA_SUBTYPE))
		{
			if (!cconv_substruct_init(cts, ctype_rawchild(cts, df),
			                          dp + df->size, uv, len, ip, refs))
				return false;

			if ((d->info & CTF_UNION))
				break;
		} /* Ignore all other entries in the chain. */
	}

	return true;
}

/* Initialize a struct/union with TValues. */
static bool cconv_struct_init(CTState *cts, CType *d, CTSize sz, uint8_t *dp,
							  uc_value_t **uv, size_t len, uc_value_t **refs)
{
	size_t i = 0;

	memset(dp, 0, sz); /* Much simpler to clear the struct first. */

	if (!cconv_substruct_init(cts, d, dp, uv, len, &i, refs))
		return false;

	if (i < len)
		return cconv_err_initov(cts, d);

	return true;
}

/* Initialize a struct/union with a ucode object. */
static bool cconv_struct_object_init(CTState *cts, CType *d, CTSize sz, uint8_t *dp,
                                     uc_value_t *obj, uc_value_t **refs)
{
	CTypeID id = d->sib;

	memset(dp, 0, sz);

	while (id)
	{
		CType *df = ctype_get(cts, id);
		id = df->sib;

		if (ctype_isfield(df->info) || ctype_isbitfield(df->info))
		{
			if (!df->uv_name)
				continue;

			uc_value_t *uv = ucv_object_get(obj, ucv_string_get(df->uv_name), NULL);

			if (uv)
			{
				if (ctype_isfield(df->info)) {
					if (!uc_cconv_ct_tv(cts, ctype_rawchild(cts, df),
					                    dp + df->size, uv, 0, refs))
						return false;
				}
				else {
					if (!uc_cconv_bf_tv(cts, df, dp + df->size, uv, refs))
						return false;
				}
			}

			if ((d->info & CTF_UNION))
				break;
		}
		else if (ctype_isxattrib(df->info, CTA_SUBTYPE))
		{
			CType *child = ctype_rawchild(cts, df);
			if (!cconv_struct_object_init(cts, child, child->size,
			                              dp + df->size, obj, refs))
				return false;

			if ((d->info & CTF_UNION))
				break;
		}
	}

	return true;
}

/* Check whether to use a multi-value initializer.
** This is true if an aggregate is to be initialized with a value.
** Valarrays are treated as values here so ct_tv handles (V|C, I|F).
*/
int uc_cconv_multi_init(CTState *cts, CType *d, uc_value_t *uv)
{
	uc_type_t ut = ucv_type(uv);
	GCcdata *cd = (ut == UC_RESOURCE) ? ucv_resource_data(uv, "ffi.ctype") : NULL;

	if (!(ctype_isrefarray(d->info) || ctype_isstruct(d->info)))
		return 0; /* Destination is not an aggregate. */
	if (ut == UC_ARRAY || ut == UC_OBJECT || (ut == UC_STRING && !ctype_isstruct(d->info)))
		return 0; /* Initializer is not a value. */
	if (cd && uc_ctype_rawref(cts, cd->ctypeid) == d)
		return 0; /* Source and destination are identical aggregates. */
	return 1;	  /* Otherwise the initializer is a value. */
}

/* Initialize C type with TValues. Caveat: expects to get the raw CType! */
bool uc_cconv_ct_init(CTState *cts, CType *d, CTSize sz,
					  uint8_t *dp, uc_value_t **uv, size_t len, uc_value_t **refs)
{
	if (len == 0)
		return memset(dp, 0, sz);
	else if (len == 1 && !uc_cconv_multi_init(cts, d, *uv))
		return uc_cconv_ct_tv(cts, d, dp, *uv, 0, refs);
	else if (ctype_isarray(d->info)) /* Also handles valarray init with len>1. */
		return cconv_array_init(cts, d, sz, dp, uv, len, refs);
	else if (ctype_isstruct(d->info)) {
		if (len == 1 && ucv_type(*uv) == UC_OBJECT)
			return cconv_struct_object_init(cts, d, sz, dp, *uv, refs);
		return cconv_struct_init(cts, d, sz, dp, uv, len, refs);
	}
	else
		return cconv_err_initov(cts, d);
}
