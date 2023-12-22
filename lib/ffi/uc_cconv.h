/*
** C type conversions.
** Copyright (C) 2005-2025 Mike Pall. See Copyright Notice below.
**
** This header contains derived work from LuaJIT's FFI conversion machinery.
**
** Modifications:
** - Adapted for ucode VM integration
** - Removed JIT-specific dependencies
**
** See NOTICE and ATTRIBUTION.md for complete attribution details.
*/

#ifndef _UC_CCONV_H
#define _UC_CCONV_H

#include "uc_ctype.h"

/* Compressed C type index. ORDER CCX. */
enum {
  CCX_B,	/* Bool. */
  CCX_I,	/* Integer. */
  CCX_F,	/* Floating-point number. */
  CCX_C,	/* Complex. */
  CCX_V,	/* Vector. */
  CCX_P,	/* Pointer. */
  CCX_A,	/* Refarray. */
  CCX_S		/* Struct/union. */
};

/* Convert C type info to compressed C type index. ORDER CT. ORDER CCX. */
static UC_AINLINE uint32_t cconv_idx(CTInfo info)
{
  uint32_t idx = ((info >> 26) & 15u);  /* Dispatch bits. */
  uc_assertX(ctype_type(info) <= CT_MAYCONVERT,
	     "cannot convert ctype %08x", info);
#if UC_64
  idx = ((uint32_t)(0xf436fff5fff7f021ULL >> 4*idx) & 15u);
#else
  idx = (((idx < 8 ? 0xfff7f021u : 0xf436fff5) >> 4*(idx & 7u)) & 15u);
#endif
  uc_assertX(idx < 8, "cannot convert ctype %08x", info);
  return idx;
}

#define cconv_idx2(dinfo, sinfo) \
  ((cconv_idx((dinfo)) << 3) + cconv_idx((sinfo)))

#define CCX(dst, src)		((CCX_##dst << 3) + CCX_##src)

/* Conversion flags. */
#define CCF_CAST	0x00000001u
#define CCF_FROMTV	0x00000002u
#define CCF_SAME	0x00000004u
#define CCF_IGNQUAL	0x00000008u

#define CCF_ARG_SHIFT	8
#define CCF_ARG(n)	((n) << CCF_ARG_SHIFT)
#define CCF_GETARG(f)	((f) >> CCF_ARG_SHIFT)

static inline bool
uc_cconv_needref(uc_value_t *arg)
{
  switch (ucv_type(arg)) {
  case UC_STRING:
  case UC_ARRAY:
  case UC_OBJECT:
  case UC_CLOSURE:
  case UC_CFUNCTION:
    return true;

  default:
    return false;
  }
}

static inline uc_value_t **
uc_cconv_uvref(uc_value_t ***args, uc_value_t ***refs)
{
  uc_value_t **arg = (*args)++;

  return uc_cconv_needref(*arg) ? (*refs)++ : arg;
}

static inline uc_value_t *
uc_cconv_addref(uc_value_t **refs, uc_value_t *uv)
{
  if (!refs || ucv_type(uv) != UC_STRING)
    return uv;

  /* turn tagged pointer short string into heap string */
  if ((uintptr_t)uv & 3) {
    uc_string_t *ustr = xalloc(sizeof(uc_string_t) + ucv_string_length(uv) + 1);

    ustr->length = ucv_string_length(uv);
    ustr->header.type = UC_STRING;

    memcpy(ustr->str, ucv_string_get(uv), ustr->length);

    uv = &ustr->header;
  }

  if (!*refs)
    *refs = ucv_array_new(NULL);

  return ucv_array_push(*refs, ucv_get(uv));
}

UC_NOAPI int uc_cconv_compatptr(CTState *cts, CType *d, CType *s, CTInfo flags);
UC_NOAPI bool uc_cconv_ct_ct(CTState *cts, CType *d, CType *s,
			    uint8_t *dp, uint8_t *sp, CTInfo flags);
UC_NOAPI int uc_cconv_tv_ct(CTState *cts, CType *s, CTypeID sid,
			   uc_value_t **uv, uint8_t *sp);
UC_NOAPI int uc_cconv_tv_bf(CTState *cts, CType *s,
          uc_value_t **uv, uint8_t *sp);
UC_NOAPI bool uc_cconv_ct_tv(CTState *cts, CType *d,
			    uint8_t *dp, uc_value_t *uv, CTInfo flags, uc_value_t **refs);
UC_NOAPI bool uc_cconv_bf_tv(CTState *cts, CType *d, uint8_t *dp,
          uc_value_t *uv, uc_value_t **refs);
UC_NOAPI int uc_cconv_multi_init(CTState *cts, CType *d, uc_value_t *uv);
UC_NOAPI bool uc_cconv_ct_init(CTState *cts, CType *d, CTSize sz,
			      uint8_t *dp, uc_value_t **uv, size_t len, uc_value_t **refs);

#endif
