/*
** ucode common internal definitions.
** Copyright (C) 2005-2025 Mike Pall. See Copyright Notice in NOTICE.
**
** Derived from LuaJIT's internal definitions.
** See NOTICE and ATTRIBUTION.md for complete attribution details.
*/

#ifndef _UC_DEF_H
#define _UC_DEF_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* -- Target detection ---------------------------------------------------- */

/* -- Arch-specific settings ---------------------------------------------- */

#if defined(__i386__) || defined(__i386) || defined(__x86_64__) || defined(__x86_64)

#define UC_TARGET_X86		1
#define UC_TARGET_X86ORX64	1
#if defined(__x86_64__) || defined(__x86_64)
#define UC_TARGET_X64		1
#endif

#elif defined(__ppc__) || defined(__ppc) || defined(__PPC__) || defined(__PPC) || defined(__powerpc__) || defined(__powerpc) || defined(__POWERPC__) || defined(__POWERPC)

#define UC_TARGET_PPC		1

#endif

/* -- Derived defines ----------------------------------------------------- */

#if UINTPTR_MAX == 0xffffffffffffffffULL
#define UC_64			1
#else
#define UC_64			0
#endif

#pragma pack(push, 8)
typedef union TValue {
  uint64_t u64;
  double n;
  struct {
    uint32_t lo;
    uint32_t hi;
  } u32;
  int32_t i;
} TValue;
#pragma pack(pop)
typedef const TValue cTValue;

#define uc_num2int(n)   ((int32_t)(n))

#define UC_STATIC_ASSERT(cond) \
  extern void uc_static_assert(int STATIC_ASSERTION_FAILED[(cond)?1:-1])

#define uc_rol(x, n)	(((x)<<(n)) | ((x)>>(-(int)(n)&(8*sizeof(x)-1))))

#if defined(__GNUC__) || defined(__clang__)

#define UC_NORET		__attribute__((noreturn))
#define UC_AINLINE		inline __attribute__((always_inline))
#define UC_NOINLINE		__attribute__((noinline))

#if defined(__ELF__) || defined(__MACH__)
#define UC_NOAPI		extern __attribute__((visibility("hidden")))
#endif

#if defined(__i386__)
#define UC_FASTCALL		__attribute__((fastcall))
#endif

#define UC_LIKELY(x)		__builtin_expect(!!(x), 1)
#define UC_UNLIKELY(x)		__builtin_expect(!!(x), 0)

#define uc_fls(x)		((uint32_t)(__builtin_clz(x)^31))

static UC_AINLINE uint64_t uc_num2u64(double n)
{
#if defined(__i386__) || defined(__x86_64__)
  int64_t i = (int64_t)n;
  if (i < 0) i = (int64_t)(n - 18446744073709551616.0);
  return (uint64_t)i;
#else
  return (uint64_t)n;
#endif
}

#ifndef UC_FASTCALL
#define UC_FASTCALL
#endif
#ifndef UC_NORET
#define UC_NORET
#endif
#ifndef UC_NOAPI
#define UC_NOAPI	extern
#endif
#ifndef UC_LIKELY
#define UC_LIKELY(x)	(x)
#define UC_UNLIKELY(x)	(x)
#endif

#ifdef LUA_USE_ASSERT
#define uc_assertG_(g, c, ...) \
  ((c) ? (void)0 : uc_assert_fail((g), __FILE__, __LINE__, __func__, __VA_ARGS__))
#define uc_assertG(c, ...)	uc_assertG_(g, (c), __VA_ARGS__)
#define uc_assertX(c, ...)	uc_assertG_(NULL, (c), __VA_ARGS__)
#define check_exp(c, e)		(uc_assertX((c), #c), (e))
#else
#define uc_assertG_(g, c, ...)	((void)0)
#define uc_assertG(c, ...)	((void)g)
#define uc_assertX(c, ...)	((void)0)
#define check_exp(c, e)		(e)
#endif

#endif

#endif
