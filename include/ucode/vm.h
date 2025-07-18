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

#ifndef UCODE_VM_H
#define UCODE_VM_H

#include <stdbool.h>
#include <stdarg.h>

#include "chunk.h"
#include "util.h"
#include "lexer.h"
#include "types.h"
#include "program.h"

#define UCODE_BYTECODE_VERSION 0x01

#define __insns \
__insn(NOOP) \
__insn(LOAD) \
__insn(LOAD8) \
__insn(LOAD16) \
__insn(LOAD32) \
__insn(LTHIS) \
__insn(LREXP) \
__insn(LNULL) \
__insn(LTRUE) \
__insn(LFALSE) \
__insn(LLOC) \
__insn(LUPV) \
__insn(LVAR) \
__insn(LVAL) \
__insn(PVAL) \
__insn(CLFN) \
__insn(ARFN) \
__insn(SLOC) \
__insn(SUPV) \
__insn(SVAR) \
__insn(SVAL) \
__insn(ULOC) \
__insn(UUPV) \
__insn(UVAR) \
__insn(UVAL) \
__insn(NARR) \
__insn(PARR) \
__insn(MARR) \
__insn(NOBJ) \
__insn(SOBJ) \
__insn(MOBJ) \
__insn(BOR) \
__insn(BXOR) \
__insn(BAND) \
__insn(EQS) \
__insn(NES) \
__insn(EQ) \
__insn(NE) \
__insn(LT) \
__insn(LE) \
__insn(GT) \
__insn(GE) \
__insn(IN) \
__insn(LSHIFT) \
__insn(RSHIFT) \
__insn(ADD) \
__insn(SUB) \
__insn(MUL) \
__insn(DIV) \
__insn(MOD) \
__insn(EXP) \
__insn(NOT) \
__insn(COMPL) \
__insn(PLUS) \
__insn(MINUS) \
__insn(JMP) \
__insn(JMPZ) \
__insn(JMPNT) \
__insn(COPY) \
__insn(POP) \
__insn(CUPV) \
__insn(RETURN) \
__insn(CALL) \
__insn(PRINT) \
__insn(NEXTK) \
__insn(NEXTKV) \
__insn(DELETE) \
__insn(IMPORT) \
__insn(EXPORT) \
__insn(DYNLOAD)


#undef __insn
#define __insn(_name) I_##_name,

typedef enum {
	__insns
	__I_MAX
} uc_vm_insn_t;

typedef enum {
	STATUS_OK,
	STATUS_EXIT,
	ERROR_COMPILE,
	ERROR_RUNTIME
} uc_vm_status_t;

typedef enum {
	GC_ENABLED = (1 << 0)
} uc_vm_gc_flags_t;

#define GC_DEFAULT_INTERVAL 1000

extern uint32_t insns[__I_MAX];

void uc_vm_init(uc_vm_t *vm, uc_parse_config_t *config);
void uc_vm_free(uc_vm_t *vm);

uc_value_t *uc_vm_scope_get(uc_vm_t *vm);
void uc_vm_scope_set(uc_vm_t *vm, uc_value_t *ctx);

bool uc_vm_registry_exists(uc_vm_t *vm, const char *key);
uc_value_t *uc_vm_registry_get(uc_vm_t *vm, const char *key);
void uc_vm_registry_set(uc_vm_t *vm, const char *key, uc_value_t *value);
bool uc_vm_registry_delete(uc_vm_t *vm, const char *key);

void uc_vm_stack_push(uc_vm_t *vm, uc_value_t *value);
uc_value_t *uc_vm_stack_pop(uc_vm_t *vm);
uc_value_t *uc_vm_stack_peek(uc_vm_t *vm, size_t offset);

uc_exception_handler_t *uc_vm_exception_handler_get(uc_vm_t *vm);
void uc_vm_exception_handler_set(uc_vm_t *vm, uc_exception_handler_t *exhandler);

uint32_t uc_vm_trace_get(uc_vm_t *vm);
void uc_vm_trace_set(uc_vm_t *vm, uint32_t level);

bool uc_vm_gc_start(uc_vm_t *vm, uint16_t interval);
bool uc_vm_gc_stop(uc_vm_t *vm);

uc_exception_type_t uc_vm_call(uc_vm_t *vm, bool mcall, size_t nargs);

void __attribute__((format(printf, 3, 0)))
uc_vm_raise_exception(uc_vm_t *vm, uc_exception_type_t type, const char *fmt, ...);
uc_value_t *uc_vm_exception_object(uc_vm_t *vm);

uc_vm_status_t uc_vm_execute(uc_vm_t *vm, uc_program_t *fn, uc_value_t **retval);
uc_value_t *uc_vm_invoke(uc_vm_t *vm, const char *fname, size_t nargs, ...);

uc_exception_type_t uc_vm_signal_dispatch(uc_vm_t *vm);
void uc_vm_signal_raise(uc_vm_t *vm, int signo);
int uc_vm_signal_notifyfd(uc_vm_t *vm);

#endif /* UCODE_VM_H */
