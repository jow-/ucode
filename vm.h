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

#ifndef __VM_H_
#define __VM_H_

#include <stdbool.h>
#include <stdarg.h>

#include "chunk.h"
#include "object.h"
#include "util.h"
#include "lexer.h"

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
__insn(PLUS) \
__insn(MINUS) \
__insn(ADD) \
__insn(SUB) \
__insn(MUL) \
__insn(DIV) \
__insn(MOD) \
__insn(LSHIFT) \
__insn(RSHIFT) \
__insn(BAND) \
__insn(BXOR) \
__insn(BOR) \
__insn(COMPL) \
__insn(EQ) \
__insn(NE) \
__insn(EQS) \
__insn(NES) \
__insn(LT) \
__insn(GT) \
__insn(IN) \
__insn(NOT) \
__insn(JMP) \
__insn(JMPZ) \
__insn(COPY) \
__insn(POP) \
__insn(CUPV) \
__insn(RETURN) \
__insn(CALL) \
__insn(MCALL) \
__insn(PRINT) \
__insn(NEXTK) \
__insn(NEXTKV)


#undef __insn
#define __insn(_name) I_##_name,

enum insn_type {
	__insns
	__I_MAX
};

typedef struct {
	int8_t stack_pop;
	int8_t stack_push;
	int8_t operand_bytes;
	bool operand_is_skip;
} uc_insn_definition;

typedef enum {
	EXCEPTION_NONE,
	EXCEPTION_SYNTAX,
	EXCEPTION_RUNTIME,
	EXCEPTION_TYPE,
	EXCEPTION_REFERENCE,
	EXCEPTION_USER
} uc_exception_type_t;

typedef struct {
	uc_exception_type_t type;
	json_object *stacktrace;
	char *message;
} uc_exception;

typedef struct {
	uint8_t *ip;
	uc_closure *closure;
	uc_cfunction *cfunction;
	size_t stackframe;
	json_object *ctx;
	bool mcall;
} uc_callframe;

uc_declare_vector(uc_callframes, uc_callframe);
uc_declare_vector(uc_stack, json_object *);

typedef struct uc_vm {
	uc_stack stack;
	uc_exception exception;
	uc_callframes callframes;
	uc_upvalref *open_upvals;
	uc_parse_config *config;
	uc_prototype *globals;
	uc_source *sources;
	union {
		uint32_t u32;
		int32_t s32;
		uint16_t u16;
		int16_t s16;
		uint8_t u8;
		int8_t s8;
	} arg;
	size_t spread_values;
	uint8_t trace;
} uc_vm;

typedef enum {
	STATUS_OK,
	ERROR_COMPILE,
	ERROR_RUNTIME
} uc_vm_status_t;

extern uint32_t insns[__I_MAX];

void uc_vm_init(uc_vm *vm, uc_parse_config *config);
void uc_vm_free(uc_vm *vm);

void uc_vm_stack_push(uc_vm *vm, json_object *value);
json_object *uc_vm_stack_pop(uc_vm *vm);
json_object *uc_vm_stack_peek(uc_vm *vm, size_t offset);

uc_exception_type_t uc_vm_call(uc_vm *vm, bool mcall, size_t nargs);

void __attribute__((format(printf, 3, 0)))
uc_vm_raise_exception(uc_vm *vm, uc_exception_type_t type, const char *fmt, ...);

uc_vm_status_t uc_vm_execute(uc_vm *vm, uc_function *fn, uc_prototype *globals, json_object *modules);

#endif /* __VM_H_ */
