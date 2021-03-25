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

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <math.h>

#include "vm.h"
#include "compiler.h"
#include "lib.h" /* format_error_context() */

#undef __insn
#define __insn(_name) #_name,

static const char *insn_names[__I_MAX] = {
	__insns
};

static const uc_insn_definition insn_defs[__I_MAX] = {
	[I_NOOP] = { 0, 0, 0 },

	[I_LOAD] = { 0, 1, 4 },
	[I_LOAD8] = { 0, 1, -1 },
	[I_LOAD16] = { 0, 1, -2 },
	[I_LOAD32] = { 0, 1, -4 },

	[I_LREXP] = { 0, 1, 4 },
	[I_LNULL] = { 0, 1, 0 },
	[I_LTRUE] = { 0, 1, 0 },
	[I_LFALSE] = { 0, 1, 0 },
	[I_LTHIS] = { 0, 1, 0 },

	[I_LLOC] = { 0, 1, 4 },
	[I_LVAR] = { 0, 1, 4 },
	[I_LUPV] = { 0, 1, 4 },
	[I_LVAL] = { 2, 1, 0 },

	[I_CLFN] = { 0, 1, 4, true },
	[I_ARFN] = { 0, 1, 4, true },

	[I_SLOC] = { 0, 0, 4 },
	[I_SUPV] = { 0, 0, 4 },
	[I_SVAR] = { 0, 0, 4 },
	[I_SVAL] = { 3, 1, 0 },

	[I_ULOC] = { 1, 0, 4 },
	[I_UUPV] = { 1, 0, 4 },
	[I_UVAR] = { 1, 0, 4 },
	[I_UVAL] = { 3, 1, 1 },

	[I_NARR] = { 0, 1, 4 },
	[I_PARR] = { -1, 0, 4 },
	[I_MARR] = { 1, 0, 0 },

	[I_NOBJ] = { 0, 1, 4 },
	[I_SOBJ] = { -1, 0, 4 },
	[I_MOBJ] = { 1, 0, 0 },

	[I_ADD] = { 2, 1, 0 },
	[I_SUB] = { 2, 1, 0 },
	[I_MUL] = { 2, 1, 0 },
	[I_DIV] = { 2, 1, 0 },
	[I_MOD] = { 2, 1, 0 },
	[I_LSHIFT] = { 2, 1, 0 },
	[I_RSHIFT] = { 2, 1, 0 },
	[I_BAND] = { 2, 1, 0 },
	[I_BXOR] = { 2, 1, 0 },
	[I_BOR] = { 2, 1, 0 },
	[I_EQ] = { 2, 1, 0 },
	[I_NE] = { 2, 1, 0 },
	[I_EQS] = { 2, 1, 0 },
	[I_NES] = { 2, 1, 0 },
	[I_LT] = { 2, 1, 0 },
	[I_GT] = { 2, 1, 0 },
	[I_IN] = { 2, 1, 0 },

	[I_JMP] = { 0, 0, -4, true },
	[I_JMPZ] = { 1, 0, -4, true },

	[I_COPY] = { 0, 1, 1 },
	[I_POP] = { 1, 0, 0 },
	[I_CUPV] = { 1, 0, 0 },

	[I_PLUS] = { 1, 1, 0 },
	[I_MINUS] = { 1, 1, 0 },

	[I_RETURN] = { 1, 0, 0 },
	[I_CALL] = { -2, 1, 4 },
	[I_MCALL] = { -3, 1, 4 },

	[I_NEXTK] = { 2, 2, 0 },
	[I_NEXTKV] = { 2, 3, 0 },

	[I_PRINT] = { 1, 0, 0 }
};

static const char *exception_type_strings[] = {
	[EXCEPTION_SYNTAX] = "Syntax error",
	[EXCEPTION_RUNTIME] = "Runtime error",
	[EXCEPTION_TYPE] = "Type error",
	[EXCEPTION_REFERENCE] = "Reference error",
	[EXCEPTION_USER] = "Error",
};


static void
uc_vm_reset_stack(uc_vm *vm)
{
	while (vm->stack.count > 0) {
		vm->stack.count--;
		uc_value_put(vm->stack.entries[vm->stack.count]);
		vm->stack.entries[vm->stack.count] = NULL;
	}
}

static json_object *
uc_vm_callframe_pop(uc_vm *vm);

static void
uc_vm_reset_callframes(uc_vm *vm)
{
	while (vm->callframes.count > 0)
		uc_value_put(uc_vm_callframe_pop(vm));
}

void uc_vm_init(uc_vm *vm, uc_parse_config *config)
{
	char *s = getenv("TRACE");

	vm->exception.type = EXCEPTION_NONE;
	vm->exception.message = NULL;

	vm->trace = s ? strtoul(s, NULL, 0) : 0;

	vm->config = config;

	vm->open_upvals = NULL;

	uc_vm_reset_stack(vm);
}

void uc_vm_free(uc_vm *vm)
{
	uc_upvalref *ref;

	uc_value_put(vm->exception.stacktrace);
	free(vm->exception.message);

	while (vm->open_upvals) {
		ref = vm->open_upvals->next;
		uc_value_put(vm->open_upvals->header.jso);
		vm->open_upvals = ref;
	}

	uc_vm_reset_callframes(vm);
	uc_vm_reset_stack(vm);
	uc_vector_clear(&vm->stack);
	uc_vector_clear(&vm->callframes);
}

static uc_chunk *
uc_vm_frame_chunk(uc_callframe *frame)
{
	return frame->closure ? &frame->closure->function->chunk : NULL;
}

static uc_callframe *
uc_vm_current_frame(uc_vm *vm)
{
	return uc_vector_last(&vm->callframes);
}

static uc_chunk *
uc_vm_current_chunk(uc_vm *vm)
{
	return uc_vm_frame_chunk(uc_vm_current_frame(vm));
}

static enum insn_type
uc_vm_decode_insn(uc_vm *vm, uc_callframe *frame, uc_chunk *chunk)
{
	enum insn_type insn;

#ifndef NDEBUG
	uint8_t *end = chunk->entries + chunk->count;
#endif

	assert(frame->ip < end);

	insn = frame->ip[0];
	frame->ip++;

	assert(frame->ip + abs(insn_defs[insn].operand_bytes) <= end);

	switch (insn_defs[insn].operand_bytes) {
	case 0:
		break;

	case -1:
		vm->arg.s8 = frame->ip[0] - 0x7f;
		frame->ip++;
		break;

	case -2:
		vm->arg.s16 = (
			frame->ip[0] * 0x100 +
			frame->ip[1]
		) - 0x7fff;
		frame->ip += 2;
		break;

	case -4:
		vm->arg.s32 = (
			frame->ip[0] * 0x1000000 +
			frame->ip[1] * 0x10000 +
			frame->ip[2] * 0x100 +
			frame->ip[3]
		) - 0x7fffffff;
		frame->ip += 4;
		break;

	case 1:
		vm->arg.u8 = frame->ip[0];
		frame->ip++;
		break;

	case 4:
		vm->arg.u32 = (
			frame->ip[0] * 0x1000000 +
			frame->ip[1] * 0x10000 +
			frame->ip[2] * 0x100 +
			frame->ip[3]
		);
		frame->ip += 4;
		break;

	default:
		fprintf(stderr, "Unhandled operand format: %d\n", insn_defs[insn].operand_bytes);
		abort();
	}

	return insn;
}


static void
uc_vm_frame_dump(uc_vm *vm, uc_callframe *frame)
{
	uc_chunk *chunk = uc_vm_frame_chunk(frame);
	uc_function *function;
	uc_closure *closure;
	uc_upvalref *ref;
	size_t i;

	fprintf(stderr, "  [*] CALLFRAME[%zx]\n",
		frame - vm->callframes.entries);

	fprintf(stderr, "   |- stackframe %zu/%zu\n",
		frame->stackframe, vm->stack.count);

	fprintf(stderr, "   |- ctx %s\n",
		json_object_to_json_string(frame->ctx));

	if (chunk) {
		fprintf(stderr, "   |- %zu constants\n",
			chunk->constants.isize);

		for (i = 0; i < chunk->constants.isize; i++)
			fprintf(stderr, "   | [%zu] %s\n",
				i,
				json_object_to_json_string(uc_chunk_get_constant(chunk, i)));

		closure = frame->closure;
		function = closure->function;

		fprintf(stderr, "   `- %zu upvalues\n",
			function->nupvals);

		for (i = 0; i < function->nupvals; i++) {
			ref = closure->upvals[i];

			if (ref->closed)
				fprintf(stderr, "     [%zu] <%p> %s {closed} %s\n",
					i,
					ref,
					json_object_to_json_string(
						uc_chunk_debug_get_variable(chunk, 0, i, true)),
					json_object_to_json_string(ref->value));
			else
				fprintf(stderr, "     [%zu] <%p> %s {open[%zu]} %s\n",
					i,
					ref,
					json_object_to_json_string(
						uc_chunk_debug_get_variable(chunk, 0, i, true)),
					ref->slot,
					json_object_to_json_string(vm->stack.entries[ref->slot]));
		}
	}
}

void
uc_vm_stack_push(uc_vm *vm, json_object *value)
{
	uc_vector_grow(&vm->stack);

	uc_value_put(vm->stack.entries[vm->stack.count]);

	vm->stack.entries[vm->stack.count] = value;
	vm->stack.count++;

	if (vm->trace)
		fprintf(stderr, "  [+%zd] %s\n",
			vm->stack.count,
			json_object_to_json_string(value));
}

json_object *
uc_vm_stack_pop(uc_vm *vm)
{
	json_object *rv;

	vm->stack.count--;
	rv = vm->stack.entries[vm->stack.count];
	vm->stack.entries[vm->stack.count] = NULL;

	if (vm->trace)
		fprintf(stderr, "  [-%zd] %s\n",
			vm->stack.count + 1,
			json_object_to_json_string(rv));

	return rv;
}

json_object *
uc_vm_stack_peek(uc_vm *vm, size_t offset)
{
	return vm->stack.entries[vm->stack.count + (-1 - offset)];
}

static void
uc_vm_stack_set(uc_vm *vm, size_t offset, json_object *value)
{
	if (vm->trace)
		fprintf(stderr, "  [!%zu] %s\n",
			offset, json_object_to_json_string(value));

	uc_value_put(vm->stack.entries[offset]);
	vm->stack.entries[offset] = value;
}

static void
uc_vm_call_native(uc_vm *vm, json_object *ctx, uc_cfunction *fptr, bool mcall, size_t nargs)
{
	json_object *res = NULL;
	uc_callframe *frame;

	/* add new callframe */
	uc_vector_grow(&vm->callframes);

	frame = &vm->callframes.entries[vm->callframes.count++];
	frame->stackframe = vm->stack.count - nargs - 1;
	frame->cfunction = fptr;
	frame->closure = NULL;
	frame->ctx = ctx;
	frame->mcall = mcall;

	if (vm->trace)
		uc_vm_frame_dump(vm, frame);

	res = fptr->cfn(vm, nargs);

	/* reset stack */
	uc_value_put(uc_vm_callframe_pop(vm));

	/* push return value */
	if (!vm->exception.type)
		uc_vm_stack_push(vm, res);
	else
		uc_value_put(res);
}

static bool
uc_vm_call_function(uc_vm *vm, json_object *ctx, json_object *fno, bool mcall, size_t argspec)
{
	size_t i, j, stackoff, nargs = argspec & 0xffff, nspreads = argspec >> 16;
	uc_callframe *frame = uc_vm_current_frame(vm);
	json_object *ellip, *arg;
	uc_function *function;
	uc_closure *closure;
	uint16_t slot, tmp;

	/* XXX: make dependent on stack size */
	if (vm->callframes.count >= 1000) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Too much recursion");

		return false;
	}

	stackoff = vm->stack.count - nargs - 1;

	/* argument list contains spread operations, we need to reshuffle the stack */
	if (nspreads > 0) {
		/* create temporary array */
		ellip = xjs_new_array_size(nargs);

		/* pop original stack values and push to temp array in reverse order */
		for (i = 0; i < nargs; i++)
			json_object_array_add(ellip, uc_vm_stack_pop(vm));

		/* for each spread value index ... */
		for (i = 0, slot = nargs; i < nspreads; i++) {
			/* decode stack depth value */
			tmp = frame->ip[0] * 0x100 + frame->ip[1];
			frame->ip += 2;

			/* push each preceeding non-spread value to the stack */
			for (j = slot; j > tmp + 1; j--)
				uc_vm_stack_push(vm, uc_value_get(json_object_array_get_idx(ellip, j - 1)));

			/* read spread value at index... */
			slot = tmp;
			arg = uc_value_get(json_object_array_get_idx(ellip, slot));

			/* ... ensure that it is an array type ... */
			if (!json_object_is_type(arg, json_type_array)) {
				uc_vm_raise_exception(vm, EXCEPTION_TYPE,
				                      "(%s) is not iterable",
				                      json_object_to_json_string(arg));

				return false;
			}

			/* ... and push each spread array value as argument to the stack */
			for (j = 0; j < json_object_array_length(arg); j++)
				uc_vm_stack_push(vm, uc_value_get(json_object_array_get_idx(arg, j)));

			uc_value_put(arg);
		}

		/* push remaining non-spread arguments to the stack */
		for (i = slot; i > 0; i--)
			uc_vm_stack_push(vm, uc_value_get(json_object_array_get_idx(ellip, i - 1)));

		/* free temp array */
		uc_value_put(ellip);

		/* update arg count */
		nargs = vm->stack.count - stackoff - 1;
	}

	/* is a native function */
	if (uc_object_is_type(fno, UC_OBJ_CFUNCTION)) {
		uc_vm_call_native(vm, ctx, uc_object_as_cfunction(fno), mcall, nargs);

		return true;
	}

	if (!uc_object_is_type(fno, UC_OBJ_CLOSURE)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "left-hand side is not a function");

		return false;
	}

	closure = uc_object_as_closure(fno);
	function = closure->function;

	/* fewer arguments on stack than function expects => pad */
	if (nargs < function->nargs) {
		for (i = nargs; i < function->nargs; i++) {
			if (function->vararg && (i + 1) == function->nargs)
				uc_vm_stack_push(vm, xjs_new_array_size(0));
			else
				uc_vm_stack_push(vm, NULL);
		}
	}

	/* more arguments on stack than function expects... */
	else if (nargs > function->nargs - function->vararg) {
		/* is a vararg function => pass excess args as array */
		if (function->vararg) {
			ellip = xjs_new_array_size(nargs - (function->nargs - 1));

			for (i = function->nargs; i <= nargs; i++)
				json_object_array_add(ellip, uc_vm_stack_peek(vm, nargs - i));

			for (i = function->nargs; i <= nargs; i++)
				uc_vm_stack_pop(vm);

			uc_vm_stack_push(vm, ellip);
		}

		/* static amount of args => drop excess values */
		else {
			for (i = function->nargs; i < nargs; i++)
				uc_value_put(uc_vm_stack_pop(vm));
		}
	}

	uc_vector_grow(&vm->callframes);

	frame = &vm->callframes.entries[vm->callframes.count++];
	frame->stackframe = stackoff;
	frame->cfunction = NULL;
	frame->closure = closure;
	frame->ctx = ctx;
	frame->ip = function->chunk.entries;
	frame->mcall = mcall;

	if (vm->trace)
		uc_vm_frame_dump(vm, frame);

	return true;
}

static uc_source *last_source = NULL;
static size_t last_srcpos = 0;

static void
uc_dump_insn(uc_vm *vm, uint8_t *pos, enum insn_type insn)
{
	uc_callframe *frame = uc_vm_current_frame(vm);
	uc_chunk *chunk = uc_vm_frame_chunk(frame);
	size_t msglen = 0, srcpos;
	json_object *cnst = NULL;
	char *msg = NULL;

	srcpos = uc_function_get_srcpos(frame->closure->function, pos - chunk->entries);

	if (last_srcpos == 0 || last_source != frame->closure->function->source || srcpos != last_srcpos) {
		format_source_context(&msg, &msglen,
			frame->closure->function->source,
			srcpos, true);

		fprintf(stderr, "%s", msg);
		free(msg);

		last_source = frame->closure->function->source;
		last_srcpos = srcpos;
	}

	fprintf(stderr, "%08zx  %s", pos - chunk->entries, insn_names[insn]);

	switch (insn_defs[insn].operand_bytes) {
	case 0:
		break;

	case -1:
		fprintf(stderr, " {%s%hhd}", vm->arg.s8 < 0 ? "" : "+", vm->arg.s8);
		break;

	case -2:
		fprintf(stderr, " {%s%hx}", vm->arg.s16 < 0 ? "" : "+", vm->arg.s16);
		break;

	case -4:
		fprintf(stderr, " {%s%x}", vm->arg.s32 < 0 ? "" : "+", vm->arg.s32);
		break;

	case 1:
		fprintf(stderr, " {%hhu}", vm->arg.u8);
		break;

	case 2:
		fprintf(stderr, " {%hx}", vm->arg.u16);
		break;

	case 4:
		fprintf(stderr, " {%x}", vm->arg.u32);
		break;

	default:
		fprintf(stderr, " (unknown operand format: %d)", insn_defs[insn].operand_bytes);
		break;
	}

	switch (insn) {
	case I_LOAD:
	case I_LVAR:
	case I_SVAR:
		cnst = uc_chunk_get_constant(uc_vm_frame_chunk(uc_vector_last(&vm->callframes)), vm->arg.u32);

		fprintf(stderr, "\t; %s", cnst ? json_object_to_json_string(cnst) : "null");
		uc_value_put(cnst);
		break;

	case I_LLOC:
	case I_LUPV:
	case I_SLOC:
	case I_SUPV:
		cnst = uc_chunk_debug_get_variable(chunk, pos - chunk->entries, vm->arg.u32, (insn == I_LUPV || insn == I_SUPV));

		fprintf(stderr, "\t; %s", cnst ? json_object_to_json_string(cnst) : "(?)");
		uc_value_put(cnst);
		break;

	case I_ULOC:
	case I_UUPV:
		cnst = uc_chunk_debug_get_variable(chunk, pos - chunk->entries, vm->arg.u32 & 0x00ffffff, (insn == I_UUPV));
		/* fall through */

	case I_UVAR:
		if (!cnst)
			cnst = uc_chunk_get_constant(uc_vm_frame_chunk(uc_vector_last(&vm->callframes)), vm->arg.u32 & 0x00ffffff);

		fprintf(stderr, "\t; %s (%s)",
			cnst ? json_object_to_json_string(cnst) : "(?)",
			insn_names[vm->arg.u32 >> 24]);

		uc_value_put(cnst);
		break;

	case I_UVAL:
		fprintf(stderr, "\t; (%s)", insn_names[vm->arg.u32]);
		break;

	default:
		break;
	}

	fprintf(stderr, "\n");
}

static int
uc_vm_exception_tostring(json_object *jso, struct printbuf *pb, int level, int flags)
{
	bool strict = (level > 0) || (flags & JSON_C_TO_STRING_STRICT);
	json_object *message = json_object_object_get(jso, "message");

	return sprintbuf(pb, "%s",
		strict ? json_object_to_json_string(message) : json_object_get_string(message));
}

static bool
uc_vm_handle_exception(uc_vm *vm)
{
	uc_callframe *frame = uc_vm_current_frame(vm);
	uc_chunk *chunk = NULL;
	json_object *exo;
	size_t i, pos;

	if (!frame->closure)
		return false;

	chunk = uc_vm_frame_chunk(frame);
	pos = frame->ip - chunk->entries;

	/* iterate the known exception ranges, see if the current ip falls into any of them */
	for (i = 0; i < chunk->ehranges.count; i++) {
		/* skip nonmatching ranges */
		if (pos < chunk->ehranges.entries[i].from ||
		    pos >= chunk->ehranges.entries[i].to)
			continue;

		/* we found a matching range... first unwind stack */
		while (vm->stack.count > frame->stackframe + chunk->ehranges.entries[i].slot)
			uc_value_put(uc_vm_stack_pop(vm));

		/* prepare exception object and expose it to user handler code */
		exo = xjs_new_object();

		json_object_object_add(exo, "type", xjs_new_string(exception_type_strings[vm->exception.type]));
		json_object_object_add(exo, "message", xjs_new_string(vm->exception.message));
		json_object_object_add(exo, "stacktrace", uc_value_get(vm->exception.stacktrace));

		json_object_set_serializer(exo, uc_vm_exception_tostring, NULL, NULL);
		uc_vm_stack_push(vm, exo);

		/* reset exception information */
		free(vm->exception.message);

		vm->exception.type = EXCEPTION_NONE;
		vm->exception.message = NULL;

		/* jump to exception handler */
		if (chunk->ehranges.entries[i].target >= chunk->count) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "jump target out of range");
			return false;
		}

#if 0
		if (vm->trace && chunk->entries + chunk->ehranges.entries[i].target > frame->ip) {
			while (frame->ip < chunk->entries + chunk->ehranges.entries[i].target) {
				fprintf(stderr, "(eh:skip) [%p:%zu] ", chunk, frame->ip - chunk->entries);
				uc_dump_insn(vm, frame->ip, uc_vm_decode_insn(vm, frame, chunk));
			}
		}
#endif

		frame->ip = chunk->entries + chunk->ehranges.entries[i].target;

		return true;
	}

	return false;
}

static json_object *
uc_vm_capture_stacktrace(uc_vm *vm, size_t i)
{
	json_object *stacktrace, *entry, *last = NULL;
	uc_function *function;
	uc_callframe *frame;
	size_t off, srcpos;
	char *name;

	stacktrace = xjs_new_array();

	for (; i > 0; i--) {
		frame = &vm->callframes.entries[i - 1];
		entry = xjs_new_object();

		if (frame->closure) {
			function = frame->closure->function;

			off = (frame->ip - uc_vm_frame_chunk(frame)->entries) - 1;
			srcpos = uc_function_get_srcpos(function, off);

			json_object_object_add(entry, "filename", xjs_new_string(function->source->filename));
			json_object_object_add(entry, "line", xjs_new_int64(uc_source_get_line(function->source, &srcpos)));
			json_object_object_add(entry, "byte", xjs_new_int64(srcpos));
		}

		if (i > 1) {
			if (frame->closure) {
				if (frame->closure->function->name)
					name = frame->closure->function->name;
				else if (frame->closure->is_arrow)
					name = "[arrow function]";
				else
					name = "[anonymous function]";
			}
			else {
				name = frame->cfunction->name;
			}

			json_object_object_add(entry, "function", xjs_new_string(name));
		}

		if (!json_object_equal(last, entry)) {
			json_object_array_add(stacktrace, entry);
			last = entry;
		}
		else {
			uc_value_put(entry);
		}
	}

	return stacktrace;
}

static json_object *
uc_vm_get_error_context(uc_vm *vm)
{
	json_object *stacktrace;
	uc_callframe *frame;
	uc_chunk *chunk;
	size_t offset, len = 0, i;
	char *msg = NULL;

	/* skip to first non-native function call frame */
	for (i = vm->callframes.count; i > 0; i--)
		if (vm->callframes.entries[i - 1].closure)
			break;

	frame = &vm->callframes.entries[i - 1];

	if (!frame->closure)
		return NULL;

	chunk = uc_vm_frame_chunk(frame);
	offset = uc_function_get_srcpos(frame->closure->function, (frame->ip - chunk->entries) - 1);
	stacktrace = uc_vm_capture_stacktrace(vm, i);

	if (offset)
		format_error_context(&msg, &len, frame->closure->function->source, stacktrace, offset);
	else
		xasprintf(&msg, "At offset %zu", (frame->ip - chunk->entries) - 1);

	json_object_object_add(json_object_array_get_idx(stacktrace, 0), "context", xjs_new_string(msg));

	free(msg);

	return stacktrace;
}

void __attribute__((format(printf, 3, 0)))
uc_vm_raise_exception(uc_vm *vm, uc_exception_type_t type, const char *fmt, ...)
{
	va_list ap;

	vm->exception.type = type;

	free(vm->exception.message);

	va_start(ap, fmt);
	xvasprintf(&vm->exception.message, fmt, ap);
	va_end(ap);

	uc_value_put(vm->exception.stacktrace);
	vm->exception.stacktrace = uc_vm_get_error_context(vm);
}


static void
uc_vm_insn_load(uc_vm *vm, enum insn_type insn)
{
	switch (insn) {
	case I_LOAD:
		uc_vm_stack_push(vm, uc_chunk_get_constant(uc_vm_current_chunk(vm), vm->arg.u32));
		break;

	case I_LOAD8:
		uc_vm_stack_push(vm, xjs_new_int64(vm->arg.s8));
		break;

	case I_LOAD16:
		uc_vm_stack_push(vm, xjs_new_int64(vm->arg.s16));
		break;

	case I_LOAD32:
		uc_vm_stack_push(vm, xjs_new_int64(vm->arg.s32));
		break;

	default:
		break;
	}
}

static void
uc_vm_insn_load_regexp(uc_vm *vm, enum insn_type insn)
{
	bool icase = false, newline = false, global = false;
	json_object *jstr = uc_chunk_get_constant(uc_vm_current_chunk(vm), vm->arg.u32);
	const char *str;
	uc_regexp *re;
	char *err;

	if (!json_object_is_type(jstr, json_type_string) || json_object_get_string_len(jstr) < 2) {
		uc_vm_stack_push(vm, NULL);
		uc_value_put(jstr);

		return;
	}

	str = json_object_get_string(jstr);

	global  = (*str & (1 << 0));
	icase   = (*str & (1 << 1));
	newline = (*str & (1 << 2));

	re = uc_regexp_new(++str, icase, newline, global, &err);

	uc_value_put(jstr);

	if (re)
		uc_vm_stack_push(vm, re->header.jso);
	else
		uc_vm_raise_exception(vm, EXCEPTION_SYNTAX, "%s", err);
}

static void
uc_vm_insn_load_null(uc_vm *vm, enum insn_type insn)
{
	uc_vm_stack_push(vm, NULL);
}

static void
uc_vm_insn_load_bool(uc_vm *vm, enum insn_type insn)
{
	uc_vm_stack_push(vm, xjs_new_boolean(insn == I_LTRUE));
}

static void
uc_vm_insn_load_var(uc_vm *vm, enum insn_type insn)
{
	json_object *name, *val = NULL;
	uc_prototype *scope, *next;

	scope = vm->globals;
	name = uc_chunk_get_constant(uc_vm_current_chunk(vm), vm->arg.u32);

 	while (json_object_get_type(name) == json_type_string) {
		if (json_object_object_get_ex(scope->header.jso, json_object_get_string(name), &val))
			break;

		next = scope->parent;

		if (!next) {
			if (vm->config->strict_declarations) {
				uc_vm_raise_exception(vm, EXCEPTION_REFERENCE,
				                      "access to undeclared variable %s",
				                      json_object_get_string(name));
			}

			break;
		}

		scope = next;
	}

	uc_value_put(name);

	uc_vm_stack_push(vm, uc_value_get(val));
}

static void
uc_vm_insn_load_val(uc_vm *vm, enum insn_type insn)
{
	json_object *k = uc_vm_stack_pop(vm);
	json_object *v = uc_vm_stack_pop(vm);

	switch (json_object_get_type(v)) {
	case json_type_object:
	case json_type_array:
		uc_vm_stack_push(vm, uc_getval(v, k));
		break;

	default:
		uc_vm_raise_exception(vm, EXCEPTION_REFERENCE,
		                      "left-hand side expression is %s",
		                      v ? "not an array or object" : "null");

		break;
	}


	uc_value_put(k);
	uc_value_put(v);
}

static void
uc_vm_insn_load_upval(uc_vm *vm, enum insn_type insn)
{
	uc_callframe *frame = uc_vm_current_frame(vm);
	uc_upvalref *ref = frame->closure->upvals[vm->arg.u32];

	if (ref->closed)
		uc_vm_stack_push(vm, uc_value_get(ref->value));
	else
		uc_vm_stack_push(vm, uc_value_get(vm->stack.entries[ref->slot]));
}

static void
uc_vm_insn_load_local(uc_vm *vm, enum insn_type insn)
{
	uc_callframe *frame = uc_vm_current_frame(vm);

	uc_vm_stack_push(vm, uc_value_get(vm->stack.entries[frame->stackframe + vm->arg.u32]));
}

static uc_upvalref *
uc_vm_capture_upval(uc_vm *vm, size_t slot)
{
	uc_upvalref *curr = vm->open_upvals;
	uc_upvalref *prev = NULL;
	uc_upvalref *created;

	while (curr && curr->slot > slot) {
		prev = curr;
		curr = curr->next;
	}

	if (curr && curr->slot == slot) {
		if (vm->trace)
			fprintf(stderr, "  {+%zu} <%p> %s\n",
				slot,
				curr,
				json_object_to_json_string(vm->stack.entries[slot]));

		return curr;
	}

	created = uc_upvalref_new(slot);
	created->next = curr;

	if (vm->trace)
		fprintf(stderr, "  {*%zu} <%p> %s\n",
			slot,
			created,
			json_object_to_json_string(vm->stack.entries[slot]));

	if (prev)
		prev->next = created;
	else
		vm->open_upvals = created;

	return created;
}

static void
uc_vm_close_upvals(uc_vm *vm, size_t slot)
{
	uc_upvalref *ref;

	while (vm->open_upvals && vm->open_upvals->slot >= slot) {
		ref = vm->open_upvals;
		ref->value = uc_value_get(vm->stack.entries[ref->slot]);
		ref->closed = true;

		if (vm->trace)
			fprintf(stderr, "  {!%zu} <%p> %s\n",
				ref->slot,
				ref,
				json_object_to_json_string(ref->value));

		vm->open_upvals = ref->next;
		json_object_put(ref->header.jso);
	}
}

static void
uc_vm_insn_load_closure(uc_vm *vm, enum insn_type insn)
{
	uc_callframe *frame = uc_vm_current_frame(vm);
	json_object *fno = uc_chunk_get_constant(uc_vm_current_chunk(vm), vm->arg.u32);
	uc_function *function = uc_object_as_function(fno);
	uc_closure *closure = uc_closure_new(function, insn == I_ARFN);
	volatile int32_t uv;
	size_t i;

	uc_vm_stack_push(vm, closure->header.jso);

	for (i = 0; i < function->nupvals; i++) {
		uv = (
			frame->ip[0] * 0x1000000 +
			frame->ip[1] * 0x10000 +
			frame->ip[2] * 0x100 +
			frame->ip[3]
		) - 0x7fffffff;

		if (uv < 0)
			closure->upvals[i] = uc_vm_capture_upval(vm, frame->stackframe - (uv + 1));
		else
			closure->upvals[i] = frame->closure->upvals[uv];

		uc_value_get(closure->upvals[i]->header.jso);

		frame->ip += 4;
	}
}

static void
uc_vm_insn_store_var(uc_vm *vm, enum insn_type insn)
{
	json_object *name, *v = uc_vm_stack_pop(vm);
	uc_prototype *scope, *next;

	scope = vm->globals;
	name = uc_chunk_get_constant(uc_vm_current_chunk(vm), vm->arg.u32);

 	while (json_object_get_type(name) == json_type_string) {
		if (json_object_object_get_ex(scope->header.jso, json_object_get_string(name), NULL))
			break;

		next = scope->parent;

		if (!next) {
			if (vm->config->strict_declarations) {
				uc_vm_raise_exception(vm, EXCEPTION_REFERENCE,
				                      "access to undeclared variable %s",
				                      json_object_get_string(name));
			}

			break;
		}

		scope = next;
	}

	if (scope && json_object_get_type(name) == json_type_string)
		json_object_object_add(scope->header.jso, json_object_get_string(name), uc_value_get(v));

	uc_value_put(name);
	uc_vm_stack_push(vm, v);
}

static void
uc_vm_insn_store_val(uc_vm *vm, enum insn_type insn)
{
	json_object *v = uc_vm_stack_pop(vm);
	json_object *k = uc_vm_stack_pop(vm);
	json_object *o = uc_vm_stack_pop(vm);

	const char *typenames[] = {
		[json_type_string] = "string",
		[json_type_int] = "integer",
		[json_type_double] = "double",
		[json_type_boolean] = "boolean",
		[json_type_null] = "null"
	};

	switch (json_object_get_type(o)) {
	case json_type_object:
	case json_type_array:
		uc_vm_stack_push(vm, uc_setval(o, k, v));
		break;

	default:
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		                      "attempt to set property on %s value",
		                      typenames[json_object_get_type(o)]);
	}

	uc_value_put(o);
	uc_value_put(k);
}

static void
uc_vm_insn_store_upval(uc_vm *vm, enum insn_type insn)
{
	uc_callframe *frame = uc_vm_current_frame(vm);
	uc_upvalref *ref = frame->closure->upvals[vm->arg.u32];
	json_object *val = uc_value_get(uc_vm_stack_peek(vm, 0));

	if (ref->closed) {
		uc_value_put(ref->value);
		ref->value = val;
	}
	else {
		uc_vm_stack_set(vm, ref->slot, val);
	}
}

static void
uc_vm_insn_store_local(uc_vm *vm, enum insn_type insn)
{
	uc_callframe *frame = uc_vm_current_frame(vm);
	json_object *val = uc_value_get(uc_vm_stack_peek(vm, 0));

	uc_vm_stack_set(vm, frame->stackframe + vm->arg.u32, val);
}

static json_object *
uc_vm_value_bitop(uc_vm *vm, enum insn_type operation, json_object *value, json_object *operand)
{
	json_object *rv = NULL;
	int64_t n1, n2;
	double d;

	if (uc_cast_number(value, &n1, &d) == json_type_double)
		n1 = isnan(d) ? 0 : (int64_t)d;

	if (uc_cast_number(operand, &n2, &d) == json_type_double)
		n2 = isnan(d) ? 0 : (int64_t)d;

	switch (operation) {
	case I_LSHIFT:
		rv = xjs_new_int64(n1 << n2);
		break;

	case I_RSHIFT:
		rv = xjs_new_int64(n1 >> n2);
		break;

	case I_BAND:
		rv = xjs_new_int64(n1 & n2);
		break;

	case I_BXOR:
		rv = xjs_new_int64(n1 ^ n2);
		break;

	case I_BOR:
		rv = xjs_new_int64(n1 | n2);
		break;

	default:
		break;
	}

	return rv;
}

static json_object *
uc_vm_value_arith(uc_vm *vm, enum insn_type operation, json_object *value, json_object *operand)
{
	json_object *rv = NULL;
	enum json_type t1, t2;
	const char *s1, *s2;
	size_t len1, len2;
	int64_t n1, n2;
	double d1, d2;
	char *s;

	if (operation > I_MOD)
		return uc_vm_value_bitop(vm, operation, value, operand);

	if (operation == I_ADD &&
	    (json_object_is_type(value, json_type_string) ||
	     json_object_is_type(operand, json_type_string))) {
		s1 = value ? json_object_get_string(value) : "null";
		s2 = operand ? json_object_get_string(operand) : "null";
		len1 = strlen(s1);
		len2 = strlen(s2);
		s = xalloc(len1 + len2 + 1);

		snprintf(s, len1 + len2 + 1, "%s%s", s1, s2);

		rv = xjs_new_string(s);

		free(s);

		return rv;
	}

	t1 = uc_cast_number(value, &n1, &d1);
	t2 = uc_cast_number(operand, &n2, &d2);

	if (t1 == json_type_double || t2 == json_type_double) {
		d1 = (t1 == json_type_double) ? d1 : (double)n1;
		d2 = (t2 == json_type_double) ? d2 : (double)n2;

		switch (operation) {
		case I_ADD:
		case I_PLUS:
			rv = uc_double_new(d1 + d2);
			break;

		case I_SUB:
			rv = uc_double_new(d1 - d2);
			break;

		case I_MUL:
			rv = uc_double_new(d1 * d2);
			break;

		case I_DIV:
			if (d2 == 0.0)
				rv = uc_double_new(INFINITY);
			else if (isnan(d2))
				rv = uc_double_new(NAN);
			else if (!isfinite(d2))
				rv = uc_double_new(isfinite(d1) ? 0.0 : NAN);
			else
				rv = uc_double_new(d1 / d2);

			break;

		case I_MOD:
			rv = uc_double_new(NAN);
			break;

		default:
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			                      "undefined arithmetic operation %d",
			                      operation);
			break;
		}
	}
	else {
		switch (operation) {
		case I_ADD:
		case I_PLUS:
			rv = xjs_new_int64(n1 + n2);
			break;

		case I_SUB:
			rv = xjs_new_int64(n1 - n2);
			break;

		case I_MUL:
			rv = xjs_new_int64(n1 * n2);
			break;

		case I_DIV:
			if (n2 == 0)
				rv = uc_double_new(INFINITY);
			else
				rv = xjs_new_int64(n1 / n2);

			break;

		case I_MOD:
			rv = xjs_new_int64(n1 % n2);
			break;

		default:
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME,
			                      "undefined arithmetic operation %d",
			                      operation);
			break;
		}
	}

	return rv;
}

static void
uc_vm_insn_update_var(uc_vm *vm, enum insn_type insn)
{
	json_object *name, *val, *inc = uc_vm_stack_pop(vm);
	uc_prototype *scope, *next;

	scope = vm->globals;
	name = uc_chunk_get_constant(uc_vm_current_chunk(vm), vm->arg.u32 & 0x00FFFFFF);

	assert(json_object_is_type(name, json_type_string));

 	while (true) {
		if (json_object_object_get_ex(scope->header.jso, json_object_get_string(name), &val))
			break;

		next = scope->parent;

		if (!next) {
			if (vm->config->strict_declarations) {
				uc_vm_raise_exception(vm, EXCEPTION_REFERENCE,
				                      "access to undeclared variable %s",
				                      json_object_get_string(name));
			}

			break;
		}

		scope = next;
	}

	val = uc_vm_value_arith(vm, vm->arg.u32 >> 24, val, inc);

	json_object_object_add(scope->header.jso, json_object_get_string(name), uc_value_get(val));
	uc_vm_stack_push(vm, val);

	uc_value_put(name);
	uc_value_put(inc);
}

static void
uc_vm_insn_update_val(uc_vm *vm, enum insn_type insn)
{
	json_object *inc = uc_vm_stack_pop(vm);
	json_object *k = uc_vm_stack_pop(vm);
	json_object *v = uc_vm_stack_pop(vm);
	json_object *val = NULL;

	switch (json_object_get_type(v)) {
	case json_type_object:
	case json_type_array:
		val = uc_getval(v, k);
		uc_vm_stack_push(vm, uc_setval(v, k, uc_vm_value_arith(vm, vm->arg.u8, val, inc)));
		break;

	default:
		uc_vm_raise_exception(vm, EXCEPTION_REFERENCE,
		                      "left-hand side expression is %s",
		                      v ? "not an array or object" : "null");

		break;
	}

	uc_value_put(val);
	uc_value_put(inc);
	uc_value_put(v);
	uc_value_put(k);
}

static void
uc_vm_insn_update_upval(uc_vm *vm, enum insn_type insn)
{
	uc_callframe *frame = uc_vm_current_frame(vm);
	size_t slot = vm->arg.u32 & 0x00FFFFFF;
	uc_upvalref *ref = frame->closure->upvals[slot];
	json_object *inc = uc_vm_stack_pop(vm);
	json_object *val;

	if (ref->closed)
		val = ref->value;
	else
		val = vm->stack.entries[ref->slot];

	val = uc_vm_value_arith(vm, vm->arg.u32 >> 24, val, inc);

	uc_vm_stack_push(vm, val);

	uc_value_put(inc);

	if (ref->closed) {
		uc_value_put(ref->value);
		ref->value = uc_value_get(uc_vm_stack_peek(vm, 0));
	}
	else {
		uc_vm_stack_set(vm, ref->slot, uc_value_get(uc_vm_stack_peek(vm, 0)));
	}
}

static void
uc_vm_insn_update_local(uc_vm *vm, enum insn_type insn)
{
	uc_callframe *frame = uc_vm_current_frame(vm);
	size_t slot = vm->arg.u32 & 0x00FFFFFF;
	json_object *inc = uc_vm_stack_pop(vm);
	json_object *val;

	val = uc_vm_value_arith(vm, vm->arg.u32 >> 24,
	                        vm->stack.entries[frame->stackframe + slot], inc);

	uc_vm_stack_push(vm, val);

	uc_value_put(inc);
	uc_vm_stack_set(vm, frame->stackframe + slot, uc_value_get(uc_vm_stack_peek(vm, 0)));
}

static void
uc_vm_insn_narr(uc_vm *vm, enum insn_type insn)
{
	json_object *arr = xjs_new_array_size(vm->arg.u32);

	uc_vm_stack_push(vm, arr);
}

static void
uc_vm_insn_parr(uc_vm *vm, enum insn_type insn)
{
	json_object *arr = uc_vm_stack_peek(vm, vm->arg.u32);
	size_t idx;

	for (idx = 0; idx < vm->arg.u32; idx++)
		json_object_array_add(arr, uc_vm_stack_peek(vm, vm->arg.u32 - idx - 1));

	for (idx = 0; idx < vm->arg.u32; idx++)
		uc_vm_stack_pop(vm);

	//uc_vm_shrink(state, vm->arg.u32);
}

static void
uc_vm_insn_marr(uc_vm *vm, enum insn_type insn)
{
	json_object *src = uc_vm_stack_pop(vm);
	json_object *dst = uc_vm_stack_peek(vm, 0);
	size_t i;

	if (!json_object_is_type(src, json_type_array)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		                      "(%s) is not iterable",
		                      json_object_to_json_string(src));

		return;
	}

	for (i = 0; i < json_object_array_length(src); i++)
		json_object_array_add(dst, uc_value_get(json_object_array_get_idx(src, i)));

	uc_value_put(src);
}

static void
uc_vm_insn_nobj(uc_vm *vm, enum insn_type insn)
{
	json_object *arr = xjs_new_object();

	uc_vm_stack_push(vm, arr);
}

static void
uc_vm_insn_sobj(uc_vm *vm, enum insn_type insn)
{
	json_object *obj = uc_vm_stack_peek(vm, vm->arg.u32);
	size_t idx;

	for (idx = 0; idx < vm->arg.u32; idx += 2) {
		json_object_object_add(obj,
			json_object_get_string(uc_vm_stack_peek(vm, vm->arg.u32 - idx - 1)),
			uc_value_get(uc_vm_stack_peek(vm, vm->arg.u32 - idx - 2)));
	}

	for (idx = 0; idx < vm->arg.u32; idx++)
		uc_value_put(uc_vm_stack_pop(vm));
}

static void
uc_vm_insn_mobj(uc_vm *vm, enum insn_type insn)
{
	json_object *src = uc_vm_stack_pop(vm);
	json_object *dst = uc_vm_stack_peek(vm, 0);
	char *istr;
	size_t i;

	switch (json_object_get_type(src)) {
	case json_type_object:
		; /* a label can only be part of a statement and a declaration is not a statement */
		json_object_object_foreach(src, k, v)
			json_object_object_add(dst, k, uc_value_get(v));

		uc_value_put(src);
		break;

	case json_type_array:
		for (i = 0; i < json_object_array_length(src); i++) {
			xasprintf(&istr, "%zu", i);
			json_object_object_add(dst, istr, uc_value_get(json_object_array_get_idx(src, i)));
			free(istr);
		}

		uc_value_put(src);
		break;

	default:
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		                      "Value (%s) is not iterable",
		                      json_object_to_json_string(src));

		break;
	}
}

static void
uc_vm_insn_arith(uc_vm *vm, enum insn_type insn)
{
	json_object *r2 = uc_vm_stack_pop(vm);
	json_object *r1 = uc_vm_stack_pop(vm);
	json_object *rv;

	rv = uc_vm_value_arith(vm, insn, r1, r2);

	uc_value_put(r1);
	uc_value_put(r2);

	uc_vm_stack_push(vm, rv);
}

static void
uc_vm_insn_plus_minus(uc_vm *vm, enum insn_type insn)
{
	struct json_object *v = uc_vm_stack_pop(vm);
	bool is_sub = (insn == I_MINUS);
	enum json_type t;
	int64_t n;
	double d;

	t = uc_cast_number(v, &n, &d);

	json_object_put(v);

	switch (t) {
	case json_type_int:
		uc_vm_stack_push(vm, xjs_new_int64(is_sub ? -n : n));
		break;

	default:
		uc_vm_stack_push(vm, uc_double_new(is_sub ? -d : d));
		break;
	}
}

static void
uc_vm_insn_bitop(uc_vm *vm, enum insn_type insn)
{
	json_object *r2 = uc_vm_stack_pop(vm);
	json_object *r1 = uc_vm_stack_pop(vm);
	json_object *rv;

	rv = uc_vm_value_bitop(vm, insn, r1, r2);

	uc_value_put(r1);
	uc_value_put(r2);

	uc_vm_stack_push(vm, rv);
}

static void
uc_vm_insn_complement(uc_vm *vm, enum insn_type insn)
{
	struct json_object *v = uc_vm_stack_pop(vm);
	int64_t n;
	double d;

	if (uc_cast_number(v, &n, &d) == json_type_double)
		n = isnan(d) ? 0 : (int64_t)d;

	json_object_put(v);

	uc_vm_stack_push(vm, xjs_new_int64(~n));
}

static void
uc_vm_insn_rel(uc_vm *vm, enum insn_type insn)
{
	json_object *r2 = uc_vm_stack_pop(vm);
	json_object *r1 = uc_vm_stack_pop(vm);
	bool res = false;

	switch (insn) {
	case I_LT:
		res = uc_cmp(TK_LT, r1, r2);
		break;

	case I_GT:
		res = uc_cmp(TK_GT, r1, r2);
		break;

	case I_EQ:
		res = uc_cmp(TK_EQ, r1, r2);
		break;

	case I_NE:
		res = uc_cmp(TK_NE, r1, r2);
		break;

	default:
		break;
	}

	uc_value_put(r1);
	uc_value_put(r2);

	uc_vm_stack_push(vm, xjs_new_boolean(res));
}

static void
uc_vm_insn_in(uc_vm *vm, enum insn_type insn)
{
	json_object *r2 = uc_vm_stack_pop(vm);
	json_object *r1 = uc_vm_stack_pop(vm);
	json_object *item;
	size_t arrlen, arridx;
	bool found = false;
	const char *key;

	switch (json_object_get_type(r2)) {
	case json_type_array:
		for (arridx = 0, arrlen = json_object_array_length(r2);
		     arridx < arrlen; arridx++) {
			item = json_object_array_get_idx(r2, arridx);

			if (uc_cmp(TK_EQ, r1, item)) {
				found = true;
				break;
			}
		}

		break;

	case json_type_object:
		key = r1 ? json_object_get_string(r1) : "null";
		found = json_object_object_get_ex(r2, key, NULL);
		break;

	default:
		found = false;
	}

	uc_value_put(r1);
	uc_value_put(r2);

	uc_vm_stack_push(vm, xjs_new_boolean(found));
}

static void
uc_vm_insn_equality(uc_vm *vm, enum insn_type insn)
{
	json_object *r2 = uc_vm_stack_pop(vm);
	json_object *r1 = uc_vm_stack_pop(vm);
	bool equal = uc_eq(r1, r2);

	uc_value_put(r1);
	uc_value_put(r2);

	uc_vm_stack_push(vm, xjs_new_boolean((insn == I_EQS) ? equal : !equal));
}

static void
uc_vm_insn_not(uc_vm *vm, enum insn_type insn)
{
	json_object *r1 = uc_vm_stack_pop(vm);

	uc_vm_stack_push(vm, xjs_new_boolean(!uc_val_is_truish(r1)));
	uc_value_put(r1);
}

static void
uc_vm_insn_jmp(uc_vm *vm, enum insn_type insn)
{
	uc_callframe *frame = uc_vm_current_frame(vm);
	uc_chunk *chunk = uc_vm_frame_chunk(frame);
	int32_t addr = vm->arg.s32;

	/* ip already has been incremented */
	addr -= 5;

	if (frame->ip + addr < chunk->entries ||
	    frame->ip + addr >= chunk->entries + chunk->count) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "jump target out of range");
		return;
	}

	frame->ip += addr;
}

static void
uc_vm_insn_jmpz(uc_vm *vm, enum insn_type insn)
{
	uc_callframe *frame = uc_vm_current_frame(vm);
	uc_chunk *chunk = uc_vm_frame_chunk(frame);
	json_object *v = uc_vm_stack_pop(vm);
	int32_t addr = vm->arg.s32;

	/* ip already has been incremented */
	addr -= 5;

	if (frame->ip + addr < chunk->entries ||
	    frame->ip + addr >= chunk->entries + chunk->count) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "jump target out of range");
		return;
	}

	if (!uc_val_is_truish(v))
		frame->ip += addr;

	uc_value_put(v);
}

static void
uc_vm_insn_next(uc_vm *vm, enum insn_type insn)
{
	json_object *k = uc_vm_stack_pop(vm);
	json_object *v = uc_vm_stack_pop(vm);
	struct lh_entry *curr;
	int64_t n;

	switch (json_object_get_type(v)) {
	case json_type_object:
		curr = k ? json_object_get_userdata(k) : json_object_get_object(v)->head;

		if (curr) {
			if (!k)
				k = xjs_new_string("[key]");

			json_object_set_userdata(k, curr->next, NULL);

			uc_vm_stack_push(vm, xjs_new_string(curr->k));

			if (insn == I_NEXTKV)
				uc_vm_stack_push(vm, uc_value_get((json_object *)curr->v));

			uc_vm_stack_push(vm, k);
			uc_value_put(v);

			return;
		}

		break;

	case json_type_array:
		if (!k)
			k = xjs_new_int64(0);

		n = json_object_get_int64(k);

		if (json_object_is_type(k, json_type_int) && n < json_object_array_length(v)) {
			json_object_int_inc(k, 1);

			if (insn == I_NEXTKV)
				uc_vm_stack_push(vm, xjs_new_int64(n));

			uc_vm_stack_push(vm, uc_value_get(json_object_array_get_idx(v, n)));

			uc_vm_stack_push(vm, k);
			uc_value_put(v);

			return;
		}

		uc_value_put(k);

		break;

	default:
		break;
	}

	uc_vm_stack_push(vm, NULL);
	uc_vm_stack_push(vm, NULL);

	if (insn == I_NEXTKV)
		uc_vm_stack_push(vm, NULL);

	uc_value_put(v);
}

static void
uc_vm_insn_close_upval(uc_vm *vm, enum insn_type insn)
{
	uc_vm_close_upvals(vm, vm->stack.count - 1);
	uc_value_put(uc_vm_stack_pop(vm));
}

static void
uc_vm_insn_call(uc_vm *vm, enum insn_type insn)
{
	json_object *fno = uc_value_get(uc_vm_stack_peek(vm, vm->arg.u32 & 0xffff));
	json_object *ctx = NULL;

	if (!uc_object_is_type(fno, UC_OBJ_CLOSURE) || !uc_object_as_closure(fno)->is_arrow)
		ctx = NULL;
	else if (vm->callframes.count > 0)
		ctx = uc_value_get(uc_vm_current_frame(vm)->ctx);

	uc_vm_call_function(vm, ctx, fno, false, vm->arg.u32);
}

static void
uc_vm_insn_mcall(uc_vm *vm, enum insn_type insn)
{
	size_t key_slot = vm->stack.count - (vm->arg.u32 & 0xffff) - 1;
	json_object *ctx = vm->stack.entries[key_slot - 1];
	json_object *key = vm->stack.entries[key_slot];
	json_object *fno = uc_getval(ctx, key);

	uc_vm_stack_set(vm, key_slot, fno);

	/* arrow functions as method calls inherit the parent ctx */
	if (uc_object_is_type(fno, UC_OBJ_CLOSURE) && uc_object_as_closure(fno)->is_arrow)
		ctx = uc_vm_current_frame(vm)->ctx;

	uc_vm_call_function(vm, uc_value_get(ctx), uc_value_get(fno), true, vm->arg.u32);
}

static void
uc_vm_insn_print(uc_vm *vm, enum insn_type insn)
{
	json_object *v = uc_vm_stack_pop(vm);
	const char *p;
	size_t len;

	switch (json_object_get_type(v)) {
	case json_type_object:
	case json_type_array:
		p = json_object_to_json_string_ext(v, JSON_C_TO_STRING_NOSLASHESCAPE|JSON_C_TO_STRING_SPACED);
		len = strlen(p);
		break;

	case json_type_string:
		p = json_object_get_string(v);
		len = json_object_get_string_len(v);
		break;

	case json_type_null:
		p = "";
		len = 0;
		break;

	default:
		p = json_object_get_string(v);
		len = strlen(p);
	}

	fwrite(p, 1, len, stdout);

	uc_value_put(v);
}

static json_object *
uc_vm_callframe_pop(uc_vm *vm)
{
	uc_callframe *frame = uc_vm_current_frame(vm);
	json_object *retval;

	/* close upvalues */
	uc_vm_close_upvals(vm, frame->stackframe);

	if (vm->stack.count > frame->stackframe)
		retval = uc_vm_stack_pop(vm);
	else
		retval = NULL;

	/* reset function stack frame */
	while (vm->stack.count > frame->stackframe)
		uc_value_put(uc_vm_stack_pop(vm));

	/* for method calls, release context as well */
	if (frame->mcall)
		uc_value_put(uc_vm_stack_pop(vm));

	/* release function */
	uc_value_put(frame->closure ? frame->closure->header.jso : NULL);
	uc_value_put(frame->cfunction ? frame->cfunction->header.jso : NULL);

	/* release context */
	uc_value_put(frame->ctx);

	vm->callframes.count--;

	return retval;
}

static void
uc_vm_output_exception(uc_vm *vm)
{
	if (vm->exception.type == EXCEPTION_USER)
		fprintf(stderr, "%s\n", vm->exception.message);
	else
		fprintf(stderr, "%s: %s\n",
			    exception_type_strings[vm->exception.type] ? exception_type_strings[vm->exception.type] : "Error",
			    vm->exception.message);

	fprintf(stderr, "%s\n\n",
		json_object_get_string(
			json_object_object_get(
				json_object_array_get_idx(vm->exception.stacktrace, 0), "context")));
}

static uc_vm_status_t
uc_vm_execute_chunk(uc_vm *vm)
{
	uc_callframe *frame = uc_vm_current_frame(vm);
	uc_chunk *chunk = uc_vm_frame_chunk(frame);
	json_object *retval;
	enum insn_type insn;

	while (chunk) {
		if (vm->trace)
			uc_dump_insn(vm, frame->ip, (insn = uc_vm_decode_insn(vm, frame, chunk)));
		else
			insn = uc_vm_decode_insn(vm, frame, chunk);

		switch (insn) {
		case I_LOAD:
		case I_LOAD8:
		case I_LOAD16:
		case I_LOAD32:
			uc_vm_insn_load(vm, insn);
			break;

		case I_LREXP:
			uc_vm_insn_load_regexp(vm, insn);
			break;

		case I_LNULL:
			uc_vm_insn_load_null(vm, insn);
			break;

		case I_LTRUE:
		case I_LFALSE:
			uc_vm_insn_load_bool(vm, insn);
			break;

		case I_LTHIS:
			uc_vm_stack_push(vm, uc_value_get(frame->ctx));
			break;

		case I_LVAR:
			uc_vm_insn_load_var(vm, insn);
			break;

		case I_LVAL:
			uc_vm_insn_load_val(vm, insn);
			break;

		case I_LUPV:
			uc_vm_insn_load_upval(vm, insn);
			break;

		case I_LLOC:
			uc_vm_insn_load_local(vm, insn);
			break;

		case I_CLFN:
		case I_ARFN:
			uc_vm_insn_load_closure(vm, insn);
			break;

		case I_NARR:
			uc_vm_insn_narr(vm, insn);
			break;

		case I_PARR:
			uc_vm_insn_parr(vm, insn);
			break;

		case I_MARR:
			uc_vm_insn_marr(vm, insn);
			break;

		case I_NOBJ:
			uc_vm_insn_nobj(vm, insn);
			break;

		case I_SOBJ:
			uc_vm_insn_sobj(vm, insn);
			break;

		case I_MOBJ:
			uc_vm_insn_mobj(vm, insn);
			break;

		case I_SVAR:
			uc_vm_insn_store_var(vm, insn);
			break;

		case I_SVAL:
			uc_vm_insn_store_val(vm, insn);
			break;

		case I_SUPV:
			uc_vm_insn_store_upval(vm, insn);
			break;

		case I_SLOC:
			uc_vm_insn_store_local(vm, insn);
			break;

		case I_UVAR:
			uc_vm_insn_update_var(vm, insn);
			break;

		case I_UVAL:
			uc_vm_insn_update_val(vm, insn);
			break;

		case I_UUPV:
			uc_vm_insn_update_upval(vm, insn);
			break;

		case I_ULOC:
			uc_vm_insn_update_local(vm, insn);
			break;

		case I_ADD:
		case I_SUB:
		case I_MUL:
		case I_DIV:
		case I_MOD:
			uc_vm_insn_arith(vm, insn);
			break;

		case I_PLUS:
		case I_MINUS:
			uc_vm_insn_plus_minus(vm, insn);
			break;

		case I_LSHIFT:
		case I_RSHIFT:
		case I_BAND:
		case I_BXOR:
		case I_BOR:
			uc_vm_insn_bitop(vm, insn);
			break;

		case I_COMPL:
			uc_vm_insn_complement(vm, insn);
			break;

		case I_EQS:
		case I_NES:
			uc_vm_insn_equality(vm, insn);
			break;

		case I_EQ:
		case I_NE:
		case I_LT:
		case I_GT:
			uc_vm_insn_rel(vm, insn);
			break;

		case I_IN:
			uc_vm_insn_in(vm, insn);
			break;

		case I_NOT:
			uc_vm_insn_not(vm, insn);
			break;

		case I_JMP:
			uc_vm_insn_jmp(vm, insn);
			break;

		case I_JMPZ:
			uc_vm_insn_jmpz(vm, insn);
			break;

		case I_NEXTK:
		case I_NEXTKV:
			uc_vm_insn_next(vm, insn);
			break;

		case I_COPY:
			uc_vm_stack_push(vm, uc_value_get(uc_vm_stack_peek(vm, vm->arg.u8)));
			break;

		case I_POP:
			uc_value_put(uc_vm_stack_pop(vm));
			break;

		case I_CUPV:
			uc_vm_insn_close_upval(vm, insn);
			break;

		case I_CALL:
			uc_vm_insn_call(vm, insn);
			frame = uc_vm_current_frame(vm);
			chunk = frame->closure ? uc_vm_frame_chunk(frame) : NULL;
			break;

		case I_MCALL:
			uc_vm_insn_mcall(vm, insn);
			frame = uc_vm_current_frame(vm);
			chunk = frame->closure ? uc_vm_frame_chunk(frame) : NULL;
			break;

		case I_RETURN:
			retval = uc_vm_callframe_pop(vm);

			if (vm->callframes.count == 0) {
				uc_value_put(retval);

				return STATUS_OK;
			}

			uc_vm_stack_push(vm, retval);

			frame = uc_vector_last(&vm->callframes);
			chunk = uc_vm_frame_chunk(frame);
			break;

		case I_PRINT:
			uc_vm_insn_print(vm, insn);
			break;

		default:
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "unknown opcode %d", insn);
			break;
		}

		/* previous instruction raised exception */
		if (vm->exception.type != EXCEPTION_NONE) {
			/* walk up callframes until something handles the exception or the root is reached */
			while (!uc_vm_handle_exception(vm)) {
				/* no further callframe to pop, report unhandled exception and terminate */
				if (vm->callframes.count == 1) {
					uc_vm_output_exception(vm);

					return ERROR_RUNTIME;
				}

				/* if VM returned into native function, don't bubble up */
				if (!chunk)
					return ERROR_RUNTIME;

				/* no exception handler in current function, pop callframe */
				uc_value_put(uc_vm_callframe_pop(vm));

				/* resume execution at topmost remaining callframe */
				frame = uc_vector_last(&vm->callframes);
				chunk = uc_vm_frame_chunk(frame);
			}
		}
	}

	return STATUS_OK;
}

static uc_vm_status_t
uc_vm_preload(uc_vm *vm, json_object *modules)
{
	json_object *requirefn, *module, *name;
	uc_exception_type_t ex;
	size_t i;

	if (!json_object_is_type(modules, json_type_array))
		return STATUS_OK;

	requirefn = uc_prototype_lookup(vm->globals, "require");

	if (!uc_object_is_type(requirefn, UC_OBJ_CFUNCTION))
		return STATUS_OK;

	for (i = 0; i < json_object_array_length(modules); i++) {
		name = json_object_array_get_idx(modules, i);

		uc_vm_stack_push(vm, uc_value_get(requirefn));
		uc_vm_stack_push(vm, uc_value_get(name));

		ex = uc_vm_call(vm, false, 1);

		if (ex)
			return ERROR_RUNTIME;

		module = uc_vm_stack_pop(vm);

		uc_value_put(uc_setval(vm->globals->header.jso, name, module));
	}

	return STATUS_OK;
}

uc_vm_status_t
uc_vm_execute(uc_vm *vm, uc_function *fn, uc_prototype *globals, json_object *modules)
{
	uc_closure *closure = uc_closure_new(fn, false);
	uc_callframe *frame;
	uc_vm_status_t rv;

	vm->globals = globals;
	uc_value_get(globals ? globals->header.jso : NULL);

	uc_vector_grow(&vm->callframes);

	frame = &vm->callframes.entries[vm->callframes.count++];
	frame->closure = closure;
	frame->stackframe = 0;
	frame->ip = uc_vm_frame_chunk(frame)->entries;

	if (vm->trace) {
		size_t msglen = 0;
		char *msg = NULL;

		format_source_context(&msg, &msglen,
			fn->source, 0, true);

		fprintf(stderr, "%s", msg);

		uc_vm_frame_dump(vm, frame);
	}

	//uc_vm_stack_push(vm, closure->header.jso);
	uc_vm_stack_push(vm, NULL);

	rv = uc_vm_preload(vm, modules);

	if (rv != STATUS_OK)
		uc_vm_output_exception(vm);
	else
		rv = uc_vm_execute_chunk(vm);

	uc_value_put(vm->globals->header.jso);
	vm->globals = NULL;

	return rv;
}

uc_exception_type_t
uc_vm_call(uc_vm *vm, bool mcall, size_t nargs)
{
	json_object *ctx = mcall ? uc_value_get(uc_vm_stack_peek(vm, nargs - 1)) : NULL;
	json_object *fno = uc_value_get(uc_vm_stack_peek(vm, nargs));

	if (uc_vm_call_function(vm, ctx, fno, mcall, nargs & 0xffff)) {
		if (!uc_object_is_type(fno, UC_OBJ_CFUNCTION))
			uc_vm_execute_chunk(vm);
	}

	return vm->exception.type;
}
