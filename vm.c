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

static const int8_t insn_operand_bytes[__I_MAX] = {
	[I_LOAD] = 4,
	[I_LOAD8] = -1,
	[I_LOAD16] = -2,
	[I_LOAD32] = -4,

	[I_LREXP] = 4,

	[I_LLOC] = 4,
	[I_LVAR] = 4,
	[I_LUPV] = 4,

	[I_CLFN] = 4,
	[I_ARFN] = 4,

	[I_SLOC] = 4,
	[I_SUPV] = 4,
	[I_SVAR] = 4,

	[I_ULOC] = 4,
	[I_UUPV] = 4,
	[I_UVAR] = 4,
	[I_UVAL] = 1,

	[I_NARR] = 4,
	[I_PARR] = 4,

	[I_NOBJ] = 4,
	[I_SOBJ] = 4,

	[I_JMP] = -4,
	[I_JMPZ] = -4,

	[I_COPY] = 1,

	[I_CALL] = 4,
	[I_MCALL] = 4
};

static const char *exception_type_strings[] = {
	[EXCEPTION_SYNTAX] = "Syntax error",
	[EXCEPTION_RUNTIME] = "Runtime error",
	[EXCEPTION_TYPE] = "Type error",
	[EXCEPTION_REFERENCE] = "Reference error",
	[EXCEPTION_USER] = "Error",
	[EXCEPTION_EXIT] = "Exit"
};


static void
uc_vm_reset_stack(uc_vm_t *vm)
{
	while (vm->stack.count > 0) {
		vm->stack.count--;
		ucv_put(vm->stack.entries[vm->stack.count]);
		vm->stack.entries[vm->stack.count] = NULL;
	}
}

static uc_value_t *
uc_vm_callframe_pop(uc_vm_t *vm);

static void
uc_vm_reset_callframes(uc_vm_t *vm)
{
	while (vm->callframes.count > 0)
		ucv_put(uc_vm_callframe_pop(vm));
}

static uc_value_t *
uc_vm_alloc_global_scope(uc_vm_t *vm)
{
	const char *path[] = { LIB_SEARCH_PATH };
	uc_value_t *scope, *arr;
	size_t i;

	scope = ucv_object_new(vm);

	/* build default require() search path */
	arr = ucv_array_new(vm);

	for (i = 0; i < ARRAY_SIZE(path); i++)
		ucv_array_push(arr, ucv_string_new(path[i]));

	/* register module related constants */
	ucv_object_add(scope, "REQUIRE_SEARCH_PATH", arr);
	ucv_object_add(scope, "modules", ucv_object_new(vm));

	/* register scope math constants */
	ucv_object_add(scope, "NaN", ucv_double_new(NAN));
	ucv_object_add(scope, "Infinity", ucv_double_new(INFINITY));

	/* register global property */
	ucv_object_add(scope, "global", ucv_get(scope));

	uc_vm_scope_set(vm, scope);

	return scope;
}

static void
uc_vm_output_exception(uc_vm_t *vm, uc_exception_t *ex);

void uc_vm_init(uc_vm_t *vm, uc_parse_config_t *config)
{
	vm->exception.type = EXCEPTION_NONE;
	vm->exception.message = NULL;

	vm->config = config;

	vm->open_upvals = NULL;

	vm->values.prev = &vm->values;
	vm->values.next = &vm->values;

	vm->strbuf = NULL;

	vm->output = stdout;

	uc_vm_reset_stack(vm);

	uc_vm_alloc_global_scope(vm);

	uc_vm_exception_handler_set(vm, uc_vm_output_exception);

	uc_vm_trace_set(vm, 0);
}

void uc_vm_free(uc_vm_t *vm)
{
	uc_upval_tref_t *ref;
	size_t i;

	ucv_put(vm->exception.stacktrace);
	free(vm->exception.message);

	while (vm->open_upvals) {
		ref = vm->open_upvals->next;
		ucv_put(&vm->open_upvals->header);
		vm->open_upvals = ref;
	}

	for (i = 0; i < vm->restypes.count; i++)
		ucv_put(vm->restypes.entries[i]->proto);

	uc_vm_reset_callframes(vm);
	uc_vm_reset_stack(vm);
	uc_vector_clear(&vm->stack);
	uc_vector_clear(&vm->callframes);

	printbuf_free(vm->strbuf);

	ucv_gc(vm, true);

	for (i = 0; i < vm->restypes.count; i++)
		free(vm->restypes.entries[i]);

	uc_vector_clear(&vm->restypes);
}

static uc_chunk_t *
uc_vm_frame_chunk(uc_callframe_t *frame)
{
	return frame->closure ? &frame->closure->function->chunk : NULL;
}

static uc_callframe_t *
uc_vm_current_frame(uc_vm_t *vm)
{
	return uc_vector_last(&vm->callframes);
}

static uc_chunk_t *
uc_vm_current_chunk(uc_vm_t *vm)
{
	return uc_vm_frame_chunk(uc_vm_current_frame(vm));
}

static bool
uc_vm_is_strict(uc_vm_t *vm)
{
	return uc_vm_current_frame(vm)->strict;
}

static uc_vm_insn_t
uc_vm_decode_insn(uc_vm_t *vm, uc_callframe_t *frame, uc_chunk_t *chunk)
{
	uc_vm_insn_t insn;

#ifndef NDEBUG
	uint8_t *end = chunk->entries + chunk->count;
#endif

	assert(frame->ip < end);

	insn = frame->ip[0];
	frame->ip++;

	assert(frame->ip + abs(insn_operand_bytes[insn]) <= end);

	switch (insn_operand_bytes[insn]) {
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
			frame->ip[0] * 0x1000000UL +
			frame->ip[1] * 0x10000UL +
			frame->ip[2] * 0x100UL +
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
			frame->ip[0] * 0x1000000UL +
			frame->ip[1] * 0x10000UL +
			frame->ip[2] * 0x100UL +
			frame->ip[3]
		);
		frame->ip += 4;
		break;

	default:
		fprintf(stderr, "Unhandled operand format: %" PRId8 "\n", insn_operand_bytes[insn]);
		abort();
	}

	return insn;
}


static char *
uc_vm_format_val(uc_vm_t *vm, uc_value_t *val)
{
	if (!vm->strbuf)
		vm->strbuf = xprintbuf_new();
	else
		printbuf_reset(vm->strbuf);

	ucv_to_stringbuf(NULL, vm->strbuf, val, true);

	if (printbuf_length(vm->strbuf) >= 64) {
		printbuf_memset(vm->strbuf, 60, '.', 3);
		printbuf_memset(vm->strbuf, 63, 0, 1);
	}

	return vm->strbuf->buf;
}

static void
uc_vm_frame_dump(uc_vm_t *vm, uc_callframe_t *frame)
{
	uc_chunk_t *chunk = uc_vm_frame_chunk(frame);
	uc_function_t *function;
	uc_closure_t *closure;
	uc_upval_tref_t *ref;
	uc_value_t *v;
	size_t i;

	fprintf(stderr, "  [*] CALLFRAME[%zx]\n",
		frame - vm->callframes.entries);

	fprintf(stderr, "   |- stackframe %zu/%zu\n",
		frame->stackframe, vm->stack.count);

	fprintf(stderr, "   |- ctx %s\n",
		uc_vm_format_val(vm, frame->ctx));

	if (chunk) {
		fprintf(stderr, "   |- %zu constants\n",
			chunk->constants.isize);

		for (i = 0; i < chunk->constants.isize; i++) {
			v = uc_chunk_get_constant(chunk, i);

			fprintf(stderr, "   | [%zu] %s\n",
				i, uc_vm_format_val(vm, v));

			ucv_put(v);
		}

		closure = frame->closure;
		function = closure->function;

		fprintf(stderr, "   `- %zu upvalues\n",
			function->nupvals);

		for (i = 0; i < function->nupvals; i++) {
			ref = closure->upvals[i];
			v = uc_chunk_debug_get_variable(chunk, 0, i, true);

			fprintf(stderr, "     [%zu] <%p> %s ",
				i, (void *)ref, uc_vm_format_val(vm, v));

			if (ref->closed) {
				fprintf(stderr, "{closed} %s\n",
					uc_vm_format_val(vm, ref->value));
			}
			else {
				fprintf(stderr, "{open[%zu]} %s\n",
					ref->slot,
					uc_vm_format_val(vm, vm->stack.entries[ref->slot]));
			}

			ucv_put(v);
		}
	}
}

void
uc_vm_stack_push(uc_vm_t *vm, uc_value_t *value)
{
	uc_vector_grow(&vm->stack);

	ucv_put(vm->stack.entries[vm->stack.count]);

	vm->stack.entries[vm->stack.count] = value;
	vm->stack.count++;

	if (vm->trace) {
		fprintf(stderr, "  [+%zd] %s\n",
			vm->stack.count - 1,
			uc_vm_format_val(vm, value));
	}
}

uc_value_t *
uc_vm_stack_pop(uc_vm_t *vm)
{
	uc_value_t *rv;

	vm->stack.count--;
	rv = vm->stack.entries[vm->stack.count];
	vm->stack.entries[vm->stack.count] = NULL;

	if (vm->trace) {
		fprintf(stderr, "  [-%zd] %s\n",
			vm->stack.count,
			uc_vm_format_val(vm, rv));
	}

	return rv;
}

uc_value_t *
uc_vm_stack_peek(uc_vm_t *vm, size_t offset)
{
	return vm->stack.entries[vm->stack.count + (-1 - offset)];
}

static void
uc_vm_stack_set(uc_vm_t *vm, size_t offset, uc_value_t *value)
{
	if (vm->trace) {
		fprintf(stderr, "  [!%zu] %s\n",
			offset,
			uc_vm_format_val(vm, value));
	}

	ucv_put(vm->stack.entries[offset]);
	vm->stack.entries[offset] = value;
}

static void
uc_vm_call_native(uc_vm_t *vm, uc_value_t *ctx, uc_cfunction_t *fptr, bool mcall, size_t nargs)
{
	uc_value_t *res = NULL;
	uc_callframe_t *frame;

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
	ucv_put(uc_vm_callframe_pop(vm));

	/* push return value */
	if (!vm->exception.type)
		uc_vm_stack_push(vm, res);
	else
		ucv_put(res);
}

static bool
uc_vm_call_function(uc_vm_t *vm, uc_value_t *ctx, uc_value_t *fno, bool mcall, size_t argspec)
{
	size_t i, j, stackoff, nargs = argspec & 0xffff, nspreads = argspec >> 16;
	uc_callframe_t *frame = NULL;
	uc_value_t *ellip, *arg;
	uc_function_t *function;
	uc_closure_t *closure;
	uint16_t slot, tmp;
	char *s;

	/* XXX: make dependent on stack size */
	if (vm->callframes.count >= 1000) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Too much recursion");

		return false;
	}

	stackoff = vm->stack.count - nargs - 1;

	/* argument list contains spread operations, we need to reshuffle the stack */
	if (nspreads > 0) {
		frame = uc_vm_current_frame(vm);

		/* create temporary array */
		ellip = ucv_array_new_length(vm, nargs);

		/* pop original stack values and push to temp array in reverse order */
		for (i = 0; i < nargs; i++)
			ucv_array_push(ellip, uc_vm_stack_pop(vm));

		/* for each spread value index ... */
		for (i = 0, slot = nargs; i < nspreads; i++) {
			/* decode stack depth value */
			tmp = frame->ip[0] * 0x100 + frame->ip[1];
			frame->ip += 2;

			/* push each preceeding non-spread value to the stack */
			for (j = slot; j > tmp + 1UL; j--)
				uc_vm_stack_push(vm, ucv_get(ucv_array_get(ellip, j - 1)));

			/* read spread value at index... */
			slot = tmp;
			arg = ucv_get(ucv_array_get(ellip, slot));

			/* ... ensure that it is an array type ... */
			if (ucv_type(arg) != UC_ARRAY) {
				s = ucv_to_string(vm, arg);
				uc_vm_raise_exception(vm, EXCEPTION_TYPE, "(%s) is not iterable", s);
				free(s);

				return false;
			}

			/* ... and push each spread array value as argument to the stack */
			for (j = 0; j < ucv_array_length(arg); j++)
				uc_vm_stack_push(vm, ucv_get(ucv_array_get(arg, j)));

			ucv_put(arg);
		}

		/* push remaining non-spread arguments to the stack */
		for (i = slot; i > 0; i--)
			uc_vm_stack_push(vm, ucv_get(ucv_array_get(ellip, i - 1)));

		/* free temp array */
		ucv_put(ellip);

		/* update arg count */
		nargs = vm->stack.count - stackoff - 1;
	}

	/* is a native function */
	if (ucv_type(fno) == UC_CFUNCTION) {
		uc_vm_call_native(vm, ctx, (uc_cfunction_t *)fno, mcall, nargs);

		return true;
	}

	if (ucv_type(fno) != UC_CLOSURE) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "left-hand side is not a function");

		return false;
	}

	closure = (uc_closure_t *)fno;
	function = closure->function;

	/* fewer arguments on stack than function expects => pad */
	if (nargs < function->nargs) {
		for (i = nargs; i < function->nargs; i++) {
			if (function->vararg && (i + 1) == function->nargs)
				uc_vm_stack_push(vm, ucv_array_new_length(vm, 0));
			else
				uc_vm_stack_push(vm, NULL);
		}
	}

	/* more arguments on stack than function expects... */
	else if (nargs > function->nargs - function->vararg) {
		/* is a vararg function => pass excess args as array */
		if (function->vararg) {
			ellip = ucv_array_new_length(vm, nargs - (function->nargs - 1));

			for (i = function->nargs; i <= nargs; i++)
				ucv_array_push(ellip, uc_vm_stack_peek(vm, nargs - i));

			for (i = function->nargs; i <= nargs; i++)
				uc_vm_stack_pop(vm);

			uc_vm_stack_push(vm, ellip);
		}

		/* static amount of args => drop excess values */
		else {
			for (i = function->nargs; i < nargs; i++)
				ucv_put(uc_vm_stack_pop(vm));
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
	frame->strict = function->strict;

	if (vm->trace)
		uc_vm_frame_dump(vm, frame);

	return true;
}

static uc_source_t *last_source = NULL;
static size_t last_srcpos = 0;

static void
uc_dump_insn(uc_vm_t *vm, uint8_t *pos, uc_vm_insn_t insn)
{
	uc_callframe_t *frame = uc_vm_current_frame(vm);
	uc_chunk_t *chunk = uc_vm_frame_chunk(frame);
	uc_stringbuf_t *buf = NULL;
	uc_value_t *cnst = NULL;
	size_t srcpos;

	srcpos = ucv_function_srcpos(&frame->closure->function->header, pos - chunk->entries);

	if (last_srcpos == 0 || last_source != frame->closure->function->source || srcpos != last_srcpos) {
		buf = xprintbuf_new();

		format_source_context(buf, frame->closure->function->source, srcpos, true);
		fwrite(buf->buf, 1, printbuf_length(buf), stderr);
		printbuf_free(buf);

		last_source = frame->closure->function->source;
		last_srcpos = srcpos;
	}

	fprintf(stderr, "%08zx  %s", pos - chunk->entries, insn_names[insn]);

	switch (insn_operand_bytes[insn]) {
	case 0:
		break;

	case -1:
		fprintf(stderr, " {%s%hhd}", vm->arg.s8 < 0 ? "" : "+", vm->arg.s8);
		break;

	case -2:
		fprintf(stderr, " {%c0x%hx}",
			vm->arg.s16 < 0 ? '-' : '+',
			(uint16_t)(vm->arg.s16 < 0 ? -vm->arg.s16 : vm->arg.s16));
		break;

	case -4:
		fprintf(stderr, " {%c0x%x}",
			vm->arg.s32 < 0 ? '-' : '+',
			(uint32_t)(vm->arg.s32 < 0 ? -vm->arg.s32 : vm->arg.s32));
		break;

	case 1:
		fprintf(stderr, " {%hhu}", vm->arg.u8);
		break;

	case 2:
		fprintf(stderr, " {0x%hx}", vm->arg.u16);
		break;

	case 4:
		fprintf(stderr, " {0x%x}", vm->arg.u32);
		break;

	default:
		fprintf(stderr, " (unknown operand format: %" PRId8 ")", insn_operand_bytes[insn]);
		break;
	}

	switch (insn) {
	case I_LOAD:
	case I_LVAR:
	case I_SVAR:
		cnst = uc_chunk_get_constant(uc_vm_frame_chunk(uc_vector_last(&vm->callframes)), vm->arg.u32);

		fprintf(stderr, "\t; %s",
			cnst ? uc_vm_format_val(vm, cnst) : "(?)");

		ucv_put(cnst);
		break;

	case I_LLOC:
	case I_LUPV:
	case I_SLOC:
	case I_SUPV:
		cnst = uc_chunk_debug_get_variable(chunk, pos - chunk->entries, vm->arg.u32, (insn == I_LUPV || insn == I_SUPV));

		fprintf(stderr, "\t; %s",
			cnst ? uc_vm_format_val(vm, cnst) : "(?)");

		ucv_put(cnst);
		break;

	case I_ULOC:
	case I_UUPV:
		cnst = uc_chunk_debug_get_variable(chunk, pos - chunk->entries, vm->arg.u32 & 0x00ffffff, (insn == I_UUPV));
		/* fall through */

	case I_UVAR:
		if (!cnst)
			cnst = uc_chunk_get_constant(uc_vm_frame_chunk(uc_vector_last(&vm->callframes)), vm->arg.u32 & 0x00ffffff);

		fprintf(stderr, "\t; %s (%s)",
			cnst ? uc_vm_format_val(vm, cnst) : "(?)",
			insn_names[vm->arg.u32 >> 24]);

		ucv_put(cnst);
		break;

	case I_UVAL:
		fprintf(stderr, "\t; (%s)", insn_names[vm->arg.u32]);
		break;

	default:
		break;
	}

	fprintf(stderr, "\n");
}

static uc_value_t *
uc_vm_exception_tostring(uc_vm_t *vm, size_t nargs)
{
	uc_callframe_t *frame = uc_vm_current_frame(vm);
	uc_value_t *message = ucv_object_get(frame->ctx, "message", NULL);

	return message ? ucv_get(message) : ucv_string_new("Exception");
}

static uc_value_t *exception_prototype = NULL;

static uc_value_t *
uc_vm_exception_new(uc_vm_t *vm, uc_exception_type_t type, const char *message, uc_value_t *stacktrace)
{
	uc_value_t *exo;

	if (exception_prototype == NULL) {
		exception_prototype = ucv_object_new(vm);

		ucv_object_add(exception_prototype, "tostring",
			ucv_cfunction_new("tostring", uc_vm_exception_tostring));
	}

	exo = ucv_object_new(vm);

	ucv_object_add(exo, "type", ucv_string_new(exception_type_strings[type]));
	ucv_object_add(exo, "message", ucv_string_new(message));
	ucv_object_add(exo, "stacktrace", ucv_get(stacktrace));

	ucv_prototype_set(exo, ucv_get(exception_prototype));

	return exo;
}

static bool
uc_vm_handle_exception(uc_vm_t *vm)
{
	uc_callframe_t *frame = NULL;
	uc_chunk_t *chunk = NULL;
	uc_value_t *exo;
	size_t i, pos;

	if (vm->callframes.count)
		frame = uc_vm_current_frame(vm);

	if (!frame || !frame->closure)
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
			ucv_put(uc_vm_stack_pop(vm));

		/* prepare exception object and expose it to user handler code */
		exo = uc_vm_exception_new(vm, vm->exception.type, vm->exception.message, vm->exception.stacktrace);

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

static uc_value_t *
uc_vm_capture_stacktrace(uc_vm_t *vm, size_t i)
{
	uc_value_t *stacktrace, *entry, *last = NULL;
	uc_function_t *function;
	uc_callframe_t *frame;
	size_t off, srcpos;
	char *name;

	stacktrace = ucv_array_new(vm);

	for (; i > 0; i--) {
		frame = &vm->callframes.entries[i - 1];
		entry = ucv_object_new(vm);

		if (frame->closure) {
			function = frame->closure->function;

			off = (frame->ip - uc_vm_frame_chunk(frame)->entries) - 1;
			srcpos = ucv_function_srcpos(&function->header, off);

			ucv_object_add(entry, "filename", ucv_string_new(function->source->filename));
			ucv_object_add(entry, "line", ucv_int64_new(uc_source_get_line(function->source, &srcpos)));
			ucv_object_add(entry, "byte", ucv_int64_new(srcpos));
		}

		if (i > 1) {
			if (frame->closure) {
				if (frame->closure->function->name[0])
					name = frame->closure->function->name;
				else if (frame->closure->is_arrow)
					name = "[arrow function]";
				else
					name = "[anonymous function]";
			}
			else {
				name = frame->cfunction->name;
			}

			ucv_object_add(entry, "function", ucv_string_new(name));
		}

		if (!ucv_equal(last, entry)) {
			ucv_array_push(stacktrace, entry);
			last = entry;
		}
		else {
			ucv_put(entry);
		}
	}

	return stacktrace;
}

static uc_value_t *
uc_vm_get_error_context(uc_vm_t *vm)
{
	uc_value_t *stacktrace;
	uc_callframe_t *frame;
	uc_stringbuf_t *buf;
	uc_chunk_t *chunk;
	size_t offset, i;

	/* skip to first non-native function call frame */
	for (i = vm->callframes.count; i > 1; i--)
		if (vm->callframes.entries[i - 1].closure)
			break;

	frame = &vm->callframes.entries[i - 1];

	if (!frame->closure)
		return NULL;

	chunk = uc_vm_frame_chunk(frame);
	offset = ucv_function_srcpos(&frame->closure->function->header, (frame->ip - chunk->entries) - 1);
	stacktrace = uc_vm_capture_stacktrace(vm, i);

	buf = ucv_stringbuf_new();

	if (offset)
		format_error_context(buf, frame->closure->function->source, stacktrace, offset);
	else if (frame->ip != chunk->entries)
		ucv_stringbuf_printf(buf, "At instruction %zu", (frame->ip - chunk->entries) - 1);
	else
		ucv_stringbuf_append(buf, "At start of program");

	ucv_object_add(ucv_array_get(stacktrace, 0), "context", ucv_stringbuf_finish(buf));

	return stacktrace;
}

void __attribute__((format(printf, 3, 0)))
uc_vm_raise_exception(uc_vm_t *vm, uc_exception_type_t type, const char *fmt, ...)
{
	va_list ap;

	vm->exception.type = type;

	free(vm->exception.message);

	va_start(ap, fmt);
	xvasprintf(&vm->exception.message, fmt, ap);
	va_end(ap);

	ucv_put(vm->exception.stacktrace);
	vm->exception.stacktrace = uc_vm_get_error_context(vm);
}


static void
uc_vm_insn_load(uc_vm_t *vm, uc_vm_insn_t insn)
{
	switch (insn) {
	case I_LOAD:
		uc_vm_stack_push(vm, uc_chunk_get_constant(uc_vm_current_chunk(vm), vm->arg.u32));
		break;

	case I_LOAD8:
		uc_vm_stack_push(vm, ucv_int64_new(vm->arg.s8));
		break;

	case I_LOAD16:
		uc_vm_stack_push(vm, ucv_int64_new(vm->arg.s16));
		break;

	case I_LOAD32:
		uc_vm_stack_push(vm, ucv_int64_new(vm->arg.s32));
		break;

	default:
		break;
	}
}

static void
uc_vm_insn_load_regexp(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *re, *jstr = uc_chunk_get_constant(uc_vm_current_chunk(vm), vm->arg.u32);
	bool icase = false, newline = false, global = false;
	char *str, *err = NULL;

	if (ucv_type(jstr) != UC_STRING || ucv_string_length(jstr) < 2) {
		uc_vm_stack_push(vm, NULL);
		ucv_put(jstr);

		return;
	}

	str = ucv_string_get(jstr);

	global  = (*str & (1 << 0));
	icase   = (*str & (1 << 1));
	newline = (*str & (1 << 2));

	re = ucv_regexp_new(++str, icase, newline, global, &err);

	ucv_put(jstr);

	if (re)
		uc_vm_stack_push(vm, re);
	else
		uc_vm_raise_exception(vm, EXCEPTION_SYNTAX, "%s", err);

	free(err);
}

static void
uc_vm_insn_load_null(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_vm_stack_push(vm, NULL);
}

static void
uc_vm_insn_load_bool(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_vm_stack_push(vm, ucv_boolean_new(insn == I_LTRUE));
}

static void
uc_vm_insn_load_var(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *name, *val = NULL;
	uc_value_t *scope, *next;
	bool found;

	scope = vm->globals;
	name = uc_chunk_get_constant(uc_vm_current_chunk(vm), vm->arg.u32);

	while (ucv_type(name) == UC_STRING) {
		val = ucv_object_get(scope, ucv_string_get(name), &found);

		if (found)
			break;

		next = ucv_prototype_get(scope);

		if (!next) {
			if (uc_vm_is_strict(vm)) {
				uc_vm_raise_exception(vm, EXCEPTION_REFERENCE,
				                      "access to undeclared variable %s",
				                      ucv_string_get(name));
			}

			break;
		}

		scope = next;
	}

	ucv_put(name);

	uc_vm_stack_push(vm, ucv_get(val));
}

static void
uc_vm_insn_load_val(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *k = uc_vm_stack_pop(vm);
	uc_value_t *v = uc_vm_stack_pop(vm);

	switch (ucv_type(v)) {
	case UC_OBJECT:
	case UC_ARRAY:
		uc_vm_stack_push(vm, uc_getval(vm, v, k));
		break;

	default:
		uc_vm_raise_exception(vm, EXCEPTION_REFERENCE,
		                      "left-hand side expression is %s",
		                      v ? "not an array or object" : "null");

		break;
	}

	ucv_put(k);
	ucv_put(v);
}

static void
uc_vm_insn_load_upval(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_callframe_t *frame = uc_vm_current_frame(vm);
	uc_upval_tref_t *ref = frame->closure->upvals[vm->arg.u32];

	if (ref->closed)
		uc_vm_stack_push(vm, ucv_get(ref->value));
	else
		uc_vm_stack_push(vm, ucv_get(vm->stack.entries[ref->slot]));
}

static void
uc_vm_insn_load_local(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_callframe_t *frame = uc_vm_current_frame(vm);

	uc_vm_stack_push(vm, ucv_get(vm->stack.entries[frame->stackframe + vm->arg.u32]));
}

static uc_upval_tref_t *
uc_vm_capture_upval(uc_vm_t *vm, size_t slot)
{
	uc_upval_tref_t *curr = vm->open_upvals;
	uc_upval_tref_t *prev = NULL;
	uc_upval_tref_t *created;
	char *s;

	while (curr && curr->slot > slot) {
		prev = curr;
		curr = curr->next;
	}

	if (curr && curr->slot == slot) {
		if (vm->trace) {
			s = ucv_to_string(NULL, vm->stack.entries[slot]);
			fprintf(stderr, "  {+%zu} <%p> %s\n", slot, (void *)curr, s);
			free(s);
		}

		return curr;
	}

	created = (uc_upval_tref_t *)ucv_upvalref_new(slot);
	created->next = curr;

	if (vm->trace) {
		s = ucv_to_string(NULL, vm->stack.entries[slot]);
		fprintf(stderr, "  {*%zu} <%p> %s\n", slot, (void *)created, s);
		free(s);
	}

	if (prev)
		prev->next = created;
	else
		vm->open_upvals = created;

	return created;
}

static void
uc_vm_close_upvals(uc_vm_t *vm, size_t slot)
{
	uc_upval_tref_t *ref;

	while (vm->open_upvals && vm->open_upvals->slot >= slot) {
		ref = vm->open_upvals;
		ref->value = ucv_get(vm->stack.entries[ref->slot]);
		ref->closed = true;

		if (vm->trace) {
			fprintf(stderr, "  {!%zu} <%p> %s\n", ref->slot,
				(void *)ref,
				uc_vm_format_val(vm, ref->value));
		}

		vm->open_upvals = ref->next;
		ucv_put(&ref->header);
	}
}

static void
uc_vm_insn_load_closure(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_callframe_t *frame = uc_vm_current_frame(vm);
	uc_value_t *fno = uc_chunk_get_constant(uc_vm_current_chunk(vm), vm->arg.u32);
	uc_function_t *function = (uc_function_t *)fno;
	uc_closure_t *closure = (uc_closure_t *)ucv_closure_new(vm, function, insn == I_ARFN);
	volatile int32_t uv;
	size_t i;

	uc_vm_stack_push(vm, &closure->header);

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

		ucv_get(&closure->upvals[i]->header);

		frame->ip += 4;
	}
}

static void
uc_vm_insn_store_var(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *name, *v = uc_vm_stack_pop(vm);
	uc_value_t *scope, *next;
	bool found;

	scope = vm->globals;
	name = uc_chunk_get_constant(uc_vm_current_chunk(vm), vm->arg.u32);

	while (ucv_type(name) == UC_STRING) {
		ucv_object_get(scope, ucv_string_get(name), &found);

		if (found)
			break;

		next = ucv_prototype_get(scope);

		if (!next) {
			if (uc_vm_is_strict(vm)) {
				uc_vm_raise_exception(vm, EXCEPTION_REFERENCE,
				                      "access to undeclared variable %s",
				                      ucv_string_get(name));
			}

			break;
		}

		scope = next;
	}

	if (scope && ucv_type(name) == UC_STRING)
		ucv_object_add(scope, ucv_string_get(name), ucv_get(v));

	ucv_put(name);
	uc_vm_stack_push(vm, v);
}

static void
uc_vm_insn_store_val(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *v = uc_vm_stack_pop(vm);
	uc_value_t *k = uc_vm_stack_pop(vm);
	uc_value_t *o = uc_vm_stack_pop(vm);

	switch (ucv_type(o)) {
	case UC_OBJECT:
	case UC_ARRAY:
		uc_vm_stack_push(vm, uc_setval(vm, o, k, v));
		break;

	default:
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		                      "attempt to set property on %s value",
		                      ucv_typename(o));
	}

	ucv_put(o);
	ucv_put(k);
}

static void
uc_vm_insn_store_upval(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_callframe_t *frame = uc_vm_current_frame(vm);
	uc_upval_tref_t *ref = frame->closure->upvals[vm->arg.u32];
	uc_value_t *val = ucv_get(uc_vm_stack_peek(vm, 0));

	if (ref->closed) {
		ucv_put(ref->value);
		ref->value = val;
	}
	else {
		uc_vm_stack_set(vm, ref->slot, val);
	}
}

static void
uc_vm_insn_store_local(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_callframe_t *frame = uc_vm_current_frame(vm);
	uc_value_t *val = ucv_get(uc_vm_stack_peek(vm, 0));

	uc_vm_stack_set(vm, frame->stackframe + vm->arg.u32, val);
}

static uc_value_t *
uc_vm_value_bitop(uc_vm_t *vm, uc_vm_insn_t operation, uc_value_t *value, uc_value_t *operand)
{
	uc_value_t *rv = NULL;
	int64_t n1, n2;
	double d;

	if (uc_cast_number(value, &n1, &d) == UC_DOUBLE)
		n1 = isnan(d) ? 0 : (int64_t)d;

	if (uc_cast_number(operand, &n2, &d) == UC_DOUBLE)
		n2 = isnan(d) ? 0 : (int64_t)d;

	switch (operation) {
	case I_LSHIFT:
		rv = ucv_int64_new(n1 << n2);
		break;

	case I_RSHIFT:
		rv = ucv_int64_new(n1 >> n2);
		break;

	case I_BAND:
		rv = ucv_int64_new(n1 & n2);
		break;

	case I_BXOR:
		rv = ucv_int64_new(n1 ^ n2);
		break;

	case I_BOR:
		rv = ucv_int64_new(n1 | n2);
		break;

	default:
		break;
	}

	return rv;
}

static uc_value_t *
uc_vm_value_arith(uc_vm_t *vm, uc_vm_insn_t operation, uc_value_t *value, uc_value_t *operand)
{
	uc_value_t *rv = NULL;
	uc_type_t t1, t2;
	char *s, *s1, *s2;
	size_t len1, len2;
	int64_t n1, n2;
	double d1, d2;

	if (operation == I_LSHIFT || operation == I_RSHIFT ||
	    operation == I_BAND || operation == I_BXOR || operation == I_BOR)
		return uc_vm_value_bitop(vm, operation, value, operand);

	if (operation == I_ADD && (ucv_type(value) == UC_STRING || ucv_type(operand) == UC_STRING)) {
		s1 = (ucv_type(value) != UC_STRING) ? ucv_to_string(vm, value) : NULL;
		s2 = (ucv_type(operand) != UC_STRING) ? ucv_to_string(vm, operand) : NULL;
		len1 = s1 ? strlen(s1) : ucv_string_length(value);
		len2 = s2 ? strlen(s2) : ucv_string_length(operand);
		s = xalloc(len1 + len2 + 1);

		memcpy(s, s1 ? s1 : ucv_string_get(value), len1);
		memcpy(s + len1, s2 ? s2 : ucv_string_get(operand), len2);
		free(s1);
		free(s2);

		rv = ucv_string_new_length(s, len1 + len2);

		free(s);

		return rv;
	}

	t1 = uc_cast_number(value, &n1, &d1);
	t2 = uc_cast_number(operand, &n2, &d2);

	if (t1 == UC_DOUBLE || t2 == UC_DOUBLE) {
		d1 = (t1 == UC_DOUBLE) ? d1 : (double)n1;
		d2 = (t2 == UC_DOUBLE) ? d2 : (double)n2;

		switch (operation) {
		case I_ADD:
		case I_PLUS:
			rv = ucv_double_new(d1 + d2);
			break;

		case I_SUB:
			rv = ucv_double_new(d1 - d2);
			break;

		case I_MUL:
			rv = ucv_double_new(d1 * d2);
			break;

		case I_DIV:
			if (d2 == 0.0)
				rv = ucv_double_new(INFINITY);
			else if (isnan(d2))
				rv = ucv_double_new(NAN);
			else if (!isfinite(d2))
				rv = ucv_double_new(isfinite(d1) ? 0.0 : NAN);
			else
				rv = ucv_double_new(d1 / d2);

			break;

		case I_MOD:
			rv = ucv_double_new(NAN);
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
			rv = ucv_int64_new(n1 + n2);
			break;

		case I_SUB:
			rv = ucv_int64_new(n1 - n2);
			break;

		case I_MUL:
			rv = ucv_int64_new(n1 * n2);
			break;

		case I_DIV:
			if (n2 == 0)
				rv = ucv_double_new(INFINITY);
			else
				rv = ucv_int64_new(n1 / n2);

			break;

		case I_MOD:
			rv = ucv_int64_new(n1 % n2);
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
uc_vm_insn_update_var(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *name, *val, *inc = uc_vm_stack_pop(vm);
	uc_value_t *scope, *next;
	bool found;

	scope = vm->globals;
	name = uc_chunk_get_constant(uc_vm_current_chunk(vm), vm->arg.u32 & 0x00FFFFFF);

	assert(ucv_type(name) == UC_STRING);

	while (true) {
		val = ucv_object_get(scope, ucv_string_get(name), &found);

		if (found)
			break;

		next = ucv_prototype_get(scope);

		if (!next) {
			if (uc_vm_is_strict(vm)) {
				uc_vm_raise_exception(vm, EXCEPTION_REFERENCE,
				                      "access to undeclared variable %s",
				                      ucv_string_get(name));
			}

			break;
		}

		scope = next;
	}

	val = uc_vm_value_arith(vm, vm->arg.u32 >> 24, val, inc);

	ucv_object_add(scope, ucv_string_get(name), ucv_get(val));
	uc_vm_stack_push(vm, val);

	ucv_put(name);
	ucv_put(inc);
}

static void
uc_vm_insn_update_val(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *inc = uc_vm_stack_pop(vm);
	uc_value_t *k = uc_vm_stack_pop(vm);
	uc_value_t *v = uc_vm_stack_pop(vm);
	uc_value_t *val = NULL;

	switch (ucv_type(v)) {
	case UC_OBJECT:
	case UC_ARRAY:
		val = uc_getval(vm, v, k);
		uc_vm_stack_push(vm, uc_setval(vm, v, k, uc_vm_value_arith(vm, vm->arg.u8, val, inc)));
		break;

	default:
		uc_vm_raise_exception(vm, EXCEPTION_REFERENCE,
		                      "left-hand side expression is %s",
		                      v ? "not an array or object" : "null");

		break;
	}

	ucv_put(val);
	ucv_put(inc);
	ucv_put(v);
	ucv_put(k);
}

static void
uc_vm_insn_update_upval(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_callframe_t *frame = uc_vm_current_frame(vm);
	size_t slot = vm->arg.u32 & 0x00FFFFFF;
	uc_upval_tref_t *ref = frame->closure->upvals[slot];
	uc_value_t *inc = uc_vm_stack_pop(vm);
	uc_value_t *val;

	if (ref->closed)
		val = ref->value;
	else
		val = vm->stack.entries[ref->slot];

	val = uc_vm_value_arith(vm, vm->arg.u32 >> 24, val, inc);

	uc_vm_stack_push(vm, val);

	ucv_put(inc);

	if (ref->closed) {
		ucv_put(ref->value);
		ref->value = ucv_get(uc_vm_stack_peek(vm, 0));
	}
	else {
		uc_vm_stack_set(vm, ref->slot, ucv_get(uc_vm_stack_peek(vm, 0)));
	}
}

static void
uc_vm_insn_update_local(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_callframe_t *frame = uc_vm_current_frame(vm);
	size_t slot = vm->arg.u32 & 0x00FFFFFF;
	uc_value_t *inc = uc_vm_stack_pop(vm);
	uc_value_t *val;

	val = uc_vm_value_arith(vm, vm->arg.u32 >> 24,
	                        vm->stack.entries[frame->stackframe + slot], inc);

	uc_vm_stack_push(vm, val);

	ucv_put(inc);
	uc_vm_stack_set(vm, frame->stackframe + slot, ucv_get(uc_vm_stack_peek(vm, 0)));
}

static void
uc_vm_insn_narr(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *arr = ucv_array_new_length(vm, vm->arg.u32);

	uc_vm_stack_push(vm, arr);
}

static void
uc_vm_insn_parr(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *arr = uc_vm_stack_peek(vm, vm->arg.u32);
	size_t idx;

	for (idx = 0; idx < vm->arg.u32; idx++)
		ucv_array_push(arr, uc_vm_stack_peek(vm, vm->arg.u32 - idx - 1));

	for (idx = 0; idx < vm->arg.u32; idx++)
		uc_vm_stack_pop(vm);

	//uc_vm_shrink(state, vm->arg.u32);
}

static void
uc_vm_insn_marr(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *src = uc_vm_stack_pop(vm);
	uc_value_t *dst = uc_vm_stack_peek(vm, 0);
	size_t i;
	char *s;

	if (ucv_type(src) != UC_ARRAY) {
		s = ucv_to_string(vm, src);
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "(%s) is not iterable", s);
		ucv_put(src);
		free(s);

		return;
	}

	for (i = 0; i < ucv_array_length(src); i++)
		ucv_array_push(dst, ucv_get(ucv_array_get(src, i)));

	ucv_put(src);
}

static void
uc_vm_insn_nobj(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *obj = ucv_object_new(vm);

	uc_vm_stack_push(vm, obj);
}

static void
uc_vm_insn_sobj(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *obj = uc_vm_stack_peek(vm, vm->arg.u32);
	uc_value_t *val;
	size_t idx;

	for (idx = 0; idx < vm->arg.u32; idx += 2) {
		val = uc_vm_stack_peek(vm, vm->arg.u32 - idx - 1);
		ucv_object_add(obj,
			ucv_string_get(val),
			ucv_get(uc_vm_stack_peek(vm, vm->arg.u32 - idx - 2)));
	}

	for (idx = 0; idx < vm->arg.u32; idx++)
		ucv_put(uc_vm_stack_pop(vm));
}

static void
uc_vm_insn_mobj(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *src = uc_vm_stack_pop(vm);
	uc_value_t *dst = uc_vm_stack_peek(vm, 0);
	size_t i;
	char *s;

	switch (ucv_type(src)) {
	case UC_OBJECT:
		; /* a label can only be part of a statement and a declaration is not a statement */
		ucv_object_foreach(src, k, v)
			ucv_object_add(dst, k, ucv_get(v));

		ucv_put(src);
		break;

	case json_type_array:
		for (i = 0; i < ucv_array_length(src); i++) {
			xasprintf(&s, "%zu", i);
			ucv_object_add(dst, s, ucv_get(ucv_array_get(src, i)));
			free(s);
		}

		ucv_put(src);
		break;

	default:
		s = ucv_to_string(vm, src);
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Value (%s) is not iterable", s);
		free(s);

		break;
	}
}

static void
uc_vm_insn_arith(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *r2 = uc_vm_stack_pop(vm);
	uc_value_t *r1 = uc_vm_stack_pop(vm);
	uc_value_t *rv;

	rv = uc_vm_value_arith(vm, insn, r1, r2);

	ucv_put(r1);
	ucv_put(r2);

	uc_vm_stack_push(vm, rv);
}

static void
uc_vm_insn_plus_minus(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *v = uc_vm_stack_pop(vm);
	bool is_sub = (insn == I_MINUS);
	uc_type_t t;
	int64_t n;
	double d;

	t = uc_cast_number(v, &n, &d);

	ucv_put(v);

	switch (t) {
	case UC_INTEGER:
		uc_vm_stack_push(vm, ucv_int64_new(is_sub ? -n : n));
		break;

	default:
		uc_vm_stack_push(vm, ucv_double_new(is_sub ? -d : d));
		break;
	}
}

static void
uc_vm_insn_bitop(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *r2 = uc_vm_stack_pop(vm);
	uc_value_t *r1 = uc_vm_stack_pop(vm);
	uc_value_t *rv;

	rv = uc_vm_value_bitop(vm, insn, r1, r2);

	ucv_put(r1);
	ucv_put(r2);

	uc_vm_stack_push(vm, rv);
}

static void
uc_vm_insn_complement(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *v = uc_vm_stack_pop(vm);
	int64_t n;
	double d;

	if (uc_cast_number(v, &n, &d) == UC_DOUBLE)
		n = isnan(d) ? 0 : (int64_t)d;

	ucv_put(v);

	uc_vm_stack_push(vm, ucv_int64_new(~n));
}

static void
uc_vm_insn_rel(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *r2 = uc_vm_stack_pop(vm);
	uc_value_t *r1 = uc_vm_stack_pop(vm);

	bool res = uc_cmp(insn, r1, r2);

	ucv_put(r1);
	ucv_put(r2);

	uc_vm_stack_push(vm, ucv_boolean_new(res));
}

static void
uc_vm_insn_in(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *r2 = uc_vm_stack_pop(vm);
	uc_value_t *r1 = uc_vm_stack_pop(vm);
	uc_value_t *item;
	size_t arrlen, arridx;
	bool found = false;
	char *key;

	switch (ucv_type(r2)) {
	case UC_ARRAY:
		for (arridx = 0, arrlen = ucv_array_length(r2);
		     arridx < arrlen; arridx++) {
			item = ucv_array_get(r2, arridx);

			if (uc_cmp(I_EQ, r1, item)) {
				found = true;
				break;
			}
		}

		break;

	case UC_OBJECT:
		if (ucv_type(r1) == UC_STRING) {
			ucv_object_get(r2, ucv_string_get(r1), &found);
		}
		else {
			key = ucv_to_string(vm, r1);
			ucv_object_get(r2, key, &found);
			free(key);
		}

		break;

	default:
		found = false;
	}

	ucv_put(r1);
	ucv_put(r2);

	uc_vm_stack_push(vm, ucv_boolean_new(found));
}

static void
uc_vm_insn_equality(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *r2 = uc_vm_stack_pop(vm);
	uc_value_t *r1 = uc_vm_stack_pop(vm);
	bool equal;

	if (ucv_is_scalar(r1) && ucv_is_scalar(r2))
		equal = ucv_equal(r1, r2);
	else
		equal = (r1 == r2);

	ucv_put(r1);
	ucv_put(r2);

	uc_vm_stack_push(vm, ucv_boolean_new((insn == I_EQS) ? equal : !equal));
}

static void
uc_vm_insn_not(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *r1 = uc_vm_stack_pop(vm);

	uc_vm_stack_push(vm, ucv_boolean_new(!uc_val_is_truish(r1)));
	ucv_put(r1);
}

static void
uc_vm_insn_jmp(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_callframe_t *frame = uc_vm_current_frame(vm);
	uc_chunk_t *chunk = uc_vm_frame_chunk(frame);
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
uc_vm_insn_jmpz(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_callframe_t *frame = uc_vm_current_frame(vm);
	uc_chunk_t *chunk = uc_vm_frame_chunk(frame);
	uc_value_t *v = uc_vm_stack_pop(vm);
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

	ucv_put(v);
}

static void
uc_vm_insn_next(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *k = uc_vm_stack_pop(vm);
	uc_value_t *v = uc_vm_stack_pop(vm);
	void *end = (void *)~(uintptr_t)0;
	uc_ressource_t *iterk;
	struct lh_entry *curr;
	uint64_t n;

	if (k != NULL && ucv_type(k) != UC_RESSOURCE) {
		fprintf(stderr, "Invalid iterator value\n");
		abort();
	}

	if (k == NULL)
		k = ucv_ressource_new(NULL, NULL);

	iterk = (uc_ressource_t *)k;

	switch (ucv_type(v)) {
	case UC_OBJECT:
		curr = iterk->data ? iterk->data : ((uc_object_t *)v)->table->head;

		if (curr != NULL && curr != end) {
			iterk->data = curr->next ? curr->next : end;

			uc_vm_stack_push(vm, ucv_string_new(curr->k));

			if (insn == I_NEXTKV)
				uc_vm_stack_push(vm, ucv_get((uc_value_t *)curr->v));

			uc_vm_stack_push(vm, k);
			ucv_put(v);

			return;
		}

		break;

	case UC_ARRAY:
		n = (uintptr_t)iterk->data;

		if (n < ucv_array_length(v)) {
			iterk->data = (void *)(uintptr_t)(n + 1);

			if (insn == I_NEXTKV)
				uc_vm_stack_push(vm, ucv_uint64_new(n));

			uc_vm_stack_push(vm, ucv_get(ucv_array_get(v, n)));

			uc_vm_stack_push(vm, k);
			ucv_put(v);

			return;
		}

		break;

	default:
		break;
	}

	uc_vm_stack_push(vm, NULL);
	uc_vm_stack_push(vm, NULL);

	if (insn == I_NEXTKV)
		uc_vm_stack_push(vm, NULL);

	ucv_put(k);
	ucv_put(v);
}

static void
uc_vm_insn_close_upval(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_vm_close_upvals(vm, vm->stack.count - 1);
	ucv_put(uc_vm_stack_pop(vm));
}

static void
uc_vm_insn_call(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *fno = ucv_get(uc_vm_stack_peek(vm, vm->arg.u32 & 0xffff));
	uc_value_t *ctx = NULL;

	if (!ucv_is_arrowfn(fno))
		ctx = NULL;
	else if (vm->callframes.count > 0)
		ctx = uc_vm_current_frame(vm)->ctx;

	uc_vm_call_function(vm, ucv_get(ctx), fno, false, vm->arg.u32);
}

static void
uc_vm_insn_mcall(uc_vm_t *vm, uc_vm_insn_t insn)
{
	size_t key_slot = vm->stack.count - (vm->arg.u32 & 0xffff) - 1;
	uc_value_t *ctx = vm->stack.entries[key_slot - 1];
	uc_value_t *key = vm->stack.entries[key_slot];
	uc_value_t *fno = uc_getval(vm, ctx, key);

	uc_vm_stack_set(vm, key_slot, fno);

	/* arrow functions as method calls inherit the parent ctx */
	if (ucv_is_arrowfn(fno))
		ctx = uc_vm_current_frame(vm)->ctx;

	uc_vm_call_function(vm, ucv_get(ctx), ucv_get(fno), true, vm->arg.u32);
}

static void
uc_vm_insn_print(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *v = uc_vm_stack_pop(vm);
	char *p;

	switch (ucv_type(v)) {
	case UC_OBJECT:
	case UC_ARRAY:
		p = ucv_to_jsonstring(vm, v);
		fwrite(p, 1, strlen(p), vm->output);
		free(p);
		break;

	case UC_STRING:
		fwrite(ucv_string_get(v), 1, ucv_string_length(v), vm->output);
		break;

	case UC_NULL:
		break;

	default:
		p = ucv_to_string(vm, v);
		fwrite(p, 1, strlen(p), vm->output);
		free(p);
	}

	ucv_put(v);
}

static void
uc_vm_insn_delete(uc_vm_t *vm, uc_vm_insn_t insn)
{
	uc_value_t *k = uc_vm_stack_pop(vm);
	uc_value_t *v = uc_vm_stack_pop(vm);
	bool rv;

	switch (ucv_type(v)) {
	case UC_OBJECT:
		rv = uc_delval(vm, v, k);
		uc_vm_stack_push(vm, ucv_boolean_new(rv));
		break;

	default:
		uc_vm_raise_exception(vm, EXCEPTION_REFERENCE,
		                      "left-hand side expression is %s",
		                      v ? "not an object" : "null");

		break;
	}

	ucv_put(k);
	ucv_put(v);
}

static uc_value_t *
uc_vm_callframe_pop(uc_vm_t *vm)
{
	uc_callframe_t *frame = uc_vm_current_frame(vm);
	uc_value_t *retval;

	/* close upvalues */
	uc_vm_close_upvals(vm, frame->stackframe);

	if (vm->stack.count > frame->stackframe)
		retval = uc_vm_stack_pop(vm);
	else
		retval = NULL;

	/* reset function stack frame */
	while (vm->stack.count > frame->stackframe)
		ucv_put(uc_vm_stack_pop(vm));

	/* for method calls, release context as well */
	if (frame->mcall)
		ucv_put(uc_vm_stack_pop(vm));

	/* release function */
	if (frame->closure)
		ucv_put(&frame->closure->header);

	if (frame->cfunction)
		ucv_put(&frame->cfunction->header);

	/* release context */
	ucv_put(frame->ctx);

	vm->callframes.count--;

	return retval;
}

static void
uc_vm_output_exception(uc_vm_t *vm, uc_exception_t *ex)
{
	uc_value_t *ctx;

	if (ex->type == EXCEPTION_USER)
		fprintf(stderr, "%s\n", ex->message);
	else
		fprintf(stderr, "%s: %s\n",
			    exception_type_strings[ex->type] ? exception_type_strings[ex->type] : "Error",
			    ex->message);

	ctx = ucv_object_get(ucv_array_get(ex->stacktrace, 0), "context", NULL);

	if (ctx)
		fprintf(stderr, "%s\n", ucv_string_get(ctx));

	fprintf(stderr, "\n");
}

static uc_vm_status_t
uc_vm_execute_chunk(uc_vm_t *vm, uc_value_t **retvalp)
{
	uc_callframe_t *frame = uc_vm_current_frame(vm);
	uc_chunk_t *chunk = uc_vm_frame_chunk(frame);
	uc_value_t *retval;
	uc_vm_insn_t insn;

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
			uc_vm_stack_push(vm, ucv_get(frame->ctx));
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
		case I_LE:
		case I_GT:
		case I_GE:
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
			uc_vm_stack_push(vm, ucv_get(uc_vm_stack_peek(vm, vm->arg.u8)));
			break;

		case I_POP:
			ucv_put(uc_vm_stack_pop(vm));
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
				if (retvalp)
					*retvalp = retval;
				else
					ucv_put(retval);

				return STATUS_OK;
			}

			uc_vm_stack_push(vm, retval);

			frame = uc_vector_last(&vm->callframes);
			chunk = uc_vm_frame_chunk(frame);
			break;

		case I_PRINT:
			uc_vm_insn_print(vm, insn);
			break;

		case I_DELETE:
			uc_vm_insn_delete(vm, insn);
			break;

		default:
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "unknown opcode %d", insn);
			break;
		}

		/* previous instruction raised exception */
		if (vm->exception.type != EXCEPTION_NONE) {
			/* VM termination was requested */
			if (vm->exception.type == EXCEPTION_EXIT) {
				uc_vm_reset_callframes(vm);

				if (retvalp)
					*retvalp = ucv_int64_new(vm->arg.s32);

				return STATUS_EXIT;
			}

			/* walk up callframes until something handles the exception or the root is reached */
			while (!uc_vm_handle_exception(vm)) {
				/* no further callframe to pop, report unhandled exception and terminate */
				if (vm->callframes.count <= 1) {
					if (vm->exhandler)
						vm->exhandler(vm, &vm->exception);

					return ERROR_RUNTIME;
				}

				/* if VM returned into native function, don't bubble up */
				if (!chunk)
					return ERROR_RUNTIME;

				/* no exception handler in current function, pop callframe */
				ucv_put(uc_vm_callframe_pop(vm));

				/* resume execution at topmost remaining callframe */
				frame = uc_vector_last(&vm->callframes);
				chunk = uc_vm_frame_chunk(frame);
			}
		}
	}

	return STATUS_OK;
}

uc_vm_status_t
uc_vm_execute(uc_vm_t *vm, uc_function_t *fn, uc_value_t **retval)
{
	uc_closure_t *closure = (uc_closure_t *)ucv_closure_new(vm, fn, false);
	uc_callframe_t *frame;
	uc_stringbuf_t *buf;

	uc_vector_grow(&vm->callframes);

	frame = &vm->callframes.entries[vm->callframes.count++];
	frame->closure = closure;
	frame->stackframe = 0;
	frame->ip = uc_vm_frame_chunk(frame)->entries;
	frame->strict = fn->strict;

	if (vm->trace) {
		buf = xprintbuf_new();

		format_source_context(buf, fn->source, 0, true);

		fwrite(buf->buf, 1, printbuf_length(buf), stderr);
		printbuf_free(buf);

		uc_vm_frame_dump(vm, frame);
	}

	//uc_vm_stack_push(vm, closure->header.jso);
	uc_vm_stack_push(vm, NULL);

	if (retval)
		*retval = NULL;

	return uc_vm_execute_chunk(vm, retval);
}

uc_exception_type_t
uc_vm_call(uc_vm_t *vm, bool mcall, size_t nargs)
{
	uc_value_t *ctx = mcall ? ucv_get(uc_vm_stack_peek(vm, nargs + 1)) : NULL;
	uc_value_t *fno = ucv_get(uc_vm_stack_peek(vm, nargs));

	if (uc_vm_call_function(vm, ctx, fno, mcall, nargs & 0xffff)) {
		if (ucv_type(fno) != UC_CFUNCTION)
			uc_vm_execute_chunk(vm, NULL);
	}

	return vm->exception.type;
}

uc_value_t *
uc_vm_scope_get(uc_vm_t *vm)
{
	return vm->globals;
}

void
uc_vm_scope_set(uc_vm_t *vm, uc_value_t *ctx)
{
	ucv_put(vm->globals);
	vm->globals = ctx;
}

uc_value_t *
uc_vm_invoke(uc_vm_t *vm, const char *fname, size_t nargs, ...)
{
	uc_exception_type_t ex;
	uc_value_t *fno, *arg;
	va_list ap;
	size_t i;

	fno = ucv_property_get(vm->globals, fname);

	if (!ucv_is_callable(fno))
		return NULL;

	uc_vm_stack_push(vm, ucv_get(fno));

	va_start(ap, nargs);

	for (i = 0; i < nargs; i++) {
		arg = va_arg(ap, uc_value_t *);
		uc_vm_stack_push(vm, ucv_get(arg));
	}

	va_end(ap);

	ex = uc_vm_call(vm, false, nargs);

	if (ex)
		return NULL;

	return uc_vm_stack_pop(vm);
}

uc_exception_handler_t *
uc_vm_exception_handler_get(uc_vm_t *vm)
{
	return vm->exhandler;
}

void
uc_vm_exception_handler_set(uc_vm_t *vm, uc_exception_handler_t *exhandler)
{
	vm->exhandler = exhandler;
}

uint32_t
uc_vm_trace_get(uc_vm_t *vm)
{
	return vm->trace;
}

void
uc_vm_trace_set(uc_vm_t *vm, uint32_t level)
{
	vm->trace = level;
}
