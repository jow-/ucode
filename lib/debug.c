/*
 * Copyright (C) 2023 Jo-Philipp Wich <jo@mein.io>
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

/**
 * # Debugger Module
 *
 * This module provides runtime debug functionality for ucode scripts.
 *
 * Functions can be individually imported and directly accessed using the
 * {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import#named_import named import}
 * syntax:
 *
 *   ```
 *   import { memdump, traceback } from 'debug';
 *
 *   let stacktrace = traceback(1);
 *
 *   memdump("/tmp/dump.txt");
 *   ```
 *
 * Alternatively, the module namespace can be imported
 * using a wildcard import statement:
 *
 *   ```
 *   import * as debug from 'debug';
 *
 *   let stacktrace = debug.traceback(1);
 *
 *   debug.memdump("/tmp/dump.txt");
 *   ```
 *
 * Additionally, the debug module namespace may also be imported by invoking the
 * `ucode` interpreter with the `-ldebug` switch.
 *
 * Upon loading, the `debug` module will register a `SIGUSR2` signal handler
 * which, upon receipt of the signal, will write a memory dump of the currently
 * running program to `/tmp/ucode.$timestamp.$pid.memdump`. This default
 * behavior can be inhibited by setting the `UCODE_DEBUG_MEMDUMP_ENABLED`
 * environment variable to `0` when starting the process. The memory dump signal
 * and output directory can be overridden with the `UCODE_DEBUG_MEMDUMP_SIGNAL`
 * and `UCODE_DEBUG_MEMDUMP_PATH` environment variables respectively.
 *
 * @module debug
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>

#ifdef HAVE_ULOOP
#include <libubox/uloop.h>
#endif

#include <json-c/printbuf.h>
#include <json-c/linkhash.h>

#include "ucode/module.h"
#include "ucode/platform.h"


static char *memdump_signal = "USR2";
static char *memdump_directory = "/tmp";

struct memdump_walk_ctx {
	FILE *out;
	uc_closure_t *current_closure;
	struct lh_table *seen;
};

static uc_callframe_t *
debuginfo_stackslot_to_callframe(uc_vm_t *vm, size_t slot)
{
	size_t stackframe, i;

	for (i = vm->callframes.count; i > 0; i--) {
		stackframe = vm->callframes.entries[i - 1].stackframe;

		if (vm->callframes.entries[i - 1].mcall)
			stackframe--;

		if (stackframe <= slot)
			return &vm->callframes.entries[i - 1];
	}

	return NULL;
}

static void
uc_debug_discover_ucv(uc_value_t *uv, struct lh_table *seen);

static void
uc_debug_discover_ucv(uc_value_t *uv, struct lh_table *seen)
{
	uc_function_t *function;
	uc_closure_t *closure;
	uc_upvalref_t *upval;
	uc_object_t *object;
	uc_array_t *array;
	uc_resource_type_t *restype;
	uc_program_t *program;
	struct lh_entry *entry;
	unsigned long hash;
	size_t i;

	hash = lh_get_hash(seen, uv);

	if (ucv_is_scalar(uv))
		return;

	if (lh_table_lookup_entry_w_hash(seen, uv, hash))
		return;

	lh_table_insert_w_hash(seen, uv, NULL, hash, 0);

	switch (ucv_type(uv)) {
	case UC_ARRAY:
		array = (uc_array_t *)uv;

		uc_debug_discover_ucv(array->proto, seen);

		for (i = 0; i < array->count; i++)
			uc_debug_discover_ucv(array->entries[i], seen);

		break;

	case UC_OBJECT:
		object = (uc_object_t *)uv;

		uc_debug_discover_ucv(object->proto, seen);

		lh_foreach(object->table, entry)
			uc_debug_discover_ucv((uc_value_t *)lh_entry_v(entry), seen);

		break;

	case UC_CLOSURE:
		closure = (uc_closure_t *)uv;
		function = closure->function;

		for (i = 0; i < function->nupvals; i++)
			uc_debug_discover_ucv(&closure->upvals[i]->header, seen);

		uc_debug_discover_ucv(&function->program->header, seen);

		break;

	case UC_UPVALUE:
		upval = (uc_upvalref_t *)uv;
		uc_debug_discover_ucv(upval->value, seen);
		break;

	case UC_RESOURCE:
		restype = ucv_resource_type(uv);

		if (restype)
			uc_debug_discover_ucv(restype->proto, seen);

		break;

	case UC_PROGRAM:
		program = (uc_program_t *)uv;

		for (i = 0; i < program->sources.count; i++)
			uc_debug_discover_ucv(&program->sources.entries[i]->header, seen);

		for (i = 0; i < program->exports.count; i++)
			uc_debug_discover_ucv(&program->exports.entries[i]->header, seen);

		break;

	default:
		break;
	}
}

static void
print_value(FILE *out, size_t pad, struct lh_table *seen,
            uc_vm_t *vm, uc_value_t *uv);

static void
print_value(FILE *out, size_t pad, struct lh_table *seen,
            uc_vm_t *vm, uc_value_t *uv)
{
	uc_resource_type_t *restype;
	uc_closure_t *closure;
	uc_object_t *object;
	uc_array_t *array;
	size_t i, j;
	char *s;

	fprintf(out, "%s", ucv_typename(uv));

	if (!uv) {
		fprintf(out, "\n");

		return;
	}

	if (!ucv_is_scalar(uv))
		fprintf(out, "; %" PRIu32 " refs", uv->refcount);

	if (!lh_table_lookup_entry(seen, uv))
		fprintf(out, "; unreachable");

	if (ucv_is_constant(uv))
		fprintf(out, "; constant");

	fprintf(out, "\n");

	for (j = 0; j < pad + 1; j++)
		fprintf(out, "  ");

	s = ucv_to_string(NULL, uv);
	fprintf(out, "#value = %s\n", s);
	free(s);

	if (ucv_type(uv) == UC_CLOSURE) {
		closure = (uc_closure_t *)uv;

		for (i = 0; i < closure->function->nupvals; i++) {
			for (j = 0; j < pad + 1; j++)
				fprintf(out, "  ");

			fprintf(out, "#upvalue[%zu] ", i);

			if (closure->upvals[i]->closed) {
				fprintf(out, "closed; ");
				print_value(out, pad + 1, seen, vm, closure->upvals[i]->value);
			}
			else {
				fprintf(out, "open; stack slot %zu\n",
					closure->upvals[i]->slot);
			}
		}
	}
	else if (ucv_type(uv) == UC_OBJECT) {
		object = (uc_object_t *)uv;

		if (object->proto) {
			for (j = 0; j < pad + 1; j++)
				fprintf(out, "  ");

			fprintf(out, "#prototype = ");
			print_value(out, pad + 1, seen, vm, object->proto);
		}
	}
	else if (ucv_type(uv) == UC_ARRAY) {
		array = (uc_array_t *)uv;

		if (array->proto) {
			for (j = 0; j < pad + 1; j++)
				fprintf(out, "  ");

			fprintf(out, "#prototype = ");
			print_value(out, pad + 1, seen, vm, array->proto);
		}
	}
	else if (ucv_type(uv) == UC_RESOURCE) {
		restype = ucv_resource_type(uv);

		if (restype) {
			for (j = 0; j < pad + 1; j++)
				fprintf(out, "  ");

			fprintf(out, "#type %s\n", restype->name);

			if (restype->proto) {
				for (j = 0; j < pad + 2; j++)
					fprintf(out, "  ");

				fprintf(out, "#prototype = ");
				print_value(out, pad + 2, seen, vm, restype->proto);
			}
		}
	}
}

static size_t
insnoff_to_srcpos(uc_function_t *function, size_t *insnoff)
{
	size_t byteoff, lineno;
	uc_source_t *source;

	source = uc_program_function_source(function);
	byteoff = uc_program_function_srcpos(function, *insnoff);
	lineno = uc_source_get_line(source, &byteoff);

	*insnoff = byteoff;

	return lineno;
}

static void
print_declaration_srcpos(FILE *out, uc_callframe_t *frame, size_t off, size_t slot, bool upval)
{
	uc_function_t *function = frame->closure->function;
	uc_variables_t *variables = &function->chunk.debuginfo.variables;
	size_t i, line;

	assert(slot <= ((size_t)-1 / 2));

	if (upval)
		slot += (size_t)-1 / 2;

	for (i = 0; i < variables->count; i++) {
		if (variables->entries[i].slot != slot ||
		    variables->entries[i].from > off ||
		    variables->entries[i].to < off)
			continue;

		off = variables->entries[i].from;
		line = insnoff_to_srcpos(function, &off);

		fprintf(out, "%s:%zu:%zu",
			uc_program_function_source(function)->filename, line, off);

		return;
	}

	fprintf(out, "[unknown source position]");
}

static void
print_function_srcpos(FILE *out, uc_closure_t *closure)
{
	size_t line, off;

	if (!closure)
		return;

	off = 0;
	line = insnoff_to_srcpos(closure->function, &off);

	fprintf(out, " @ %s:%zu:%zu",
		uc_program_function_source(closure->function)->filename, line, off);
}

static void
print_ip_srcpos(FILE *out, uc_callframe_t *frame)
{
	uc_function_t *function;
	size_t line, off;

	if (!frame->closure)
		return;

	function = frame->closure->function;
	off = frame->ip - function->chunk.entries;
	line = insnoff_to_srcpos(function, &off);

	fprintf(out, " @ %s:%zu:%zu",
		uc_program_function_source(function)->filename, line, off);
}

static void
print_memdump(uc_vm_t *vm, FILE *out)
{
	struct memdump_walk_ctx ctx = { 0 };
	uc_callframe_t *frame;
	uc_chunk_t *chunk;
	uc_weakref_t *ref;
	uc_value_t *uv;
	size_t i;
	char *s;

	ctx.out = out;
	ctx.seen = lh_kptr_table_new(16, NULL);

	if (!ctx.seen) {
		fprintf(stderr, "Unable to allocate lookup table: %m\n");

		return;
	}

	fprintf(ctx.out, "STACK\n");

	for (i = 0; i < vm->stack.count; i++) {
		fprintf(ctx.out, "[%zu]", i);

		frame = debuginfo_stackslot_to_callframe(vm, i);

		if (frame) {
			chunk = frame->closure ? &frame->closure->function->chunk : NULL;
			uv = chunk ? uc_chunk_debug_get_variable(
				chunk,
				frame->ip - chunk->entries + 1,
				i - frame->stackframe,
				false) : NULL;

			if (uv) {
				fprintf(ctx.out, " %s @ ",
					ucv_string_get(uv));

				print_declaration_srcpos(ctx.out, frame,
					frame->ip - chunk->entries + 1,
					i - frame->stackframe, false);

				ucv_put(uv);
			}
			else if (frame->mcall && i == frame->stackframe - 1) {
				fprintf(ctx.out, " (this)");

				if (frame->closure)
					print_function_srcpos(ctx.out, frame->closure);
				else
					fprintf(ctx.out, " @ [C function \"%s\"]",
						frame->cfunction->name);
			}
			else if (i == frame->stackframe) {
				fprintf(ctx.out, " (callee)");

				if (frame->closure)
					print_function_srcpos(ctx.out, frame->closure);
				else
					fprintf(ctx.out, " @ [C function \"%s\"]",
						frame->cfunction->name);
			}
			else if (i > frame->stackframe) {
				fprintf(ctx.out, " (argument #%zu)",
					i - frame->stackframe);

				if (frame->closure)
					print_function_srcpos(ctx.out, frame->closure);
				else
					fprintf(ctx.out, " @ [C function \"%s\"]",
						frame->cfunction->name);
			}
		}

		fprintf(ctx.out, "\n");

		uc_debug_discover_ucv(vm->stack.entries[i], ctx.seen);

		s = ucv_to_string(NULL, vm->stack.entries[i]);
		fprintf(ctx.out, "  #value = %s\n", s);
		free(s);
	}

	fprintf(ctx.out, "---\n\n");

	fprintf(ctx.out, "CALLFRAMES\n");

	for (i = 0; i < vm->callframes.count; i++) {
		fprintf(ctx.out, "[%zu]", i);
		print_ip_srcpos(ctx.out, &vm->callframes.entries[i]);
		fprintf(ctx.out, "\n");

		uc_debug_discover_ucv(vm->callframes.entries[i].ctx,
			ctx.seen);

		uc_debug_discover_ucv(&vm->callframes.entries[i].closure->header,
			ctx.seen);

		uc_debug_discover_ucv(&vm->callframes.entries[i].cfunction->header,
			ctx.seen);

		s = ucv_to_string(NULL, vm->callframes.entries[i].ctx);
		fprintf(ctx.out, "  #context = %s\n", s);
		free(s);

		if (vm->callframes.entries[i].closure) {
			s = ucv_to_string(NULL,
				&vm->callframes.entries[i].closure->header);
			fprintf(ctx.out, "  #closure = %s\n", s);
			free(s);
		}

		if (vm->callframes.entries[i].cfunction) {
			s = ucv_to_string(NULL,
				&vm->callframes.entries[i].cfunction->header);

			fprintf(ctx.out, "  #cfunction = %s\n", s);
			free(s);
		}
	}

	fprintf(ctx.out, "---\n\n");

	fprintf(ctx.out, "GLOBALS\n");
	uc_debug_discover_ucv(vm->globals, ctx.seen);
	i = 0;
	ucv_object_foreach(vm->globals, gk, gv) {
		s = ucv_to_string(NULL, gv);
		fprintf(ctx.out, "[%zu] %s\n", i++, gk);
		fprintf(ctx.out, "  #value = %s\n", s);
		free(s);
	}
	fprintf(ctx.out, "---\n\n");

	fprintf(ctx.out, "REGISTRY\n");
	uc_debug_discover_ucv(vm->registry, ctx.seen);
	i = 0;
	ucv_object_foreach(vm->registry, rk, rv) {
		s = ucv_to_string(NULL, rv);
		fprintf(ctx.out, "[%zu] %s\n", i++, rk);
		fprintf(ctx.out, "  #value = %s\n", s);
		free(s);
	}
	fprintf(ctx.out, "---\n\n");

	fprintf(ctx.out, "EXCEPTION\n");
	uc_debug_discover_ucv(vm->exception.stacktrace, ctx.seen);
	s = ucv_to_string(NULL, vm->exception.stacktrace);
	fprintf(ctx.out, "%s\n", s);
	free(s);
	fprintf(ctx.out, "---\n\n");

	fprintf(ctx.out, "RESOURCE TYPES\n");

	for (i = 0; i < vm->restypes.count; i++) {
		fprintf(ctx.out, "[%zu] %s\n", i,
			vm->restypes.entries[i]->name);

		uc_debug_discover_ucv(vm->restypes.entries[i]->proto, ctx.seen);

		s = ucv_to_string(NULL, vm->restypes.entries[i]->proto);
		fprintf(ctx.out, "  #prototype = %s\n", s);
		free(s);
	}

	fprintf(ctx.out, "---\n\n");

	fprintf(ctx.out, "OBJECT POOL\n");

	for (ref = vm->values.next, i = 0;
	     ref != &vm->values;
	     ref = ref->next, i++) {

		uv = (uc_value_t *)((uintptr_t)ref - offsetof(uc_array_t, ref));

		fprintf(ctx.out, "[%zu] ", i);
		print_value(ctx.out, 0, ctx.seen, vm, uv);
	}

	lh_table_free(ctx.seen);
}

static uc_value_t *
debug_handle_memdump(uc_vm_t *vm, size_t nargs)
{
	char *path;
	FILE *out;

	xasprintf(&path, "%s/ucode.%llu.%llu.memdump",
		memdump_directory,
		(long long unsigned int)time(NULL),
		(long long unsigned int)getpid());

	out = fopen(path, "w");

	if (!out) {
		fprintf(stderr, "Unable to open memdump file '%s': %m\n", path);

		return NULL;
	}

	print_memdump(vm, out);

	fclose(out);
	free(path);

	return NULL;
}

#ifdef HAVE_ULOOP
/* The uloop signal handling activation has been intentionally copied from
   the uloop module here to ensure that uloop signal dispatching also works
   when just loading the debug module without the uloop one. */
static struct {
	struct uloop_fd ufd;
	uc_vm_t *vm;
} signal_handle;

static void
uc_uloop_signal_cb(struct uloop_fd *ufd, unsigned int events)
{
	if (uc_vm_signal_dispatch(signal_handle.vm) != EXCEPTION_NONE)
		uloop_end();
}

static void
debug_setup_uloop(uc_vm_t *vm)
{
	int signal_fd = uc_vm_signal_notifyfd(vm);

	if (signal_fd != -1 && uloop_init() == 0) {
		signal_handle.vm = vm;
		signal_handle.ufd.cb = uc_uloop_signal_cb;
		signal_handle.ufd.fd = signal_fd;

		uloop_fd_add(&signal_handle.ufd, ULOOP_READ);
	}
}
#else
static void debug_setup_uloop(uc_vm_t *vm) {}
#endif

static void
debug_setup_memdump(uc_vm_t *vm)
{
	uc_cfn_ptr_t ucsignal = uc_stdlib_function("signal");
	uc_value_t *memdump = ucv_cfunction_new("memdump", debug_handle_memdump);
	char *ev;

	ev = getenv("UCODE_DEBUG_MEMDUMP_PATH");
	memdump_directory = ev ? ev : memdump_directory;

	ev = getenv("UCODE_DEBUG_MEMDUMP_SIGNAL");
	memdump_signal = ev ? ev : memdump_signal;

	debug_setup_uloop(vm);

	uc_vm_stack_push(vm, ucv_string_new(memdump_signal));
	uc_vm_stack_push(vm, memdump);

	if (ucsignal(vm, 2) != memdump)
		fprintf(stderr, "Unable to install debug signal handler\n");

	ucv_put(uc_vm_stack_pop(vm));
	ucv_put(uc_vm_stack_pop(vm));
}

static void
debug_setup(uc_vm_t *vm)
{
	char *ev;

	ev = getenv("UCODE_DEBUG_MEMDUMP_ENABLED");

	if (!ev || !strcmp(ev, "1") || !strcmp(ev, "yes") || !strcmp(ev, "true"))
		debug_setup_memdump(vm);
}


/**
 * Write a memory dump report to the given file.
 *
 * This function generates a human readable memory dump of ucode values
 * currently managed by the running VM which is useful to track down logical
 * memory leaks in scripts.
 *
 * The file parameter can be either a string value containing a file path, in
 * which case this function tries to create and write the report file at the
 * given location, or an already open file handle this function should write to.
 *
 * Returns `true` if the report has been written.
 *
 * Returns `null` if the file could not be opened or if the handle was invalid.
 *
 * @function module:debug#memdump
 *
 * @param {string|module:fs.file|module:fs.proc} file
 * The file path or open file handle to write report to.
 *
 * @return {?boolean}
 */
static uc_value_t *
uc_memdump(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *file = uc_fn_arg(0);
	FILE *fp = NULL;

	if (ucv_type(file) == UC_RESOURCE) {
		fp = ucv_resource_data(file, "fs.file");

		if (!fp)
			fp = ucv_resource_data(file, "fs.proc");
	}
	else if (ucv_type(file) == UC_STRING) {
		fp = fopen(ucv_string_get(file), "w");
	}

	if (!fp)
		return NULL;

	print_memdump(vm, fp);

	return ucv_boolean_new(true);
}

/**
 * Capture call stack trace.
 *
 * This function captures the current call stack and returns it. The optional
 * level parameter controls how many calls up the trace should start. It
 * defaults to `1`, that is the function calling this `traceback()` function.
 *
 * Returns an array of stack trace entries describing the function invocations
 * up to the point where `traceback()` is called.
 *
 * @function module:debug#traceback
 *
 * @param {number} [level=1]
 * The number of callframes up the call trace should start, `0` is this function
 * itself, `1` the function calling it and so on.
 *
 * @return {module:debug.StackTraceEntry[]}
 */

/**
 * @typedef {Object} module:debug.StackTraceEntry
 *
 * @property {function} callee
 * The function that was called.
 *
 * @property {*} this
 * The `this` context the function was called with.
 *
 * @property {boolean} mcall
 * Indicates whether the function was invoked as a method.
 *
 * @property {boolean} [strict]
 * Indicates whether the VM was running in strict mode when the function was
 * called (only applicable to non-C, pure ucode calls).
 *
 * @property {string} [filename]
 * The name of the source file that called the function (only applicable to
 * non-C, pure ucode calls).
 *
 * @property {number} [line]
 * The source line of the function call (only applicable to non-C, pure ucode
 * calls).
 *
 * @property {number} [byte]
 * The source line offset of the function call (only applicable to non-C, pure
 * ucode calls).
 *
 * @property {string} [context]
 * The surrounding source code context formatted as human-readable string,
 * useful for generating debug messages (only applicable to non-C, pure ucode
 * calls).
 */

static uc_value_t *
uc_traceback(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *stacktrace, *entry, *level = uc_fn_arg(0);
	uc_function_t *function;
	uc_stringbuf_t *context;
	uc_callframe_t *frame;
	uc_source_t *source;
	size_t off, srcpos;
	size_t i, lv;

	lv = level ? ucv_uint64_get(level) : 1;

	if (level && errno)
		return NULL;

	stacktrace = ucv_array_new(vm);

	for (i = (lv < vm->callframes.count) ? vm->callframes.count - lv : 0;
	     i > 0;
	     i--) {

		frame = &vm->callframes.entries[i - 1];
		entry = ucv_object_new(vm);

		if (frame->closure) {
			function = frame->closure->function;
			source = uc_program_function_source(function);

			off = (frame->ip - function->chunk.entries) - 1;
			srcpos = uc_program_function_srcpos(function, off);

			context = ucv_stringbuf_new();

			uc_source_context_format(context,
				uc_program_function_source(function),
				srcpos, false);

			ucv_object_add(entry, "callee", ucv_get(&frame->closure->header));
			ucv_object_add(entry, "this", ucv_get(frame->ctx));
			ucv_object_add(entry, "mcall", ucv_boolean_new(frame->mcall));
			ucv_object_add(entry, "strict", ucv_boolean_new(frame->strict));
			ucv_object_add(entry, "filename", ucv_string_new(source->filename));
			ucv_object_add(entry, "line", ucv_int64_new(uc_source_get_line(source, &srcpos)));
			ucv_object_add(entry, "byte", ucv_int64_new(srcpos));
			ucv_object_add(entry, "context", ucv_stringbuf_finish(context));
		}
		else if (frame->cfunction) {
			ucv_object_add(entry, "callee", ucv_get(&frame->cfunction->header));
			ucv_object_add(entry, "this", ucv_get(frame->ctx));
			ucv_object_add(entry, "mcall", ucv_boolean_new(frame->mcall));
		}

		ucv_array_push(stacktrace, entry);
	}

	return stacktrace;
}

/**
 * Obtain information about the current source position.
 *
 * The `sourcepos()` function determines the source code position of the
 * current instruction invoking this function.
 *
 * Returns a dictionary containing the filename, line number and line byte
 * offset of the call site.
 *
 * Returns `null` if this function was invoked from C code.
 *
 * @function module:debug#sourcepos
 *
 * @return {?module:debug.SourcePosition}
 */

/**
 * @typedef {Object} module:debug.SourcePosition
 *
 * @property {string} filename
 * The name of the source file that called this function.
 *
 * @property {number} line
 * The source line of the function call.
 *
 * @property {number} byte
 * The source line offset of the function call.
 */

static uc_value_t *
uc_sourcepos(uc_vm_t *vm, size_t nargs)
{
	uc_function_t *function;
	uc_callframe_t *frame;
	uc_source_t *source;
	uc_value_t *rv;
	size_t byte;

	if (vm->callframes.count < 2)
		return NULL;

	frame = &vm->callframes.entries[vm->callframes.count - 2];

	if (!frame->closure)
		return NULL;

	function = frame->closure->function;
	source = uc_program_function_source(function);
	byte = uc_program_function_srcpos(function,
		(frame->ip - function->chunk.entries) - 1);

	rv = ucv_object_new(vm);

	ucv_object_add(rv, "filename", ucv_string_new(source->filename));
	ucv_object_add(rv, "line", ucv_int64_new(uc_source_get_line(source, &byte)));
	ucv_object_add(rv, "byte", ucv_int64_new(byte));

	return rv;
}

static uc_value_t *
uc_getinfo_fnargs(uc_vm_t *vm, uc_function_t *function)
{
	uc_value_t *rv = NULL, *name;
	size_t i;

	for (i = 0; i < function->nargs; i++) {
		name = uc_chunk_debug_get_variable(&function->chunk, i, i + 1, false);

		if (!name)
			continue;

		if (!rv)
			rv = ucv_array_new_length(vm, function->nargs);

		ucv_array_push(rv, name);
	}

	return rv;
}

/**
 * @typedef {Object} module:debug.UpvalRef
 *
 * @property {string} name
 * The name of the captured variable.
 *
 * @property {boolean} closed
 * Indicates whether the captured variable (upvalue) is closed or not. A closed
 * upvalue means that the function value outlived the declaration scope of the
 * captured variable.
 *
 * @property {*} value
 * The current value of the captured variable.
 *
 * @property {number} [slot]
 * The stack slot of the captured variable. Only applicable to open (non-closed)
 * captured variables.
 */
static uc_value_t *
uc_getinfo_upvals(uc_vm_t *vm, uc_closure_t *closure)
{
	uc_function_t *function = closure->function;
	uc_upvalref_t **upvals = closure->upvals;
	uc_value_t *rv = NULL, *up, *name;
	size_t i;

	for (i = 0; i < function->nupvals; i++) {
		up = ucv_object_new(vm);
		name = uc_chunk_debug_get_variable(&function->chunk, 0, i, true);

		if (name)
			ucv_object_add(up, "name", name);

		if (upvals[i]->closed) {
			ucv_object_add(up, "closed", ucv_boolean_new(true));
			ucv_object_add(up, "value", ucv_get(upvals[i]->value));
		}
		else {
			ucv_object_add(up, "closed", ucv_boolean_new(false));
			ucv_object_add(up, "slot", ucv_uint64_new(upvals[i]->slot));
			ucv_object_add(up, "value",
				ucv_get(vm->stack.entries[upvals[i]->slot]));
		}

		if (!rv)
			rv = ucv_array_new_length(vm, function->nupvals);

		ucv_array_push(rv, up);
	}

	return rv;
}

/**
 * Obtain information about the given value.
 *
 * The `getinfo()` function allows querying internal information about the
 * given ucode value, such as the current reference count, the mark bit state
 * etc.
 *
 * Returns a dictionary with value type specific details.
 *
 * Returns `null` if a `null` value was provided.
 *
 * @function module:debug#getinfo
 *
 * @param {*} value
 * The value to query information for.
 *
 * @return {?module:debug.ValueInformation}
 */

/**
 * @typedef {Object} module:debug.ValueInformation
 *
 * @property {string} type
 * The name of the value type, one of `integer`, `boolean`, `string`, `double`,
 * `array`, `object`, `regexp`, `cfunction`, `closure`, `upvalue` or `resource`.
 *
 * @property {*} value
 * The value itself.
 *
 * @property {boolean} tagged
 * Indicates whether the given value is internally stored as tagged pointer
 * without an additional heap allocation.
 *
 * @property {boolean} [mark]
 * Indicates whether the value has it's mark bit set, which is used for loop
 * detection during recursive object traversal on garbage collection cycles or
 * complex value stringification. Only applicable to non-tagged values.
 *
 * @property {number} [refcount]
 * The current reference count of the value. Note that the `getinfo()` function
 * places a reference to the value into the `value` field of the resulting
 * information dictionary, so the ref count will always be at least 2 - one
 * reference for the function call argument and one for the value property in
 * the result dictionary. Only applicable to non-tagged values.
 *
 * @property {boolean} [unsigned]
 * Whether the number value is internally stored as unsigned integer. Only
 * applicable to non-tagged integer values.
 *
 * @property {number} [address]
 * The address of the underlying C heap memory. Only applicable to non-tagged
 * `string`, `array`, `object`, `cfunction` or `resource` values.
 *
 * @property {number} [length]
 * The length of the underlying string memory. Only applicable to non-tagged
 * `string` values.
 *
 * @property {number} [count]
 * The amount of elements in the underlying memory structure. Only applicable to
 * `array` and `object` values.
 *
 * @property {boolean} [constant]
 * Indicates whether the value is constant (immutable). Only applicable to
 * `array` and `object` values.
 *
 * @property {*} [prototype]
 * The associated prototype value, if any. Only applicable to `array`, `object`
 * and `prototype` values.
 *
 * @property {string} [source]
 * The original regex source pattern. Only applicable to `regexp` values.
 *
 * @property {boolean} [icase]
 * Whether the compiled regex has the `i` (ignore case) flag set. Only
 * applicable to `regexp` values.
 *
 * @property {boolean} [global]
 * Whether the compiled regex has the `g` (global) flag set. Only applicable to
 * `regexp` values.
 *
 * @property {boolean} [newline]
 * Whether the compiled regex has the `s` (single line) flag set. Only
 * applicable to `regexp` values.
 *
 * @property {number} [nsub]
 * The amount of capture groups within the regular expression. Only applicable
 * to `regexp` values.
 *
 * @property {string} [name]
 * The name of the non-anonymous function. Only applicable to `cfunction` and
 * `closure` values. Set to `null` for anonymous function values.
 *
 * @property {boolean} [arrow]
 * Indicates whether the ucode function value is an arrow function. Only
 * applicable to `closure` values.
 *
 * @property {boolean} [module]
 * Indicates whether the ucode function value is a module entry point. Only
 * applicable to `closure` values.
 *
 * @property {boolean} [strict]
 * Indicates whether the function body will be executed in strict mode. Only
 * applicable to `closure` values.
 *
 * @property {boolean} [vararg]
 * Indicates whether the ucode function takes a variable number of arguments.
 * Only applicable to `closure` values.
 *
 * @property {number} [nargs]
 * The number of arguments expected by the ucode function, excluding a potential
 * final variable argument ellipsis. Only applicable to `closure` values.
 *
 * @property {string[]} [argnames]
 * The names of the function arguments in their declaration order. Only
 * applicable to `closure` values.
 *
 * @property {number} [nupvals]
 * The number of upvalues associated with the ucode function. Only applicable to
 * `closure` values.
 *
 * @property {module:debug.UpvalRef[]} [upvals]
 * An array of upvalue information objects. Only applicable to `closure` values.
 *
 * @property {string} [filename]
 * The path of the source file the function was declared in. Only applicable to
 * `closure` values.
 *
 * @property {number} [line]
 * The source line number the function was declared at. Only applicable to
 * `closure` values.
 *
 * @property {number} [byte]
 * The source line offset the function was declared at. Only applicable to
 * `closure` values.
 *
 * @property {string} [type]
 * The resource type name. Only applicable to `resource` values.
 */

static uc_value_t *
uc_getinfo(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *uv = uc_fn_arg(0), *rv;
	uintptr_t pv = (uintptr_t)uv;
	uc_cfunction_t *uvcfn;
	uc_resource_t *uvres;
	uc_closure_t *uvfun;
	uc_source_t *source;
	uc_regexp_t *uvreg;
	uc_string_t *uvstr;
	uc_object_t *uvobj;
	uc_array_t *uvarr;
	size_t byte;

	if (!uv)
		return NULL;

	rv = ucv_object_new(vm);

	ucv_object_add(rv, "type", ucv_string_new(ucv_typename(uv)));
	ucv_object_add(rv, "value", ucv_get(uv));

	if (pv & 3) {
		ucv_object_add(rv, "tagged", ucv_boolean_new(true));
	}
	else {
		ucv_object_add(rv, "tagged", ucv_boolean_new(false));
		ucv_object_add(rv, "mark", ucv_boolean_new(uv->mark));
		ucv_object_add(rv, "refcount", ucv_uint64_new(uv->refcount));
	}

	switch (ucv_type(uv)) {
	case UC_INTEGER:
		ucv_object_add(rv, "unsigned",
			ucv_boolean_new(!(pv & 3) && uv->ext_flag));

		break;

	case UC_STRING:
		if (!(pv & 3)) {
			uvstr = (uc_string_t *)uv;

			ucv_object_add(rv, "address",
				ucv_uint64_new((uintptr_t)uvstr->str));

			ucv_object_add(rv, "length", ucv_uint64_new(uvstr->length));
		}

		break;

	case UC_ARRAY:
		uvarr = (uc_array_t *)uv;

		ucv_object_add(rv, "address",
			ucv_uint64_new((uintptr_t)uvarr->entries));

		ucv_object_add(rv, "count", ucv_uint64_new(uvarr->count));
		ucv_object_add(rv, "constant", ucv_boolean_new(uv->ext_flag));
		ucv_object_add(rv, "prototype", ucv_get(uvarr->proto));

		break;

	case UC_OBJECT:
		uvobj = (uc_object_t *)uv;

		ucv_object_add(rv, "address",
			ucv_uint64_new((uintptr_t)uvobj->table));

		ucv_object_add(rv, "count",
			ucv_uint64_new(lh_table_length(uvobj->table)));

		ucv_object_add(rv, "constant", ucv_boolean_new(uv->ext_flag));
		ucv_object_add(rv, "prototype", ucv_get(uvobj->proto));

		break;

	case UC_REGEXP:
		uvreg = (uc_regexp_t *)uv;

		ucv_object_add(rv, "source", ucv_string_new(uvreg->source));
		ucv_object_add(rv, "icase", ucv_boolean_new(uvreg->icase));
		ucv_object_add(rv, "global", ucv_boolean_new(uvreg->global));
		ucv_object_add(rv, "newline", ucv_boolean_new(uvreg->newline));
		ucv_object_add(rv, "nsub", ucv_uint64_new(uvreg->regexp.re_nsub));

		break;

	case UC_CFUNCTION:
		uvcfn = (uc_cfunction_t *)uv;

		ucv_object_add(rv, "name", ucv_string_new(uvcfn->name));
		ucv_object_add(rv, "address", ucv_uint64_new((uintptr_t)uvcfn->cfn));

		break;

	case UC_CLOSURE:
		uvfun = (uc_closure_t *)uv;
		byte = uvfun->function->srcpos;
		source = uc_program_function_source(uvfun->function);

		ucv_object_add(rv, "name", ucv_string_new(uvfun->function->name));
		ucv_object_add(rv, "arrow", ucv_boolean_new(uvfun->function->arrow));
		ucv_object_add(rv, "module", ucv_boolean_new(uvfun->function->module));
		ucv_object_add(rv, "strict", ucv_boolean_new(uvfun->function->strict));
		ucv_object_add(rv, "vararg", ucv_boolean_new(uvfun->function->vararg));
		ucv_object_add(rv, "nargs", ucv_uint64_new(uvfun->function->nargs));
		ucv_object_add(rv, "argnames", uc_getinfo_fnargs(vm, uvfun->function));
		ucv_object_add(rv, "nupvals", ucv_uint64_new(uvfun->function->nupvals));
		ucv_object_add(rv, "upvals", uc_getinfo_upvals(vm, uvfun));
		ucv_object_add(rv, "filename", ucv_string_new(source->filename));
		ucv_object_add(rv, "line", ucv_int64_new(uc_source_get_line(source, &byte)));
		ucv_object_add(rv, "byte", ucv_int64_new(byte));

		break;

	case UC_RESOURCE:
		uvres = (uc_resource_t *)uv;

		ucv_object_add(rv, "address", ucv_uint64_new((uintptr_t)uvres->data));

		if (uvres->type) {
			ucv_object_add(rv, "type", ucv_string_new(uvres->type->name));
			ucv_object_add(rv, "prototype", ucv_get(uvres->type->proto));
		}

		break;

	default:
		break;
	}

	return rv;
}

/**
 * @typedef {Object} module:debug.LocalInfo
 *
 * @property {number} index
 * The index of the local variable.
 *
 * @property {string} name
 * The name of the local variable.
 *
 * @property {*} value
 * The current value of the local variable.
 *
 * @property {number} linefrom
 * The source line number of the local variable declaration.
 *
 * @property {number} bytefrom
 * The source line offset of the local variable declaration.
 *
 * @property {number} lineto
 * The source line number where the local variable goes out of scope.
 *
 * @property {number} byteto
 * The source line offset where the local vatiable goes out of scope.
 */
static uc_value_t *
uc_xlocal(uc_vm_t *vm, uc_value_t *level, uc_value_t *var, uc_value_t **set)
{
	size_t lv, vn, vi, i, pos, slot = 0;
	uc_value_t *vname = NULL, *rv;
	uc_variables_t *variables;
	uc_callframe_t *frame;
	uc_source_t *source;
	uc_chunk_t *chunk;

	lv = level ? ucv_uint64_get(level) : 1;

	if ((level && errno) || lv >= vm->callframes.count)
		return NULL;

	frame = &vm->callframes.entries[vm->callframes.count - lv - 1];

	if (!frame->closure)
		return NULL;

	source = uc_program_function_source(frame->closure->function);
	chunk = &frame->closure->function->chunk;
	variables = &chunk->debuginfo.variables;

	if (ucv_type(var) == UC_INTEGER) {
		vn = ucv_uint64_get(var);
		var = NULL;

		if (errno || vn >= variables->count)
			return NULL;
	}
	else if (ucv_type(var) == UC_STRING) {
		vn = 0;
	}
	else {
		return NULL;
	}

	pos = frame->ip - chunk->entries;

	for (i = 0, vi = 0; i < variables->count; i++) {
		slot = variables->entries[i].slot;

		if (slot >= (size_t)-1 / 2)
			continue;

		if (variables->entries[i].from > pos || variables->entries[i].to < pos)
			continue;

		vname = uc_chunk_debug_get_variable(chunk, pos, slot, false);

		if (var ? ucv_is_equal(var, vname) : (vi == vn))
			break;

		ucv_put(vname);
		vname = NULL;
		vi++;
	}

	if (i == variables->count)
		return NULL;

	if (set) {
		ucv_put(vm->stack.entries[frame->stackframe + slot]);
		vm->stack.entries[frame->stackframe + slot] = ucv_get(*set);
	}

	rv = ucv_object_new(vm);

	ucv_object_add(rv, "index", ucv_uint64_new(vi));
	ucv_object_add(rv, "name", vname);
	ucv_object_add(rv, "value",
		ucv_get(vm->stack.entries[frame->stackframe + slot]));

	pos = uc_program_function_srcpos(frame->closure->function,
		variables->entries[i].from);

	ucv_object_add(rv, "linefrom",
		ucv_uint64_new(uc_source_get_line(source, &pos)));

	ucv_object_add(rv, "bytefrom",
		ucv_uint64_new(pos));

	pos = uc_program_function_srcpos(frame->closure->function,
		variables->entries[i].to);

	ucv_object_add(rv, "lineto",
		ucv_uint64_new(uc_source_get_line(source, &pos)));

	ucv_object_add(rv, "byteto",
		ucv_uint64_new(pos));

	return rv;
}

/**
 * Obtain local variable.
 *
 * The `getlocal()` function retrieves information about the specified local
 * variable at the given call stack depth.
 *
 * The call stack depth specifies the amount of levels up local variables should
 * be queried. A value of `0` refers to this `getlocal()` function call itself,
 * `1` to the function calling `getlocal()` and so on.
 *
 * The variable to query might be either specified by name or by its index with
 * index numbers following the source code declaration order.
 *
 * Returns a dictionary holding information about the given variable.
 *
 * Returns `null` if the stack depth exceeds the size of the current call stack.
 *
 * Returns `null` if the invocation at the given stack depth is a C call.
 *
 * Returns `null` if the given variable name is not found or the given variable
 * index is invalid.
 *
 * @function module:debug#getlocal
 *
 * @param {number} [level=1]
 * The amount of call stack levels up local variables should be queried.
 *
 * @param {string|number} variable
 * The variable index or variable name to obtain information for.
 *
 * @returns {?module:debug.LocalInfo}
 */
static uc_value_t *
uc_getlocal(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *level = uc_fn_arg(0);
	uc_value_t *var = uc_fn_arg(1);

	return uc_xlocal(vm, level, var, NULL);
}

/**
 * Set local variable.
 *
 * The `setlocal()` function manipulates the value of the specified local
 * variable at the given call stack depth.
 *
 * The call stack depth specifies the amount of levels up local variables should
 * be updated. A value of `0` refers to this `setlocal()` function call itself,
 * `1` to the function calling `setlocal()` and so on.
 *
 * The variable to update might be either specified by name or by its index with
 * index numbers following the source code declaration order.
 *
 * Returns a dictionary holding information about the updated variable.
 *
 * Returns `null` if the stack depth exceeds the size of the current call stack.
 *
 * Returns `null` if the invocation at the given stack depth is a C call.
 *
 * Returns `null` if the given variable name is not found or the given variable
 * index is invalid.
 *
 * @function module:debug#setlocal
 *
 * @param {number} [level=1]
 * The amount of call stack levels up local variables should be updated.
 *
 * @param {string|number} variable
 * The variable index or variable name to update.
 *
 * @param {*} [value=null]
 * The value to set the local variable to.
 *
 * @returns {?module:debug.LocalInfo}
 */
static uc_value_t *
uc_setlocal(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *level = uc_fn_arg(0);
	uc_value_t *var = uc_fn_arg(1);
	uc_value_t *val = uc_fn_arg(2);

	return uc_xlocal(vm, level, var, &val);
}


/**
 * @typedef {Object} module:debug.UpvalInfo
 *
 * @property {number} index
 * The index of the captured variable (upvalue).
 *
 * @property {string} name
 * The name of the captured variable.
 *
 * @property {boolean} closed
 * Indicates whether the captured variable is closed or not. A closed upvalue
 * means that the function outlived the declaration scope of the captured
 * variable.
 *
 * @property {*} value
 * The current value of the captured variable.
 */
static uc_value_t *
uc_xupval(uc_vm_t *vm, uc_value_t *target, uc_value_t *var, uc_value_t **set)
{
	uc_value_t *vname = NULL, *rv;
	uc_closure_t *closure = NULL;
	uc_upvalref_t *uref = NULL;
	uc_chunk_t *chunk;
	size_t vn, depth;

	if (ucv_type(target) == UC_INTEGER) {
		depth = ucv_uint64_get(target);

		if (errno || depth >= vm->callframes.count)
			return NULL;

		depth = vm->callframes.count - depth - 1;
		closure = vm->callframes.entries[depth].closure;
	}
	else if (ucv_type(target) == UC_CLOSURE) {
		closure = (uc_closure_t *)target;
	}

	if (!closure)
		return NULL;

	chunk = &closure->function->chunk;

	if (ucv_type(var) == UC_INTEGER) {
		vn = ucv_uint64_get(var);
		var = NULL;

		if (errno || vn >= closure->function->nupvals)
			return NULL;

		uref = closure->upvals[vn];
		vname = uc_chunk_debug_get_variable(chunk, 0, vn, true);
	}
	else if (ucv_type(var) == UC_STRING) {
		for (vn = 0; vn < closure->function->nupvals; vn++) {
			vname = uc_chunk_debug_get_variable(chunk, 0, vn, true);

			if (ucv_is_equal(vname, var)) {
				uref = closure->upvals[vn];
				break;
			}

			ucv_put(vname);
			vname = NULL;
		}
	}

	if (!uref)
		return NULL;

	rv = ucv_object_new(vm);

	ucv_object_add(rv, "index", ucv_uint64_new(vn));
	ucv_object_add(rv, "name", vname);

	if (uref->closed) {
		if (set) {
			ucv_put(uref->value);
			uref->value = ucv_get(*set);
		}

		ucv_object_add(rv, "closed", ucv_boolean_new(true));
		ucv_object_add(rv, "value", ucv_get(uref->value));
	}
	else {
		if (set) {
			ucv_put(vm->stack.entries[uref->slot]);
			vm->stack.entries[uref->slot] = ucv_get(*set);
		}

		ucv_object_add(rv, "closed", ucv_boolean_new(false));
		ucv_object_add(rv, "value", ucv_get(vm->stack.entries[uref->slot]));
	}

	return rv;
}

/**
 * Obtain captured variable (upvalue).
 *
 * The `getupval()` function retrieves information about the specified captured
 * variable associated with the given function value or the invoked function at
 * the given call stack depth.
 *
 * The call stack depth specifies the amount of levels up the function should be
 * selected to query associated captured variables for. A value of `0` refers to
 * this `getupval()` function call itself, `1` to the function calling
 * `getupval()` and so on.
 *
 * The variable to query might be either specified by name or by its index with
 * index numbers following the source code declaration order.
 *
 * Returns a dictionary holding information about the given variable.
 *
 * Returns `null` if the given function value is not a closure.
 *
 * Returns `null` if the stack depth exceeds the size of the current call stack.
 *
 * Returns `null` if the invocation at the given stack depth is not a closure.
 *
 * Returns `null` if the given variable name is not found or the given variable
 * index is invalid.
 *
 * @function module:debug#getupval
 *
 * @param {function|number} target
 * Either a function value referring to a closure to query upvalues for or a
 * stack depth number selecting a closure that many levels up.
 *
 * @param {string|number} variable
 * The variable index or variable name to obtain information for.
 *
 * @returns {?module:debug.UpvalInfo}
 */
static uc_value_t *
uc_getupval(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *target = uc_fn_arg(0);
	uc_value_t *var = uc_fn_arg(1);

	return uc_xupval(vm, target, var, NULL);
}

/**
 * Set upvalue.
 *
 * The `setupval()` function manipulates the value of the specified captured
 * variable associated with the given function value or the invoked function at
 * the given call stack depth.
 *
 * The call stack depth specifies the amount of levels up the function should be
 * selected to update associated captured variables for. A value of `0` refers
 * to this `setupval()` function call itself, `1` to the function calling
 * `setupval()` and so on.
 *
 * The variable to update might be either specified by name or by its index with
 * index numbers following the source code declaration order.
 *
 * Returns a dictionary holding information about the updated variable.
 *
 * Returns `null` if the given function value is not a closure.
 *
 * Returns `null` if the stack depth exceeds the size of the current call stack.
 *
 * Returns `null` if the invocation at the given stack depth is not a closure.
 *
 * Returns `null` if the given variable name is not found or the given variable
 * index is invalid.
 *
 * @function module:debug#setupval
 *
 * @param {function|number} target
 * Either a function value referring to a closure to update upvalues for or a
 * stack depth number selecting a closure that many levels up.
 *
 * @param {string|number} variable
 * The variable index or variable name to update.
 *
 * @param {*} value
 * The value to set the variable to.
 *
 * @returns {?module:debug.UpvalInfo}
 */
static uc_value_t *
uc_setupval(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *target = uc_fn_arg(0);
	uc_value_t *var = uc_fn_arg(1);
	uc_value_t *val = uc_fn_arg(2);

	return uc_xupval(vm, target, var, &val);
}


static const uc_function_list_t debug_fns[] = {
	{ "memdump",	uc_memdump },
	{ "traceback",	uc_traceback },
	{ "sourcepos",	uc_sourcepos },
	{ "getinfo",	uc_getinfo },
	{ "getlocal",	uc_getlocal },
	{ "setlocal",	uc_setlocal },
	{ "getupval",	uc_getupval },
	{ "setupval",	uc_setupval },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, debug_fns);

	debug_setup(vm);
}
