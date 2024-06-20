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
#include <sys/ioctl.h>
#include <errno.h>
#include <limits.h>
#include <dlfcn.h>
#include <fnmatch.h>
#include <regex.h>
#include <termios.h>

#ifdef HAVE_ULOOP
#include <libubox/uloop.h>
#endif

#include <json-c/printbuf.h>
#include <json-c/linkhash.h>

#include "ucode/module.h"
#include "ucode/platform.h"
#include "ucode/compiler.h"


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
	uc_resource_t *resource;
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
		resource = (uc_resource_t *)uv;

		if (resource->type)
			uc_debug_discover_ucv(resource->type->proto, seen);

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
	uc_resource_t *resource;
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
		resource = (uc_resource_t *)uv;

		if (resource->type) {
			for (j = 0; j < pad + 1; j++)
				fprintf(out, "  ");

			fprintf(out, "#type %s\n", resource->type->name);

			if (resource->type->proto) {
				for (j = 0; j < pad + 2; j++)
					fprintf(out, "  ");

				fprintf(out, "#prototype = ");
				print_value(out, pad + 2, seen, vm, resource->type->proto);
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
	uc_value_t *handler;
	char *ev;

	ev = getenv("UCODE_DEBUG_MEMDUMP_PATH");
	memdump_directory = ev ? ev : memdump_directory;

	ev = getenv("UCODE_DEBUG_MEMDUMP_SIGNAL");
	memdump_signal = ev ? ev : memdump_signal;

	debug_setup_uloop(vm);

	uc_vm_stack_push(vm, ucv_string_new(memdump_signal));
	uc_vm_stack_push(vm, memdump);

	handler = ucsignal(vm, 2);

	if (handler != memdump)
		fprintf(stderr, "Unable to install debug signal handler\n");

	ucv_put(uc_vm_stack_pop(vm));
	ucv_put(uc_vm_stack_pop(vm));
	ucv_put(handler);
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
			ucv_boolean_new(!(pv & 3) && uv->u64_or_constant));

		break;

	case UC_STRING:
		if (pv & 3) {
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
		ucv_object_add(rv, "constant", ucv_boolean_new(uv->u64_or_constant));
		ucv_object_add(rv, "prototype", ucv_get(uvarr->proto));

		break;

	case UC_OBJECT:
		uvobj = (uc_object_t *)uv;

		ucv_object_add(rv, "address",
			ucv_uint64_new((uintptr_t)uvobj->table));

		ucv_object_add(rv, "count",
			ucv_uint64_new(lh_table_length(uvobj->table)));

		ucv_object_add(rv, "constant", ucv_boolean_new(uv->u64_or_constant));
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


/* ========================================================================== */
/* Interactive debugger implementation follows                                */
/* ========================================================================== */

typedef enum {
	BK_ONCE,
	BK_USER,
	BK_STEP,
	BK_CATCH,
} debug_breakpoint_kind_t;

typedef struct debug_breakpoint {
	uc_breakpoint_t bk;
	uc_function_t *fn;
	size_t depth;
	debug_breakpoint_kind_t kind;
} debug_breakpoint_t;

typedef struct {
	size_t nesting;
	size_t off_start, off_end;
	size_t pos_start, pos_end, pos_ip;
	uint8_t *ip_start, *ip_end;
} insn_span_t;

typedef struct {
	const char *path;
	size_t line;
	size_t column;
	size_t offset;
	uc_program_t *program;
	uc_source_t *source;
	uc_function_t *function;
} location_t;

typedef enum {
	ARGTYPE_NONE,
	ARGTYPE_ERROR,
	ARGTYPE_STRING,
	ARGTYPE_NUMBER,
} argtype_t;

typedef struct {
	argtype_t type;
	size_t off;
	size_t nv;
	char *sv;
} arg_t;

typedef struct {
	size_t count;
	char **entries;
} suggestions_t;

typedef struct {
	size_t pos, len, size, width;
	uint32_t *chars;
} termline_t;

static struct {
	bool initialized;
	char data[128];
	size_t pos, fill;
	size_t rows, cols, col_offset;
	struct termios orig_settings, curr_settings;
	struct {
		size_t count;
		termline_t *entries;
	} history;
	struct {
		size_t count;
		regex_t *entries;
	} patterns;
} termstate;

enum {
	HOME_KEY = 0x110000,
	END_KEY,
	DEL_KEY,
	PAGE_UP,
	PAGE_DOWN,
	ARROW_UP,
	ARROW_DOWN,
	ARROW_LEFT,
	ARROW_RIGHT,
	CTRL_UP,
	CTRL_DOWN,
	CTRL_LEFT,
	CTRL_RIGHT,
};

#define HISTORY_SIZE 100

enum {
	BOLD       = (1 << 0),
	FAINT      = (1 << 1),
	ULINE      = (1 << 2),
};

typedef enum {
	FG_BLACK   =  30,
	FG_RED     =  31,
	FG_GREEN   =  32,
	FG_YELLOW  =  33,
	FG_BLUE    =  34,
	FG_MAGENTA =  35,
	FG_CYAN    =  36,
	FG_GRAY    =  37,
	FG_BBLACK  =  90,
	FG_BRED    =  91,
	FG_BGREEN  =  92,
	FG_BYELLOW =  93,
	FG_BBLUE   =  94,
	FG_BMAGENT =  95,
	FG_BCYAN   =  96,
	FG_BWHITE  =  97,
} fg_color_t;

typedef enum {
	BG_BLACK   =  40,
	BG_GRAY    = 100,
} bg_color_t;

typedef struct {
	fg_color_t fg;
	bg_color_t bg;
	uint32_t styles;
} style_t;

#define uc_vector_add(vec, ...) ({ \
	uc_vector_push((vec), ((typeof((vec)->entries[0]))__VA_ARGS__)); \
	uc_vector_last(vec); \
})

static void
cs(uc_stringbuf_t *sb, style_t *style)
{
	int codes[8] = { 0 };
	size_t i = 0;

	if (style == NULL) {
		printbuf_strappend(sb, "\033[0m");
		return;
	}

	if ((style->styles & (BOLD|FAINT|ULINE)) == 0)
		codes[i++] = 0;

	if (style->styles & BOLD)  codes[i++] = 1;
	if (style->styles & FAINT) codes[i++] = 2;
	if (style->styles & ULINE) codes[i++] = 4;

	codes[i++] = style->fg ? style->fg : 39;
	codes[i++] = style->bg ? style->bg : 49;

	printbuf_strappend(sb, "\033[");

	for (size_t n = 0; n < i; n++)
		sprintbuf(sb, "%s%d", n ? ";" : "", codes[n]);

	printbuf_strappend(sb, "m");
}

static uc_callframe_t *
uc_debug_curr_frame(uc_vm_t *vm, size_t off)
{
	if (off > vm->callframes.count)
		return NULL;

	for (size_t i = vm->callframes.count - off; i > 0; i--)
		if (vm->callframes.entries[i-1].closure)
			return &vm->callframes.entries[i-1];

	return NULL;
}

static bool cmd_help(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv);
static bool cmd_break(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv);
static bool cmd_delete(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv);
static bool cmd_list(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv);
static bool cmd_next(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv);
static bool cmd_step(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv);
static bool cmd_continue(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv);
static bool cmd_return(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv);
static bool cmd_backtrace(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv);
static bool cmd_variables(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv);
static bool cmd_sources(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv);
static bool cmd_quit(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv);
static bool cmd_print(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv);
static bool cmd_lines(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv);
static bool cmd_throw(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv);
static bool cmd_disasm(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv);

static const struct {
	const char *command;
	bool (*cb)(uc_vm_t *, debug_breakpoint_t *, size_t, arg_t *);
	const char *help;
} commands[] = {
	{ "help\0", cmd_help,
		"Print help information." },
	{ "break\0", cmd_break,
		"The break command sets a breakpoint at the given location, "
		"instructing the virtual machine to stop execution at this "
		"point and handing control to the debugger.\n\n"
		"Breakpoint locations may be specified either as filename, "
		"line number and optional character offset within the line "
		"or as a ucode expression that evaluates to a function in "
		"which a breakpoint is set.\n\n"
		"Examples:\n"
		"  break example.uc:13  # Set breakpoint in line 13 of example.uc\n"
		"  break 4:17           # Break in line in 4, char 17 of current file\n"
		"  break myobj.method   # Break in function `method` of `myobj`\n"
		"  break (string.uc)    # Parens to disambiguate expression from path"
	},
	{ "delete\0", cmd_delete,
		"Delete a breakpoint. When no argument is given, the current "
		"breakpoint is deleted, otherwise this function deletes the breakpoint "
		"with the given index.\n\n"
		"Examples:\n"
		"  delete               # Delete current breakpoint\n"
		"  delete 2             # Delete breakpoint #2"
	},
	{ "list\0ls\0", cmd_list,
		"List all currently set breakpoints. User defined breakpoints are "
		"prefixed with a number identifying the breakpoint, internal "
		"breakpoints used by the debugger are prefixed with a breakpoint type "
		"enclosed in parens, e.g. '(step)'."
	},
	{ "next\0", cmd_next,
		"Execute the next statement and stop again."
	},
	{ "step\0", cmd_step,
		"Execute the next statement, in case of function calls step into the "
		"called function and stop there."
	},
	{ "continue\0", cmd_continue,
		"Continue execution until the next breakpoint or end of program."
	},
	{ "return\0", cmd_return,
		"Continue executing the current function until it returns, then stop. "
		"in the calling function. If the current function is the program entry "
		"function, then run until the end of the program."
	},
	{ "backtrace\0bt\0", cmd_backtrace,
		"Print a trace of the current callstack, with most recent callframes "
		"output first. If the optional 'full' argument is specified, "
		"additional information about each call frame is printed.\n\n"
		"Examples:\n"
		"  backtrace            # Print backtrace\n"
		"  backtrace full       # Print backtrace with additional information"
	},
	{ "variables\0", cmd_variables,
		"Print local variables and their contents for the current execution "
		"context. Internal variables which are unreachable by script code "
		"are colored grey, upvalues (variables captured from parent scopes) "
		"are colored blue and ordinary variables use the default color.\n\n"
		"If the optional 'full' argument is specified, the complete value for "
		"each variable is shown, instead of an abbreviated line truncated to "
		"the current terminal width.\n\n"
		"Examples:\n"
		"  variables            # Print local variables\n"
		"  variables full       # Print variables with complete content"
	},
	{ "sources\0src\0", cmd_sources,
		"Print a list of loaded source buffers.\n"
	},
	{ "print\0", cmd_print,
		"Evaluate an ucode expression and print the resulting value.\n\n"
		"Examples:\n"
		"  print varname        # Print value of variable 'varname'\n"
		"  print myobj.prop     # Print `prop` property of `myobj`\n"
		"  print keys(myobj)    # Invoke a stdlib function"
	},
	{ "lines\0ln\0", cmd_lines,
		"Print source code lines surrounding the given location specified "
		"either as filename with line number or as expression evaluating to a "
		"function value.\n\n"
		"The amount of preceeding and following lines to print may be "
		"specified as second and third argument respecitely. By default, two "
		"lines of context are printed before and after the location.\n\n"
		"Examples:\n"
		"  lines                # Output lines surrounding current line\n"
		"  lines example.uc     # Print first three lines of example.uc\n"
		"  lines (obj.func)     # Parens to disambiguate expression from path\n"
		"  lines foo 5 8        # Print 5 lines before foo() till 8 lines in\n"
		"  lines #123           # Print source of instruction offset 123\n"
		"  lines +0 3 3         # Print 3 lines before and after current line\n"
		"  lines -5             # Print source 5 lines before current line\n"
		"  lines +3             # Print source 3 lines after current line"
	},
	{ "throw\0", cmd_throw,
		"Raise an exception at the current instruction offset.\n\n"
		"Examples:\n"
		"  throw \"Message\"    # Throw exception with given message"
	},
	{ "disassemble\0disasm\0", cmd_disasm,
		"Disassembe the given function or statement location and output the "
		"corresponding byte code in a human readable manner. The location to "
		"disassemble may be either a function name, a single instruction "
		"offset, an instruction offset range or a ucode expression.\n\n"
		"Examples:\n"
		"  disassemble          # Disassemble current statment\n"
		"  disassemble foo      # Disassemble body of foo()\n"
		"  disassemble foo+100  # Disassemble first 100 byte of function foo()\n"
		"  disassemble #5       # Disassemble statement containing instruction 5\n"
		"  disassemble #2-10    # Disassemble instructions 2 to 10\n"
		"  disassemble #22+100  # Disassemble instructions 22 to 122\n"
		"  disassemble (12/3*4) # Disassemble ucode expression\n"
	},
	{ "quit\0", cmd_quit,
		"Forcibly terminate the currently running program. The termination "
		"happens in the same manner as if 'exit()' has been called from "
		"script code."
	}
};

/* -- convert file path to module name -------------------------------------- */
static char *
filename_to_modulename(uc_vm_t *vm, const char *filename)
{
	char *module_path = realpath(filename, NULL);
	char *rv = NULL;

	if (!module_path)
		module_path = (char *)filename;

	size_t len_module_path = strlen(module_path);

	uc_value_t *search =
		ucv_object_get(uc_vm_scope_get(vm), "REQUIRE_SEARCH_PATH", NULL);

	for (size_t i = 0; rv == NULL && i < ucv_array_length(search); i++) {
		uc_value_t *p = ucv_array_get(search, i);

		if (ucv_type(p) != UC_STRING)
			continue;

		char *search_spec = xstrdup(ucv_string_get(p));
		char *search_ext = strchr(search_spec, '*');

		if (!search_ext) {
			free(search_spec);
			continue;
		}

		*search_ext++ = 0;

		char *search_path = realpath(search_spec, NULL);

		if (!search_path) {
			free(search_spec);
			continue;
		}

		size_t len_search_path = strlen(search_path);
		size_t len_search_ext = strlen(search_ext);

		if (!strncmp(module_path, search_path, len_search_path) &&
		    module_path[len_search_path] == '/' &&
		    len_module_path > len_search_ext &&
		    !strcmp(module_path + len_module_path - len_search_ext, search_ext))
		{
			xasprintf(&rv, "%.*s",
				(int)(len_module_path - (len_search_path + 1 + len_search_ext)),
				module_path + len_search_path + 1);

			for (char *p = rv; *p; p++)
				if (*p == '/')
					*p = '.';
		}

		free(search_spec);
		free(search_path);
	}

	free(module_path);

	return rv;
}

/* -- helper routines to deal with print buffers ---------------------------- */
static size_t
utf8_sequence_length(const char *s)
{
	const uint8_t *c = (const uint8_t *)s;

	if ((c[0] & 0xe0) == 0xc0 &&
	    (c[1] & 0xc0) == 0x80)
		return 2;

	if ((c[0] & 0xf0) == 0xe0 &&
	    (c[1] & 0xc0) == 0x80 &&
	    (c[2] & 0xc0) == 0x80)
		return 3;

	if ((c[0] & 0xf8) == 0xf0 &&
	    (c[1] & 0xc0) == 0x80 &&
	    (c[2] & 0xc0) == 0x80 &&
	    (c[3] & 0xc0) == 0x80)
		return 4;

	return (*c != 0);
}

static size_t
esc_sequence_length(const char *s)
{
	if (s[0] == '\033' && s[1] == '[') {
		size_t i = 2;

		while (s[i] != '\0' && s[i] != 'm')
			i++;

		return i + (s[i] == 'm');
	}

	return 0;
}

static size_t
strwidth(const char *s)
{
	size_t len = 0;

	while (*s) {
		s += esc_sequence_length(s);

		size_t n = utf8_sequence_length(s);

		if (n) {
			s += n;
			len++;
		}
	}

	return len;
}

static bool
str_startswith(const char *s, const char *substr)
{
	if (substr == NULL)
		return true;

	return strncmp(s, substr, strlen(substr)) == 0;
}

static size_t
printbuf_truncate(uc_stringbuf_t *sb, size_t off, size_t maxcols, bool tail)
{
	if (maxcols == 0) {
		sb->bpos = off;
		sb->buf[off] = 0;

		return 0;
	}

	size_t len = strwidth(sb->buf + off);
	char *s = sb->buf + off;

	if (tail == false && len > maxcols) {
		for (size_t i = 0; i < len - maxcols + 1; i++) {
			s += esc_sequence_length(s);
			s += utf8_sequence_length(s);
		}

		size_t keeplen = (sb->buf + sb->bpos) - s;
		size_t trunclen = s - (sb->buf + off);
		size_t elliplen = sizeof("…") - 1;

		/* Reserve enough additional space for ellipsis mb sequence. */
		if (trunclen < elliplen)
			printbuf_memset(sb, -1, ' ', elliplen - trunclen);

		memmove(sb->buf + off + elliplen, s, keeplen);
		memcpy(sb->buf + off, "…", elliplen);

		sb->bpos += elliplen;
		sb->bpos -= trunclen;
		sb->buf[sb->bpos] = 0;

		return maxcols;
	}

	if (tail == true && len > maxcols) {
		for (size_t i = 0; i < maxcols - 1; i++) {
			s += esc_sequence_length(s);
			s += utf8_sequence_length(s);
		}

		sb->bpos = s - sb->buf;
		printbuf_strappend(sb, "…");

		return maxcols;
	}

	return len;
}

static size_t
printbuf_append_uv(uc_stringbuf_t *sb, uc_vm_t *vm, uc_value_t *val,
                   size_t maxcols)
{
	int pos = sb->bpos;
	const char *end;
	size_t len;

	ucv_to_stringbuf(vm, sb, val, false);

	len = strwidth(sb->buf + pos);

	if (len > maxcols) {
		switch (sb->buf[pos]) {
		case '{': len = maxcols - 3; end = "… }"; break;
		case '[': len = maxcols - 3; end = "… ]"; break;
		case '"': len = maxcols - 2; end = "…\""; break;
		default:  len = maxcols - 1; end = "…";   break;
		}

		for (sb->bpos = pos; len > 0; len--)
			sb->bpos += utf8_sequence_length(sb->buf + sb->bpos);

		printbuf_memappend_fast(sb, end, strlen(end));

		return maxcols;
	}

	return len;
}

static size_t
printbuf_append_funcname(uc_stringbuf_t *sb, uc_vm_t *vm, uc_value_t *val,
                         size_t maxcols)
{
	char *placeholder = NULL;
	int off = sb->bpos;

	for (size_t i = 0; i < vm->restypes.count; i++) {
		uc_resource_type_t *rt = vm->restypes.entries[i];

		ucv_object_foreach(rt->proto, k, v) {
			(void)k;

			if (v == val) {
				printbuf_memappend_fast(sb, rt->name, strlen(rt->name));
				printbuf_strappend(sb, "#");
				goto name;
			}
		}
	}

	uc_value_t *modtable = ucv_object_get(uc_vm_scope_get(vm), "modules", NULL);

	ucv_object_foreach(modtable, modname, modscope) {
		ucv_object_foreach(modscope, symname, symval) {
			(void)symname;

			if (symval == val) {
				printbuf_memappend_fast(sb, modname, strlen(modname));
				printbuf_strappend(sb, ".");
				goto name;
			}
		}
	}

name:
	if (ucv_type(val) == UC_CLOSURE) {
		uc_function_t *fn = ((uc_closure_t *)val)->function;

		if (fn->name[0]) {
			printbuf_memappend_fast(sb, fn->name, strlen(fn->name));
			goto done;
		}

		placeholder = fn->arrow ? "λ" : "𝑓";
	}
	else if (ucv_type(val) == UC_CFUNCTION) {
		uc_cfunction_t *cf = (uc_cfunction_t *)val;

		if (cf->name[0]) {
			printbuf_memappend_fast(sb, cf->name, strlen(cf->name));
			goto done;
		}

		placeholder = "𝑓";
	}
	else {
		return 0;
	}

	/* no prefix and no name yet, try to name by containing property name */
	for (uc_weakref_t *ref = vm->values.next;
		ref != &vm->values && sb->bpos == off;
		ref = ref->next)
	{
		uc_object_t *obj =
			(uc_object_t *)((char *)ref - offsetof(uc_object_t, ref));

		if (obj->header.type != UC_OBJECT)
			continue;

		ucv_object_foreach(&obj->header, k, v) {
			if (v == val) {
				printbuf_memappend_fast(sb, k, strlen(k));
				printbuf_strappend(sb, ":");
				break;
			}
		}
	}

	printbuf_memappend_fast(sb, placeholder, strlen(placeholder));

done:
	return printbuf_truncate(sb, off, maxcols, true);
}

static size_t
printbuf_append_function(uc_stringbuf_t *sb, uc_vm_t *vm, uc_value_t *val,
                         uc_callframe_t *frame, size_t maxcols)
{
	uc_type_t t = ucv_type(val);
	int off = sb->bpos;

	if (t == UC_CFUNCTION) {
		printbuf_append_funcname(sb, vm, val, SIZE_MAX);
		printbuf_strappend(sb, "(");

		if (frame) {
			size_t prev_frame = vm->stack.count;

			for (size_t i = vm->callframes.count; i > 0; i--) {
				if (&vm->callframes.entries[i - 1] == frame)
					break;

				prev_frame = vm->callframes.entries[i - 1].stackframe;
			}

			for (size_t j = 1; j < prev_frame - frame->stackframe; j++) {
				if (j > 1)
					printbuf_strappend(sb, ", ");

				uc_value_t *argval =
					(frame->stackframe + j < vm->stack.count)
						? vm->stack.entries[frame->stackframe + j]
						: NULL;

				printbuf_append_uv(sb, vm, argval, 32);
			}
		}

		printbuf_strappend(sb, ")");
	}
	else if (t == UC_CLOSURE) {
		uc_closure_t *cl = (uc_closure_t *)val;
		uc_source_t *source = uc_program_function_source(cl->function);

		if (cl->function->module) {
			char *s = filename_to_modulename(vm, source->filename);
			sprintbuf(sb, "module(%s)", s ? s : "");
			free(s);
		}
		else {
			printbuf_append_funcname(sb, vm, val, SIZE_MAX);
			printbuf_strappend(sb, "(");

			if (frame) {
				for (size_t i = 0; i < cl->function->nargs; i++) {
					uc_value_t *argname = uc_chunk_debug_get_variable(
						&cl->function->chunk, i, i + 1, false);

					if (i > 0)
						printbuf_strappend(sb, ", ");

					if (i + 1 == cl->function->nargs && cl->function->vararg)
						printbuf_strappend(sb, "...");

					if (argname) {
						printbuf_memappend_fast(sb,
							ucv_string_get(argname),
							ucv_string_length(argname));

						printbuf_strappend(sb, "=");
						ucv_put(argname);
					}
					else {
						sprintbuf(sb, "$%zu=", i + 1);
					}

					uc_value_t *argval =
						(frame->stackframe + i + 1 < vm->stack.count)
							? vm->stack.entries[frame->stackframe + i + 1]
							: NULL;

					printbuf_append_uv(sb, vm, argval, 32);
				}
			}

			printbuf_strappend(sb, ")");
		}
	}

	return printbuf_truncate(sb, off, maxcols, true);
}

static size_t
printbuf_append_srcpath(uc_stringbuf_t *sb, uc_source_t *source, size_t maxcols)
{
	int off = sb->bpos;

	printbuf_memset(sb, off + PATH_MAX, 0, 1);

	if (realpath(source->filename, sb->buf + off)) {
		size_t pathlen = strlen(sb->buf + off);
		char cwd[PATH_MAX];

		if (getcwd(cwd, sizeof(cwd))) {
			size_t cwdlen = strlen(cwd);

			if (strncmp(sb->buf + off, cwd, cwdlen) == 0 &&
			    sb->buf[off + cwdlen] == '/')
			{
				pathlen -= cwdlen + 1;
				memmove(sb->buf + off, sb->buf + off + cwdlen + 1, pathlen);
			}
		}

		sb->bpos = off + pathlen;
		sb->buf[sb->bpos] = 0;
	}
	else {
		sb->bpos = off;
		printbuf_memappend_fast(sb,
			source->filename, strlen(source->filename));
	}

	return printbuf_truncate(sb, off, maxcols, false);
}

static size_t
printbuf_cs(uc_stringbuf_t *sb, const char *fmt, ...)
{
	uc_stringbuf_t fmtbuf = { 0 };
	style_t *styles[8] = { 0 };
	uint8_t nstyles = 0;
	va_list ap, ap1;

	for (const char *p = fmt; *p; p++)
		if (*p >= '\1' && *p <= '\7' && *p > nstyles)
			nstyles = *p;

	va_start(ap, fmt);

	for (uint8_t i = 0; i < nstyles; i++)
		styles[i] = va_arg(ap, style_t *);

	const char *p, *l;

	for (p = l = fmt; *p; p++) {
		if ((*p >= '\1' && *p <= '\7') || *p == '\177') {
			printbuf_memappend_fast((&fmtbuf), l, p - l);
			cs(&fmtbuf, (*p <= '\7' ? styles[(size_t)*p - 1] : NULL));
			l = p + 1;
		}
	}

	printbuf_memappend_fast((&fmtbuf), l, p - l);

	va_copy(ap1, ap);
	int len = vsnprintf(NULL, 0, fmtbuf.buf, ap1);
	va_end(ap1);

	if (len > 0) {
		printbuf_memset(sb, sb->bpos + len - 1, '\0', 1);
		vsnprintf(sb->buf + sb->bpos - len, len + 1, fmtbuf.buf, ap);
	}

	va_end(ap);

	free(fmtbuf.buf);

	return (len > 0) ? len : 0;
}


static void
bk_enter_cli(uc_vm_t *vm, uc_breakpoint_t *bk);

static void
bk_handle_catch(uc_vm_t *vm, uc_breakpoint_t *bk);

static debug_breakpoint_t *
get_breakpoint(uc_vm_t *vm, debug_breakpoint_kind_t kind)
{
	debug_breakpoint_t *dbk;

	for (size_t i = 0; i < vm->breakpoints.count; i++) {
		dbk = (debug_breakpoint_t *)vm->breakpoints.entries[i];

		if (dbk != NULL && dbk->kind == kind)
			return dbk;
	}

	dbk = xalloc(sizeof(*dbk));
	dbk->kind = kind;
	uc_vector_push(&vm->breakpoints, &dbk->bk);

	return dbk;
}

static void
update_breakpoint(uc_vm_t *vm, debug_breakpoint_kind_t kind,
                  void (*cb)(uc_vm_t *, uc_breakpoint_t *), uint8_t *ip,
                  uc_function_t *fn, size_t depth)
{
	debug_breakpoint_t *dbk = get_breakpoint(vm, kind);

	dbk->bk.cb = cb;
	dbk->depth = depth;
	dbk->fn = fn;

	/* If the target instruction is the same then invoke handler directly */
	if (dbk->bk.ip == ip)
		dbk->bk.cb(vm, &dbk->bk);
	else
		dbk->bk.ip = ip;
}

static bool
free_breakpoint(uc_vm_t *vm, uc_breakpoint_t *bk)
{
	uc_breakpoints_t *bks = &vm->breakpoints;
	bool found = false;

	/* Blank out breakpoint slot */
	for (size_t i = bks->count; i > 0; i--) {
		if (bks->entries[i - 1] == bk) {
			bks->entries[i - 1] = NULL;
			found = true;
			break;
		}
	}

	/* Cleanup empty tail of the breakpoint vector */
	while (bks->count > 0 && bks->entries[bks->count - 1] == NULL)
		bks->count--;

	free(bk);

	return found;
}

static size_t
patch_breakpoint(uc_vm_t *vm, uc_function_t *fn, size_t insnoff,
                 debug_breakpoint_kind_t kind, size_t depth)
{
	debug_breakpoint_t *dbk = xalloc(sizeof(debug_breakpoint_t));
	uc_callframe_t *frame = uc_debug_curr_frame(vm, 0);
	uc_breakpoints_t *bks = &vm->breakpoints;

	dbk->bk.ip = fn ? &fn->chunk.entries[insnoff] : NULL;
	dbk->bk.cb = bk_enter_cli;
	dbk->fn = fn;
	dbk->kind = kind;
	dbk->depth = depth;

	/* When the user breakpoint to be installed is at the same instruction
	   offset as the current VM instruction pointer then ensure to append it
	   to the breakpoint stack, otherwise reclaim free entry. */
	if (frame == NULL || frame->ip != dbk->bk.ip) {
		for (size_t i = 0; i < bks->count; i++) {
			if (bks->entries[i] == NULL) {
				bks->entries[i] = &dbk->bk;

				return i + 1;
			}
		}
	}

	uc_vector_push(bks, &dbk->bk);

	return bks->count;
}

static bool
filename_matches_pattern(const char *filename, const char *pattern)
{
	if (strchr(pattern, '/') || strchr(pattern, '*'))
		return (fnmatch(filename, pattern, 0) == 0);

	const char *basename = strrchr(filename, '/');

	if (basename)
		return (strcmp(basename + 1, pattern) == 0);

	return false;
}

static bool
lookup_source(uc_vm_t *vm, location_t *loc)
{
	uc_stringbuf_t pattern = { 0 }, filename = { 0 };
	uc_weakref_t *ref;
	uc_closure_t *uc;

	if (loc->program != NULL && loc->source != NULL)
		return true;

	if (loc->path == NULL)
		return false;

	printbuf_append_srcpath(&pattern,
		&((uc_source_t){ .filename = (char *)loc->path }), SIZE_MAX);

	/* iterate all existing closures to find programs */
	for (ref = vm->values.next; ref != &vm->values; ref = ref->next) {
		uc = (uc_closure_t *)((uintptr_t)ref - offsetof(uc_closure_t, ref));

		if (uc->header.type != UC_CLOSURE)
			continue;

		if (!uc->function || !uc->function->program)
			continue;

		uc_program_t *program = uc->function->program;

		/* iterate all program sources looking for a patchname match */
		for (size_t i = 0; i < program->sources.count; i++) {
			uc_source_t *source = program->sources.entries[i];

			printbuf_append_srcpath(&filename, source, SIZE_MAX);

			if (filename_matches_pattern(filename.buf, pattern.buf)) {
				size_t col = (loc->column > 0) ? loc->column - 1 : 0;
				size_t rem = (loc->line > 0) ? loc->line - 1 : 0;
				uc_lineinfo_t *lines = &source->lineinfo;

				/* iterate line lengths looking for exact offset */
				for (size_t j = 0, llen = 0, off = 0; j < lines->count; j++) {
					size_t bytes = lines->entries[j] & 0x7f;

					if (rem == 0 && col >= llen && col <= llen + bytes) {
						loc->program = program;
						loc->source = source;
						loc->offset = off + llen + col;

						free(filename.buf);
						free(pattern.buf);

						return true;
					}

					llen += bytes;

					if (j > 0 && lines->entries[j] & 0x80) {
						off += llen + 1;
						llen = 0;
						rem--;
					}
				}
			}

			printbuf_reset(&filename);
		}
	}

	free(filename.buf);
	free(pattern.buf);

	return false;
}

static bool
lookup_offset(uc_vm_t *vm, location_t *loc)
{
	if (!lookup_source(vm, loc))
		return false;

	size_t column = (loc->column > 0) ? loc->column - 1 : 0;
	size_t remaining = (loc->line > 0) ? loc->line - 1 : 0;
	uc_lineinfo_t *lines = &loc->source->lineinfo;

	/* iterate line lengths looking for exact offset */
	for (size_t j = 0, linelen = 0, offset = 0; j < lines->count; j++) {
		size_t bytes = lines->entries[j] & 0x7f;

		if (remaining == 0 && column >= linelen && column <= linelen + bytes) {
			loc->offset = offset + linelen + column;

			return true;
		}

		linelen += bytes;

		if (j > 0 && lines->entries[j] & 0x80) {
			offset += linelen + 1;
			linelen = 0;
			remaining--;
		}
	}

	return false;
}

static bool
lookup_function(uc_vm_t *vm, location_t *loc)
{
	if (loc->function != NULL)
		return true;

	if (!lookup_offset(vm, loc))
		return false;

	uc_program_function_foreach(loc->program, fn) {
		if (uc_program_function_source(fn) != loc->source)
			continue;

		size_t beg = uc_program_function_srcpos(fn, 0);
		size_t end = uc_program_function_srcpos(fn, SIZE_MAX);

		if (beg <= loc->offset && end >= loc->offset) {
			loc->function = fn;

			return true;
		}
	}

	return false;
}

static bool
lookup_stmt_boundary(uc_vm_t *vm, location_t *loc, insn_span_t *sp)
{
	if (!lookup_function(vm, loc))
		return false;

	struct { insn_span_t *entries; size_t count; } sp_stack = { 0 };
	uc_chunk_t *chunk = &loc->function->chunk;
	uc_offsetinfo_t *offsets = &chunk->debuginfo.offsets;
	size_t bytes = loc->function->srcpos;
	insn_span_t *s = NULL;

	for (size_t i = 0, insns = 0; i < offsets->count; i++) {
		uc_offset_t *o = &offsets->entries[i];

		if (o->bytes & 0x80) {
			size_t nesting = sp_stack.count + 1;

			s = uc_vector_add(&sp_stack, {
				.nesting   = nesting,
				.off_start = i,
				.pos_start = bytes,
				.pos_ip    = bytes,
				.ip_start  = chunk->entries + insns
			});
		}

		bytes += o->bytes & 0x7f;
		insns += o->insns & 0x7f;

		if (insns > chunk->count)
			goto not_found; /* out of range / invalid offset coding */

		if (o->insns & 0x80) {
			if (sp_stack.count == 0)
				goto not_found; /* invalid offset coding */

			s->off_end = i;
			s->pos_end = bytes;
			s->ip_end  = chunk->entries + insns;

			if (s->pos_start <= loc->offset && s->pos_end >= loc->offset)
				goto found;

			s = --sp_stack.count ? uc_vector_last(&sp_stack) : NULL;
		}

		if (bytes > loc->offset && s == NULL)
			goto not_found; /* past searched offset w/o matching range start */
	}

not_found:
	memset(sp, 0, sizeof(*sp));
	uc_vector_clear(&sp_stack);

	return false;

found:
	*sp = *uc_vector_last(&sp_stack);
	uc_vector_clear(&sp_stack);

	return true;
}

static size_t
add_breakpoint(uc_vm_t *vm, const char *path, size_t line, size_t byte,
               debug_breakpoint_kind_t kind)
{
	location_t loc = { .path = path, .line = line, .column = byte };
	insn_span_t stmt;

	if (!lookup_stmt_boundary(vm, &loc, &stmt))
		return 0;

	return patch_breakpoint(vm, loc.function,
		stmt.ip_start - loc.function->chunk.entries, kind, stmt.nesting);
}

static uint8_t *
next_parent(uc_vm_t *vm, uc_function_t **fnp)
{
	for (size_t i = vm->callframes.count - 1; i > 0; i--) {
		uc_callframe_t *pframe = &vm->callframes.entries[i - 1];

		if (!pframe->closure)
			continue;

		*fnp = pframe->closure->function;

		return pframe->ip;
	}

	return NULL;
}

static bool
find_statement_boundaries(uc_function_t *fn, uint8_t *ip, size_t depth, insn_span_t *sp)
{
	struct { insn_span_t *entries; size_t count; } sp_stack = { 0 };
	uc_offsetinfo_t *offsets = &fn->chunk.debuginfo.offsets;
	size_t off = ip - fn->chunk.entries;
	size_t i = 0, bytes = 0, insns = 0;
	insn_span_t *s = NULL;

	for (i = 0; i < offsets->count; i++) {
		uc_offset_t *o = &offsets->entries[i];

		bytes += o->bytes & 0x7f;

		if (o->bytes & 0x80) {
			size_t nesting = sp_stack.count + 1;

			s = uc_vector_add(&sp_stack, {
				.nesting   = nesting,
				.off_start = i,
				.pos_start = fn->srcpos + bytes,
				.pos_ip    = fn->srcpos + bytes,
				.ip_start  = &fn->chunk.entries[insns]
			});
		}

		if (insns <= off && insns + (o->insns & 0x7f) > off && s != NULL)
			s->pos_ip = fn->srcpos + bytes;

		insns += o->insns & 0x7f;

		if (insns > fn->chunk.count)
			goto not_found; /* out of range / invalid offset codiing */

		if (o->insns & 0x80) {
			if (sp_stack.count == 0)
				goto not_found; /* invalid offset coding */

			if (depth == 0 || sp_stack.count == depth) {
				s->off_end = i;
				s->pos_end = fn->srcpos + bytes;
				s->ip_end = &fn->chunk.entries[insns];

				if (s->ip_start <= ip && s->ip_end > ip)
					goto found;
			}

			s = --sp_stack.count ? uc_vector_last(&sp_stack) : NULL;
		}

		if (insns > off && s == NULL)
			goto not_found; /* past searched offset w/o matching range start */
	}

not_found:
	memset(sp, 0, sizeof(*sp));
	uc_vector_clear(&sp_stack);

	return false;

found:
	*sp = *uc_vector_last(&sp_stack);
	uc_vector_clear(&sp_stack);

	return true;
}

static void
term_dimensions(void)
{
	struct winsize w;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) {
		termstate.rows = w.ws_row;
		termstate.cols = w.ws_col;
	}
	else {
		termstate.rows = 26;
		termstate.cols = 80;
	}
}

static size_t
term_width(void)
{
	if (termstate.cols == 0)
		term_dimensions();

	return termstate.cols;
}

static void
term_reset(void)
{
	if (tcsetattr(STDOUT_FILENO, TCSAFLUSH, &termstate.orig_settings) == -1)
		fprintf(stderr, "tcsetattr(): %m\n");

	while (termstate.patterns.count > 0) {
		regex_t *re = &termstate.patterns.entries[--termstate.patterns.count];
		if (re)	regfree(re);
	}

	while (termstate.history.count > 0)
		free(termstate.history.entries[--termstate.history.count].chars);

	uc_vector_clear(&termstate.patterns);
	uc_vector_clear(&termstate.history);
}

static bool
term_raw(void)
{
	if (tcgetattr(STDOUT_FILENO, &termstate.orig_settings) == -1) {
		fprintf(stderr, "tcgetattr(): %m\n");

		return false;
	}

	atexit(term_reset);

	termstate.curr_settings = termstate.orig_settings;

	termstate.curr_settings.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
	termstate.curr_settings.c_cflag |= (CS8);
	termstate.curr_settings.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
	termstate.curr_settings.c_cc[VMIN] = 0;
	termstate.curr_settings.c_cc[VTIME] = 1;

	if (tcsetattr(STDOUT_FILENO, TCSAFLUSH, &termstate.curr_settings) == -1) {
		fprintf(stderr, "tcsetattr(): %m\n");

		return false;
	}

	return true;
}

static bool
term_isig(bool enable)
{
	struct termios t;

	if (tcgetattr(STDOUT_FILENO, &t) == -1) {
		fprintf(stderr, "tcgetattr(): %m\n");

		return false;
	}

	if (enable)
		t.c_lflag |= ISIG;
	else
		t.c_lflag &= ~ISIG;

	if (tcsetattr(STDOUT_FILENO, TCSAFLUSH, &t) == -1) {
		fprintf(stderr, "tcsetattr(): %m\n");

		return false;
	}

	return true;
}

static ssize_t
fgetline(FILE *stream, char **buf, size_t *bufsize)
{
	ssize_t n = 0;

	while (true) {
		n = getline(buf, bufsize, stream);

		if (n == -1 && errno == EINTR) {
			clearerr(stream);
			continue;
		}

		break;
	}

	return n;
}

static int
term_getc_raw(void)
{
	ssize_t rlen;

	if (termstate.pos >= termstate.fill) {
		while (true) {
			rlen = read(STDIN_FILENO, termstate.data, sizeof(termstate.data));

			if (rlen == -1) {
				if (errno == EINTR)
					continue;

				return -1;
			}

			if (rlen == 0)
				continue;

			termstate.fill = rlen;
			termstate.pos = 0;
			break;
		}
	}

	return termstate.data[termstate.pos++];
}

static bool is_utf8_2b(char c) { return (c & 0xe0) == 0xc0; }
static bool is_utf8_3b(char c) { return (c & 0xf0) == 0xe0; }
static bool is_utf8_4b(char c) { return (c & 0xf8) == 0xf0; }
static bool is_utf8_ct(char c) { return (c & 0xc0) == 0x80; }

static int
term_getc(void)
{
	int chr = term_getc_raw();
	int seq[5];

	/* escape sequence */
	if (chr == '\033') {
		if ((seq[0] = term_getc_raw()) == -1) return '\033';
		if ((seq[1] = term_getc_raw()) == -1) return '\033';

		switch (seq[0]) {
		case '[':
			switch (seq[1]) {
			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
				if ((seq[2] = term_getc_raw()) == -1) return '\033';

				switch (seq[2]) {
				case '~':
					switch (seq[1]) {
					case '1': return HOME_KEY;
					case '3': return DEL_KEY;
					case '4': return END_KEY;
					case '5': return PAGE_UP;
					case '6': return PAGE_DOWN;
					case '7': return HOME_KEY;
					case '8': return END_KEY;
					}
					break;

				case ';':
					if ((seq[3] = term_getc_raw()) == -1) return '\033';

					switch (seq[3]) {
					case '5':
						if ((seq[4] = term_getc_raw()) == -1) return '\033';

						switch (seq[4]) {
						case 'A': return CTRL_UP;
						case 'B': return CTRL_DOWN;
						case 'C': return CTRL_RIGHT;
						case 'D': return CTRL_LEFT;
						}
						break;
					}
					break;
				}
				break;

			case 'A': return ARROW_UP;
			case 'B': return ARROW_DOWN;
			case 'C': return ARROW_RIGHT;
			case 'D': return ARROW_LEFT;
			case 'H': return HOME_KEY;
			case 'F': return END_KEY;
			}
			break;

		case 'O':
			switch (seq[1]) {
			case 'H': return HOME_KEY;
			case 'F': return END_KEY;
			}
			break;
		}

		return '\033';
	}

	/* two byte utf-8 sequence */
	if (is_utf8_2b(chr) &&
	    is_utf8_ct(seq[0] = term_getc_raw()))
	{
		return ((chr    & 0x1f) <<  6) |
		        (seq[0] & 0x3f);
	}

	/* three byte utf-8 sequence */
	if (is_utf8_3b(chr) &&
	    is_utf8_ct(seq[0] = term_getc_raw()) &&
	    is_utf8_ct(seq[1] = term_getc_raw()))
	{
		return ((chr    & 0x0f) << 12) |
		       ((seq[0] & 0x3f) <<  6) |
		        (seq[1] & 0x3f);
	}

	/* four byte utf-8 sequence */
	if (is_utf8_4b(chr) &&
	    is_utf8_ct(seq[0] = term_getc_raw()) &&
	    is_utf8_ct(seq[1] = term_getc_raw()) &&
	    is_utf8_ct(seq[2] = term_getc_raw()))
	{
		return ((chr    & 0x07) << 18) |
		       ((seq[0] & 0x3f) << 12) |
		       ((seq[1] & 0x3f) <<  6) |
		        (seq[2] & 0x3f);
	}

	return chr;
}

static bool
term_write(const char *s, size_t len)
{
	ssize_t wlen = write(STDOUT_FILENO, s, len);

	return (wlen > -1 && (size_t)wlen == len);
}

#define term_print(x) term_write(x, sizeof(x) - 1)
#define term_printf(fmt, ...) dprintf(STDOUT_FILENO, fmt, __VA_ARGS__)

static void
uc_vector_addcp(void *vec, uint32_t cp)
{
	struct { size_t count; char *entries; } *v = vec;

	if (cp <= 0x7F) {
		uc_vector_add(v, cp);
	}
	else if (cp <= 0x7FF) {
		uc_vector_add(v, ((cp >>  6) & 0x1F) | 0xC0);
		uc_vector_add(v, ( cp        & 0x3F) | 0x80);
	}
	else if (cp <= 0xFFFF) {
		uc_vector_add(v, ((cp >> 12) & 0x0F) | 0xE0);
		uc_vector_add(v, ((cp >>  6) & 0x3F) | 0x80);
		uc_vector_add(v, ( cp        & 0x3F) | 0x80);
	}
	else if (cp <= 0x10FFFF) {
		uc_vector_add(v, ((cp >> 18) & 0x07) | 0xF0);
		uc_vector_add(v, ((cp >> 12) & 0x3F) | 0x80);
		uc_vector_add(v, ((cp >>  6) & 0x3F) | 0x80);
		uc_vector_add(v, ( cp        & 0x3F) | 0x80);
	}
}

static bool
term_line_parsearg(termline_t *line, size_t *off, arg_t *arg, bool silent)
{
	struct { size_t count; char *entries; } buf = { 0 }, nesting = { 0 };
	uint32_t *end, *cp, q;
	unsigned long n;
	bool esc;

	if (line == NULL || *off >= line->width) {
		arg->type = ARGTYPE_NONE;
		arg->off = line->width;
		arg->sv = NULL;
		arg->nv = 0;

		return false;
	}

	end = line->chars + line->width;
	cp = line->chars + *off;

	while (cp < end && strchr(" \t\r\n", *cp) != NULL)
		cp++;

	arg->off = cp - line->chars;

	if (cp < end && strchr("\"'", *cp) != NULL) {
		for (esc = false, q = *cp++; cp < end; cp++) {
			if (esc) {
				if (cp[0] >= '0' && cp[0] <= '7') {
					int n = cp[0] - '0';
					int i = 0;

					if (cp[1] >= '0' && cp[1] <= '7') {
						n = n * 8 + (cp[1] - '0');
						i++;

						if (cp[2] >= '0' && cp[2] <= '7') {
							n = n * 8 + (cp[2] - '0');
							i++;
						}
					}

					if (n <= 255) {
						uc_vector_addcp(&buf, n);
					}
					else {
						uc_vector_add(&buf, cp[-1]);
						uc_vector_add(&buf, cp[0]);
						if (i > 0) uc_vector_addcp(&buf, cp[1]);
						if (i > 1) uc_vector_addcp(&buf, cp[2]);
					}

					cp += i;
				}
				else if (cp[0] == 'x') {
					char c = cp[1]|32;
					char d = c ? cp[2]|32 : 0;

					if (((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) &&
					    ((d >= '0' && d <= '9') || (d >= 'a' && d <= 'f')))
					{
						uc_vector_add(&buf,
							(c > '9' ? 10 + c - 'a' : c - '0') * 16 +
							(d > '9' ? 10 + d - 'a' : d - '0'));
					}
					else {
						uc_vector_add(&buf, cp[-1]);
						uc_vector_add(&buf, cp[0]);
						if (c) uc_vector_addcp(&buf, cp[1]);
						if (d) uc_vector_addcp(&buf, cp[2]);
					}

					cp += !!c + !!d;
				}
				else {
					switch (cp[0]) {
					case 'n': uc_vector_add(&buf, '\n'); break;
					case 't': uc_vector_add(&buf, '\t'); break;
					case 'r': uc_vector_add(&buf, '\r'); break;
					case 'b': uc_vector_add(&buf, '\b'); break;
					default:  uc_vector_addcp(&buf, *cp);  break;
					}
				}

				esc = false;
				continue;
			}

			if (*cp == '\\') {
				esc = true;
				continue;
			}

			if (*cp == q)
				break;

			uc_vector_addcp(&buf, *cp);
		}

		*off = cp - line->chars;

		uc_vector_add(&buf, 0);

		arg->sv = buf.entries, buf.entries = NULL;
		arg->nv = buf.count;

		uc_vector_clear(&buf);

		if (esc == true || cp == end || *cp != q) {
			if (!silent)
				term_print("Unterminated string\n");

			arg->type = ARGTYPE_ERROR;
		}
		else {
			arg->type = ARGTYPE_STRING;
		}

		return true;
	}

	for (n = 0; cp < end && *cp >= '0' && *cp <= '9'; cp++) {
		uint32_t d = *cp - '0';

		uc_vector_add(&buf, *cp);

		if (n > ULONG_MAX / 10) {
			n = ULONG_MAX;
			continue;
		}

		n *= 10;

		if (n > ULONG_MAX - d) {
			n = ULONG_MAX;
			continue;
		}

		n += d;
	}

	*off = cp - line->chars;

	if (buf.count > 0 && (cp == end || strchr(" \t\r\n", *cp) != NULL)) {
		uc_vector_add(&buf, 0);

		arg->type = ARGTYPE_NUMBER;
		arg->sv = buf.entries, buf.entries = NULL;
		arg->nv = n;

		uc_vector_clear(&buf);

		return true;
	}

	for (esc = false, q = 0; cp < end; cp++) {
		if (esc) {
			esc = false;
		}
		else if (*cp == '\\') {
			esc = true;
		}
		else if (q != 0 && *cp == q) {
			q = 0;
		}
		else if (q == 0) {
			switch (*cp) {
			case '(': uc_vector_push(&nesting, ')'); break;
			case '{': uc_vector_push(&nesting, '}'); break;
			case '[': uc_vector_push(&nesting, ']'); break;

			case '"':
			case '\'':
				q = *cp;
				break;

			case ']':
			case '}':
			case ')':
				if (nesting.count > 0 && *uc_vector_last(&nesting) == (char)*cp)
					nesting.count--;

				break;
			}
		}

		if (strchr(" \t\r\n", *cp) && nesting.count == 0 && esc == false)
			break;

		uc_vector_addcp(&buf, *cp);
	}

	uc_vector_clear(&nesting);

	*off = cp - line->chars;

	n = buf.count;

	uc_vector_add(&buf, 0);

	arg->sv = buf.entries, buf.entries = NULL;
	arg->nv = n;

	uc_vector_clear(&buf);

	if (esc == true || q != 0) {
		if (!silent)
			term_print("Unterminated string\n");

		arg->type = ARGTYPE_ERROR;
	}
	else if (n > 0 || silent == true) {
		arg->type = ARGTYPE_STRING;
	}
	else {
		free(arg->sv);

		arg->type = ARGTYPE_NONE;
		arg->sv = NULL;

		return false;
	}

	return true;
}

static size_t
term_line_toargv(termline_t *line, bool silent, arg_t **argp)
{
	struct { size_t count; arg_t *entries; } argv = { 0 };
	size_t off = 0;

	while (true) {
		arg_t arg;
		argtype_t t = term_line_parsearg(line, &off, &arg, silent);

		if (t == ARGTYPE_NONE)
			break;

		uc_vector_add(&argv, arg);
	}

	*argp = argv.entries;

	return argv.count;
}

static size_t
term_line_fromstr(termline_t *line, size_t from, char *s, size_t len)
{
	size_t needed = 0;

	for (const char *p = s, *e = s + len; p < e; needed++) {
		if      (is_utf8_2b(p[0]) && is_utf8_ct(p[1]))
			p += 2;
		else if (is_utf8_3b(p[0]) && is_utf8_ct(p[1]) &&
		         is_utf8_ct(p[2]))
			p += 3;
		else if (is_utf8_4b(p[0]) && is_utf8_ct(p[1]) &&
		         is_utf8_ct(p[2]) && is_utf8_ct(p[3]))
			p += 4;
		else
			p++;
	}

	if (from + needed > line->size) {
		line->size = ((from + needed + 127) >> 7) << 7;
		line->chars = xrealloc(line->chars, line->size * sizeof(*line->chars));
	}

	uint32_t *cp = line->chars + from;

	for (const char *p = s, *e = s + len; p < e; cp++) {
		if      (is_utf8_2b(p[0]) && is_utf8_ct(p[1])) {
			*cp  = ((*p++ & 0x1f) <<  6);
			*cp |=  (*p++ & 0x3f);
		}
		else if (is_utf8_3b(p[0]) && is_utf8_ct(p[1]) &&
		         is_utf8_ct(p[2])) {
			*cp  = ((*p++ & 0x0f) << 12);
			*cp |= ((*p++ & 0x3f) <<  6);
			*cp |=  (*p++ & 0x3f);
		}
		else if (is_utf8_4b(p[0]) && is_utf8_ct(p[1]) &&
		         is_utf8_ct(p[2]) && is_utf8_ct(p[3])) {
			*cp  = ((*p++ & 0x07) << 18);
			*cp |= ((*p++ & 0x3f) << 12);
			*cp |= ((*p++ & 0x3f) <<  6);
			*cp |=  (*p++ & 0x3f);
		}
		else {
			*cp = *p++;
		}
	}

	line->width = cp - line->chars;

	return line->width;
}

static bool
term_line_setcur(termline_t *line, size_t pos)
{
	size_t columns = term_width();
	size_t from_row = (termstate.col_offset + line->pos) / columns;
	size_t from_col = ((termstate.col_offset + line->pos) % columns) + 1;
	size_t to_row = (termstate.col_offset + pos) / columns;
	size_t to_col = ((termstate.col_offset + pos) % columns) + 1;
	size_t len = 0;
	char buf[64];

	if (from_row > to_row)
		len = snprintf(buf, sizeof(buf), "\033[%zuA", from_row - to_row);
	else if (from_row < to_row)
		len = snprintf(buf, sizeof(buf), "\033[%zuB", to_row - from_row);

	if (from_col > to_col)
		len += snprintf(buf + len, sizeof(buf) - len,
			"\033[%zuD", from_col - to_col);
	else if (from_col < to_col)
		len += snprintf(buf + len, sizeof(buf) - len,
			"\033[%zuC", to_col - from_col);

	line->pos = pos;

	return (len == 0 || term_write(buf, len) == true);
}

static bool
term_line_clear(termline_t *line, size_t from)
{
	/* move cursor to initial position, erase screen after curser */
	return term_line_setcur(line, from) && term_print("\033[0J");
}

static bool
term_line_needlf(termline_t *line)
{
	return (((termstate.col_offset + line->width) % term_width()) == 0);
}

static bool
term_line_write(termline_t *line, size_t off)
{
	struct { size_t count; char *entries; } buf = { 0 };
	bool ret;

	for (size_t i = off; i < line->width; i++)
		uc_vector_addcp(&buf, line->chars[i]);

	ret = (buf.count == 0 || term_write(buf.entries, buf.count) == true);

	uc_vector_clear(&buf);

	/* if the printed string filled the entire line then print one more
	   character and erase it again in order to force scrolling to the next
	   line */
	if (term_line_needlf(line))
		ret &= term_print(" \033[1D\033[0K");

	line->pos = line->width;

	return ret;
}

static bool
term_line_cancel(termline_t *line)
{
	term_print("^C");
	term_line_setcur(line, line->width);
	term_print("\n");

	return true;
}

static bool
term_line_prevword(termline_t *line)
{
	if (line->width == 0)
		return true;

	/* find offset */
	size_t off = (line->pos < line->width) ? line->pos : line->width - 1;

	/* skip spaces before cursor */
	while (off > 0 && strchr(" \t", line->chars[off - 1]) != NULL)
		off--;

	/* skip non-whitespace before cursor */
	while (off > 0 && strchr(" \t", line->chars[off - 1]) == NULL)
		off--;

	return term_line_setcur(line, off);
}

static bool
term_line_nextword(termline_t *line)
{
	if (line->width == 0)
		return true;

	/* find offset */
	size_t off = (line->pos < line->width) ? line->pos : line->width - 1;

	/* skip spaces after cursor */
	while (off < line->width && strchr(" \t", line->chars[off]) != NULL)
		off++;

	/* skip non-whitespace after cursor */
	while (off < line->width && strchr(" \t", line->chars[off]) == NULL)
		off++;

	return term_line_setcur(line, off);
}

static bool
term_line_delchr(termline_t *line)
{
	if (line->pos >= line->width || line->width == 0)
		return true;

	/* remember original position */
	size_t pos = line->pos;

	/* move cursor before last char, erase */
	term_line_setcur(line, line->width - 1);
	term_print("\033[0K");

	/* move cursor to original position */
	term_line_setcur(line, pos);

	/* rearrange char buffer */
	for (size_t i = pos + 1; i < line->width; i++)
		line->chars[i-1] = line->chars[i];

	line->width--;

	/* re-write tail, will move cursor to eol */
	term_line_write(line, pos);

	/* reset cursor to original position */
	term_line_setcur(line, pos);

	return true;
}

static bool
term_line_delword(termline_t *line)
{
	if (line->width == 0)
		return true;

	/* find offset */
	size_t off = (line->pos < line->width) ? line->pos : line->width - 1;

	/* skip spaces before cursor */
	while (off > 0 && strchr(" \t", line->chars[off - 1]) != NULL)
		off--;

	/* skip non-whitespace before cursor */
	while (off > 0 && strchr(" \t", line->chars[off - 1]) == NULL)
		off--;

	/* calculate shift offset */
	size_t shift = line->pos - off;

	if (shift > 0) {
		/* erase everything after offset */
		term_line_clear(line, off);

		/* rearrange char buffer */
		for (size_t i = off + shift; i < line->width; i++)
			line->chars[i - shift] = line->chars[i];

		line->width -= shift;

		/* re-write tail, will move cursor to eol */
		term_line_write(line, off);

		/* reset cursor to offset position */
		term_line_setcur(line, off);
	}

	return true;
}

static bool
term_line_addchr(termline_t *line, uint32_t chr)
{
	if (line->width == line->size) {
		line->size += 128;
		line->chars = xrealloc(line->chars, line->size * sizeof(*line->chars));
	}

	size_t pos = line->pos;

	for (size_t i = line->width; i > pos; i--)
		line->chars[i] = line->chars[i-1];

	line->chars[pos] = chr;
	line->width++;

	/* write tail, will move cursor to eol */
	term_line_write(line, pos);

	/* restore cursor to original position + 1 */
	term_line_setcur(line, pos + 1);

	return true;
}

static int
qsort_strcmp(const void *a, const void *b)
{
	return strcmp(*(const char **)a, *(const char **)b);
}

static char *
common_prefix(suggestions_t *suggests)
{
	if (!suggests || suggests->count == 0 || *suggests->entries[0] == '\0')
		return NULL;

	char *prefix = xstrdup(suggests->entries[0]);
	size_t prefixlen = strlen(prefix);

	for (size_t i = 1; i < suggests->count; i++) {
		while (strncmp(suggests->entries[i], prefix, prefixlen) != 0) {
			prefix[--prefixlen] = '\0';

			if (prefixlen == 0) {
				free(prefix);

				return NULL;
			}
		}
	}

	return prefix;
}

static void
term_line_tabcomplete(termline_t *line, const char *prompt,
                      void (*cb)(size_t, arg_t *, suggestions_t *, void *),
                      void *ud)
{
	arg_t *argv = NULL;
	size_t argc = term_line_toargv(line, true, &argv);

	suggestions_t suggests = { 0 };

	cb(argc, argv, &suggests, ud);

	if (suggests.count > 1) {
		size_t longest = 0;

		for (size_t i = 0; i < suggests.count; i++) {
			size_t itemlen = strlen(suggests.entries[i]) + 2;

			if (itemlen > longest)
				longest = itemlen;
		}

		size_t cols = term_width() / longest;

		if (cols == 0)
			cols = 1;

		qsort(suggests.entries, suggests.count,
			sizeof(suggests.entries[0]), qsort_strcmp);

		term_print("\n");

		for (size_t row = 0; row < suggests.count; row += cols) {
			for (size_t col = 0; col < cols && row + col < suggests.count; col++)
				term_printf("%-*s", (int)longest, suggests.entries[row + col]);

			term_print("\n");
		}

		fflush(stdout);

		if (prompt)
			term_write(prompt, termstate.col_offset);
	}
	else {
		term_line_clear(line, 0);
	}

	char *prefix = common_prefix(&suggests);

	if (prefix) {
		if (argc > 0) {
			arg_t *partial = argv + argc - 1;

			term_line_fromstr(line, partial->off, prefix, strlen(prefix));
		}
		else {
			term_line_fromstr(line, line->width, prefix, strlen(prefix));
		}

		if (suggests.count == 1)
			term_line_fromstr(line, line->width, " ", 1);

		free(prefix);
	}

	term_line_write(line, 0);

	for (size_t i = 0; i < suggests.count; i++)
		free(suggests.entries[i]);

	uc_vector_clear(&suggests);

	for (size_t i = 0; i < argc; i++)
		free(argv[i].sv);

	free(argv);
}

static ssize_t
term_getline(const char *prompt, arg_t **argv,
             void (*completion_cb)(size_t, arg_t *, suggestions_t *, void *),
             void *ud)
{
	termline_t line = { 0 };
	termline_t *curr_line = &line;
	termline_t *next_line;

	if (prompt != NULL) {
		termstate.col_offset = strwidth(prompt);
		term_write(prompt, termstate.col_offset);
	}
	else {
		termstate.col_offset = 0;
	}

	while (true) {
		int chr = term_getc();

		switch (chr) {
		case HOME_KEY:
		case CTRL_UP:
			term_line_setcur(curr_line, 0);
			break;

		case END_KEY:
		case CTRL_DOWN:
			term_line_setcur(curr_line, curr_line->width);
			break;

		case DEL_KEY:
			term_line_delchr(curr_line);
			break;

		case PAGE_UP:
		case ARROW_UP:
			if (termstate.history.count > 0 &&
			    curr_line != uc_vector_first(&termstate.history)) {

				if (curr_line == &line)
					next_line = uc_vector_last(&termstate.history);
				else
					next_line = curr_line - 1;

				term_line_clear(curr_line, 0);
				term_line_write(next_line, 0);
				curr_line = next_line;
			}
			break;

		case PAGE_DOWN:
		case ARROW_DOWN:
			if (termstate.history.count > 0 && curr_line != &line) {
				if (curr_line == uc_vector_last(&termstate.history))
					next_line = &line;
				else
					next_line = curr_line + 1;

				term_line_clear(curr_line, 0);
				term_line_write(next_line, 0);
				curr_line = next_line;
			}
			break;

		case ARROW_LEFT:
			if (curr_line->pos > 0)
				term_line_setcur(curr_line, curr_line->pos - 1);
			break;

		case ARROW_RIGHT:
			if (curr_line->pos < curr_line->width)
				term_line_setcur(curr_line, curr_line->pos + 1);
			break;

		case CTRL_LEFT:
			term_line_prevword(curr_line);
			break;

		case CTRL_RIGHT:
			term_line_nextword(curr_line);
			break;

		case '\3': /* Ctrl-C */
			term_line_cancel(curr_line);

			*argv = NULL;

			return 0;

		case '\11': /* tab */
			if (completion_cb != NULL)
				term_line_tabcomplete(curr_line, prompt, completion_cb, ud);
			break;

		case '\15': /* carriage return */
			/* save to history if no other line was selected */
			if (curr_line == &line && curr_line->width > 0) {
				if (termstate.history.count >= HISTORY_SIZE) {
					free(termstate.history.entries[0].chars);

					for (size_t i = 1; i < termstate.history.count; i++)
						termstate.history.entries[i-1] =
							termstate.history.entries[i];

					termstate.history.count--;
				}

				uc_vector_push(&termstate.history, line);
			}

			term_print("\n");

			return term_line_toargv(curr_line, false, argv);

		case '\27': /* Ctrl-W */
			term_line_delword(curr_line);
			break;

		case '\177': /* backspace */
			if (curr_line->pos > 0) {
				term_line_setcur(curr_line, curr_line->pos - 1);
				term_line_delchr(curr_line);
			}
			break;

		default:
			if (chr >= ' ')
				term_line_addchr(curr_line, chr);
			break;
		}
	}

	*argv = NULL;

	return -1;
}

static uc_value_t *
uc_debug_sigint_handler(uc_vm_t *vm, size_t nargs);

static size_t
format_context_breadcrumb(uc_stringbuf_t *sb, uc_vm_t *vm, size_t maxcols)
{
	int off = sb->bpos;

	for (size_t i = 0; i < vm->callframes.count; i++) {
		uc_callframe_t *frame = &vm->callframes.entries[i];

		if (frame->cfunction != NULL &&
		    frame->cfunction->cfn == uc_debug_sigint_handler)
			continue;

		if (sb->bpos > off)
			printbuf_strappend(sb, " » ");

		printbuf_append_function(sb, vm,
			frame->closure
				? &frame->closure->header : &frame->cfunction->header,
			NULL, SIZE_MAX);
	}

	return printbuf_truncate(sb, off, maxcols, false);
}

static void
format_context_header_backtrace(uc_stringbuf_t *sb, uc_vm_t *vm)
{
	size_t columns = term_width();
	size_t filename_width = (columns >= 42) ? (columns - 2) / 4 : columns - 2;
	uc_callframe_t *frame = uc_debug_curr_frame(vm, 0);
	uc_source_t *source = uc_program_function_source(frame->closure->function);
	size_t printed = 0;

	cs(sb, &((style_t){ FG_BWHITE, BG_GRAY, 0 }));

	printbuf_strappend(sb, "[");
	printed += 2 + printbuf_append_srcpath(sb, source, filename_width);
	printbuf_strappend(sb, "]");

	if (columns - printed - 2 > 10) {
		printbuf_strappend(sb, " ");
		printed += 2 + format_context_breadcrumb(sb, vm, columns - printed - 2);
		printbuf_strappend(sb, " ");
	}

	printbuf_memset(sb, -1, ' ', columns - printed);

	cs(sb, NULL);
}

static void
format_context_header_callframe(uc_stringbuf_t *sb, uc_vm_t *vm,
                                uc_callframe_t *frame, size_t left_pad)
{
	size_t columns = term_width() - left_pad;
	size_t filename_width = (columns >= 42) ? (columns - 2) / 4 : columns - 2;
	size_t printed = 0;

	printbuf_memset(sb, -1, ' ', left_pad);

	cs(sb, &((style_t){ FG_BWHITE, BG_GRAY, 0 }));

	if (frame->closure) {
		uc_source_t *source = uc_program_function_source(frame->closure->function);

		printbuf_strappend(sb, "[");
		printed += 2 + printbuf_append_srcpath(sb, source, filename_width);
		printbuf_strappend(sb, "]");
	}
	else {
		printbuf_strappend(sb, "[C]");
		printed += 3;
	}

	if (columns - printed - 2 > 10) {
		printbuf_strappend(sb, " ");
		printed += 2 + printbuf_append_function(sb, vm,
			frame->closure ? &frame->closure->header : &frame->cfunction->header,
			frame, columns - printed - 2);
		printbuf_strappend(sb, " ");
	}

	printbuf_memset(sb, -1, ' ', columns - printed);

	cs(sb, NULL);
}

static bool have_highlighting = false;

static struct {
	fg_color_t color;
	char *start, *end;
} highlight_rules[] = {
	{ FG_GRAY, "^#!.*", NULL },

	/* declarations */
	{ FG_GREEN, "\\<(let|const|function|this)\\>", NULL },

	/* arrow functions */
	{ FG_GREEN, "(\\<\\w+\\>|\\([[:alnum:][:space:]_,.]*\\))[[:space:]]*=>", NULL },

	/* flow control */
	{ FG_BYELLOW, "\\<(while|if|else|elif|switch|case|default|for|in|endif|endfor|endwhile|endfunction)\\>", NULL },

	/* keywords */
	{ FG_BYELLOW, "\\<(export|import|try|catch|delete)\\>", NULL },

	/* exit points */
	{ FG_MAGENTA, "\\<(break|continue|return)\\>", NULL },

	/* numeric literals */
	{ FG_CYAN, "\\<([0-9]+\\.[0-9]+([eE][+-]?[0-9]+)?|[0-9]+[eE][+-]?[0-9]+)\\>", NULL },
	{ FG_CYAN, "\\<0[xX][[:xdigit:]]+(\\.[[:xdigit:]]+)?\\>", NULL },
	{ FG_CYAN, "\\<(0[oO][0-7]+|0[bB][01]+|[0-9]+)\\>", NULL },

	/* special values */
	{ FG_CYAN, "\\<(true|false|null|NaN|Infinity)\\>", NULL },

	/* strings */
	{ FG_BMAGENT, "\"([^\"\\{%#}]|\\\\.|\\{[^\"\\{%#]|[%#}][^\"\\}]|[{%#}]\\\\.)*[{%#}]?\"", NULL },
	{ FG_BMAGENT, "'([^'\\{%#}]|\\\\.|\\{[^'\\{%#]|[%#}][^'\\}]|[{%#}]\\\\.)*[{%#}]?'", NULL },
	{ FG_BMAGENT, "`([^`\\{%#}]|\\\\.|\\{[^`\\{%#]|[%#}][^`\\}]|[{%#}]\\\\.)*[{%#}]?`", NULL },

	/* template string expressions */
	{ FG_BWHITE, "\\$\\{", "}" },

	/* comments */
	{ FG_BBLUE, "(^|[[:blank:]])//.*", NULL },
	{ FG_BBLUE, "(^|[[:space:]])/\\*", "\\*/" },
	{ FG_BBLUE, "\\{#", "#\\}" },

	/* text outside template directives */
	{ FG_GRAY, "[}%#]\\}", "\\{[{%#]" },
	{ FG_GRAY, "^#!.*(\\<utpl\\>|[[:space:]]-[[:alnum:]]*T[[:alnum:]]*\\>)", "\\{[{%#]" },
	{ FG_GRAY, "^([^{%#}]|\\{[^{%#]|[%#}][^}])+\\{[{%#]", NULL },

	/* template tags */
	{ FG_BWHITE, "\\{[{%][+-]?|-?[%}]\\}", NULL },
	{ FG_BBLUE, "\\{#[+-]?|-?#\\}", NULL },
};

static bool
compile_patterns(void)
{
	regex_t *re = NULL;
	int err = 0;

	if (termstate.patterns.count > 0)
		return true;

	for (size_t i = 0; i < ARRAY_SIZE(highlight_rules); i++) {
		re = uc_vector_add(&termstate.patterns, { 0 });
		err = regcomp(re, highlight_rules[i].start, REG_EXTENDED);

		if (err != 0)
			goto err;

		re = uc_vector_add(&termstate.patterns, { 0 });

		if (highlight_rules[i].end) {
			err = regcomp(re, highlight_rules[i].end, REG_EXTENDED);

			if (err != 0)
				goto err;
		}
	}

	return true;

err:
	char errbuf[128];
	regerror(err, re, errbuf, sizeof(errbuf));
	fprintf(stderr, "Regex error: %s\n", errbuf);

	for (size_t i = 0; i < termstate.patterns.count; i++) {
		regex_t *re = &termstate.patterns.entries[i];
		if (re) regfree(re);
	}

	uc_vector_clear(&termstate.patterns);

	return false;
}

typedef struct {
	uint32_t style;
	size_t from, to;
} style_range_t;

typedef struct {
	size_t count;
	style_range_t *entries;
} style_ranges_t;

typedef struct {
	size_t from, to;
} line_range_t;

static void
print_source_location(uc_stringbuf_t *sb, uc_vm_t *vm, uc_source_t *source,
                      size_t nranges, line_range_t *ranges, insn_span_t *hl,
                      size_t left_pad)
{
	size_t columns = term_width() - left_pad;
	off_t offset = ftello(source->fp);

	fseeko(source->fp, 0, SEEK_SET);

	size_t linesize = 0, byte_pos = 0, start_line = SIZE_MAX, end_line = 0;
	size_t hl_start = hl ? hl->pos_start : SIZE_MAX;
	size_t cursor_pos = hl ? hl->pos_ip : SIZE_MAX;
	size_t hl_end = hl ? hl->pos_end : SIZE_MAX;
	style_t style = { FG_BWHITE, BG_BLACK, 0 };
	regex_t *ml_rule_re_end = NULL;
	uint32_t ml_rule_color = 0;
	ssize_t last_indent = -1;
	char *linestr = NULL;

	for (size_t i = 0; i < nranges; i++) {
		if (ranges[i].from == 0 || ranges[i].to == 0)
			continue;

		if (ranges[i].from < start_line)
			start_line = ranges[i].from;

		if (ranges[i].to > end_line)
			end_line = ranges[i].to;
	}

	for (size_t linenum = 1; linenum <= end_line; linenum++) {
		ssize_t linelen = fgetline(source->fp, &linestr, &linesize);

		struct {
			size_t count;
			struct { fg_color_t color; ssize_t from, to; } *entries;
		} colors = { 0 };

		if (linelen == -1)
			break;

		/* apply highlighting rules */
		if (have_highlighting) {
			size_t ml_rule_from;
			regmatch_t m;
			char *p;
			int rf;

			/* apply single line matches */
			for (size_t i = 0; i < ARRAY_SIZE(highlight_rules); i++) {
				regex_t *re = &termstate.patterns.entries[i * 2];

				/* only consider single line matches */
				if (highlight_rules[i].end != NULL)
					continue;

				for (rf = 0, p = linestr;
				     regexec(re, p, 1, &m, rf) == 0;
				     rf = REG_NOTBOL, p += m.rm_eo)
				{
					uc_vector_add(&colors, {
						.color = highlight_rules[i].color,
						.from  = p + m.rm_so - linestr,
						.to    = p + m.rm_eo - linestr
					});
				}
			}

			/* apply multi line matches */
			for (rf = 0, p = linestr, ml_rule_from = 0;
			     rf == 0 || ml_rule_re_end != NULL;
			     rf = REG_NOTBOL) {

				/* handle unterminated multiline matches */
				if (ml_rule_re_end != NULL) {
					/* end match found on this line, colorize until match */
					if (regexec(ml_rule_re_end, p, 1, &m, 0) == 0) {
						uc_vector_add(&colors, {
							.color = ml_rule_color,
							.from  = ml_rule_from,
							.to    = p + m.rm_eo - linestr
						});

						ml_rule_re_end = NULL;
						ml_rule_color = 0;
						ml_rule_from = 0;
						p += m.rm_eo;
					}

					/* no end match, colorize entire remainder and skip rest */
					else {
						uc_vector_add(&colors, {
							.color = ml_rule_color,
							.from  = ml_rule_from,
							.to    = linelen
						});

						break;
					}
				}

				/* look for next multiline start match */
				for (size_t i = 0; i < ARRAY_SIZE(highlight_rules); i++) {
					regex_t *re_start = &termstate.patterns.entries[i * 2];
					regex_t *re_end = &termstate.patterns.entries[i * 2 + 1];

					/* only consider multi line rules */
					if (highlight_rules[i].end == NULL)
						continue;

					/* found another multi line start */
					if (regexec(re_start, p, 1, &m, rf) == 0) {
						ml_rule_re_end = re_end;
						ml_rule_color = highlight_rules[i].color;
						ml_rule_from = p + m.rm_so - linestr;
						p += m.rm_eo;
						break;
					}
				}
			}
		}

		bool print_line = false, more_lines = false;

		for (size_t i = 0; i < nranges; i++) {
			if (ranges[i].from == 0 || ranges[i].to == 0)
				continue;

			print_line |= (linenum >= ranges[i].from && linenum <= ranges[i].to);
			more_lines |= (ranges[i].from > start_line && ranges[i].from == linenum + 1);
		}

		if (!print_line) {
			uc_vector_clear(&colors);
			byte_pos += linelen;

			if (more_lines) {
				printbuf_memset(sb, -1, ' ', left_pad);
				cs(sb, &((style_t){ FG_GRAY, BG_BLACK, FAINT }));
				printbuf_strappend(sb, "   … ");
				printbuf_memset(sb, -1, ' ', last_indent);
				printbuf_strappend(sb, "…");
				printbuf_memset(sb, -1, ' ', columns - 6 - last_indent);
				cs(sb, &((style_t){ FG_BWHITE, BG_BLACK, 0 }));
				printbuf_strappend(sb, "\n");
			}

			continue;
		}

		if (linelen > 0 && linestr[linelen - 1] == '\n')
			linelen--;

		size_t trunc = 0;

		/* determine display width of line and whether it is too long */
		for (size_t i = 0, c = 0; i < (size_t)linelen; i++) {
			c += (linestr[i] == '\t') ? 4 : 1;

			if (columns > 6 && c > columns - 6) {
				trunc = linelen - i;
				linelen = i;
				break;
			}
		}

		size_t linecols = 0;

		printbuf_memset(sb, -1, ' ', left_pad);
		cs(sb, &((style_t){ FG_GRAY, BG_BLACK, FAINT }));
		sprintbuf(sb, "%4zu ", linenum);
		cs(sb, &style);

		last_indent = -1;

		/* format line (substitute tabs and ctrls with placeholders) */
		for (ssize_t i = 0; i < linelen; i++, byte_pos++) {
			style_t newstyle = {
				.fg = FG_BWHITE,
				.bg = (byte_pos >= hl_start && byte_pos < hl_end)
					? BG_GRAY : BG_BLACK,
				.styles = (cursor_pos == byte_pos) ? ULINE : 0
			};

			for (size_t j = 0; j < colors.count; j++)
				if (colors.entries[j].from <= i && colors.entries[j].to > i)
					newstyle.fg = colors.entries[j].color;

			if (memcmp(&style, &newstyle, sizeof(style))) {
				style = newstyle;
				cs(sb, &style);
			}

			if (linestr[i] == '\t') {
				linecols += 4;
				cs(sb, &((style_t){ FG_BBLACK, style.bg, FAINT }));
				printbuf_strappend(sb, "<-> ");
				cs(sb, &style);
			}
			else if (linestr[i] < ' ' || linestr[i] == 0x7f) {
				linecols++;
				cs(sb, &((style_t){ FG_BBLACK, style.bg, FAINT }));
				printbuf_strappend(sb, ".");
				cs(sb, &style);
			}
			else {
				if (last_indent == -1)
					last_indent = linecols;

				linecols++;
				printbuf_memappend_fast(sb, linestr + i, 1);
			}
		}

		/* reset char styles */
		style.styles = 0;
		style.bg = (byte_pos >= hl_start &&
		            byte_pos + trunc <= hl_end) ? BG_GRAY : BG_BLACK;
		cs(sb, &style);

		/* if truncated, add ellipsis */
		if (trunc > 0) {
			if (linecols < columns - 6)
				printbuf_memset(sb, -1, ' ', (columns - 6) - linecols);

			printbuf_strappend(sb, "…");
			byte_pos += trunc;
		}

		/* if shorter than display width, pad with trailing spaces */
		else if (linecols < columns - 5) {
			if (linestr[linelen] == '\n') {
				printbuf_memset(sb, -1, ' ', 1);
				linecols++;
			}

			if (style.bg != BG_BLACK) {
				style.bg = BG_BLACK;
				cs(sb, &style);
			}

			printbuf_memset(sb, -1, ' ', (columns - 5) - linecols);
		}

		cs(sb, &((style_t){ 0, 0, 0 }));
		printbuf_strappend(sb, "\n");

		uc_vector_clear(&colors);

		byte_pos++;
	}

	free(linestr);

	fseeko(source->fp, offset, SEEK_SET);
}

static void
format_context_statement(uc_stringbuf_t *sb, uc_vm_t *vm,
                         uc_function_t *fn, insn_span_t *stmt,
                         size_t ctx_before, size_t ctx_after, size_t left_pad)
{
	size_t beg_line = 1, beg_off = 0, end_line = 1, end_off = 0, ip_line = 1;
	uc_source_t *source = uc_program_function_source(fn);
	uc_lineinfo_t *lines = &source->lineinfo;

	/* determine start and end byte position of first and last statement line */
	for (size_t i = 0, lineoff = 0; i < lines->count; i++) {
		// FIXME: >= stmt->pos_start ?
		if (end_off <= stmt->pos_start &&
		    end_off + (lines->entries[i] & 0x7f) > stmt->pos_start)
		{
			beg_line = end_line;
			beg_off = lineoff;
		}

		if (end_off <= stmt->pos_ip &&
		    end_off + (lines->entries[i] & 0x7f) >= stmt->pos_ip)
		{
			ip_line = end_line;
		}

		if (i > 0 && lines->entries[i] & 0x80) {
			end_line++;
			end_off++;
			lineoff = end_off;

			if (end_off >= stmt->pos_end)
				break;
		}

		end_off += lines->entries[i] & 0x7f;
	}

	if (beg_off >= end_off)
		return;

	line_range_t ranges[3] = { 0 };

	if (end_line - beg_line <= 4) {
		ranges[0].from = beg_line;
		ranges[0].to = end_line;
	}
	else {
		if (ip_line - beg_line <= (ctx_before + ctx_after + 2)) {
			ranges[1].from = beg_line;
		}
		else {
			ranges[0].from = beg_line;
			ranges[0].to = beg_line + ctx_after;

			ranges[1].from = ip_line - ctx_before;
		}

		if (end_line - ip_line <= (ctx_before + ctx_after + 2)) {
			ranges[1].to = end_line;
		}
		else {
			ranges[1].to = ip_line + ctx_after;

			ranges[2].from = end_line - ctx_before;
			ranges[2].to = end_line;
		}
	}

	print_source_location(sb, vm, source, 3, ranges, stmt, left_pad);
}

static void
format_context_cfunction(uc_stringbuf_t *sb, uc_vm_t *vm,
                         uc_cfunction_t *cfn, size_t left_pad)
{
	void *loadaddr = NULL, *symaddr = NULL;
	const char *filename = "Not available";
	const char *symname = "Not available";
	size_t columns = term_width() - left_pad;
	Dl_info dli;
	int n;

	if (dladdr(cfn->cfn, &dli)) {
		if (dli.dli_fname)
			filename = dli.dli_fname;

		if (dli.dli_sname)
			symname = dli.dli_sname;

		loadaddr = dli.dli_fbase;
		symaddr = dli.dli_saddr;
	}

	printbuf_memset(sb, -1, ' ', left_pad);
	cs(sb, &((style_t){ FG_BWHITE, BG_BLACK, FAINT }));
	n = sprintbuf(sb, "  Dynamic library: %s (%p)", filename, loadaddr);
	printbuf_memset(sb, -1, ' ', columns - n);
	cs(sb, NULL);
	printbuf_strappend(sb, "\n");

	printbuf_memset(sb, -1, ' ', left_pad);
	cs(sb, &((style_t){ FG_BWHITE, BG_BLACK, FAINT }));
	n = sprintbuf(sb, "  Symbol name:     %s (%p)", symname, symaddr);
	printbuf_memset(sb, -1, ' ', columns - n);
	cs(sb, NULL);
	printbuf_strappend(sb, "\n");
}

// FIXME: read beyond end of array
static int32_t
insn_s32(uint8_t *ip)
{
	return (
		ip[0] * 0x1000000UL +
		ip[1] * 0x10000UL +
		ip[2] * 0x100UL +
		ip[3]
	) - 0x7fffffff;
}

static uint32_t
insn_u32(uint8_t *ip)
{
	return (
		ip[0] * 0x1000000UL +
		ip[1] * 0x10000UL +
		ip[2] * 0x100UL +
		ip[3]
	);
}

static uint32_t
insn_u16(uint8_t *ip)
{
	return (
		ip[0] * 0x100UL +
		ip[1]
	);
}

static size_t
insn_length(uint8_t *ip, uc_program_t *prog)
{
	if (*ip == I_CALL || *ip == I_QCALL || *ip == I_MCALL || *ip == I_QMCALL)
		return 5 + insn_u16(ip + 1) * 2;

	if (*ip == I_CLFN || *ip == I_ARFN) {
		uint32_t u32 = insn_u32(ip + 1);
		size_t i = 1;
		uc_program_function_foreach(prog, fn)
			if (i++ == u32)
				return 5 + fn->nupvals * 4;
	}

	return 1 + abs(uc_vm_insn_format[*ip]);
}

static void
bk_enter_function(uc_vm_t *vm, uc_breakpoint_t *bk)
{
	debug_breakpoint_t *dbk = (debug_breakpoint_t *)bk;
	uc_callframe_t *frame = uc_debug_curr_frame(vm, 0);
	uint8_t *ip = frame->ip;
	uint32_t argspec = 0;
	bool enter = false;

	assert(dbk->kind == BK_STEP);

	if (*ip == I_MCALL || *ip == I_QMCALL) {
		argspec = insn_u32(ip + 1);

		size_t nargs = argspec & 0xffff;

		if (nargs + 2 < vm->stack.count) {
			uc_value_t *ctx = vm->stack.entries[vm->stack.count - nargs - 2];
			uc_value_t *key = vm->stack.entries[vm->stack.count - nargs - 1];
			uc_value_t *fno = ucv_key_get(vm, ctx, key);

			ucv_put(fno); /* ucv_get_get() increases refcount */

			if (ucv_type(fno) == UC_UPVALUE) {
				uc_upvalref_t *ref = (uc_upvalref_t *)fno;

				if (ref->closed)
					fno = ref->value;
				else
					fno = vm->stack.entries[ref->slot];
			}

			if (ucv_type(fno) == UC_CLOSURE) {
				uc_function_t *fn = ((uc_closure_t *)fno)->function;

				dbk->bk.cb = bk_enter_cli;
				dbk->bk.ip = fn->chunk.entries;
				dbk->depth = 1;
				dbk->fn = fn;
				enter = true;
			}
		}
	}
	else if (*ip == I_CALL || *ip == I_QCALL) {
		argspec = insn_u32(ip + 1);

		size_t nargs = argspec & 0xffff;

		if (nargs + 1 < vm->stack.count) {
			uc_value_t *fno = vm->stack.entries[vm->stack.count - nargs - 1];

			if (ucv_type(fno) == UC_CLOSURE) {
				uc_function_t *fn = ((uc_closure_t *)fno)->function;

				dbk->bk.cb = bk_enter_cli;
				dbk->bk.ip = fn->chunk.entries;
				dbk->depth = 1;
				dbk->fn = fn;
				enter = true;
			}
		}
	}

	if (!enter) {
		dbk->bk.cb = bk_enter_cli;
		dbk->bk.ip = NULL;
		dbk->depth = 0;
		dbk->fn = NULL;
	}
}

static void
bk_leave_function(uc_vm_t *vm, uc_breakpoint_t *bk)
{
	debug_breakpoint_t *dbk = (debug_breakpoint_t *)bk;
	uc_callframe_t *frame = uc_debug_curr_frame(vm, 1);

	assert(dbk->kind == BK_STEP);

	term_print("Leaving function!\n");

	if (!frame)
		return;

	dbk->bk.cb = bk_enter_cli;
	dbk->bk.ip = frame->ip;
	dbk->depth = 0;
	dbk->fn = frame->closure->function;
}

static void
bk_follow_jump(uc_vm_t *vm, uc_breakpoint_t *bk)
{
	debug_breakpoint_t *dbk = (debug_breakpoint_t *)bk;
	uc_callframe_t *frame = uc_debug_curr_frame(vm, 0);
	uc_program_t *prog = frame->closure->function->program;
	uc_chunk_t *chunk = &frame->closure->function->chunk;
	size_t off = frame->ip - chunk->entries;
	uint8_t *ip = frame->ip;

	assert(dbk->kind == BK_STEP);

	/* skip conditional jmpz if conditition is true */
	if (*ip == I_JMPZ && ucv_is_truish(uc_vm_stack_peek(vm, 0))) {
		off += insn_length(ip, prog);
	}

	/* otherwise follow jump */
	else {
		int32_t addr = insn_s32(ip + 1);

		if ((addr < 0 && (size_t)-addr > off) ||
		    (addr >= 0 && (size_t)addr >= chunk->count))
		{
			term_print("Jump target out of range\n");
			off += insn_length(ip, prog);
		}
		else {
			off += addr;
		}
	}

	/* if the next offset is a jump instruction as well, then don't install
	   interactive breakpoint but re-invoke this breakpoint handler */
	if (chunk->entries[off] == I_JMP || chunk->entries[off] == I_JMPZ)
		dbk->bk.cb = bk_follow_jump;
	else
		dbk->bk.cb = bk_enter_cli;

	dbk->bk.ip = chunk->entries + off;
	dbk->depth = 0;
	dbk->fn = frame->closure->function;
}

static void
bk_handle_catch(uc_vm_t *vm, uc_breakpoint_t *bk)
{
#define exname(x) [EXCEPTION_##x] = "EXCEPTION_" #x
	const char *exnames[] = {
		exname(NONE),
		exname(SYNTAX),
		exname(RUNTIME),
		exname(TYPE),
		exname(REFERENCE),
		exname(USER),
		exname(EXIT)
	};
#undef exname

	term_print("Exception occurred!\n");
	term_printf("Type:    %s\n", exnames[vm->exception.type]);
	term_printf("Message: %s\n", vm->exception.message);

	bk_enter_cli(vm, bk);
}

static uint8_t *
next_step(uc_vm_t *vm, uc_function_t **fnp, uint8_t *ip, bool single, size_t *depthp)
{
	insn_span_t stmt, next;

	if (find_statement_boundaries(*fnp, ip, 0, &stmt)) {
		uc_program_t *prog = (*fnp)->program;

		for (uint8_t *p = ip; p < stmt.ip_end; p += insn_length(p, prog)) {
			switch (*p) {
			case I_CALL:
			case I_QCALL:
			case I_MCALL:
			case I_QMCALL:
				if (single) {
					update_breakpoint(vm, BK_STEP, bk_enter_function, p, *fnp, 0);

					return NULL;
				}

				break;

			case I_RETURN:
				if (single) {
					update_breakpoint(vm, BK_STEP, bk_leave_function, p, *fnp, 0);

					return NULL;
				}

				break;

			case I_JMP:
			case I_JMPZ:
				update_breakpoint(vm, BK_STEP, bk_follow_jump, p, *fnp, 0);

				return NULL;
			}
		}

		while (find_statement_boundaries(*fnp, stmt.ip_end, 0, &next)) {
			/* if next statement fully contains our statement, continue */
			if (next.ip_start <= stmt.ip_start && next.ip_end >= stmt.ip_end) {
				fprintf(stderr, "Redo %zu..%zu -> %zu..%zu\n",
					stmt.pos_start, stmt.pos_end, next.pos_start, next.pos_end);
				stmt = next;
				continue;
			}

			*depthp = next.nesting;

			return next.ip_start;
		}
	}

	term_print("No next statement, continuing in parent\n");

	*depthp = 0;

	return next_parent(vm, fnp);
}

static uc_value_t *
load_constval(uc_value_list_t *vallist, size_t cidx)
{
	uc_value_type_t t = (cidx < vallist->isize)
		? (vallist->index[cidx] & 7) : TAG_INVAL;

	if (t == TAG_STR) {
		char buf[sizeof(vallist->index[0])] = { 0 };
		size_t len = (vallist->index[cidx] >> 3) & 31;

		for (size_t j = 1; j <= len; j++)
			buf[j-1] = (vallist->index[cidx] >> (j << 3));

		return ucv_string_new_length(buf, len);
	}
	else if (t == TAG_LSTR) {
		size_t off = (vallist->index[cidx] >> 3);

		if (off + sizeof(uint32_t) <= vallist->dsize) {
			char *p = vallist->data + off;
			size_t len = be32toh(*(uint32_t *)p);

			if (off + sizeof(uint32_t) + len <= vallist->dsize)
				return ucv_string_new_length(p + sizeof(uint32_t), len);
		}
	}
	else if (t == TAG_DBL) {
		size_t off = (vallist->index[cidx] >> 3);

		if (off + sizeof(double) <= vallist->dsize)
			return ucv_double_new(uc_double_unpack(vallist->data + off, false));
	}
	else if (t == TAG_NUM) {
		return ucv_uint64_new(vallist->index[cidx] >> 3);
	}
	else if (t == TAG_LNUM) {
		size_t off = (vallist->index[cidx] >> 3);

		if (off + sizeof(uint64_t) <= vallist->dsize)
			return ucv_uint64_new(be64toh(*(uint64_t *)(vallist->data + off)));
	}

	return NULL;
}

static void
print_variables(uc_stringbuf_t *buf, uc_vm_t *vm, uc_callframe_t *frame,
                bool verbose, const char *indent)
{
	uc_chunk_t *chunk = &frame->closure->function->chunk;
	uc_variables_t *decls = &chunk->debuginfo.variables;
	uc_value_list_t *names = &chunk->debuginfo.varnames;
	size_t columns = term_width() - strlen(indent);
	size_t pos = frame->ip - chunk->entries;

	if (frame->ctx) {
		printbuf_memappend_fast(buf, indent, strlen(indent));

		cs(buf, &((style_t){ FG_BWHITE, 0, FAINT }));
		printbuf_strappend(buf, "(this)           : ");
		cs(buf, NULL);

		if (verbose)
			ucv_to_stringbuf_formatted(vm, buf, frame->ctx, 0, ' ', 2);
		else
			printbuf_append_uv(buf, vm, frame->ctx, columns - 19);

		printbuf_strappend(buf, "\n");
	}

	for (size_t i = 0; i < decls->count; i++) {
		if (decls->entries[i].from > pos || decls->entries[i].to < pos)
			continue;

		uc_value_t *vname = load_constval(names, decls->entries[i].nameidx);
		size_t slot = decls->entries[i].slot;

		printbuf_memappend_fast(buf, indent, strlen(indent));

		/* is local variable */
		if (slot < (size_t)-1 / 2) {
			bool is_internal = (vname && *ucv_string_get(vname) == '(');

			if (is_internal)
				cs(buf, &((style_t){ FG_BWHITE, 0, FAINT }));

			int n, off = buf->bpos;

			if (vname)
				n = sprintbuf(buf, "%s", ucv_string_get(vname));
			else
				n = sprintbuf(buf, "$%zu", slot);

			printbuf_truncate(buf, off, 16, true);

			if (is_internal)
				cs(buf, NULL);

			if (n < 16)
				printbuf_memset(buf, -1, ' ', 16 - n);

			cs(buf, &((style_t){ FG_BWHITE, 0, FAINT }));
			printbuf_strappend(buf, " : ");
			cs(buf, NULL);

			if (frame->stackframe + slot < vm->stack.count) {
				uc_value_t *vval = vm->stack.entries[frame->stackframe + slot];

				if (verbose)
					ucv_to_stringbuf_formatted(vm, buf, vval, 0, ' ', 2);
				else
					printbuf_append_uv(buf, vm, vval, columns - 19);
			}
			else {
				cs(buf, &((style_t){ FG_RED, 0, BOLD }));
				printbuf_strappend(buf, "<out of range>");
				cs(buf, NULL);
			}
		}

		/* is upvalue */
		else {
			cs(buf, &((style_t){ FG_CYAN, 0, BOLD }));

			int n, off = buf->bpos;

			if (vname)
				n = sprintbuf(buf, "%s", ucv_string_get(vname));
			else
				n = sprintbuf(buf, "$%zu", slot);

			printbuf_truncate(buf, off, 16, true);
			cs(buf, NULL);

			if (n < 16)
				printbuf_memset(buf, -1, ' ', 16 - n);

			cs(buf, &((style_t){ FG_BWHITE, 0, FAINT }));
			printbuf_strappend(buf, " : ");
			cs(buf, NULL);

			slot -= ((size_t)-1 / 2);

			if (slot < frame->closure->function->nupvals) {
				uc_upvalref_t *ref = frame->closure->upvals[slot];

				if (!ref) {
					cs(buf, &((style_t){ FG_BWHITE, 0, FAINT }));
					printbuf_strappend(buf, "<not initialized>");
					cs(buf, NULL);
				}
				else if (ref->closed) {
					uc_value_t *vval = ref->value;

					if (verbose)
						ucv_to_stringbuf_formatted(vm, buf, vval, 0, ' ', 2);
					else
						printbuf_append_uv(buf, vm, vval, columns - 19);
				}
				else if (ref->slot < vm->stack.count) {
					uc_value_t *vval = vm->stack.entries[ref->slot];

					if (verbose)
						ucv_to_stringbuf_formatted(vm, buf, vval, 0, ' ', 2);
					else
						printbuf_append_uv(buf, vm, vval, columns - 19);
				}
				else {
					cs(buf, &((style_t){ FG_RED, 0, BOLD }));
					printbuf_strappend(buf, "<out of range>");
					cs(buf, NULL);
				}
			}
			else {
				cs(buf, &((style_t){ FG_RED, 0, BOLD }));
				printbuf_strappend(buf, "<out of range>");
				cs(buf, NULL);
			}
		}

		ucv_put(vname);

		printbuf_strappend(buf, "\n");
	}
}

static bool
eval_expr(uc_vm_t *vm, uc_callframe_t *frame, char *expr, uc_value_t **res)
{
	uc_chunk_t *caller_chunk = &frame->closure->function->chunk;
	uc_variables_t *decls = &caller_chunk->debuginfo.variables;
	uc_value_list_t *names = &caller_chunk->debuginfo.varnames;
	size_t pos = frame->ip - caller_chunk->entries;
	char *err = NULL;

	uc_source_t *source =
		uc_source_new_buffer("[eval expression]", xstrdup(expr), strlen(expr));

	uc_parse_config_t conf = { .raw_mode = true };
	uc_program_t *prog = uc_compile(&conf, source, &err);

	uc_source_put(source);

	if (!prog) {
		term_printf("%s", err);
		free(err);
		*res = NULL;

		return false;
	}

	uc_value_t *exprfn = ucv_closure_new(vm, uc_program_entry(prog), false);
	uc_chunk_t *chunk = &((uc_closure_t *)exprfn)->function->chunk;

	if (chunk->entries[0] != I_LVAR && chunk->entries[0] != I_LTHIS) {
		term_print("Expecting expression\n");
		uc_program_put(prog);
		ucv_put(exprfn);
		*res = NULL;

		return false;
	}

	uc_value_t *scope = ucv_object_new(NULL);

	/* determine referenced variables */
	for (size_t i = 0; i < chunk->count; i += insn_length(&chunk->entries[i], prog)) {
		if (chunk->entries[i] != I_LVAR)
			continue;

		uc_value_t *varname = load_constval(
			&prog->constants,
			insn_u32(chunk->entries + i + 1));

		if (!varname)
			continue;

		uc_value_t *varval = NULL;

		for (size_t j = 0; !varval && j < decls->count; j++) {
			if (decls->entries[j].from > pos || decls->entries[j].to < pos)
				continue;

			uc_value_t *vname = load_constval(names, decls->entries[j].nameidx);
			bool match = ucv_is_equal(varname, vname);

			ucv_put(vname);

			if (!match)
				continue;

			size_t slot = decls->entries[j].slot;

			/* is local var */
			if (slot < (size_t)-1 / 2) {
				slot += frame->stackframe;

				if (slot < vm->stack.count)
					varval = ucv_get(vm->stack.entries[slot]);
			}

			/* is upvalue */
			else {
				slot -= ((size_t)-1 / 2);

				if (slot < frame->closure->function->nupvals) {
					uc_upvalref_t *ref = frame->closure->upvals[slot];

					if (ref && ref->closed)
						varval = ucv_get(ref->value);
					else if (ref && ref->slot < vm->stack.count)
						varval = ucv_get(vm->stack.entries[ref->slot]);
				}
			}
		}

		if (varval)
			ucv_object_add(scope, ucv_string_get(varname), varval);

		ucv_put(varname);
	}

	uc_value_t *prev_scope = ucv_get(uc_vm_scope_get(vm));

	ucv_prototype_set(scope, ucv_get(prev_scope));

	uc_vm_scope_set(vm, scope);

	/* Save VM callframes and stack */
	uc_upvalref_t *upvals = vm->open_upvals;
	uc_callframes_t frames = vm->callframes;
	uc_stack_t stack = vm->stack;

	vm->open_upvals = NULL;

	vm->callframes.count = 0;
	vm->callframes.entries = NULL;

	vm->stack.count = 0;
	vm->stack.entries = NULL;

	uc_vm_stack_push(vm, ucv_get(frame->ctx));
	uc_vm_stack_push(vm, ucv_get(exprfn));

	bool rv;

	if (uc_vm_call(vm, true, 0) == EXCEPTION_NONE) {
		*res = uc_vm_stack_pop(vm);
		rv = true;
	}
	else {
		term_printf("Exception: %s\n", vm->exception.message);
		vm->exception.type = EXCEPTION_NONE;
		*res = NULL;
		rv = false;
	}

	uc_vector_clear(&vm->callframes);
	uc_vector_clear(&vm->stack);

	/* Restore VM callframes and stack */
	vm->open_upvals = upvals;
	vm->callframes = frames;
	vm->stack = stack;

	uc_vm_scope_set(vm, prev_scope);
	uc_program_put(prog);
	ucv_put(exprfn);

	return rv;
}

static void
update_catchpoint(uc_vm_t *vm, uc_function_t *fn, uint8_t *ip)
{
	uc_ehranges_t *eh = &fn->chunk.ehranges;
	size_t off = ip - fn->chunk.entries;

	for (size_t i = 0; i < eh->count; i++) {
		if (off >= eh->entries[i].from && off < eh->entries[i].to) {
			update_breakpoint(vm, BK_CATCH, bk_handle_catch,
				fn->chunk.entries + eh->entries[i].target, fn, 0);

			break;
		}
	}
}

static void
print_location(uc_vm_t *vm, const char *prefix, debug_breakpoint_t *dbk)
{
	uc_callframe_t *topframe = NULL, *funframe = NULL;
	size_t depth = dbk->depth;

	for (size_t i = vm->callframes.count; i > 0; i--) {
		if (!topframe || (topframe->cfunction &&
		                  topframe->cfunction->cfn == uc_debug_sigint_handler))
			topframe = &vm->callframes.entries[i - 1];

		if (vm->callframes.entries[i - 1].closure) {
			funframe = &vm->callframes.entries[i - 1];

			/* Update location in automatic function breakpoint */
			if (dbk->fn == NULL) {
				dbk->fn = funframe->closure->function;
				dbk->bk.ip = funframe->ip;
			}

			/* Update exception catch point */
			update_catchpoint(vm, funframe->closure->function, funframe->ip);
			break;
		}
	}

	uc_stringbuf_t *pb = xprintbuf_new();

	printbuf_memappend_fast(pb, prefix, strlen(prefix));

	if (funframe) {
		uc_function_t *function = funframe->closure->function;
		uc_source_t *source = uc_program_function_source(function);
		insn_span_t stmt;

		if (find_statement_boundaries(function, funframe->ip, depth, &stmt)) {
			size_t byte = stmt.pos_start;
			size_t line = uc_source_get_line(source, &byte);

			sprintbuf(pb, "%s, line %zu:%zu\n",
				source->filename, line, byte);

			format_context_header_backtrace(pb, vm);
			format_context_statement(pb, vm, function, &stmt, 2, 2, 0);
		}
	}
	else if (topframe) {
		if (topframe->cfunction->name[0])
			sprintbuf(pb, "native function %s()\n", topframe->cfunction->name);
		else
			printbuf_strappend(pb, "unnamed native function\n");
	}
	else {
		printbuf_strappend(pb, "[unknown location]\n");
	}

	printbuf_strappend(pb, "\n");
	term_write(pb->buf, pb->bpos);

	printbuf_free(pb);
}

static bool
cmd_help(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv)
{
	char *cmd = (argc > 1) ? argv[1].sv : NULL;
	size_t columns = term_width();

	for (size_t i = 0; i < ARRAY_SIZE(commands); i++) {
		bool match = !cmd;

		if (cmd) {
			for (const char *c = commands[i].command; *c; c += strlen(c) + 1) {
				if (str_startswith(c, argv[1].sv)) {
					match = true;
					break;
				}
			}
		}

		if (match == false)
			continue;

		term_printf("\033[1m%s\033[0m\n\n", commands[i].command);

		const char *p = commands[i].help;

		while (*p != '\0') {
			size_t pad = strspn(p, " ");
			size_t len = strcspn(p, "\r\n") - pad;

			if (pad + len <= columns) {
				term_printf("%.*s\n", (int)(pad + len), p);
				p += pad + len + (p[pad + len] == '\n');
			}
			else {
				if (pad > columns)
					pad = 1;

				const char *l = p + pad;

				while (len > columns - pad) {
					term_printf("%.*s", (int)pad, p);

					for (size_t j = columns - pad; j > 0; j--) {
						if (l[j-1] == ' ') {
							term_printf("%.*s\n", (int)j, l);
							l += j;
							len -= j;
							break;
						}
					}
				}

				term_printf("%.*s", (int)pad, p);
				term_printf("%.*s\n", (int)len, l);
				p = l + len + (l[len] == '\n');
			}
		}

		term_print("\n\n");
	}

	return true;
}

static bool
cmd_break(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv)
{
	char *spec = (argc == 2) ? argv[1].sv : NULL;
	size_t id = 0;

	if (spec == NULL || *spec == '\0') {
		term_print("Usage:\n");
		term_print("  break path[:line[:offset]]\n");
		term_print("  break expr\n");

		return true;
	}

	/* path spec */
	if ((strchr(spec, '/') || strchr(spec, ':') ||
	     (*spec >= '0' && *spec <= '9')) && *spec != '(') {

		char *path, *line, *byte;

		if (*spec == ':' || (*spec >= '0' && *spec <= '9')) {
			uc_callframe_t *frame = uc_debug_curr_frame(vm, 0);
			uc_function_t *function = frame->closure->function;

			path = uc_program_function_source(function)->filename;
			line = strtok(spec, ": \t");
			byte = strtok(NULL, ": \t");
		}
		else {
			path = strtok(spec, ": \t");
			line = strtok(NULL, ": \t");
			byte = strtok(NULL, ": \t");
		}

		if (!path && !line && !byte) {
			term_print("Usage: break path[:line[:offset]]\n");

			return true;
		}

		id = add_breakpoint(vm, path,
			line ? strtoul(line, NULL, 10) : 0,
			byte ? strtoul(byte, NULL, 10) : 0,
			BK_USER);
	}

	/* expression spec or function name */
	else {
		uc_callframe_t *frame = uc_debug_curr_frame(vm, 0);
		uc_value_t *val = NULL;

		/* Before evaluating as code, try looking up function name directly. */
		if (frame != NULL) {
			uc_program_function_foreach(frame->closure->function->program, fn) {
				if (!strcmp(fn->name, spec)) {
					id = patch_breakpoint(vm, fn, 0, BK_USER, 1);
					break;
				}
			}
		}

		if (id == 0 && frame != NULL && eval_expr(vm, frame, spec, &val)) {
			if (ucv_type(val) == UC_CLOSURE) {
				id = patch_breakpoint(vm,
					((uc_closure_t *)val)->function, 0, BK_USER, 1);
			}
			else {
				char *s = ucv_to_string(vm, val);
				int len = strlen(s);

				term_printf("Value `%s` (%.*s%s) is not a function\n",
					spec,
					len > 32 ? 31 : len,
					s,
					len > 32 ? "…" : "");
			}

			ucv_put(val);
		}
	}

	if (id)
		term_printf("Breakpoint #%zu added\n", id);
	else
		term_print("Unable to resolve source location\n");

	return true;
}

static bool
cmd_delete(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv)
{
	uc_breakpoints_t *bks = &vm->breakpoints;

	if (argc > 2 || (argc == 2 && argv[1].type != ARGTYPE_NUMBER)) {
		term_print("Usage: delete [id]\n");
	}
	else if (argc == 2) {
		size_t n = 0;

		for (size_t i = 0; i < bks->count; i++) {
			debug_breakpoint_t *dbk = (debug_breakpoint_t *)bks->entries[i];

			if (dbk == NULL || dbk->kind != BK_USER)
				continue;

			if (++n == argv[1].nv) {
				free_breakpoint(vm, &dbk->bk);

				return term_printf("Breakpoint #%zu deleted\n", argv[1].nv);
			}
		}

		term_printf("No breakpoint #%zu set\n", argv[1].nv);
	}
	else {
		if (dbk->kind == BK_USER) {
			free_breakpoint(vm, &dbk->bk);
			term_print("Current breakpoint deleted\n");
		}
		else {
			term_print("Automatic breakpoint cannot be deleted\n");
		}
	}

	return true;
}

static bool
cmd_list(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv)
{
	uc_breakpoints_t *bks = &vm->breakpoints;
	uc_stringbuf_t buf = { 0 };
	size_t n = 0;

	const char *kinds[] = {
		[BK_ONCE] = "(once)",
		[BK_USER] = "(user)",
		[BK_STEP] = "(step)",
		[BK_CATCH] = "(catch)",
	};

	for (size_t i = 0; i < ARRAY_SIZE(kinds); i++) {
		for (size_t j = 0; j < bks->count; j++) {
			debug_breakpoint_t *p = (debug_breakpoint_t *)bks->entries[j];

			if (p == NULL || p->kind != i)
				continue;

			if (p->kind == BK_USER)
				sprintbuf(&buf, "#%-6zu ", ++n);
			else
				sprintbuf(&buf, "%-7s ", kinds[p->kind]);

			if (p->fn) {
				uc_source_t *source = uc_program_function_source(p->fn);
				size_t byte = uc_program_function_srcpos(p->fn,
					p->bk.ip - p->fn->chunk.entries);

				size_t line = uc_source_get_line(source, &byte);

				if (source)
					printbuf_append_srcpath(&buf, source, SIZE_MAX);
				else
					printbuf_strappend(&buf, "[unknown source]");

				sprintbuf(&buf, ":%zu:%zu - ", line, byte > 1 ? byte : 1);

				uc_closure_t cl = {
					.header = { .type = UC_CLOSURE },
					.function = p->fn
				};

				printbuf_append_function(&buf, vm, &cl.header, NULL, SIZE_MAX);


			}
			else {
				printbuf_strappend(&buf, "<next instruction>");
			}

			printbuf_strappend(&buf, "\n");
			term_write(buf.buf, buf.bpos);
			printbuf_reset(&buf);
		}
	}

	if (n == 0)
		term_print("No user breakpoints set\n");

	free(buf.buf);

	return true;
}

static bool
cmd_step_common(uc_vm_t *vm, debug_breakpoint_t *dbk, bool single)
{
	uc_callframe_t *frame = uc_debug_curr_frame(vm, 0);

	if (!frame)
		return false;

	uc_function_t *fn = frame->closure->function;
	size_t depth = dbk->depth;
	uint8_t *nextinsn = next_step(vm, &fn, frame->ip, single, &depth);

	/* no next instruction, run until completion */
	if (!nextinsn)
		return false;

	uc_source_t *source = uc_program_function_source(fn);

	size_t byte = uc_program_function_srcpos(fn,
		nextinsn - fn->chunk.entries);

	size_t line = uc_source_get_line(
		uc_program_function_source(fn), &byte);

	if (fn != frame->closure->function)
		term_printf("Entering %s()...\n",
			fn->name[0]
				? fn->name : fn->arrow
					? "[arrow function]" : "[unnamed function]");
	else
		term_printf("Continuing in %s:%zu:%zu...\n",
			source->filename, line, byte);

	update_breakpoint(vm, BK_STEP, bk_enter_cli, nextinsn, fn, depth);

	return false;
}

static bool
cmd_next(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv)
{
	return cmd_step_common(vm, dbk, false);
}

static bool
cmd_step(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv)
{
	return cmd_step_common(vm, dbk, true);
}

static bool
cmd_continue(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv)
{
	term_print("Continuing...\n");

	return false;
}

static bool
cmd_return(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv)
{
	uc_callframe_t *frame = uc_debug_curr_frame(vm, 1);

	if (frame) {
		update_breakpoint(vm, BK_STEP, bk_enter_cli, frame->ip,
			frame->closure->function, 0); /* XXX: fixup depth? */
	}
	else {
		term_print("In topmost function, running until completion...\n");
	}

	return false;
}

static bool
cmd_backtrace(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv)
{
	bool verbose = false;

	if (argc > 3 || (argc == 2 && argv[1].type != ARGTYPE_STRING))
		return term_print("Usage: backtrace [full]\n");

	if (argc == 2 && str_startswith("full", argv[1].sv))
		verbose = true;

	uc_stringbuf_t buf = { 0 };
	uc_function_t *function;
	uc_callframe_t *frame;
	bool adjust_ip = true;
	size_t i;

	for (i = vm->callframes.count; i > 0; i--) {
		frame = &vm->callframes.entries[i - 1];

		if (frame->closure) {
			function = frame->closure->function;

			printbuf_cs(&buf, "\1#%-2zu\177 in ",
				&((style_t){ 0, 0, BOLD }),
				i);

			printbuf_append_srcpath(&buf,
				uc_program_function_source(function), SIZE_MAX);

			size_t insn = frame->ip - function->chunk.entries;
			size_t byte = insn;
			size_t line = insnoff_to_srcpos(function, &byte);

			sprintbuf(&buf, ":%zu:%zu at insn #%zu in ", line, byte, insn);

			cs(&buf, &((style_t){ 0, 0, BOLD }));
			printbuf_append_funcname(&buf,
				vm, &frame->closure->header, SIZE_MAX);
			printbuf_strappend(&buf, "()\n");
			cs(&buf, NULL);

			uint8_t *ip = frame->ip;
			insn_span_t stmt;

			if (adjust_ip && i < vm->callframes.count)
				ip -= 5 - 2 * (vm->arg.u32 >> 16);

			if (find_statement_boundaries(function, ip, 0, &stmt)) {
				format_context_header_callframe(&buf, vm, frame, 2);
				format_context_statement(&buf, vm, function, &stmt, 2, 2, 2);
			}

			if (verbose) {
				printbuf_cs(&buf, "\n  \1Local variables:\177\n",
					&((style_t){ 0, 0, BOLD }));

				print_variables(&buf, vm, frame, false, "   - ");
			}
		}
		else if (frame->cfunction) {
			uc_cfunction_t *cfn = frame->cfunction;
			Dl_info dli;

			printbuf_cs(&buf, "\1#%-2zu\177 in ",
				&((style_t){ 0, 0, BOLD }),
				i);

			if (dladdr(cfn->cfn, &dli) != 0 && dli.dli_fname != NULL)
				printbuf_memappend_fast((&buf),
					dli.dli_fname, strlen(dli.dli_fname));
			else
				printbuf_strappend(&buf, "[unknown shared object]");

			printbuf_strappend(&buf, ", function ");

			cs(&buf, &((style_t){ 0, 0, BOLD }));
			printbuf_append_funcname(&buf, vm, &cfn->header, SIZE_MAX);
			printbuf_strappend(&buf, "()\n");
			cs(&buf, NULL);

			format_context_header_callframe(&buf, vm, frame, 2);
			format_context_cfunction(&buf, vm, cfn, 2);

			adjust_ip = false;
		}

		printbuf_strappend(&buf, "\n");
		term_write(buf.buf, buf.bpos);
		printbuf_reset(&buf);
	}

	free(buf.buf);

	return true;
}

static bool
cmd_variables(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv)
{
	uc_callframe_t *frame = uc_debug_curr_frame(vm, 0);
	uc_stringbuf_t buf = { 0 };
	bool verbose = false;

	if (argc > 3 || (argc == 2 && argv[1].type != ARGTYPE_STRING))
		return term_print("Usage: backtrace [full]\n");

	if (argc == 2 && str_startswith("full", argv[1].sv))
		verbose = true;

	if (!frame)
		return term_print("No local variables in current context\n");

	print_variables(&buf, vm, frame, verbose, "");

	term_write(buf.buf, buf.bpos);
	free(buf.buf);

	return true;
}

static bool
cmd_sources(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv)
{
	struct lh_table *sources = lh_kptr_table_new(16, NULL);
	uc_weakref_t *ref;

	for (ref = vm->values.next; ref != &vm->values; ref = ref->next) {
		uc_closure_t *uc =
			(uc_closure_t *)((uintptr_t)ref - offsetof(uc_closure_t, ref));

		if (uc->header.type != UC_CLOSURE)
			continue;

		if (!uc->function || !uc->function->program)
			continue;

		for (size_t i = 0; i < uc->function->program->sources.count; i++) {
			uc_source_t *source = uc->function->program->sources.entries[i];
			unsigned long hash = lh_get_hash(sources, source);

			if (!lh_table_lookup_entry_w_hash(sources, source, hash))
				lh_table_insert_w_hash(sources, source, NULL, hash, 0);
		}
	}

	struct lh_entry *e;
	size_t i = 0;

	lh_foreach(sources, e) {
		uc_source_t *source = lh_entry_k(e);

		term_printf("#%2zu %s\n", i++, source->filename);
	}

	lh_table_free(sources);

	return true;
}

static bool
cmd_print(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv)
{
	uc_callframe_t *frame = uc_debug_curr_frame(vm, 0);
	uc_stringbuf_t buf = { 0 };

	if (argc < 2)
		return term_print("Usage: print expr\n");

	for (size_t i = 1; i < argc; i++) {
		if (i > 1)
			printbuf_strappend(&buf, " ");

		printbuf_memappend_fast((&buf), argv[i].sv, strlen(argv[i].sv));
	}

	uc_value_t *res = NULL;

	if (eval_expr(vm, frame, buf.buf, &res)) {
		printbuf_reset(&buf);
		ucv_to_stringbuf_formatted(vm, &buf, res, 0, ' ', 2);
		printbuf_strappend(&buf, "\n");

		ucv_put(res);

		term_write(buf.buf, buf.bpos);
	}

	free(buf.buf);

	return true;
}

static bool
cmd_lines(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv)
{
	uc_callframe_t *frame = uc_debug_curr_frame(vm, 0);
	uc_function_t *fn = frame->closure->function;
	size_t insn = frame->ip - fn->chunk.entries;
	bool ctx_is_range = false;
	size_t ctx_before = 2;
	size_t ctx_after = 2;

	location_t loc = {
		.program = fn->program,
		.source = uc_program_function_source(fn),
		.function = fn,
		.offset = uc_program_function_srcpos(fn, insn),
	};

	insn_span_t stmt = {
		.pos_start = SIZE_MAX,
		.pos_end = SIZE_MAX,
		.pos_ip = SIZE_MAX
	};

	/* no argument */
	if (argc == 1) {
		if (find_statement_boundaries(fn, frame->ip, 0, &stmt))
			loc.offset = stmt.pos_start;

		loc.column = loc.offset;
		loc.line = uc_source_get_line(loc.source, &loc.column);
	}

	/* absolute line number */
	else if (argc >= 2 && argv[1].type == ARGTYPE_NUMBER) {
		loc.line = (argv[1].nv > 0) ? argv[1].nv : 1;
	}

	/* line or instruction offset */
	else if (argc >= 2 && argv[1].type == ARGTYPE_STRING &&
	         strchr("+-#", argv[1].sv[0]) != NULL &&
	         argv[1].sv[1] >= '0' && argv[1].sv[1] <= '9') {
		char *e;
		unsigned long n = strtoul(argv[1].sv + 1, &e, 0);

		if (*e != '\0')
			return term_print("Invalid offset\n");

		if (argv[1].sv[0] == '+') {
			loc.line += n;
		}
		else if (argv[1].sv[0] == '-') {
			loc.line = (n < loc.line) ? loc.line - n : 1;
		}
		else {
			loc.offset = uc_program_function_srcpos(fn, n);
			loc.column = loc.offset;
			loc.line = uc_source_get_line(loc.source, &loc.column);

			stmt.pos_ip = loc.offset;
		}
	}

	/* source path, function name or function expression */
	else if (argc >= 2 && argv[1].type == ARGTYPE_STRING) {
		bool found = false;

		if (argv[1].sv[0] != '(') {
			loc = ((location_t){
				.path = argv[1].sv,
				.line = 1,
				.column = 1
			});

			found = lookup_source(vm, &loc);
			ctx_is_range = true;

			if (!found) {
				uc_program_function_foreach(fn->program, pfn) {
					if (!strcmp(pfn->name, argv[1].sv)) {
						loc = ((location_t){ .function = pfn });
						found = true;
						ctx_is_range = false;
						break;
					}
				}
			}
		}

		if (!found) {
			uc_value_t *val;

			if (!eval_expr(vm, frame, argv[1].sv, &val))
				return true;

			if (ucv_type(val) != UC_CLOSURE) {
				char *s = ucv_to_string(vm, val);
				int len = strlen(s);

				term_printf("Value `%s` (%.*s%s) is not a function\n",
					argv[1].sv,
					len > 32 ? 31 : len,
					s,
					len > 32 ? "…" : "");

				ucv_put(val);
				free(s);

				return true;
			}

			loc = ((location_t){ .function = ((uc_closure_t *)val)->function });
			found = true;
			ctx_is_range = false;

			ucv_put(val);
		}

		if (loc.function) {
			size_t beg = uc_program_function_srcpos(loc.function, 0);
			size_t end = uc_program_function_srcpos(loc.function, SIZE_MAX);

			loc.program = loc.function->program;
			loc.source = uc_program_function_source(loc.function);
			loc.offset = loc.column = beg;
			loc.line = uc_source_get_line(loc.source, &loc.column);

			ctx_before = 1;
			ctx_after = uc_source_get_line(loc.source, &end) + 2 - loc.line;
		}
		else {
			ctx_before = 0;
			ctx_after = 5;
		}
	}

	if (argc >= 3 && argv[2].type != ARGTYPE_NUMBER)
		return term_print("Invalid amount of context lines\n");

	if (argc >= 4 && argv[3].type != ARGTYPE_NUMBER)
		return term_print("Invalid amount of following context lines\n");

	if (argc >= 4) {
		if (ctx_is_range) {
			loc.line = argv[2].nv > 0 ? argv[2].nv : 1;
			ctx_before = 0;
			ctx_after = (argv[3].nv > argv[2].nv) ? argv[3].nv - argv[2].nv : 1;
		}
		else {
			ctx_before = argv[2].nv;
			ctx_after = argv[3].nv;
		}
	}
	else if (argc >= 3) {
		ctx_before = 0, ctx_after = argv[2].nv;
	}

	if (!lookup_function(vm, &loc))
		return term_print("Unable to resolve source code location\n");

	uc_stringbuf_t buf = { 0 };

	line_range_t lines = {
		.from = (loc.line > ctx_before) ? loc.line - ctx_before : 1,
		.to   = loc.line + ctx_after

	};

	print_source_location(&buf, vm, loc.source, 1, &lines,
		(loc.source == uc_program_function_source(fn)) ? &stmt : NULL, 0);

	printbuf_strappend(&buf, "\n");

	term_write(buf.buf, buf.bpos);
	free(buf.buf);

	return true;
}

static bool
cmd_throw(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv)
{
	uc_exception_type_t et = EXCEPTION_USER;

	if (argc < 2 || argv[1].type != ARGTYPE_STRING || argc > 3)
		return term_print("Usage: throw [type] message\n");

	if (argc == 3) {
		if (str_startswith("syntax", argv[1].sv))
			et = EXCEPTION_SYNTAX;
		else if (str_startswith("runtime", argv[1].sv))
			et = EXCEPTION_RUNTIME;
		else if (str_startswith("type", argv[1].sv))
			et = EXCEPTION_TYPE;
		else if (str_startswith("reference", argv[1].sv))
			et = EXCEPTION_REFERENCE;
		else if (str_startswith("user", argv[1].sv))
			et = EXCEPTION_USER;
		else if (str_startswith("exit", argv[1].sv))
			et = EXCEPTION_EXIT;
		else
			return term_printf("Unrecognized exception type '%s'\n", argv[1].sv);
	}

	uc_vm_raise_exception(vm, et, "%s", argv[argc - 1].sv);

	return true;
}

#undef __insn
#define __insn(_name) #_name,

static const char *insn_names[__I_MAX] = {
	__insns
};

static bool
cmd_disasm(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv)
{
	uc_callframe_t *frame = uc_debug_curr_frame(vm, 0);
	uc_function_t *target = NULL;
	uc_stringbuf_t buf = { 0 };
	uc_program_t *prog = NULL;
	size_t from = 0, to = 0;
	size_t columns = term_width();

	if (argc > 2 || (argc == 2 && argv[1].type != ARGTYPE_STRING))
		return term_print("Usage: disassemble [target]\n");

	if (argc == 2) {
		if (*argv[1].sv == '#') {
			char *e;

			from = strtoul(argv[1].sv + 1, &e, 10);

			if (*e == '-') {
				to = strtoul(e + 1, &e, 10);

				if (*e != '\0' || to < from)
					return term_printf("Invalid instruction range '%s'\n", argv[1].sv);
			}
			else if (*e == '+') {
				to = from + strtoul(e + 1, &e, 10);

				if (*e != '\0')
					return term_printf("Invalid instruction count '%s'\n", argv[1].sv);
			}
			else if (*e == '\0') {
				to = from;
			}
			else {
				return term_printf("Invalid instruction offset '%s'\n", argv[1].sv);
			}

			target = frame->closure->function;

			if (from >= target->chunk.count || to >= target->chunk.count)
				return term_printf("Instruction offset '%s' out of range 0..%zu\n",
					argv[1].sv, target->chunk.count - 1);
		}
		else if (*argv[1].sv == '(') {
			uc_parse_config_t conf = { .raw_mode = true };
			uc_source_t *source = uc_source_new_buffer("[disasm expression]",
				xstrdup(argv[1].sv), strlen(argv[1].sv));

			char *err;
			prog = uc_compile(&conf, source, &err);

			uc_source_put(source);

			if (!prog) {
				term_write(err, strlen(err));
				free(err);

				return term_print("Invalid expression\n");
			}

			target = uc_program_entry(prog);
			from = 0;
			to = target->chunk.count - 1;
		}
		else {
			char *p = strchr(argv[1].sv, '+');
			size_t limit = SIZE_MAX;

			if (p) {
				char *e;
				limit = strtoul(p + 1, &e, 10);

				if (e == p + 1 || *e != '\0' || limit == 0)
					return term_printf("Invalid instruction count '%s'\n", p + 1);

				*p++ = 0;
			}

			uc_program_function_foreach(frame->closure->function->program, fn) {
				if (!strcmp(fn->name, argv[1].sv)) {
					target = fn;
					from = 0;
					to = (limit < target->chunk.count)
						? limit : target->chunk.count - 1;
					break;
				}
			}

			if (!target)
				return term_printf("Unable to find function '%s'\n", argv[1].sv);
		}
	}
	else {
		insn_span_t stmt;

		target = frame->closure->function;

		if (!find_statement_boundaries(target, frame->ip, 0, &stmt))
			return term_print("Unable to determine current statement boundaries\n");

		from = stmt.ip_start - target->chunk.entries;
		to   = (stmt.ip_end   - target->chunk.entries) - 1;
	}

	uint8_t *bytecode = target->chunk.entries;

	/* find nearest instruction start */
	for (size_t i = 0; i < target->chunk.count; ) {
		size_t len = insn_length(bytecode + i, target->program);

		if (i + len > from) {
			from = i;
			break;
		}

		i += len;
	}

	for (size_t i = from; i <= to; ) {
		union { uint8_t u8; uint16_t u16; uint32_t u32; int32_t s32; } arg;
		size_t n = insn_length(bytecode + i, target->program);
		uint8_t insn = bytecode[i];
		int off = buf.bpos;
		fg_color_t color;

		sprintbuf(&buf, "%06zu:", i);

		for (size_t j = 0; j <= (size_t)abs(uc_vm_insn_format[insn]); j++) {
			if (j == 0)
				color = 0;
			else if (j <= (size_t)abs(uc_vm_insn_format[insn]))
				color = FG_BMAGENT;
			else
				color = FG_BYELLOW;

			printbuf_cs(&buf, " \001%02hhx\177",
				&((style_t){ color, 0, 0 }),
				bytecode[i + j]);
		}

		printbuf_memset(&buf, -1, ' ', 3 * (4 - abs(uc_vm_insn_format[insn])));

		sprintbuf(&buf, "  %7s", insn_names[insn]);

		switch (uc_vm_insn_format[insn]) {
		case 0:
			break;

		case -4:
			arg.s32 = insn_s32(bytecode + i + 1);

			printbuf_cs(&buf, " {\1%c0x%x\177}",
				&((style_t){ FG_BMAGENT, 0, 0 }),
				arg.s32 < 0 ? '-' : '+',
				(uint32_t)(arg.s32 < 0 ? -arg.s32 : arg.s32));

			break;

		case 1:
			arg.u8 = bytecode[i + 1];

			printbuf_cs(&buf, " {\1%hhu\177}",
				&((style_t){ FG_BMAGENT, 0, 0 }),
				arg.u8);

			break;

		case 2:
			arg.u16 = insn_u16(bytecode + i + 1);

			printbuf_cs(&buf, " {\0010x%hx\177}",
				&((style_t){ FG_BMAGENT, 0, 0 }),
				arg.u16);

			break;

		case 4:
			arg.u32 = insn_u32(bytecode + i + 1);

			if (insn == I_LOAD) {
				uc_value_t *cv = load_constval(&target->program->constants, arg.u32);

				char *s = ucv_to_jsonstring(vm, cv);
				printbuf_cs(&buf, " {\0010x%x\177 : \002%s\177}",
					&((style_t){ FG_BMAGENT, 0, 0 }),
					&((style_t){ ucv_type(cv) == UC_STRING ? FG_BMAGENT : FG_CYAN, 0, 0 }),
					arg.u32, s);
				free(s);
			}
			else if (insn == I_LLOC || insn == I_SLOC || insn == I_LUPV || insn == I_SUPV) {
				bool upval = (insn == I_LUPV || insn == I_SUPV);
				uc_value_t *vn = uc_chunk_debug_get_variable(
					&target->chunk, i, arg.u32, upval);

				printbuf_cs(&buf, " {\0010x%x\177 : %s \002%s\177}",
					&((style_t){ FG_BMAGENT, 0, 0 }),
					&((style_t){ upval ? FG_CYAN : FG_BWHITE, 0, 0 }),
					arg.u32, upval ? "upval" : "local",
					vn ? ucv_string_get(vn) : "(unknown)");
			}
			else if (insn == I_LVAR || insn == I_SVAR) {
				uc_value_t *vn = load_constval(&target->program->constants, arg.u32);

				printbuf_cs(&buf, " {\0010x%x\177 : global \002%s\177}",
					&((style_t){ FG_BMAGENT, 0, 0 }),
					&((style_t){ FG_BWHITE, 0, 0 }),
					arg.u32, vn ? ucv_string_get(vn) : "(unknown)");
			}
			else if (insn == I_CLFN || insn == I_ARFN) {
				printbuf_cs(&buf, " {\0010x%x\177 : %s \001#%u\177}",
					&((style_t){ FG_BMAGENT, 0, 0 }),
					arg.u32,
					(insn == I_CLFN) ? "closure" : "arrow",
					arg.u32);
			}
			else {
				printbuf_cs(&buf, " {\0010x%x\177}",
					&((style_t){ FG_BMAGENT, 0, 0 }),
					arg.u32);
			}

			break;

		default:
			printbuf_cs(&buf, " \1(unknown operand format: %hhu)\177",
				&((style_t){ FG_RED, 0, 0 }),
				uc_vm_insn_format[insn]);

			break;
		}

		printbuf_truncate(&buf, off, columns, true);
		cs(&buf, NULL);

		printbuf_strappend(&buf, "\n");

		if (insn == I_CLFN || insn == I_ARFN) {
			size_t id = 1, nupvals = 0;
			uc_program_function_foreach(target->program, fn) {
				if (id++ == arg.u32) {
					nupvals = fn->nupvals;
					break;
				}
			}

			for (size_t j = 0; j < nupvals; j++) {
				int32_t slot = insn_s32(bytecode + i + 5 + j * 4);
				bool upval = (slot >= 0);
				uc_value_t *vn = uc_chunk_debug_get_variable(
					&target->chunk, i, (slot < 0) ? -(slot + 1) : slot, upval);

				int off = buf.bpos;

				printbuf_cs(&buf, "         … \1%02hhx %02hhx %02hhx %02hhx\177",
					&((style_t){ FG_YELLOW, 0, 0 }),
					bytecode[i + 5 + j * 4 + 0], bytecode[i + 5 + j * 4 + 1],
					bytecode[i + 5 + j * 4 + 2], bytecode[i + 5 + j * 4 + 3]);

				printbuf_cs(&buf,
					"  capture {\001%c0x%x\177 : %s \002%s\177}",
					&((style_t){ FG_YELLOW, 0, 0 }),
					&((style_t){ upval ? FG_CYAN : FG_BWHITE, 0, 0 }),
					(slot < 0) ? '-' : '+',
					(slot < 0) ? -slot : slot,
					upval ? "upval" : "local",
					vn ? ucv_string_get(vn) : "(unknown)");

				printbuf_truncate(&buf, off, columns, true);
				printbuf_strappend(&buf, "\n");
			}
		}
		else if (insn == I_CALL || insn == I_QCALL || insn == I_MCALL || insn == I_QMCALL) {
			for (size_t j = 0; j < arg.u32 >> 16; j++) {
				uint16_t slot = insn_u16(bytecode + i + 5 + j * 2);
				int off = buf.bpos;

				printbuf_cs(&buf, "         … \1%02hhx %02hhx\177",
					&((style_t){ FG_YELLOW, 0, 0 }),
					bytecode[i + 5 + j * 2 + 0], bytecode[i + 5 + j * 2 + 1]);

				printbuf_cs(&buf,
					"         unpack {\0010x%hx\177 : stack slot \002-%hx\177}",
					&((style_t){ FG_YELLOW, 0, 0 }),
					&((style_t){ FG_BMAGENT, 0, 0 }),
					slot, slot + 1);

				printbuf_truncate(&buf, off, columns, true);
				printbuf_strappend(&buf, "\n");
			}
		}

		term_write(buf.buf, buf.bpos);
		printbuf_reset(&buf);

		i += n;
	}

	free(buf.buf);

	return true;
}

static bool
cmd_quit(uc_vm_t *vm, debug_breakpoint_t *dbk, size_t argc, arg_t *argv)
{
	bool proceed = true;
	ssize_t c;
	arg_t *v;

	while ((c = term_getline("Terminate program? (y/n) > ", &v, NULL, NULL)) != -1) {
		if (c > 0 && v[0].sv[0] == 'y') {
			vm->arg.s32 = -1;
			uc_vm_raise_exception(vm, EXCEPTION_EXIT, "Terminated");
			proceed = false;
			break;
		}

		if (c > 0 && v[0].sv[0] == 'n')
			break;
	}

	while (c > 0)
		free(v[--c].sv);

	free(v);

	return proceed;
}

static void
cli_tab_complete(size_t nargs, arg_t *args, suggestions_t *suggests, void *ud)
{
	uc_vm_t *vm = ud;
	uc_callframe_t *frame = uc_debug_curr_frame(vm, 0);
	char *cmd = (nargs > 0) ? args[0].sv : NULL;

	/* no completions beyond first arg */
	if (nargs > 2)
		return;

	/* no completions without stackframe info */
	if (frame == NULL)
		return;

	/* complete command itself */
	if (nargs <= 1) {
		for (size_t i = 0; i < ARRAY_SIZE(commands); i++)
			if (nargs == 0 || str_startswith(commands[i].command, args[0].sv))
				uc_vector_add(suggests, xstrdup(commands[i].command));

		return;
	}

	/* completions for `break` and `disassemble` */
	if (str_startswith("break", cmd) ||
	    str_startswith("disasm", cmd) ||
	    str_startswith("disassemble", cmd)) {

		size_t len = strlen(args[1].sv);

		uc_program_function_foreach(frame->closure->function->program, fn) {
			if (fn->name[0] == '\0')
				continue;

			if (len > 0 && strncmp(fn->name, args[1].sv, len) != 0)
				continue;

			uc_vector_add(suggests, xstrdup(fn->name));
		}

		return;
	}

	/* completions for `lines` */
	if (str_startswith("lines", cmd) || str_startswith("ln", cmd)) {
		uc_program_t *prog = frame->closure->function->program;
		size_t len = strlen(args[1].sv);

		/* suggest function names */
		uc_program_function_foreach(prog, fn) {
			if (fn->name[0] == '\0')
				continue;

			if (len > 0 && strncmp(fn->name, args[1].sv, len) != 0)
				continue;

			uc_vector_add(suggests, xstrdup(fn->name));
		}

		/* suggest file names */
		for (size_t i = 0; i < prog->sources.count; i++) {
			uc_stringbuf_t buf = { 0 };
			printbuf_append_srcpath(&buf, prog->sources.entries[i], SIZE_MAX);

			if (len > 0 && strncmp(buf.buf, args[1].sv, len) != 0) {
				free(buf.buf);
				continue;
			}

			uc_vector_add(suggests, buf.buf);
		}

		return;
	}

	/* completions for `help` */
	if (str_startswith("help", cmd)) {
		size_t len = strlen(args[1].sv);

		/* suggest command names */
		for (size_t i = 0; i < ARRAY_SIZE(commands); i++) {
			if (len > 0 && strncmp(commands[i].command, args[1].sv, len) != 0)
				continue;

			uc_vector_add(suggests, xstrdup(commands[i].command));
		}

		return;
	}

	/* completions for `print` */
	if (str_startswith("print", cmd)) {
		uc_chunk_t *chunk = &frame->closure->function->chunk;
		uc_variables_t *decls = &chunk->debuginfo.variables;
		uc_value_list_t *names = &chunk->debuginfo.varnames;
		size_t len = strlen(args[1].sv);

		/* suggest local variable names */
		for (size_t i = 0; i < decls->count; i++) {
			uc_value_t *vname = load_constval(names, decls->entries[i].nameidx);
			char *s = ucv_string_get(vname);

			if (*s != '(' && (len == 0 || strncmp(s, args[1].sv, len) == 0))
				uc_vector_add(suggests, xstrdup(s));

			ucv_put(vname);
		}

		/* suggest global variables */
		ucv_object_foreach(uc_vm_scope_get(vm), k, v) {
			/* skip functions */
			if (ucv_is_callable(v))
				continue;

			if (len > 0 && strncmp(k, args[1].sv, len) != 0)
				continue;

			uc_vector_add(suggests, xstrdup(k));
		}
	}
}

static void
bk_enter_cli(uc_vm_t *vm, uc_breakpoint_t *bk)
{
	debug_breakpoint_t *dbk = (debug_breakpoint_t *)bk;
	arg_t *argv = NULL;
	ssize_t argc = 0;

	term_isig(false);
	print_location(vm, "Paused execution in ", dbk);

	while ((argc = term_getline("dbg > ", &argv, cli_tab_complete, vm)) > -1) {
		size_t l = (argc > 0) ? strlen(argv[0].sv) : 0, i;
		bool proceed = true;

		for (i = 0; l > 0 && i < ARRAY_SIZE(commands); i++) {
			bool match = false;

			for (const char *c = commands[i].command; *c; c += strlen(c) + 1) {
				if (strncmp(c, argv[0].sv, l) == 0) {
					match = true;
					break;
				}
			}

			if (!match)
				continue;

			proceed = commands[i].cb(vm, dbk, argc, argv);
			break;
		}

		if (l > 0 && i == ARRAY_SIZE(commands))
			term_printf("Unrecognized command '%s'\n", argv[0].sv);

		while (argc > 0)
			free(argv[--argc].sv);

		free(argv);

		if (!proceed)
			break;
	}

	if (dbk->kind == BK_ONCE)
		free_breakpoint(vm, &dbk->bk);

	term_isig(true);
}

static uc_value_t *
uc_debug_sigint_handler(uc_vm_t *vm, size_t nargs)
{
	uc_callframe_t *frame = uc_debug_curr_frame(vm, 0);

	if (!frame)
		return NULL;

	debug_breakpoint_t dbk = {
		.bk = { .ip = frame->ip },
		.fn = frame->closure->function,
		.kind = BK_USER
	};

	bk_enter_cli(vm, &dbk.bk);

	uc_value_t *sigint_handler =
		uc_vm_registry_get(vm, "debug.orig_int_signal");

	if (ucv_is_callable(sigint_handler)) {
		uc_vm_stack_push(vm, ucv_get(sigint_handler));
		uc_vm_stack_push(vm, ucv_get(uc_fn_arg(0)));

		if (uc_vm_call(vm, false, 1) == EXCEPTION_NONE)
			return uc_vm_stack_pop(vm);
	}

	return NULL;
}

static uc_value_t *
uc_debug_sigwinch_handler(uc_vm_t *vm, size_t nargs)
{
	term_dimensions();

	uc_value_t *sigwinch_handler =
		uc_vm_registry_get(vm, "debug.orig_winch_signal");

	if (ucv_is_callable(sigwinch_handler)) {
		uc_vm_stack_push(vm, ucv_get(sigwinch_handler));
		uc_vm_stack_push(vm, ucv_get(uc_fn_arg(0)));

		if (uc_vm_call(vm, false, 1) == EXCEPTION_NONE)
			return uc_vm_stack_pop(vm);
	}

	return NULL;
}

/**
 * Initialize interactive debugger.
 *
 * The `debugger()` function sets up the interactive command line debugger and
 * immediately starts it, or - when a function argument is provided - defers the
 * debugger invocation until the given function is called.
 *
 * This function does not return any value.
 *
 * @function module:debug#debugger
 *
 * @param {function} [target]
 * An optional function to attach the debugger to. When provided, a debug
 * breakpoint is installed at the first instruction of the given function,
 * causing the debug cli to get launched as soon as this function is entered.
 *
 * @example
 * // Launch debugger immediately
 * debug.debugger();
 *
 *
 * // Attach debugger to function
 * function test(a, b) {
 *   print(`Result is ${a * b}\n`);
 * }
 *
 * debug.debugger(test); // Install debug breakpoint in `test()` function
 * test();               // Starts debugger, breaking before `print(…)`
 */
static uc_value_t *
uc_debugger(uc_vm_t *vm, size_t nargs)
{
	uc_cfn_ptr_t ucsignal = uc_stdlib_function("signal");
	uc_value_t *mainfn = uc_fn_arg(0);

	if (termstate.initialized == false) {
		uc_vm_stack_push(vm, ucv_string_new("SIGINT"));
		uc_vm_registry_set(vm, "debug.orig_int_signal", ucsignal(vm, 1));
		ucv_put(uc_vm_stack_pop(vm));

		uc_vm_stack_push(vm, ucv_string_new("SIGINT"));
		uc_vm_stack_push(vm,
			ucv_cfunction_new("debug_sigint_handler", uc_debug_sigint_handler));
		ucv_put(ucsignal(vm, 2));
		ucv_put(uc_vm_stack_pop(vm));
		ucv_put(uc_vm_stack_pop(vm));

		uc_vm_stack_push(vm, ucv_string_new("SIGWINCH"));
		uc_vm_registry_set(vm, "debug.orig_winch_signal", ucsignal(vm, 1));
		ucv_put(uc_vm_stack_pop(vm));

		uc_vm_stack_push(vm, ucv_string_new("SIGWINCH"));
		uc_vm_stack_push(vm,
			ucv_cfunction_new("debug_sigwinch_handler", uc_debug_sigwinch_handler));
		ucv_put(ucsignal(vm, 2));
		ucv_put(uc_vm_stack_pop(vm));
		ucv_put(uc_vm_stack_pop(vm));

		term_raw();
		term_isig(true);

		termstate.initialized = true;
	}

	if (ucv_type(mainfn) == UC_CLOSURE) {
		uc_function_t *fn = ((uc_closure_t *)mainfn)->function;
		update_breakpoint(vm, BK_STEP, bk_enter_cli, fn->chunk.entries, fn, 1);
	}
	else {
		uc_callframe_t *frame = uc_debug_curr_frame(vm, 0);

		if (frame) {
			debug_breakpoint_t dbk = {
				.bk = { .ip = frame->ip },
				.fn = frame->closure->function,
				.kind = BK_USER
			};

			bk_enter_cli(vm, &dbk.bk);
		}
	}

	return NULL;
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
	{ "debugger",	uc_debugger },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, debug_fns);

	debug_setup(vm);

	have_highlighting = compile_patterns();
}
