/*
 * Copyright (C) 2022 Jo-Philipp Wich <jo@mein.io>
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

#include <assert.h>
#include <errno.h>
#include <endian.h>

#include "ucode/program.h"
#include "ucode/source.h"
#include "ucode/vallist.h"


uc_program_t *
uc_program_new(uc_source_t *source)
{
	uc_program_t *prog;

	prog = xalloc(sizeof(*prog));

	prog->functions.next = &prog->functions;
	prog->functions.prev = &prog->functions;

	prog->source = uc_source_get(source);

	uc_vallist_init(&prog->constants);

	return prog;
}

static inline uc_function_t *
ref_to_function(uc_weakref_t *ref)
{
	return (uc_function_t *)((uintptr_t)ref - offsetof(uc_function_t, progref));
}

static inline uc_value_t *
ref_to_uv(uc_weakref_t *ref)
{
	return (uc_value_t *)((uintptr_t)ref - offsetof(uc_function_t, progref));
}

void
uc_program_free(uc_program_t *prog)
{
	uc_weakref_t *ref, *tmp;
	uc_function_t *func;

	if (!prog)
		return;

	for (ref = prog->functions.next, tmp = ref->next; ref != &prog->functions; ref = tmp, tmp = tmp->next) {
		func = ref_to_function(ref);
		func->program = NULL;
		func->progref.next = NULL;
		func->progref.prev = NULL;

		ucv_put(&func->header);
	}

	uc_vallist_free(&prog->constants);
	uc_source_put(prog->source);
	free(prog);
}

uc_value_t *
uc_program_function_new(uc_program_t *prog, const char *name, size_t srcpos)
{
	uc_function_t *func;

	func = (uc_function_t *)ucv_function_new(name, srcpos, prog);
	func->root = (prog->functions.next == &prog->functions);

	ucv_ref(&prog->functions, &func->progref);

	return &func->header;
}

size_t
uc_program_function_id(uc_program_t *prog, uc_value_t *func)
{
	uc_weakref_t *ref;
	size_t i;

	for (ref = prog->functions.prev, i = 1; ref != &prog->functions; ref = ref->prev, i++)
		if (ref_to_uv(ref) == func)
			return i;

	return 0;
}

uc_value_t *
uc_program_function_load(uc_program_t *prog, size_t id)
{
	uc_weakref_t *ref;
	size_t i;

	for (ref = prog->functions.prev, i = 1; ref != &prog->functions; ref = ref->prev, i++)
		if (i == id)
			return ref_to_uv(ref);

	return NULL;
}

uc_value_t *
uc_program_get_constant(uc_program_t *prog, size_t idx)
{
	return uc_vallist_get(&prog->constants, idx);
}

ssize_t
uc_program_add_constant(uc_program_t *prog, uc_value_t *val)
{
	return uc_vallist_add(&prog->constants, val);
}

static void
write_u16(size_t value, FILE *file)
{
	uint16_t n;

	if (sizeof(value) > sizeof(n))
		assert(value <= UINT16_MAX);

	n = htobe16((uint16_t)value);

	fwrite(&n, 1, sizeof(n), file);
}

static void
write_u32(size_t value, FILE *file)
{
	uint32_t n;

	if (sizeof(value) > sizeof(n))
		assert(value <= UINT32_MAX);

	n = htobe32((uint32_t)value);

	fwrite(&n, 1, sizeof(n), file);
}

static void
write_u64(uint64_t value, FILE *file)
{
	uint64_t n;

	if (sizeof(value) > sizeof(n))
		assert(value <= UINT64_MAX);

	n = htobe64((uint64_t)value);

	fwrite(&n, 1, sizeof(n), file);
}

static void
_write_vector(size_t count, size_t itemsize, void *data, FILE *file)
{
	size_t pad = (~(count * itemsize) + 1) & (sizeof(uint32_t) - 1);
	char z[sizeof(uint32_t) - 1] = { 0 };

	write_u32(count, file);
	fwrite(data, itemsize, count, file);
	fwrite(z, 1, pad, file);
}

#define write_vector(vec, file) \
	_write_vector((vec)->count, sizeof((vec)->entries[0]), (vec)->entries, file)

#define write_string(str, file) \
	_write_vector(strlen(str) + 1, 1, str, file)

static void
write_vallist(uc_value_list_t *vallist, FILE *file)
{
	size_t i;

	/* write index */
	write_u32(vallist->isize, file);

	for (i = 0; i < vallist->isize; i++)
		write_u64(vallist->index[i], file);

	/* write data */
	write_u32(vallist->dsize, file);
	fwrite(vallist->data, 1, vallist->dsize, file);
}

enum {
	UC_PROGRAM_F_DEBUG      = (1 << 0),
	UC_PROGRAM_F_SOURCEINFO = (1 << 1),
	UC_PROGRAM_F_SOURCEBUF  = (1 << 2),
};

enum {
	UC_FUNCTION_F_IS_ARROW       = (1 << 0),
	UC_FUNCTION_F_IS_VARARG      = (1 << 1),
	UC_FUNCTION_F_IS_STRICT      = (1 << 2),
	UC_FUNCTION_F_HAS_EXCEPTIONS = (1 << 3),
	UC_FUNCTION_F_HAS_NAME       = (1 << 4),
	UC_FUNCTION_F_HAS_VARDBG     = (1 << 5),
	UC_FUNCTION_F_HAS_OFFSETDBG  = (1 << 6),
};

static void
write_chunk(uc_chunk_t *chunk, FILE *file, uint32_t flags)
{
	size_t i;

	/* write bytecode data */
	write_vector(chunk, file);

	/* write exception ranges */
	if (flags & UC_FUNCTION_F_HAS_EXCEPTIONS) {
		write_u32(chunk->ehranges.count, file);

		for (i = 0; i < chunk->ehranges.count; i++) {
			write_u32(chunk->ehranges.entries[i].from,   file);
			write_u32(chunk->ehranges.entries[i].to,     file);
			write_u32(chunk->ehranges.entries[i].target, file);
			write_u32(chunk->ehranges.entries[i].slot,   file);
		}
	}

	/* write variable info */
	if (flags & UC_FUNCTION_F_HAS_VARDBG) {
		write_u32(chunk->debuginfo.variables.count, file);

		for (i = 0; i < chunk->debuginfo.variables.count; i++) {
			write_u32(chunk->debuginfo.variables.entries[i].from,    file);
			write_u32(chunk->debuginfo.variables.entries[i].to,      file);
			write_u32(chunk->debuginfo.variables.entries[i].slot,    file);
			write_u32(chunk->debuginfo.variables.entries[i].nameidx, file);
		}

		write_vallist(&chunk->debuginfo.varnames, file);
	}

	/* write offset info */
	if (flags & UC_FUNCTION_F_HAS_OFFSETDBG)
		write_vector(&chunk->debuginfo.offsets, file);
}

static void
write_function(uc_function_t *func, FILE *file, bool debug)
{
	uint32_t flags = 0;

	if (func->arrow)
		flags |= UC_FUNCTION_F_IS_ARROW;

	if (func->vararg)
		flags |= UC_FUNCTION_F_IS_VARARG;

	if (func->strict)
		flags |= UC_FUNCTION_F_IS_STRICT;

	if (func->chunk.ehranges.count)
		flags |= UC_FUNCTION_F_HAS_EXCEPTIONS;

	if (debug && func->name[0])
		flags |= UC_FUNCTION_F_HAS_NAME;

	if (debug && func->chunk.debuginfo.variables.count)
		flags |= UC_FUNCTION_F_HAS_VARDBG;

	if (debug && func->chunk.debuginfo.offsets.count)
		flags |= UC_FUNCTION_F_HAS_OFFSETDBG;

	write_u32(flags, file);

	if (flags & UC_FUNCTION_F_HAS_NAME)
		write_string(func->name, file);

	write_u16(func->nargs, file);
	write_u16(func->nupvals, file);
	write_u32(func->srcpos, file);

	write_chunk(&func->chunk, file, flags);
}

void
uc_program_write(uc_program_t *prog, FILE *file, bool debug)
{
	uint32_t flags = 0;
	uc_weakref_t *ref;
	size_t i;

	if (debug)
		flags |= UC_PROGRAM_F_DEBUG;

	if (debug && prog->source) {
		flags |= UC_PROGRAM_F_SOURCEINFO;

		if (prog->source->buffer)
			flags |= UC_PROGRAM_F_SOURCEBUF;
	}

	/* magic word + flags */
	write_u32(UC_PRECOMPILED_BYTECODE_MAGIC, file);
	write_u32(flags, file);

	if (flags & UC_PROGRAM_F_SOURCEINFO) {
		/* write source file name */
		write_string(prog->source->filename, file);

		/* include source buffer if program was compiled from stdin */
		if (flags & UC_PROGRAM_F_SOURCEBUF)
			write_string(prog->source->buffer, file);

		/* write lineinfo data */
		write_vector(&prog->source->lineinfo, file);
	}

	/* write constants */
	write_vallist(&prog->constants, file);

	/* write program sections */
	for (i = 0, ref = prog->functions.prev; ref != &prog->functions; ref = ref->prev)
		i++;

	write_u32(i, file);

	for (ref = prog->functions.prev; ref != &prog->functions; ref = ref->prev)
		write_function(ref_to_function(ref), file, debug);
}

static bool
read_error(FILE *file, char **errp, const char *subject, size_t rlen, size_t len)
{
	const char *reason;

	if (feof(file))
		reason = "Premature EOF";
	else
		reason = strerror(errno);

	if (errp)
		xasprintf(errp,
		          "%s while reading %s at offset %ld, got %zu of %zu bytes\n",
		          reason, subject, ftell(file) - rlen, rlen, len);

	return false;
}

static bool
skip_padding(FILE *file, size_t len, char **errp)
{
	size_t pad = (~len + 1) & (sizeof(uint32_t) - 1), rlen;
	char buf[sizeof(uint32_t) - 1];

	if (pad != 0) {
		rlen = fread(buf, 1, pad, file);

		if (rlen != pad)
			return read_error(file, errp, "padding", rlen, pad);
	}

	return true;
}

static bool
read_u32(FILE *file, uint32_t *n, const char *subj, char **errp)
{
	size_t rlen = fread(n, 1, sizeof(*n), file);

	if (rlen != sizeof(*n)) {
		*n = 0;

		return read_error(file, errp, subj ? subj : "uint32_t", rlen, sizeof(*n));
	}

	*n = be32toh(*n);

	return true;
}

static bool
read_u64(FILE *file, uint64_t *n, const char *subj, char **errp)
{
	size_t rlen = fread(n, 1, sizeof(*n), file);

	if (rlen != sizeof(*n)) {
		*n = 0;

		return read_error(file, errp, subj ? subj : "uint64_t", rlen, sizeof(*n));
	}

	*n = be64toh(*n);

	return true;
}

static bool
read_size_t(FILE *file, size_t *n, size_t size, const char *subj, char **errp)
{
	union { uint8_t u8; uint16_t u16; uint32_t u32; uint64_t u64; } nval;
	size_t rlen;

	rlen = fread(&nval.u64, 1, size, file);

	if (rlen != size) {
		*n = 0;

		if (!subj) {
			switch (size) {
			case 1: subj = "uint8_t";  break;
			case 2: subj = "uint16_t"; break;
			case 4: subj = "uint32_t"; break;
			case 8: subj = "uint64_t"; break;
			}
		}

		return read_error(file, errp, subj, rlen, sizeof(nval));
	}

	switch (size) {
	case 1: *n = (size_t)        nval.u8;   break;
	case 2: *n = (size_t)be16toh(nval.u16); break;
	case 4: *n = (size_t)be32toh(nval.u32); break;
	case 8: *n = (size_t)be64toh(nval.u64); break;
	}

	return true;
}

static bool
_read_vector(FILE *file, void *ptr, size_t itemsize, const char *subj, char **errp)
{
	struct { size_t count; void *data; } *vec = ptr;
	size_t rlen, len;
	char subjbuf[64];

	snprintf(subjbuf, sizeof(subjbuf), "%s vector size", subj);

	if (!read_size_t(file, &vec->count, sizeof(uint32_t), subjbuf, errp))
		return false;

	vec->data = xcalloc(vec->count, itemsize);

	len = vec->count;
	rlen = fread(vec->data, itemsize, len, file);

	if (rlen != len) {
		free(vec->data);

		vec->count = 0;
		vec->data = NULL;

		snprintf(subjbuf, sizeof(subjbuf), "%s vector data", subj);

		return read_error(file, errp, subjbuf, rlen * itemsize, len * itemsize);
	}

	return skip_padding(file, vec->count * itemsize, errp);
}

#define read_vector(file, vec, subj, errp) \
	_read_vector(file, vec, sizeof((vec)->entries[0]), subj, errp)

static bool
read_string(FILE *file, char *dst, size_t len, const char *subj, char **errp)
{
	size_t rlen;

	rlen = fread(dst, 1, len, file);

	if (rlen != len)
		return read_error(file, errp, subj, rlen, len);

	return skip_padding(file, len, errp);
}

static bool
read_vallist(FILE *file, uc_value_list_t *vallist, const char *subj, char **errp)
{
	char subjbuf[64];
	size_t i;

	/* read index */
	snprintf(subjbuf, sizeof(subjbuf), "%s index size", subj);

	if (!read_size_t(file, &vallist->isize, sizeof(uint32_t), subjbuf, errp))
		goto out;

	vallist->index = xcalloc(sizeof(vallist->index[0]), vallist->isize);

	for (i = 0; i < vallist->isize; i++) {
		snprintf(subjbuf, sizeof(subjbuf), "%s index entry %zu of %zu", subj, i, vallist->isize);

		if (!read_u64(file, &vallist->index[i], subjbuf, errp))
			goto out;
	}

	/* read data */
	snprintf(subjbuf, sizeof(subjbuf), "%s data size", subj);

	if (!read_size_t(file, &vallist->dsize, sizeof(uint32_t), subjbuf, errp))
		goto out;

	vallist->data = xalloc(vallist->dsize);

	snprintf(subjbuf, sizeof(subjbuf), "%s data", subj);

	if (!read_string(file, vallist->data, vallist->dsize, subj, errp))
		goto out;

	return true;

out:
	free(vallist->index);
	free(vallist->data);

	vallist->isize = 0;
	vallist->index = NULL;

	vallist->dsize = 0;
	vallist->data = NULL;

	return false;
}

static uc_source_t *
read_sourceinfo(uc_source_t *input, uint32_t flags, char **errp)
{
	char *path = NULL, *code = NULL;
	uc_source_t *source = NULL;
	size_t len;

	if (flags & UC_PROGRAM_F_SOURCEINFO) {
		if (!read_size_t(input->fp, &len, sizeof(uint32_t), "sourceinfo filename length", errp))
			goto out;

		path = xalloc(len);

		if (!read_string(input->fp, path, len, "sourceinfo filename", errp))
			goto out;

		if (flags & UC_PROGRAM_F_SOURCEBUF) {
			if (!read_size_t(input->fp, &len, sizeof(uint32_t), "sourceinfo code buffer length", errp))
				goto out;

			code = xalloc(len);

			if (!read_string(input->fp, code, len, "sourceinfo code buffer data", errp)) {
				free(code);
				goto out;
			}

			source = uc_source_new_buffer(path, code, len);
		}
		else {
			source = uc_source_new_file(path);

			if (!source) {
				fprintf(stderr, "Unable to open source file %s: %s\n", path, strerror(errno));
				source = uc_source_new_buffer(path, xstrdup(""), 0);
			}
		}

		if (!read_vector(input->fp, &source->lineinfo, "sourceinfo lineinfo", errp)) {
			uc_source_put(source);
			source = NULL;
			goto out;
		}
	}
	else {
		source = uc_source_new_buffer("[no source]", xstrdup(""), 0);
	}

	uc_source_runpath_set(source, input->runpath);

out:
	free(path);

	return source;
}

static bool
read_chunk(FILE *file, uc_chunk_t *chunk, uint32_t flags, const char *subj, char **errp)
{
	uc_varrange_t *varrange;
	uc_ehrange_t *ehrange;
	char subjbuf[192];
	size_t i;

	/* read bytecode data */
	snprintf(subjbuf, sizeof(subjbuf), "%s byte code", subj);

	if (!read_vector(file, chunk, subjbuf, errp))
		goto out;

	/* read exception ranges */
	if (flags & UC_FUNCTION_F_HAS_EXCEPTIONS) {
		snprintf(subjbuf, sizeof(subjbuf), "%s exception ranges count", subj);

		if (!read_size_t(file, &chunk->ehranges.count, sizeof(uint32_t), subjbuf, errp))
			goto out;

		chunk->ehranges.entries = xcalloc(
			sizeof(chunk->ehranges.entries[0]),
			chunk->ehranges.count);

		for (i = 0; i < chunk->ehranges.count; i++) {
			snprintf(subjbuf, sizeof(subjbuf), "%s exception range %zu of %zu offset",
				subj, i, chunk->ehranges.count);

			ehrange = &chunk->ehranges.entries[i];

			if (!read_size_t(file, &ehrange->from,   sizeof(uint32_t), subjbuf, errp) ||
			    !read_size_t(file, &ehrange->to,     sizeof(uint32_t), subjbuf, errp) ||
			    !read_size_t(file, &ehrange->target, sizeof(uint32_t), subjbuf, errp) ||
			    !read_size_t(file, &ehrange->slot,   sizeof(uint32_t), subjbuf, errp))
				goto out;
		}
	}

	/* read variable info */
	if (flags & UC_FUNCTION_F_HAS_VARDBG) {
		snprintf(subjbuf, sizeof(subjbuf), "%s variable scopes count", subj);

		if (!read_size_t(file, &chunk->debuginfo.variables.count, sizeof(uint32_t), subjbuf, errp))
			goto out;

		chunk->debuginfo.variables.entries = xcalloc(
			sizeof(chunk->debuginfo.variables.entries[0]),
			chunk->debuginfo.variables.count);

		for (i = 0; i < chunk->debuginfo.variables.count; i++) {
			snprintf(subjbuf, sizeof(subjbuf), "%s variable scope %zu of %zu offset",
				subj, i, chunk->debuginfo.variables.count);

			varrange = &chunk->debuginfo.variables.entries[i];

			if (!read_size_t(file, &varrange->from,    sizeof(uint32_t), subjbuf, errp) ||
			    !read_size_t(file, &varrange->to,      sizeof(uint32_t), subjbuf, errp) ||
			    !read_size_t(file, &varrange->slot,    sizeof(uint32_t), subjbuf, errp) ||
			    !read_size_t(file, &varrange->nameidx, sizeof(uint32_t), subjbuf, errp))
			    goto out;
		}

		snprintf(subjbuf, sizeof(subjbuf), "%s variable names", subj);

		if (!read_vallist(file, &chunk->debuginfo.varnames, subjbuf, errp))
			goto out;
	}

	/* read offset info */
	if (flags & UC_FUNCTION_F_HAS_OFFSETDBG) {
		snprintf(subjbuf, sizeof(subjbuf), "%s source offsets", subj);

		if (!read_vector(file, &chunk->debuginfo.offsets, subjbuf, errp))
			goto out;
	}

	return true;

out:
	uc_vallist_free(&chunk->debuginfo.varnames);

	free(chunk->entries);
	free(chunk->ehranges.entries);
	free(chunk->debuginfo.variables.entries);

	chunk->count = 0;
	chunk->entries = NULL;

	chunk->ehranges.count = 0;
	chunk->ehranges.entries = NULL;

	chunk->debuginfo.variables.count = 0;
	chunk->debuginfo.variables.entries = NULL;

	return false;
}

static bool
read_function(FILE *file, uc_program_t *program, size_t idx, char **errp)
{
	char subjbuf[64], *name = NULL;
	uc_function_t *func = NULL;
	uint32_t flags, u32;

	snprintf(subjbuf, sizeof(subjbuf), "function #%zu flags", idx);

	if (!read_u32(file, &flags, subjbuf, errp))
		goto out;

	if (flags & UC_FUNCTION_F_HAS_NAME) {
		snprintf(subjbuf, sizeof(subjbuf), "function #%zu name length", idx);

		if (!read_u32(file, &u32, subjbuf, errp))
			goto out;

		name = xalloc(u32);

		snprintf(subjbuf, sizeof(subjbuf), "function #%zu name", idx);

		if (!read_string(file, name, u32, subjbuf, errp))
			goto out;
	}

	snprintf(subjbuf, sizeof(subjbuf), "function #%zu (%s) arg count and offset", idx, name ? name : "-");

	func = (uc_function_t *)uc_program_function_new(program, name, 0);
	func->arrow   = (flags & UC_FUNCTION_F_IS_ARROW);
	func->vararg  = (flags & UC_FUNCTION_F_IS_VARARG);
	func->strict  = (flags & UC_FUNCTION_F_IS_STRICT);

	if (!read_size_t(file, &func->nargs,   sizeof(uint16_t), subjbuf, errp) ||
	    !read_size_t(file, &func->nupvals, sizeof(uint16_t), subjbuf, errp) ||
	    !read_size_t(file, &func->srcpos,  sizeof(uint32_t), subjbuf, errp))
		goto out;

	snprintf(subjbuf, sizeof(subjbuf), "function #%zu (%s) body", idx, name ? name : "-");

	if (!read_chunk(file, &func->chunk, flags, subjbuf, errp))
		goto out;

	free(name);

	return true;

out:
	free(name);

	return false;
}

uc_program_t *
uc_program_load(uc_source_t *input, char **errp)
{
	uc_program_t *program = NULL;
	uc_source_t *source = NULL;
	uint32_t flags, nfuncs, i;

	if (!read_u32(input->fp, &i, "file magic", errp))
		goto out;

	if (i != UC_PRECOMPILED_BYTECODE_MAGIC) {
		xasprintf(errp, "Invalid file magic\n");
		goto out;
	}

	if (!read_u32(input->fp, &flags, "program flags", errp))
		goto out;

	source = read_sourceinfo(input, flags, errp);

	if (!source)
		goto out;

	program = uc_program_new(source);

	uc_source_put(source);

	if (!read_vallist(input->fp, &program->constants, "constants", errp))
		goto out;

	if (!read_u32(input->fp, &nfuncs, "function count", errp))
		goto out;

	for (i = 0; i < nfuncs; i++)
		if (!read_function(input->fp, program, i, errp))
			goto out;

	return program;

out:
	uc_program_free(program);

	return NULL;
}

uc_function_t *
uc_program_entry(uc_program_t *program)
{
	if (program->functions.prev == &program->functions)
		return NULL;

	return ref_to_function(program->functions.prev);
}
