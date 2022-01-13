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
