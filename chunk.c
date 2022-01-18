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

#include <assert.h>

#include "ucode/chunk.h"
#include "ucode/types.h"
#include "ucode/util.h"

#define OFFSETINFO_BITS (sizeof(((uc_offsetinfo_t *)NULL)->entries[0]) * 8)
#define OFFSETINFO_BYTE_BITS 3
#define OFFSETINFO_INSN_BITS (OFFSETINFO_BITS - OFFSETINFO_BYTE_BITS)
#define OFFSETINFO_MAX_BYTES ((1 << OFFSETINFO_BYTE_BITS) - 1)
#define OFFSETINFO_MAX_INSNS ((1 << OFFSETINFO_INSN_BITS) - 1)
#define OFFSETINFO_NUM_BYTES(n) ((n) & OFFSETINFO_MAX_BYTES)
#define OFFSETINFO_NUM_INSNS(n) ((n) >> OFFSETINFO_BYTE_BITS)
#define OFFSETINFO_ENCODE(line, insns) ((line & OFFSETINFO_MAX_BYTES) | (((insns) << OFFSETINFO_BYTE_BITS) & ~OFFSETINFO_MAX_BYTES))


void
uc_chunk_init(uc_chunk_t *chunk)
{
	chunk->count = 0;
	chunk->entries = NULL;

	chunk->ehranges.count = 0;
	chunk->ehranges.entries = NULL;

	chunk->debuginfo.offsets.count = 0;
	chunk->debuginfo.offsets.entries = NULL;

	chunk->debuginfo.variables.count = 0;
	chunk->debuginfo.variables.entries = NULL;

	uc_vallist_init(&chunk->debuginfo.varnames);
}

void
uc_chunk_free(uc_chunk_t *chunk)
{
	uc_vector_clear(chunk);
	uc_vector_clear(&chunk->ehranges);

	uc_vector_clear(&chunk->debuginfo.offsets);
	uc_vector_clear(&chunk->debuginfo.variables);
	uc_vallist_free(&chunk->debuginfo.varnames);

	uc_chunk_init(chunk);
}

size_t
uc_chunk_add(uc_chunk_t *chunk, uint8_t byte, size_t offset)
{
	uc_offsetinfo_t *offsets = &chunk->debuginfo.offsets;
	size_t i;

	uc_vector_grow(chunk);

	chunk->entries[chunk->count] = byte;

	/* offset info is encoded in bytes, for each byte, the first three bits
	 * specify the number of source text bytes to advance since the last entry
	 * and the remaining five bits specify the amount of instructions belonging
	 * to any given source text offset */
	if (offset > 0 || offsets->count == 0) {
		/* if this offset is farther than seven (2 ** 3 - 1) bytes apart from
		 * the last one, we need to emit intermediate "jump" bytes with zero
		 * instructions each */
		for (i = offset; i > OFFSETINFO_MAX_BYTES; i -= OFFSETINFO_MAX_BYTES) {
			/* advance by 7 bytes */
			uc_vector_grow(offsets);
			offsets->entries[offsets->count++] = OFFSETINFO_ENCODE(OFFSETINFO_MAX_BYTES, 0);
		}

		/* advance by `i` bytes, count one instruction */
		uc_vector_grow(offsets);
		offsets->entries[offsets->count++] = OFFSETINFO_ENCODE(i, 1);
	}

	/* update instruction count at current offset entry */
	else {
		/* since we encode the per-offset instruction count in five bits, we
		 * can only count up to 31 instructions. If we exceed that limit,
		 * emit another offset entry with the initial three bits set to zero */
		if (OFFSETINFO_NUM_INSNS(offsets->entries[offsets->count - 1]) >= OFFSETINFO_MAX_INSNS) {
			/* advance by 0 bytes, count one instruction */
			uc_vector_grow(offsets);
			offsets->entries[offsets->count++] = OFFSETINFO_ENCODE(0, 1);
		}
		else {
			offsets->entries[offsets->count - 1] = OFFSETINFO_ENCODE(
				OFFSETINFO_NUM_BYTES(offsets->entries[offsets->count - 1]),
				OFFSETINFO_NUM_INSNS(offsets->entries[offsets->count - 1]) + 1
			);
		}
	}

	return chunk->count++;
}

void
uc_chunk_pop(uc_chunk_t *chunk)
{
	uc_offsetinfo_t *offsets = &chunk->debuginfo.offsets;
	int n_insns;

	assert(chunk->count > 0);

	chunk->count--;

	n_insns = OFFSETINFO_NUM_INSNS(offsets->entries[offsets->count - 1]);

	if (n_insns > 0) {
		offsets->entries[offsets->count - 1] = OFFSETINFO_ENCODE(
			OFFSETINFO_NUM_BYTES(offsets->entries[offsets->count - 1]),
			n_insns - 1
		);
	}
	else {
		offsets->count--;
	}
}

size_t
uc_chunk_debug_get_srcpos(uc_chunk_t *chunk, size_t off)
{
	uc_offsetinfo_t *offsets = &chunk->debuginfo.offsets;
	size_t i, inum = 0, lnum = 0;

	if (!offsets->count)
		return 0;

	for (i = 0; i < offsets->count && inum < off; i++) {
		lnum += OFFSETINFO_NUM_BYTES(offsets->entries[i]);
		inum += OFFSETINFO_NUM_INSNS(offsets->entries[i]);
	}

	return lnum;
}

void
uc_chunk_debug_add_variable(uc_chunk_t *chunk, size_t from, size_t to, size_t slot, bool upval, uc_value_t *name)
{
	uc_variables_t *variables = &chunk->debuginfo.variables;
	uc_value_list_t *varnames = &chunk->debuginfo.varnames;

	assert(slot <= ((size_t)-1 / 2));

	if (upval)
		slot += (size_t)-1 / 2;

	uc_vector_grow(variables);

	variables->entries[variables->count].nameidx = uc_vallist_add(varnames, name);
	variables->entries[variables->count].slot    = slot;
	variables->entries[variables->count].from    = from;
	variables->entries[variables->count].to      = to;

	variables->count++;
}

uc_value_t *
uc_chunk_debug_get_variable(uc_chunk_t *chunk, size_t off, size_t slot, bool upval)
{
	uc_variables_t *variables = &chunk->debuginfo.variables;
	uc_value_list_t *varnames = &chunk->debuginfo.varnames;
	uc_value_t *name = NULL;
	size_t i;

	assert(slot <= ((size_t)-1 / 2));

	if (upval)
		slot += (size_t)-1 / 2;

	for (i = 0; i < variables->count; i++) {
		if (variables->entries[i].slot != slot ||
		    variables->entries[i].from > off ||
		    variables->entries[i].to < off)
			continue;

		name = uc_vallist_get(varnames, variables->entries[i].nameidx);
	}

	return name;
}
