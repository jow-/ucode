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

/* Public compilation API: uc_compile() and the parse configuration. */

#ifndef UCODE_COMPILER_H
#define UCODE_COMPILER_H

#include <stddef.h>
#include <stdbool.h>

#include <ucode/types.h>
#include <ucode/source.h>


uc_declare_vector(uc_search_path_t, char *);

struct uc_parse_config {
	bool lstrip_blocks;
	bool trim_blocks;
	bool strict_declarations;
	bool raw_mode;
	uc_search_path_t module_search_path;
	uc_search_path_t force_dynlink_list;
	bool setup_signal_handlers;
	bool compile_module;
};

extern uc_parse_config_t uc_default_parse_config;

void uc_search_path_init(uc_search_path_t *search_path);

static inline void
uc_search_path_add(uc_search_path_t *search_path, char *path) {
	uc_vector_push(search_path, xstrdup(path));
}

static inline void
uc_search_path_free(uc_search_path_t *search_path) {
	while (search_path->count > 0)
		free(search_path->entries[--search_path->count]);

	uc_vector_clear(search_path);
}

/*
 * Compile the given source into a program. On success returns a new
 * uc_program_t (caller must release with uc_program_put()); on failure
 * returns NULL and, if errp is non-NULL, stores a heap-allocated error
 * message (caller must free()).
 */
uc_program_t *uc_compile(uc_parse_config_t *config, uc_source_t *source, char **errp);

#endif /* UCODE_COMPILER_H */
