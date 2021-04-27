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

#ifndef __COMPILER_H_
#define __COMPILER_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef JSONC
	#include <json.h>
#else
	#include <json-c/json.h>
#endif

#include "source.h"
#include "lexer.h"
#include "types.h"
#include "util.h"

typedef enum {
	P_NONE,

	P_COMMA,	/* , */

	P_ASSIGN,	/* = += -= *= /= %= <<= >>= &= ^= |= */

	P_TERNARY,	/* ?: */

	P_OR,		/* || */
	P_AND,		/* && */
	P_BOR,		/* | */
	P_BXOR,		/* ^ */
	P_BAND,		/* & */

	P_EQUAL,	/* === !== == != */
	P_COMPARE,	/* < <= > >= in */

	P_SHIFT,	/* << >> */

	P_ADD,		/* + - */
	P_MUL,		/* * / % */

	P_UNARY,	/* ! ~ +… -… ++… --… */

	P_INC,		/* …++ …-- */

	P_CALL,		/* ….…, …[…], …(…) */

	P_PRIMARY	/* (…) */
} uc_precedence_t;

struct uc_patchlist {
	struct uc_patchlist *parent;
	size_t count, *entries;
};

typedef struct uc_patchlist uc_patchlist;

typedef struct {
	uc_value_t *name;
	ssize_t depth;
	size_t from;
	bool captured;
} uc_local;

typedef struct {
	uc_value_t *name;
	size_t index;
	bool local;
} uc_upval;

uc_declare_vector(uc_locals, uc_local);
uc_declare_vector(uc_upvals, uc_upval);
uc_declare_vector(uc_jmplist, size_t);

typedef struct {
	uc_parse_config *config;
	uc_lexer lex;
	uc_token prev, curr;
	bool synchronizing;
	uc_stringbuf_t *error;
} uc_parser;

struct uc_compiler {
	struct uc_compiler *parent;
	uc_locals locals;
	uc_upvals upvals;
	uc_patchlist *patchlist;
	uc_value_t *function;
	uc_parser *parser;
	size_t scope_depth, current_srcpos, last_insn;
	bool statement_emitted;
};

typedef struct uc_compiler uc_compiler;

typedef struct {
	void (*prefix)(uc_compiler *, bool);
	void (*infix)(uc_compiler *, bool);
	uc_precedence_t precedence;
} uc_parse_rule;

uc_function_t *uc_compile(uc_parse_config *config, uc_source *source, char **errp);

#endif /* __COMPILER_H_ */
