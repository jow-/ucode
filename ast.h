/*
 * Copyright (C) 2020 Jo-Philipp Wich <jo@mein.io>
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

#ifndef __AST_H_
#define __AST_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef JSONC
	#include <json.h>
#else
	#include <json-c/json.h>
#endif

#define UT_ERRMSG_OOM "Runtime error: Memory allocation failure"

enum ut_error_type {
	UT_ERROR_NO_ERROR,
	UT_ERROR_OUT_OF_MEMORY,
	UT_ERROR_UNTERMINATED_COMMENT,
	UT_ERROR_UNTERMINATED_STRING,
	UT_ERROR_UNTERMINATED_BLOCK,
	UT_ERROR_UNEXPECTED_TOKEN,
	UT_ERROR_UNEXPECTED_CHAR,
	UT_ERROR_OVERLONG_STRING,
	UT_ERROR_INVALID_ESCAPE,
	UT_ERROR_NESTED_BLOCKS,
	UT_ERROR_EXCEPTION
};

enum ut_block_type {
	UT_BLOCK_NONE,
	UT_BLOCK_STATEMENT,
	UT_BLOCK_EXPRESSION,
	UT_BLOCK_COMMENT
};

struct ut_opcode {
	int type;
	struct json_object *val;
	struct ut_opcode *operand[4], *next, *sibling;
	uint32_t off;
};

struct ut_state {
	struct ut_opcode *pool;
	struct ut_opcode *main;
	uint8_t semicolon_emitted:1;
	uint8_t start_tag_seen:1;
	uint8_t srand_called:1;
	size_t off;
	enum ut_block_type blocktype;
	struct {
		enum ut_error_type code;
		union {
			struct json_object *exception;
			uint64_t tokens[2];
		} info;
	} error;
	struct {
		struct json_object **scope;
		uint8_t size;
		uint8_t off;
	} stack;
};

struct ut_opcode *ut_new_op(struct ut_state *s, int type, struct json_object *val, ...);
struct ut_opcode *ut_wrap_op(struct ut_opcode *parent, ...);
struct ut_opcode *ut_append_op(struct ut_opcode *a, struct ut_opcode *b);
enum ut_error_type ut_parse(struct ut_state *s, const char *expr);
void ut_free(struct ut_state *s);

struct ut_opcode *ut_new_func(struct ut_state *s, struct ut_opcode *name, struct ut_opcode *args, struct ut_opcode *body);

struct json_object *json_object_new_double_rounded(double v);
struct json_object *json_object_new_null_obj(void);

void *ParseAlloc(void *(*mfunc)(size_t));
void Parse(void *pParser, int type, struct ut_opcode *op, struct ut_state *s);
void ParseFree(void *pParser, void (*ffunc)(void *));


static inline uint32_t getrefcnt(struct json_object *v) {
	struct {
		enum json_type o_type;
		uint32_t _ref_count;
	} *spy = (void *)v;

	return spy ? spy->_ref_count : 0;
}

#endif /* __AST_H_ */
