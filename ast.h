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
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>

#ifdef JSONC
	#include <json.h>
#else
	#include <json-c/json.h>
#endif

#define JSON_C_TO_STRING_STRICT (1<<31)

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
	UT_ERROR_INVALID_REGEXP,
	UT_ERROR_EXCEPTION
};

enum ut_lex_state {
	UT_LEX_IDENTIFY_BLOCK,
	UT_LEX_BLOCK_COMMENT_START,
	UT_LEX_BLOCK_EXPRESSION_START,
	UT_LEX_BLOCK_EXPRESSION_EMIT_TAG,
	UT_LEX_BLOCK_STATEMENT_START,
	UT_LEX_BLOCK_COMMENT,
	UT_LEX_IDENTIFY_TOKEN,
	UT_LEX_PARSE_TOKEN,
	UT_LEX_EOF
};

struct ut_op {
	uint16_t type;
	uint16_t is_first:1;
	uint16_t is_op:1;
	uint16_t is_overflow:1;
	uint16_t is_postfix:1;
	uint16_t is_for_in:1;
	uint16_t is_list:1;
	uint16_t is_reg_icase:1;
	uint16_t is_reg_newline:1;
	uint16_t is_reg_global:1;
	uint32_t off;
	struct json_object *val;
	union {
		struct {
			struct json_object *proto;
			size_t type;
			void *data;
			uint32_t off;
		} tag;
		struct {
			uint32_t next;
			uint32_t operand[4];
		} tree;
	};
};

struct ut_scope {
	struct ut_scope *next;
	struct json_object *scope, *ctx, *parent;
	size_t refs;
};

struct ut_function {
	char *name, *filename;
	struct json_object *args;
	struct ut_scope *scope, *parent_scope;
	uint32_t entry;
};

struct ut_state {
	struct ut_op *pool;
	uint32_t poolsize;
	uint32_t main;
	uint8_t srand_called:1;
	uint8_t trim_blocks:1;
	uint8_t lstrip_blocks:1;
	uint8_t strict_declarations:1;
	uint8_t skip_shebang:1;
	struct {
		enum ut_lex_state state;
		uint8_t eof:1;
		uint8_t skip_leading_whitespace:1;
		uint8_t skip_leading_newline:1;
		uint8_t within_expression_block:1;
		uint8_t within_statement_block:1;
		uint8_t semicolon_emitted:1;
		uint8_t expect_div:1;
		uint8_t is_escape:1;
		size_t buflen;
		char *buf, *bufstart, *bufend;
		size_t lookbehindlen;
		char *lookbehind;
		const void *tok;
		char esc[5];
		uint8_t esclen;
		int lead_surrogate;
		size_t off, lastoff;
	} lex;
	struct {
		enum ut_error_type code;
		union {
			struct json_object *exception;
			uint64_t tokens[2];
			char *regexp_error;
		} info;
	} error;
	struct ut_scope *scopelist, *scope;
	struct json_object *ctx, *rval;
	char *filename;
};

struct ut_extended_type {
	const char *name;
	struct json_object *proto;
	void (*free)(void *);
};

struct ut_op *ut_get_op(struct ut_state *s, uint32_t off);
struct ut_op *ut_get_child(struct ut_state *s, uint32_t off, int n);

static inline uint32_t ut_get_off(struct ut_state *s, struct ut_op *op) {
	return op ? (op - s->pool + 1) : 0;
};

static inline bool ut_is_type(struct json_object *val, int type) {
	struct ut_op *tag = json_object_get_userdata(val);

	return (tag && tag->type == type);
};


#define UT_ET_DIV (sizeof(s->error.info.tokens[0]) * 8)
#define UT_ET_TYPE typeof(s->error.info.tokens[0])

static inline void ut_set_error_token(struct ut_state *s, int tokennr) {
	s->error.info.tokens[tokennr / UT_ET_DIV] |= ((UT_ET_TYPE)1 << (tokennr % UT_ET_DIV));
}

static inline bool ut_is_error_token(struct ut_state *s, int tokennr) {
	return (s->error.info.tokens[tokennr / UT_ET_DIV] & ((UT_ET_TYPE)1 << (tokennr % UT_ET_DIV)));
}


uint32_t ut_new_op(struct ut_state *s, int type, struct json_object *val, ...);
uint32_t ut_wrap_op(struct ut_state *s, uint32_t parent, ...);
uint32_t ut_append_op(struct ut_state *s, uint32_t a, uint32_t b);
enum ut_error_type ut_parse(struct ut_state *s, const char *expr);
void ut_free(struct ut_state *s);

struct json_object *ut_new_func(struct ut_state *s, struct ut_op *decl, struct ut_scope *scope);
struct json_object *ut_new_object(struct json_object *proto);
struct json_object *ut_new_double(double v);
struct json_object *ut_new_null(void);
struct json_object *ut_new_regexp(const char *source, bool icase, bool newline, bool global, char **err);

__attribute__((format(printf, 3, 0)))
struct json_object *ut_new_exception(struct ut_state *s, uint32_t off, const char *fmt, ...);

#define ut_exception ut_new_exception

struct ut_scope *ut_new_scope(struct ut_state *s, struct ut_scope *parent);
struct ut_scope *ut_parent_scope(struct ut_scope *scope);
struct ut_scope *ut_acquire_scope(struct ut_scope *scope);
void ut_release_scope(struct ut_scope *scope);

bool ut_register_extended_type(const char *name, struct json_object *proto, void (*freefn)(void *));
struct json_object *ut_set_extended_type(struct json_object *v, const char *name, void *data);
void **ut_get_extended_type(struct json_object *val, const char *name);

void *ParseAlloc(void *(*mfunc)(size_t));
void Parse(void *pParser, int type, uint32_t off, struct ut_state *s);
void ParseFree(void *pParser, void (*ffunc)(void *));


static inline uint32_t getrefcnt(struct json_object *v) {
	struct {
		enum json_type o_type;
		uint32_t _ref_count;
	} *spy = (void *)v;

	return spy ? spy->_ref_count : 0;
}

static inline void *xalloc(size_t size) {
	void *ptr = calloc(1, size);

	if (!ptr) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return ptr;
}

static inline void *xrealloc(void *ptr, size_t size) {
	ptr = realloc(ptr, size);

	if (!ptr) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return ptr;
}

static inline struct json_object *xjs_new_object(void) {
	struct json_object *ptr = json_object_new_object();

	if (!ptr) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return ptr;
}

static inline struct json_object *xjs_new_array(void) {
	struct json_object *ptr = json_object_new_array();

	if (!ptr) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return ptr;
}

static inline struct json_object *xjs_new_int64(int64_t n) {
	struct json_object *ptr = json_object_new_int64(n);

	if (!ptr) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return ptr;
}

static inline struct json_object *xjs_new_string(const char *s) {
	struct json_object *ptr = json_object_new_string(s);

	if (!ptr) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return ptr;
}

static inline struct json_object *xjs_new_string_len(const char *s, size_t len) {
	struct json_object *ptr = json_object_new_string_len(s, len);

	if (!ptr) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return ptr;
}

static inline struct json_object *xjs_new_boolean(bool v) {
	struct json_object *ptr = json_object_new_boolean(v);

	if (!ptr) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return ptr;
}


static inline struct json_tokener *xjs_new_tokener(void) {
	struct json_tokener *tok = json_tokener_new();

	if (!tok) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return tok;
}

static inline int xasprintf(char **strp, const char *fmt, ...) {
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vasprintf(strp, fmt, ap);
	va_end(ap);

	if (len == -1) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return len;
}

static inline int xvasprintf(char **strp, const char *fmt, va_list ap) {
	int len = vasprintf(strp, fmt, ap);

	if (len == -1) {
		fprintf(stderr, "Out of memory\n");
		abort();
	}

	return len;
}

#endif /* __AST_H_ */
