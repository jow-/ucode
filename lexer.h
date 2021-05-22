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

#ifndef __LEXER_H_
#define __LEXER_H_

#include "source.h"
#include "types.h"


typedef enum {
	TK_LEXP = 1,
	TK_REXP,
	TK_LSTM,
	TK_RSTM,
	TK_IF,
	TK_ELSE,
	TK_COMMA,
	TK_ASBAND,
	TK_ASBXOR,
	TK_ASBOR,
	TK_ASLEFT,
	TK_ASRIGHT,
	TK_ASMUL,
	TK_ASDIV,
	TK_ASMOD,
	TK_ASADD,
	TK_ASSUB,
	TK_ASSIGN,
	TK_QMARK,
	TK_COLON,
	TK_OR,
	TK_AND,
	TK_BOR,
	TK_BXOR,
	TK_BAND,
	TK_EQ,
	TK_NE,
	TK_EQS,
	TK_NES,
	TK_LT,
	TK_LE,
	TK_GT,
	TK_GE,
	TK_IN,
	TK_LSHIFT,
	TK_RSHIFT,
	TK_ADD,
	TK_SUB,
	TK_MUL,
	TK_DIV,
	TK_MOD,
	TK_NOT,
	TK_COMPL,
	TK_INC,
	TK_DEC,
	TK_LPAREN,
	TK_LBRACK,
	TK_TEXT,
	TK_LBRACE,
	TK_RBRACE,
	TK_SCOL,
	TK_RPAREN,
	TK_ENDIF,
	TK_ELIF,
	TK_WHILE,
	TK_ENDWHILE,
	TK_FOR,
	TK_ENDFOR,
	TK_FUNC,
	TK_LABEL,
	TK_ENDFUNC,
	TK_TRY,
	TK_CATCH,
	TK_SWITCH,
	TK_CASE,
	TK_DEFAULT,
	TK_ELLIP,
	TK_RETURN,
	TK_BREAK,
	TK_CONTINUE,
	TK_LOCAL,
	TK_ARROW,
	TK_DOT,
	TK_RBRACK,
	TK_BOOL,
	TK_NUMBER,
	TK_DOUBLE,
	TK_STRING,
	TK_REGEXP,
	TK_NULL,
	TK_THIS,
	TK_DELETE,
	TK_CONST,

	TK_EOF,
	TK_ERROR
} uc_tokentype_t;

typedef enum {
	UT_LEX_IDENTIFY_BLOCK,
	UT_LEX_BLOCK_COMMENT_START,
	UT_LEX_BLOCK_EXPRESSION_START,
	UT_LEX_BLOCK_EXPRESSION_EMIT_TAG,
	UT_LEX_BLOCK_STATEMENT_START,
	UT_LEX_BLOCK_COMMENT,
	UT_LEX_IDENTIFY_TOKEN,
	UT_LEX_PARSE_TOKEN,
	UT_LEX_EOF
} uc_lex_state_t;

typedef struct {
	uc_tokentype_t type;
	uc_value_t *uv;
	size_t pos;
} uc_token;

typedef struct {
	uc_lex_state_t state;
	uc_parse_config *config;
	uc_source *source;
	uint8_t eof:1;
	uint8_t is_escape:1;
	uint8_t no_regexp:1;
	uint8_t no_keyword:1;
	size_t buflen;
	char *buf, *bufstart, *bufend;
	size_t lookbehindlen;
	char *lookbehind;
	const void *tok;
	uc_token curr;
	char esc[5];
	uint8_t esclen;
	int lead_surrogate;
	size_t lastoff;
	enum {
		UNSPEC,
		PLUS,
		MINUS,
		NEWLINE
	} modifier;
	enum {
		NONE,
		EXPRESSION = '{',
		STATEMENTS = '%',
		COMMENT = '#'
	} block;
} uc_lexer;


void uc_lexer_init(uc_lexer *lex, uc_parse_config *config, uc_source *source);
void uc_lexer_free(uc_lexer *lex);

uc_token *uc_lexer_next_token(uc_lexer *lex);

bool utf8enc(char **out, int *rem, int code);

const char *
uc_get_tokenname(unsigned type);

#endif /* __LEXER_H_ */
