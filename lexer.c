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

#include <stdio.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>
#include <math.h>

#include "ast.h"
#include "lexer.h"
#include "parser.h"


struct token {
	int type;
	const char *pat;
	int plen;
	int (*parse)(const char *buf, struct ut_opcode *op, struct ut_state *s);
};

#define dec(o) \
	((o) - '0')

#define hex(x) \
	(((x) >= 'a') ? (10 + (x) - 'a') : \
		(((x) >= 'A') ? (10 + (x) - 'A') : dec(x)))

static int parse_comment(const char *, struct ut_opcode *, struct ut_state *);
static int parse_string(const char *, struct ut_opcode *, struct ut_state *);
static int parse_number(const char *, struct ut_opcode *, struct ut_state *);
static int parse_label(const char *, struct ut_opcode *, struct ut_state *);
static int parse_bool(const char *, struct ut_opcode *, struct ut_state *);

static const struct token tokens[] = {
	{ 0,			" ",     1 },
	{ 0,			"\t",    1 },
	{ 0,			"\r",    1 },
	{ 0,			"\n",    1 },
	{ T_ASLEFT,		"<<=",   3 },
	{ T_ASRIGHT,	">>=",   3 },
	{ T_LEXP,		"{{-",   3 },
	{ T_REXP,		"-}}",   3 },
	{ T_LSTM,		"{%-",   3 },
	{ T_RSTM,		"-%}",   3 },
	{ T_AND,		"&&",    2 },
	{ T_ASADD,		"+=",    2 },
	{ T_ASBAND,		"&=",    2 },
	{ T_ASBOR,		"|=",    2 },
	{ T_ASBXOR,		"^=",    2 },
	{ T_ASDIV,		"/=",    2 },
	{ T_ASMOD,		"%=",    2 },
	{ T_ASMUL,		"*=",    2 },
	{ T_ASSUB,		"-=",    2 },
	{ T_DEC,		"--",    2 },
	{ T_INC,		"++",    2 },
	{ T_IF,			"if",    2 },
	{ T_EQ,			"==",    2 },
	{ T_NE,			"!=",    2 },
	{ T_LE,			"<=",    2 },
	{ T_GE,			">=",    2 },
	{ T_LSHIFT,		"<<",    2 },
	{ T_RSHIFT,		">>",    2 },
	{ 0,			"//",    2, parse_comment },
	{ 0,			"/*",    2, parse_comment },
	{ T_OR,			"||",    2 },
	{ T_LEXP,		"{{",    2 },
	{ T_REXP,		"}}",    2 },
	{ T_LSTM,		"{%",    2 },
	{ T_RSTM,		"%}",    2 },
	{ T_ADD,		"+",     1 },
	{ T_ASSIGN,		"=",     1 },
	{ T_BAND,		"&",     1 },
	{ T_BOR,		"|",     1 },
	{ T_LBRACK,		"[",     1 },
	{ T_RBRACK,		"]",     1 },
	{ T_BXOR,		"^",     1 },
	{ T_LBRACE,		"{",     1 },
	{ T_RBRACE,		"}",     1 },
	{ T_COLON,		":",     1 },
	{ T_COMMA,		",",     1 },
	{ T_COMPL,		"~",     1 },
	{ T_DIV,		"/",     1 },
	{ T_GT,			">",     1 },
	{ T_NOT,		"!",     1 },
	{ T_LT,			"<",     1 },
	{ T_MOD,		"%",     1 },
	{ T_MUL,		"*",     1 },
	{ T_LPAREN,		"(",     1 },
	{ T_RPAREN,		")",     1 },
	{ T_QMARK,		"?",     1 },
	{ T_SCOL,		";",     1 },
	{ T_SUB,		"-",     1 },
	{ T_DOT,		".",     1 },
	{ T_STRING,		"'",	 1, parse_string },
	{ T_STRING,		"\"",	 1, parse_string },
	{ T_LABEL,		"_",     1, parse_label  },
	{ T_LABEL,		"az",    0, parse_label  },
	{ T_LABEL,		"AZ",    0, parse_label  },
	{ T_NUMBER,		"09",    0, parse_number },
};

static const struct token reserved_words[] = {
	{ T_ENDFUNC,	"endfunction", 11 },
	{ T_NUMBER,		"Infinity", 8, parse_number },
	{ T_CONTINUE,	"continue", 8 },
	{ T_ENDWHILE,	"endwhile", 8 },
	{ T_FUNC,		"function", 8 },
	{ T_RETURN,		"return", 6 },
	{ T_ENDFOR,		"endfor", 6 },
	{ T_LOCAL,		"local", 5 },
	{ T_ENDIF,		"endif", 5 },
	{ T_WHILE,		"while", 5 },
	{ T_BREAK,		"break", 5 },
	{ T_BOOL,		"false", 5, parse_bool },
	{ T_BOOL,		"true",  4, parse_bool },
	{ T_ELSE,		"else",  4 },
	{ T_THIS,		"this",  4 },
	{ T_NULL,		"null",  4 },
	{ T_NUMBER,		"NaN",   3, parse_number },
	{ T_FOR,		"for",   3 },
	{ T_IN,			"in",    2 },
};

const char *tokennames[__T_MAX] = {
	[0]				= "End of file",
	[T_FUNC]        = "'function'",
	[T_LOCAL]		= "'local'",
	[T_WHILE]       = "'while",
	[T_ELSE]		= "'else'",
	[T_FOR]			= "'for'",
	[T_IF]          = "'if'",
	[T_IN]			= "'in'",
	[T_ASLEFT]		= "'x<<=y'",
	[T_ASRIGHT]		= "'x>>=y'",
	[T_AND]			= "'x&&y'",
	[T_ASADD]		= "'x+=y'",
	[T_ASBAND]		= "'x&=y'",
	[T_ASBOR]		= "'x|=y'",
	[T_ASBXOR]		= "'x^=y'",
	[T_ASDIV]		= "'x/=y'",
	[T_ASMOD]		= "'x%=y'",
	[T_ASMUL]		= "'x*=y'",
	[T_ASSUB]		= "'x-=y'",
	[T_DEC]			= "'x--'",
	[T_INC]			= "'x++'",
	[T_EQ]			= "'x==y'",
	[T_NE]			= "'x!=y'",
	[T_LE]			= "'x<=y'",
	[T_GE]			= "'x>=y'",
	[T_LSHIFT]		= "'x<<y'",
	[T_RSHIFT]		= "'x>>y'",
	[T_LEXP]		= "'{{'",
	[T_REXP]		= "'}}'",
	[T_OR]			= "'x||y'",
	[T_ADD]			= "'x+y'",
	[T_ASSIGN]		= "'x=y'",
	[T_BAND]		= "'x&y'",
	[T_BOR]			= "'x|y'",
	[T_LBRACK]		= "'['",
	[T_RBRACK]		= "']'",
	[T_BXOR]		= "'x^y'",
	[T_LBRACE]		= "'{'",
	[T_RBRACE]		= "'}'",
	[T_COLON]		= "':'",
	[T_COMMA]		= "','",
	[T_COMPL]		= "'~x'",
	[T_DIV]			= "'x/y'",
	[T_GT]			= "'x>y'",
	[T_NOT]			= "'!x'",
	[T_LT]			= "'x<y'",
	[T_MOD]			= "'x%y'",
	[T_MUL]			= "'x*y'",
	[T_LPAREN]		= "'('",
	[T_RPAREN]		= "')'",
	[T_QMARK]		= "'?'",
	[T_SCOL]		= "';'",
	[T_SUB]			= "'x-y'",
	[T_DOT]			= "'.'",
	[T_STRING]		= "String",
	[T_LABEL]		= "Label",
	[T_NUMBER]		= "Number",
	[T_DOUBLE]		= "Double",
	[T_BOOL]		= "Bool",
	[T_TEXT]		= "Text",
	[T_ENDIF]		= "'endif'",
	[T_ENDFOR]		= "'endfor'",
	[T_ENDWHILE]	= "'endwhile'",
	[T_ENDFUNC]     = "'endfuncton'",
	[T_RETURN]      = "'return'",
	[T_BREAK]    	= "'break'",
	[T_CONTINUE]    = "'continue'",
	[T_NULL]		= "'null'",
	[T_THIS]        = "'this'",
	//[T_LSTM]		= "'{%'",
	//[T_RSTM]		= "'%}'"
};


/*
 * Stores the given codepoint as a utf8 multibyte sequence into the given
 * output buffer and substracts the required amount of bytes from  the given
 * length pointer.
 *
 * Returns false if the multibyte sequence would not fit into the buffer,
 * otherwise true.
 */

bool
utf8enc(char **out, int *rem, int code)
{
	if (code >= 0 && code <= 0x7F) {
		if (*rem < 1)
			return false;

		*(*out)++ = code; (*rem)--;

		return true;
	}
	else if (code > 0 && code <= 0x7FF) {
		if (*rem < 2)
			return false;

		*(*out)++ = ((code >>  6) & 0x1F) | 0xC0; (*rem)--;
		*(*out)++ = ( code        & 0x3F) | 0x80; (*rem)--;

		return true;
	}
	else if (code > 0 && code <= 0xFFFF) {
		if (*rem < 3)
			return false;

		*(*out)++ = ((code >> 12) & 0x0F) | 0xE0; (*rem)--;
		*(*out)++ = ((code >>  6) & 0x3F) | 0x80; (*rem)--;
		*(*out)++ = ( code        & 0x3F) | 0x80; (*rem)--;

		return true;
	}
	else if (code > 0 && code <= 0x10FFFF) {
		if (*rem < 4)
			return false;

		*(*out)++ = ((code >> 18) & 0x07) | 0xF0; (*rem)--;
		*(*out)++ = ((code >> 12) & 0x3F) | 0x80; (*rem)--;
		*(*out)++ = ((code >>  6) & 0x3F) | 0x80; (*rem)--;
		*(*out)++ = ( code        & 0x3F) | 0x80; (*rem)--;

		return true;
	}

	return true;
}

/*
 * Parses a comment from the given buffer.
 *
 * Returns a negative value on error, otherwise the amount of consumed
 * characters from the given buffer.
 *
 * Error values:
 *  -UT_ERROR_UNTERMINATED_COMMENT	Unterminated string
 */

static int
parse_comment(const char *buf, struct ut_opcode *op, struct ut_state *s)
{
	const char *p = buf;

	/* single line comment */
	if (p[0] == '/' && p[1] == '/') {
		while (*p != 0 && *p != '\n')
			p++;

		return (p - buf);
	}

	/* multi line comment */
	while (*p) {
		if (p[0] == '*' && p[1] == '/')
			break;

		p++;
	}

	return *p ? (p - buf) + 2 : -UT_ERROR_UNTERMINATED_COMMENT;
}

/*
 * Parses a string literal from the given buffer.
 *
 * Returns a negative value on error, otherwise the amount of consumed
 * characters from the given buffer.
 *
 * Error values:
 *  -UT_ERROR_UNTERMINATED_STRING	Unterminated string
 *  -UT_ERROR_INVALID_ESCAPE		Invalid escape sequence
 *  -UT_ERROR_OVERLONG_STRING		String literal too long
 */

static int
parse_string(const char *buf, struct ut_opcode *op, struct ut_state *s)
{
	char q = *(buf++);
	char str[128] = { 0 };
	char *out = str;
	const char *in = buf;
	bool esc = false;
	int rem = sizeof(str) - 1;
	int code;

	while (*in) {
		/* continuation of escape sequence */
		if (esc) {
			/* \uFFFF */
			if (in[0] == 'u') {
				if (isxdigit(in[1]) && isxdigit(in[2]) &&
				    isxdigit(in[3]) && isxdigit(in[4])) {
					if (!utf8enc(&out, &rem,
					             hex(in[1]) * 16 * 16 * 16 +
					             hex(in[2]) * 16 * 16 +
					             hex(in[3]) * 16 +
					             hex(in[4]))) {
						s->off += (in - buf);

						return -UT_ERROR_OVERLONG_STRING;
					}

					in += 5;
				}
				else {
					s->off += (in - buf);

					return -UT_ERROR_INVALID_ESCAPE;
				}
			}

			/* \xFF */
			else if (in[0] == 'x') {
				if (isxdigit(in[1]) && isxdigit(in[2])) {
					if (!utf8enc(&out, &rem, hex(in[1]) * 16 + hex(in[2]))) {
						s->off += (in - buf);

						return -UT_ERROR_OVERLONG_STRING;
					}

					in += 3;
				}
				else {
					s->off += (in - buf);
					return -UT_ERROR_INVALID_ESCAPE;
				}
			}

			/* \377, \77 or \7 */
			else if (in[0] >= '0' && in[0] <= '7') {
				/* \377 */
				if (in[1] >= '0' && in[1] <= '7' &&
				    in[2] >= '0' && in[2] <= '7') {
					code = dec(in[0]) * 8 * 8 +
					       dec(in[1]) * 8 +
					       dec(in[2]);

					if (code > 255) {
						s->off += (in - buf);

						return -UT_ERROR_INVALID_ESCAPE;
					}

					if (!utf8enc(&out, &rem, code)) {
						s->off += (in - buf);

						return -UT_ERROR_OVERLONG_STRING;
					}

					in += 3;
				}

				/* \77 */
				else if (in[1] >= '0' && in[1] <= '7') {
					if (!utf8enc(&out, &rem, dec(in[0]) * 8 + dec(in[1]))) {
						s->off += (in - buf);

						return -UT_ERROR_OVERLONG_STRING;
					}

					in += 2;
				}

				/* \7 */
				else {
					if (!utf8enc(&out, &rem, dec(in[0]))) {
						s->off += (in - buf);

						return -UT_ERROR_OVERLONG_STRING;
					}

					in += 1;
				}
			}

			/* single character escape */
			else {
				if (rem-- < 1) {
					s->off += (in - buf);

					return -UT_ERROR_OVERLONG_STRING;
				}

				switch (in[0]) {
				case 'a': *out = '\a'; break;
				case 'b': *out = '\b'; break;
				case 'e': *out = '\e'; break;
				case 'f': *out = '\f'; break;
				case 'n': *out = '\n'; break;
				case 'r': *out = '\r'; break;
				case 't': *out = '\t'; break;
				case 'v': *out = '\v'; break;
				default:
					*out = *in;
					break;
				}

				in++;
				out++;
			}

			esc = false;
		}

		/* begin of escape sequence */
		else if (*in == '\\') {
			in++;
			esc = true;
		}

		/* terminating quote */
		else if (*in == q) {
			op->val = json_object_new_string_len(str, sizeof(str) - 1 - rem);

			return (in - buf) + 2;
		}

		/* ordinary char */
		else {
			if (rem-- < 1) {
				s->off += (in - buf);

				return -UT_ERROR_OVERLONG_STRING;
			}

			*out++ = *in++;
		}
	}

	return -UT_ERROR_UNTERMINATED_STRING;
}


/*
 * Parses a label from the given buffer.
 *
 * Returns a negative value on error, otherwise the amount of consumed
 * characters from the given buffer.
 *
 * Error values:
 *  -UT_ERROR_OVERLONG_STRING	Label too long
 */

static int
parse_label(const char *buf, struct ut_opcode *op, struct ut_state *s)
{
	const struct token *word;
	char str[128] = { 0 };
	char *out = str;
	const char *in = buf;
	int rem = sizeof(str) - 1;
	int i;

	while (*in == '_' || isalnum(*in)) {
		if (rem-- < 1) {
			s->off += (in - buf);
			return -UT_ERROR_OVERLONG_STRING;
		}

		*out++ = *in++;
	}

	for (i = 0, word = &reserved_words[0];
	     i < sizeof(reserved_words) / sizeof(reserved_words[0]);
	     i++, word = &reserved_words[i]) {
		if (!strcmp(str, word->pat)) {
			op->type = word->type;

			if (word->parse)
				word->parse(str, op, s);

			return (in - buf);
		}
	}

	op->val = json_object_new_string(str);

	return (in - buf);
}


/*
 * Parses a number literal from the given buffer.
 *
 * Returns a negative value on error, otherwise the amount of consumed
 * characters from the given buffer.
 *
 * Error values:
 *  -UT_ERROR_INVALID_ESCAPE	Invalid number character
 */

static int
parse_number(const char *buf, struct ut_opcode *op, struct ut_state *s)
{
	double d;
	char *e;
	int n;

	if (!strncmp(buf, "Infinity", 8)) {
		op->type = T_DOUBLE;
		op->val = json_object_new_double_rounded(INFINITY);

		return 8;
	}
	else if (!strncmp(buf, "NaN", 3)) {
		op->type = T_DOUBLE;
		op->val = json_object_new_double_rounded(NAN);

		return 3;
	}

	n = strtol(buf, &e, 0);

	if (e > buf) {
		if (*e == '.') {
			d = strtod(buf, &e);

			if (e > buf) {
				op->type = T_DOUBLE;
				op->val = json_object_new_double_rounded(d);

				return (e - buf);
			}
		}

		op->type = T_NUMBER;
		op->val = json_object_new_int64(n);

		return (e - buf);
	}

	return -UT_ERROR_INVALID_ESCAPE;
}


/*
 * Parses a bool literal from the given buffer.
 *
 * Returns the amount of consumed characters from the given buffer.
 */

static int
parse_bool(const char *buf, struct ut_opcode *op, struct ut_state *s)
{
	if (!strncmp(buf, "false", 5)) {
		op->val = json_object_new_boolean(false);

		return 5;
	}
	else if (!strncmp(buf, "true", 4)) {
		op->val = json_object_new_boolean(true);

		return 4;
	}

	return 0;
}


static int
match_token(const char *ptr, struct ut_opcode *op, struct ut_state *s)
{
	int i;
	const struct token *tok;

	for (i = 0, tok = &tokens[0];
	     i < sizeof(tokens) / sizeof(tokens[0]);
		 i++, tok = &tokens[i]) {
		if ((tok->plen > 0 && !strncmp(ptr, tok->pat, tok->plen)) ||
		    (tok->plen == 0 && *ptr >= tok->pat[0] && *ptr <= tok->pat[1])) {
			op->type = tok->type;

			if (tok->parse)
				return tok->parse(ptr, op, s);

			return tok->plen;
		}
	}

	return -UT_ERROR_UNEXPECTED_CHAR;
}

struct ut_opcode *
ut_get_token(struct ut_state *s, const char *input, int *mlen)
{
	struct ut_opcode op = { 0 };
	const char *o, *p;

	for (o = p = input; *p; p++) {
		if (s->blocktype == UT_BLOCK_NONE) {
			if (!strncmp(p, "{#", 2))
				s->blocktype = UT_BLOCK_COMMENT;
			else if (!strncmp(p, "{{", 2))
				s->blocktype = UT_BLOCK_EXPRESSION;
			else if (!strncmp(p, "{%", 2))
				s->blocktype = UT_BLOCK_STATEMENT;

			if (s->blocktype) {
				*mlen = p - input;
				s->start_tag_seen = 0;
				s->off += *mlen;

				/* strip whitespace before block */
				if (p[2] == '-')
					while (p > o && isspace(p[-1]))
						p--;

				if (p == o)
					return NULL;

				return ut_new_op(s, T_TEXT, json_object_new_string_len(o, p - o), (void *)1);
			}
		}
		else if (s->blocktype == UT_BLOCK_COMMENT) {
			if (!strncmp(p, "#}", 2) || !strncmp(p, "-#}", 3)) {
				*mlen = (p - input) + 2;

				/* strip whitespace after block */
				if (*p == '-') {
					(*mlen)++;

					while (isspace(p[3])) {
						(*mlen)++;
						p++;
					}
				}

				s->blocktype = UT_BLOCK_NONE;
				s->off += *mlen;

				return NULL;
			}
		}
		else if (s->blocktype == UT_BLOCK_STATEMENT || s->blocktype == UT_BLOCK_EXPRESSION) {
			*mlen = match_token(p, &op, s);

			if (*mlen < 0) {
				s->error.code = -*mlen;

				return NULL;
			}

			/* disallow nesting blocks */
			else if ((s->start_tag_seen && s->blocktype == UT_BLOCK_STATEMENT &&
			          (op.type == T_LEXP || op.type == T_REXP || op.type == T_LSTM)) ||
			         (s->start_tag_seen && s->blocktype == UT_BLOCK_EXPRESSION &&
			          (op.type == T_LSTM || op.type == T_RSTM || op.type == T_LEXP))) {
				s->error.code = UT_ERROR_NESTED_BLOCKS;

				return NULL;
			}

			/* emit additional empty statement (semicolon) at end of template block */
			else if ((s->blocktype == UT_BLOCK_STATEMENT && op.type == T_RSTM) ||
			         (s->blocktype == UT_BLOCK_EXPRESSION && op.type == T_REXP)) {
				if (!s->semicolon_emitted) {
					s->semicolon_emitted = true;
					op.type = T_SCOL;
					*mlen = 0;
				}
				else {
					s->semicolon_emitted = false;
					s->blocktype = UT_BLOCK_NONE;

					/* strip whitespace after block */
					if (*p == '-') {
						while (isspace(p[3])) {
							(*mlen)++;
							p++;
						}
					}
				}
			}

			s->start_tag_seen = 1;
			s->off += *mlen;

			/* do not report '{%' and '%}' tags to parser */
			if (op.type == T_LSTM || op.type == T_RSTM || op.type == 0)
				return NULL;

			return ut_new_op(s, op.type, op.val, (void *)1);
		}
	}

	/* allow unclosed '{%' blocks */
	if (s->blocktype == UT_BLOCK_EXPRESSION || s->blocktype == UT_BLOCK_COMMENT) {
		s->error.code = UT_ERROR_UNTERMINATED_BLOCK;

		return NULL;
	}

	if (p > input) {
		*mlen = p - input;
		s->off += *mlen;

		return ut_new_op(s, T_TEXT, json_object_new_string_len(o, p - o), (void *)1);
	}

	return NULL;
}
