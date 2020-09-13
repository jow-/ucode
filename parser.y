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

%token_type {uint32_t}
%extra_argument {struct ut_state *s}

%nonassoc T_LEXP T_REXP T_LSTM T_RSTM.

%nonassoc T_IF.
%nonassoc T_ELSE.

%left T_COMMA.
%right T_ASBAND T_ASBXOR T_ASBOR.
%right T_ASLEFT T_ASRIGHT.
%right T_ASMUL T_ASDIV T_ASMOD.
%right T_ASADD T_ASSUB.
%right T_ASSIGN.
%right T_QMARK T_COLON.
%left T_OR.
%left T_AND.
%left T_BOR.
%left T_BXOR.
%left T_BAND.
%left T_EQ T_NE T_EQS T_NES.
%left T_LT T_LE T_GT T_GE T_IN.
%left T_LSHIFT T_RSHIFT.
%left T_ADD T_SUB.
%left T_MUL T_DIV T_MOD.
%right T_NOT T_COMPL.
%right T_INC T_DEC.
%left T_LPAREN T_LBRACK.


%include {
#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "ast.h"
#include "lexer.h"
#include "parser.h"

#define YYSTACKDEPTH 0
#define YYNOERRORRECOVERY

#define new_op(type, val, ...) \
	ut_new_op(s, type, val, ##__VA_ARGS__, UINT32_MAX)

#define wrap_op(op, ...) \
	ut_wrap_op(s, op, ##__VA_ARGS__, UINT32_MAX)

#define append_op(op1, op2) \
	ut_append_op(s, op1, op2)

#define no_empty_obj(op) \
	ut_no_empty_obj(s, op)

static inline uint32_t
ut_no_empty_obj(struct ut_state *s, uint32_t off)
{
	struct ut_op *op = ut_get_op(s, off);

	return (!op || op->type != T_LBRACE || op->tree.operand[0]) ? off : 0;
}

}

%syntax_error {
	struct ut_op *op = TOKEN ? ut_get_op(s, TOKEN) : NULL;
	int i;

	s->error.code = UT_ERROR_UNEXPECTED_TOKEN;

	if (op)
		s->off = op->off;

	for (i = 0; i < sizeof(tokennames) / sizeof(tokennames[0]); i++)
		if (yy_find_shift_action(yypParser, (YYCODETYPE)i) < YYNSTATE + YYNRULE)
			s->error.info.tokens[i / 64] |= ((unsigned)1 << (i % 64));
}


input ::= chunks(A).									{ s->main = new_op(T_FUNC, NULL, 0, 0, A); }
input ::= .												{ s->main = new_op(T_TEXT, json_object_new_string("")); s->main = new_op(T_FUNC, NULL, 0, 0, s->main); }

chunks(A) ::= chunks(B) T_TEXT(C).						{ A = B ? append_op(B, C) : C; }
chunks(A) ::= chunks(B) tplexp(C).						{ A = B ? append_op(B, C) : C; }
chunks(A) ::= chunks(B) stmt(C).						{ A = B ? append_op(B, C) : C; }
chunks(A) ::= T_TEXT(B).								{ A = B; }
chunks(A) ::= tplexp(B).								{ A = B; }
chunks(A) ::= stmt(B).									{ A = B; }

tplexp(A) ::= T_LEXP(B) exp_stmt(C) T_REXP.				{ A = wrap_op(B, C); }

stmts(A) ::= stmts(B) stmt(C).							{ A = B ? append_op(B, C) : C; }
stmts(A) ::= stmt(B).									{ A = B; }

stmt(A) ::= cpd_stmt(B).								{ A = B; }
stmt(A) ::= exp_stmt(B).								{ A = B; }
stmt(A) ::= sel_stmt(B).								{ A = B; }
stmt(A) ::= iter_stmt(B).								{ A = B; }
stmt(A) ::= func_stmt(B).								{ A = B; }
stmt(A) ::= ret_stmt(B).								{ A = B; }
stmt(A) ::= break_stmt(B).								{ A = B; }
stmt(A) ::= decl_stmt(B).								{ A = B; }

//cpd_stmt(A) ::= T_LBRACE T_RBRACE.						{ A = NULL; }
cpd_stmt(A) ::= T_LBRACE stmts(B) exp(C) T_RBRACE.		{ A = B ? append_op(B, C) : C; }
cpd_stmt(A) ::= T_LBRACE stmts(B) T_RBRACE.				{ A = B; }
cpd_stmt(A) ::= T_LBRACE exp(B) T_RBRACE.				{ A = B; }

exp_stmt(A) ::= exp(B) T_SCOL.							{ A = B; }
exp_stmt(A) ::= T_SCOL.									{ A = 0; }

sel_stmt(A) ::= T_IF(B) T_LPAREN exp(C) T_RPAREN stmt(D) T_ELSE stmt(E).
														{ A = wrap_op(B, C, no_empty_obj(D), no_empty_obj(E)); }
sel_stmt(A) ::= T_IF(B) T_LPAREN exp(C) T_RPAREN stmt(D). [T_IF]
														{ A = wrap_op(B, C, no_empty_obj(D)); }
sel_stmt(A) ::= T_IF(B) T_LPAREN exp(C) T_RPAREN T_COLON chunks(D) T_ELSE chunks(E) T_ENDIF.
														{ A = wrap_op(B, C, D, E); }
sel_stmt(A) ::= T_IF(B) T_LPAREN exp(C) T_RPAREN T_COLON chunks(D) T_ENDIF. [T_IF]
														{ A = wrap_op(B, C, D); }

iter_stmt(A) ::= T_WHILE(B) T_LPAREN exp(C) T_RPAREN stmt(D).
														{ A = wrap_op(B, C, no_empty_obj(D)); }
iter_stmt(A) ::= T_WHILE(B) T_LPAREN exp(C) T_RPAREN T_COLON chunks(D) T_ENDWHILE.
														{ A = wrap_op(B, C, D); }
iter_stmt(A) ::= T_FOR(B) T_LPAREN for_in_exp(C) T_RPAREN stmt(D).
														{ A = wrap_op(B, C, NULL, NULL, no_empty_obj(D)); ut_get_op(s, A)->is_for_in = 1; }
iter_stmt(A) ::= T_FOR(B) T_LPAREN for_in_exp(C) T_RPAREN T_COLON chunks(D) T_ENDFOR.
														{ A = wrap_op(B, C, NULL, NULL, no_empty_obj(D)); ut_get_op(s, A)->is_for_in = 1; }
iter_stmt(A) ::= T_FOR(B) T_LPAREN decl_or_exp(C) exp_stmt(D) T_RPAREN stmt(E).
														{ A = wrap_op(B, C, D, NULL, no_empty_obj(E)); }
iter_stmt(A) ::= T_FOR(B) T_LPAREN decl_or_exp(C) exp_stmt(D) exp(E) T_RPAREN stmt(F).
														{ A = wrap_op(B, C, D, E, no_empty_obj(F)); }
iter_stmt(A) ::= T_FOR(B) T_LPAREN decl_or_exp(C) exp_stmt(D) T_RPAREN T_COLON chunks(E) T_ENDFOR.
														{ A = wrap_op(B, C, D, NULL, E); }
iter_stmt(A) ::= T_FOR(B) T_LPAREN decl_or_exp(C) exp_stmt(D) exp(E) T_RPAREN T_COLON chunks(F) T_ENDFOR.
														{ A = wrap_op(B, C, D, E, F); }

func_stmt(A) ::= T_FUNC(B) T_LABEL(C) T_LPAREN T_RPAREN cpd_stmt(D).
														{ A = wrap_op(B, C, 0, D); }
func_stmt(A) ::= T_FUNC(B) T_LABEL(C) T_LPAREN T_RPAREN empty_object.
														{ A = wrap_op(B, C, 0, 0); }
func_stmt(A) ::= T_FUNC(B) T_LABEL(C) T_LPAREN T_RPAREN T_COLON chunks(D) T_ENDFUNC.
														{ A = wrap_op(B, C, 0, D); }
func_stmt(A) ::= T_FUNC(B) T_LABEL(C) T_LPAREN args(D) T_RPAREN cpd_stmt(E).
														{ A = wrap_op(B, C, D, E); }
func_stmt(A) ::= T_FUNC(B) T_LABEL(C) T_LPAREN args(D) T_RPAREN empty_object.
														{ A = wrap_op(B, C, D, 0); }
func_stmt(A) ::= T_FUNC(B) T_LABEL(C) T_LPAREN args(D) T_RPAREN T_COLON chunks(E) T_ENDFUNC.
														{ A = wrap_op(B, C, D, E); }

args(A) ::= args(B) T_COMMA T_LABEL(C).					{ A = append_op(B, C); }
args(A) ::= T_LABEL(B).									{ A = B; }

for_in_exp(A) ::= rel_exp(B).							{ A = B; }
for_in_exp(A) ::= T_LOCAL(B) rel_exp(C).				{ A = wrap_op(B, C); }

decl_or_exp(A) ::= exp_stmt(B).							{ A = B; }
decl_or_exp(A) ::= decl_stmt(B).						{ A = B; }

ret_stmt(A) ::= T_RETURN(B) exp(C) T_SCOL.				{ A = wrap_op(B, C); }
ret_stmt(A) ::= T_RETURN(B) T_SCOL.						{ A = B; }

break_stmt(A) ::= T_BREAK(B) T_SCOL.					{ A = B; }
break_stmt(A) ::= T_CONTINUE(B) T_SCOL.					{ A = B; }

decl_stmt(A) ::= T_LOCAL(B) decls(C) T_SCOL.			{ A = wrap_op(B, C); }

decls(A) ::= decls(B) T_COMMA decl(C).					{ A = append_op(B, C); }
decls(A) ::= decl(B).									{ A = B; }

decl(A) ::= T_LABEL(B) T_ASSIGN(C) ternary_exp(D).		{ A = wrap_op(C, B, D); }
decl(A) ::= T_LABEL(B).									{ A = new_op(T_ASSIGN, NULL, B); }

exp(A) ::= exp(B) T_COMMA assign_exp(C).				{ A = append_op(B, C); }
exp(A) ::= assign_exp(B).								{ A = B; }

assign_exp(A) ::= unary_exp(B) T_ASSIGN(C) ternary_exp(D).
														{ A = wrap_op(C, B, D); }
assign_exp(A) ::= unary_exp(B) T_ASADD ternary_exp(C).	{ A = new_op(T_ADD, NULL, B, C); A = new_op(T_ASSIGN, NULL, B, A); }
assign_exp(A) ::= unary_exp(B) T_ASSUB ternary_exp(C).	{ A = new_op(T_SUB, NULL, B, C); A = new_op(T_ASSIGN, NULL, B, A); }
assign_exp(A) ::= unary_exp(B) T_ASMUL ternary_exp(C).	{ A = new_op(T_MUL, NULL, B, C); A = new_op(T_ASSIGN, NULL, B, A); }
assign_exp(A) ::= unary_exp(B) T_ASDIV ternary_exp(C).	{ A = new_op(T_DIV, NULL, B, C); A = new_op(T_ASSIGN, NULL, B, A); }
assign_exp(A) ::= unary_exp(B) T_ASMOD ternary_exp(C).	{ A = new_op(T_MOD, NULL, B, C); A = new_op(T_ASSIGN, NULL, B, A); }
assign_exp(A) ::= unary_exp(B) T_ASLEFT ternary_exp(C).	{ A = new_op(T_LSHIFT, NULL, B, C); A = new_op(T_ASSIGN, NULL, B, A); }
assign_exp(A) ::= unary_exp(B) T_ASRIGHT ternary_exp(C).
														{ A = new_op(T_RSHIFT, NULL, B, C); A = new_op(T_ASSIGN, NULL, B, A); }
assign_exp(A) ::= unary_exp(B) T_ASBAND ternary_exp(C).	{ A = new_op(T_BAND, NULL, B, C); A = new_op(T_ASSIGN, NULL, B, A); }
assign_exp(A) ::= unary_exp(B) T_ASBXOR ternary_exp(C).	{ A = new_op(T_BXOR, NULL, B, C); A = new_op(T_ASSIGN, NULL, B, A); }
assign_exp(A) ::= unary_exp(B) T_ASBOR ternary_exp(C).	{ A = new_op(T_BOR, NULL, B, C); A = new_op(T_ASSIGN, NULL, B, A); }
assign_exp(A) ::= ternary_exp(B).						{ A = B; }

ternary_exp(A) ::= or_exp(B) T_QMARK(C) assign_exp(D) T_COLON ternary_exp(E).
														{ A = wrap_op(C, B, D, E); }
ternary_exp(A) ::= or_exp(B).							{ A = B; }

or_exp(A) ::= or_exp(B) T_OR(C) and_exp(D).				{ A = wrap_op(C, B, D); }
or_exp(A) ::= and_exp(B).								{ A = B; }

and_exp(A) ::= and_exp(B) T_AND(C) bor_exp(D).			{ A = wrap_op(C, B, D); }
and_exp(A) ::= bor_exp(B).								{ A = B; }

bor_exp(A) ::= bor_exp(B) T_BOR(C) bxor_exp(D).			{ A = wrap_op(C, B, D); }
bor_exp(A) ::= bxor_exp(B).								{ A = B; }

bxor_exp(A) ::= bxor_exp(B) T_BXOR(C) band_exp(D).		{ A = wrap_op(C, B, D); }
bxor_exp(A) ::= band_exp(B).							{ A = B; }

band_exp(A) ::= band_exp(B) T_BAND(C) equal_exp(D).		{ A = wrap_op(C, B, D); }
band_exp(A) ::= equal_exp(B).							{ A = B; }

equal_exp(A) ::= equal_exp(B) T_EQ(C) rel_exp(D).		{ A = wrap_op(C, B, D); }
equal_exp(A) ::= equal_exp(B) T_NE(C) rel_exp(D).		{ A = wrap_op(C, B, D); }
equal_exp(A) ::= equal_exp(B) T_EQS(C) rel_exp(D).		{ A = wrap_op(C, B, D); }
equal_exp(A) ::= equal_exp(B) T_NES(C) rel_exp(D).		{ A = wrap_op(C, B, D); }
equal_exp(A) ::= rel_exp(B).							{ A = B; }

rel_exp(A) ::= rel_exp(B) T_LT(C) shift_exp(D).			{ A = wrap_op(C, B, D); }
rel_exp(A) ::= rel_exp(B) T_LE(C) shift_exp(D).			{ A = wrap_op(C, B, D); }
rel_exp(A) ::= rel_exp(B) T_GT(C) shift_exp(D).			{ A = wrap_op(C, B, D); }
rel_exp(A) ::= rel_exp(B) T_GE(C) shift_exp(D).			{ A = wrap_op(C, B, D); }
rel_exp(A) ::= rel_exp(B) T_IN(C) shift_exp(D).			{ A = wrap_op(C, B, D); }
rel_exp(A) ::= shift_exp(B).							{ A = B; }

shift_exp(A) ::= shift_exp(B) T_LSHIFT(C) add_exp(D).	{ A = wrap_op(C, B, D); }
shift_exp(A) ::= shift_exp(B) T_RSHIFT(C) add_exp(D).	{ A = wrap_op(C, B, D); }
shift_exp(A) ::= add_exp(B).							{ A = B; }

add_exp(A) ::= add_exp(B) T_ADD(C) mul_exp(D).			{ A = wrap_op(C, B, D); }
add_exp(A) ::= add_exp(B) T_SUB(C) mul_exp(D).			{ A = wrap_op(C, B, D); }
add_exp(A) ::= mul_exp(B).								{ A = B; }

mul_exp(A) ::= mul_exp(B) T_MUL(C) unary_exp(D).		{ A = wrap_op(C, B, D); }
mul_exp(A) ::= mul_exp(B) T_DIV(C) unary_exp(D).		{ A = wrap_op(C, B, D); }
mul_exp(A) ::= mul_exp(B) T_MOD(C) unary_exp(D).		{ A = wrap_op(C, B, D); }
mul_exp(A) ::= unary_exp(B).							{ A = B; }

unary_exp(A) ::= T_INC(B) unary_exp(C). [T_LPAREN]		{ A = wrap_op(B, C); }
unary_exp(A) ::= T_DEC(B) unary_exp(C). [T_LPAREN]		{ A = wrap_op(B, C); }
unary_exp(A) ::= T_ADD(B) unary_exp(C). [T_NOT]			{ A = wrap_op(B, C); }
unary_exp(A) ::= T_SUB(B) unary_exp(C). [T_NOT]			{ A = wrap_op(B, C); }
unary_exp(A) ::= T_COMPL(B) unary_exp(C).				{ A = wrap_op(B, C); }
unary_exp(A) ::= T_NOT(B) unary_exp(C).					{ A = wrap_op(B, C); }
unary_exp(A) ::= postfix_exp(B).						{ A = B; }

postfix_exp(A) ::= unary_exp(B) T_INC(C).				{ A = wrap_op(C, B); ut_get_op(s, A)->is_postfix = 1; }
postfix_exp(A) ::= unary_exp(B) T_DEC(C).				{ A = wrap_op(C, B); ut_get_op(s, A)->is_postfix = 1; }
postfix_exp(A) ::= unary_exp(B) T_LPAREN(C) T_RPAREN.	{ A = wrap_op(C, B); }
postfix_exp(A) ::= unary_exp(B) T_LPAREN(C) arg_exp(D) T_RPAREN.
														{ A = wrap_op(C, B, D); }
postfix_exp(A) ::= postfix_exp(B) T_DOT(C) T_LABEL(D).	{ A = wrap_op(C, B, D); }
postfix_exp(A) ::= postfix_exp(B) T_LBRACK(C) assign_exp(D) T_RBRACK.
														{ A = wrap_op(C, B, D); ut_get_op(s, A)->is_postfix = 1; }
postfix_exp(A) ::= primary_exp(B).						{ A = B; }

primary_exp(A) ::= T_BOOL(B).							{ A = B; }
primary_exp(A) ::= T_NUMBER(B).							{ A = B; }
primary_exp(A) ::= T_DOUBLE(B).							{ A = B; }
primary_exp(A) ::= T_STRING(B).							{ A = B; }
primary_exp(A) ::= T_LABEL(B).							{ A = B; }
primary_exp(A) ::= T_NULL(B).							{ A = B; }
primary_exp(A) ::= T_THIS(B).							{ A = B; }
primary_exp(A) ::= array(B).							{ A = B; }
primary_exp(A) ::= object(B).							{ A = B; }
primary_exp(A) ::= T_LPAREN assign_exp(B) T_RPAREN.		{ A = B; }
primary_exp(A) ::= T_FUNC T_LPAREN T_RPAREN empty_object.
														{ A = new_op(T_FUNC, NULL, 0, 0, 0); }
primary_exp(A) ::= T_FUNC T_LPAREN args(B) T_RPAREN empty_object.
														{ A = new_op(T_FUNC, NULL, 0, B, 0); }
primary_exp(A) ::= T_FUNC T_LPAREN T_RPAREN cpd_stmt(B).
														{ A = new_op(T_FUNC, NULL, 0, 0, B); }
primary_exp(A) ::= T_FUNC T_LPAREN args(B) T_RPAREN cpd_stmt(C).
														{ A = new_op(T_FUNC, NULL, 0, B, C); }

array(A) ::= T_LBRACK(B) T_RBRACK.						{ A = B; }
array(A) ::= T_LBRACK(B) exp(C) T_RBRACK.				{ A = wrap_op(B, C); }

object(A) ::= empty_object(B).							{ A = B; }
object(A) ::= T_LBRACE(B) tuples(C) T_RBRACE.			{ A = wrap_op(B, C); }

empty_object(A) ::= T_LBRACE(B) T_RBRACE.				{ A = B; }

tuples(A) ::= tuples(B) T_COMMA tuple(C).				{ A = append_op(B, C); }
tuples(A) ::= tuple(B).									{ A = B; }

tuple(A) ::= T_LABEL(B) T_COLON exp(C).					{ A = append_op(B, C); }
tuple(A) ::= T_STRING(B) T_COLON exp(C).				{ A = append_op(B, C); }

arg_exp(A) ::= arg_exp(B) T_COMMA assign_exp(C).		{ A = append_op(B, C); }
arg_exp(A) ::= assign_exp(B).							{ A = B; }
