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

#include "compiler.h"
#include "chunk.h"
#include "vm.h" /* I_* */
#include "source.h"
#include "lib.h" /* format_error_context() */

static void uc_compiler_compile_unary(uc_compiler *compiler, bool assignable);
static void uc_compiler_compile_binary(uc_compiler *compiler, bool assignable);
static void uc_compiler_compile_paren(uc_compiler *compiler, bool assignable);
static void uc_compiler_compile_call(uc_compiler *compiler, bool assignable);
static void uc_compiler_compile_post_inc(uc_compiler *compiler, bool assignable);
static void uc_compiler_compile_constant(uc_compiler *compiler, bool assignable);
static void uc_compiler_compile_comma(uc_compiler *compiler, bool assignable);
static void uc_compiler_compile_labelexpr(uc_compiler *compiler, bool assignable);
static void uc_compiler_compile_function(uc_compiler *compiler, bool assignable);
static void uc_compiler_compile_and(uc_compiler *compiler, bool assignable);
static void uc_compiler_compile_or(uc_compiler *compiler, bool assignable);
static void uc_compiler_compile_dot(uc_compiler *compiler, bool assignable);
static void uc_compiler_compile_subscript(uc_compiler *compiler, bool assignable);
static void uc_compiler_compile_ternary(uc_compiler *compiler, bool assignable);
static void uc_compiler_compile_array(uc_compiler *compiler, bool assignable);
static void uc_compiler_compile_object(uc_compiler *compiler, bool assignable);

static void uc_compiler_compile_declaration(uc_compiler *compiler);
static void uc_compiler_compile_statement(uc_compiler *compiler);
static void uc_compiler_compile_expstmt(uc_compiler *compiler);

static uc_parse_rule
uc_compiler_parse_rules[TK_ERROR + 1] = {
	[TK_LPAREN]	= { uc_compiler_compile_paren, uc_compiler_compile_call, P_CALL },
	[TK_SUB]	= { uc_compiler_compile_unary, uc_compiler_compile_binary, P_ADD },
	[TK_ADD]	= { uc_compiler_compile_unary, uc_compiler_compile_binary, P_ADD },
	[TK_COMPL]	= { uc_compiler_compile_unary, NULL, P_UNARY },
	[TK_NOT]	= { uc_compiler_compile_unary, NULL, P_UNARY },
	[TK_INC]	= { uc_compiler_compile_unary, uc_compiler_compile_post_inc, P_INC },
	[TK_DEC]	= { uc_compiler_compile_unary, uc_compiler_compile_post_inc, P_INC },
	[TK_DIV]	= { NULL, uc_compiler_compile_binary, P_MUL },
	[TK_MUL]	= { NULL, uc_compiler_compile_binary, P_MUL },
	[TK_MOD]	= { NULL, uc_compiler_compile_binary, P_MUL },
	[TK_NUMBER]	= { uc_compiler_compile_constant, NULL, P_NONE },
	[TK_DOUBLE] = { uc_compiler_compile_constant, NULL, P_NONE },
	[TK_STRING]	= { uc_compiler_compile_constant, NULL, P_NONE },
	[TK_BOOL]	= { uc_compiler_compile_constant, NULL, P_NONE },
	[TK_NULL]	= { uc_compiler_compile_constant, NULL, P_NONE },
	[TK_THIS]	= { uc_compiler_compile_constant, NULL, P_NONE },
	[TK_REGEXP]	= { uc_compiler_compile_constant, NULL, P_NONE },
	[TK_COMMA]	= { NULL, uc_compiler_compile_comma, P_COMMA },
	[TK_LABEL]  = { uc_compiler_compile_labelexpr, NULL, P_NONE },
	[TK_FUNC]	= { uc_compiler_compile_function, NULL, P_NONE },
	[TK_AND]    = { NULL, uc_compiler_compile_and, P_AND },
	[TK_OR]     = { NULL, uc_compiler_compile_or, P_OR },
	[TK_BOR]	= { NULL, uc_compiler_compile_binary, P_BOR },
	[TK_BXOR]	= { NULL, uc_compiler_compile_binary, P_BXOR },
	[TK_BAND]	= { NULL, uc_compiler_compile_binary, P_BAND },
	[TK_EQ]		= { NULL, uc_compiler_compile_binary, P_EQUAL },
	[TK_EQS]	= { NULL, uc_compiler_compile_binary, P_EQUAL },
	[TK_NE]		= { NULL, uc_compiler_compile_binary, P_EQUAL },
	[TK_NES]	= { NULL, uc_compiler_compile_binary, P_EQUAL },
	[TK_LT]		= { NULL, uc_compiler_compile_binary, P_COMPARE },
	[TK_LE]		= { NULL, uc_compiler_compile_binary, P_COMPARE },
	[TK_GT]		= { NULL, uc_compiler_compile_binary, P_COMPARE },
	[TK_GE]		= { NULL, uc_compiler_compile_binary, P_COMPARE },
	[TK_IN]		= { NULL, uc_compiler_compile_binary, P_COMPARE },
	[TK_LSHIFT]	= { NULL, uc_compiler_compile_binary, P_SHIFT },
	[TK_RSHIFT]	= { NULL, uc_compiler_compile_binary, P_SHIFT },
	[TK_DOT]	= { NULL, uc_compiler_compile_dot, P_CALL },
	[TK_LBRACK] = { uc_compiler_compile_array, uc_compiler_compile_subscript, P_CALL },
	[TK_QMARK]  = { NULL, uc_compiler_compile_ternary, P_TERNARY },
	[TK_LBRACE] = { uc_compiler_compile_object, NULL, P_NONE },
};

static ssize_t
uc_compiler_declare_local(uc_compiler *compiler, json_object *name);

static ssize_t
uc_compiler_initialize_local(uc_compiler *compiler);

static void
uc_compiler_init(uc_compiler *compiler, const char *name, size_t srcpos, uc_source *source)
{
	json_object *varname = xjs_new_string("(callee)");

	compiler->scope_depth = 0;

	compiler->function = uc_function_new(name, srcpos, source);

	compiler->locals.count = 0;
	compiler->locals.entries = NULL;

	compiler->upvals.count = 0;
	compiler->upvals.entries = NULL;

	compiler->patchlist = NULL;

	compiler->parent = NULL;

	compiler->current_srcpos = srcpos;

	/* reserve stack slot 0 */
	uc_compiler_declare_local(compiler, varname);
	uc_compiler_initialize_local(compiler);
	uc_value_put(varname);
}

static uc_chunk *
uc_compiler_current_chunk(uc_compiler *compiler)
{
	return &compiler->function->chunk;
}

__attribute__((format(printf, 3, 0))) static void
uc_compiler_syntax_error(uc_compiler *compiler, size_t off, const char *fmt, ...)
{
	size_t line = 0, byte = 0, len = 0;
	char *context = NULL;
	char *s, *tmp;
	va_list ap;

	if (compiler->parser->synchronizing)
		return;

	compiler->parser->synchronizing = true;

	if (!off)
		off = uc_function_get_srcpos(compiler->function,
			uc_compiler_current_chunk(compiler)->count);

	if (off) {
		byte = off;
		line = uc_source_get_line(compiler->function->source, &byte);

		format_error_context(&context, &len, compiler->function->source, NULL, off);
	}

	va_start(ap, fmt);
	xvasprintf(&s, fmt, ap);
	va_end(ap);

	xasprintf(&tmp, "Syntax error: %s\n", s);
	free(s);
	s = tmp;

	if (line) {
		xasprintf(&tmp, "%sIn line %zu, byte %zu:\n", s, line, byte);
		free(s);
		s = tmp;
	}

	if (context) {
		xasprintf(&tmp, "%s%s\n\n", s, context);
		free(context);
		free(s);
		s = tmp;
	}

	if (compiler->parser->error) {
		xasprintf(&tmp, "%s%s", compiler->parser->error, s);
		free(compiler->parser->error);
		free(s);
		compiler->parser->error = tmp;
	}
	else {
		compiler->parser->error = s;
	}
}

static size_t
uc_compiler_set_srcpos(uc_compiler *compiler, size_t srcpos)
{
	size_t delta;

	/* ensure that lines counts are strictly increasing */
	assert(srcpos == 0 || srcpos >= compiler->current_srcpos);

	delta = srcpos ? srcpos - compiler->current_srcpos : 0;
	compiler->current_srcpos += delta;

	return delta;
}

static void
uc_compiler_parse_advance(uc_compiler *compiler)
{
	bool no_regexp;

	uc_value_put(compiler->parser->prev.val);
	compiler->parser->prev = compiler->parser->curr;

	while (true) {
		/* Follow JSLint logic and treat a slash after any of the
		* `(,=:[!&|?{};` characters as the beginning of a regex
		* literal... */
		switch (compiler->parser->prev.type) {
		case TK_LPAREN:
		case TK_COMMA:

		case TK_ASADD:
		case TK_ASBAND:
		case TK_ASBOR:
		case TK_ASBXOR:
		case TK_ASDIV:
		case TK_ASLEFT:
		case TK_ASMOD:
		case TK_ASMUL:
		case TK_ASRIGHT:
		case TK_ASSIGN:
		case TK_ASSUB:
		case TK_EQ:
		case TK_EQS:
		case TK_GE:
		case TK_LE:
		case TK_NE:
		case TK_NES:

		case TK_COLON:
		case TK_LBRACK:
		case TK_NOT:

		case TK_AND:
		case TK_BAND:

		case TK_OR:
		case TK_BOR:

		case TK_QMARK:

		case TK_LBRACE:
		case TK_RBRACE:

		case TK_LSTM:
		case TK_LEXP:

		case TK_SCOL:
			no_regexp = false;
			break;

		default:
			no_regexp = (compiler->parser->prev.type != 0);
		}

		compiler->parser->curr = *uc_lexer_next_token(&compiler->parser->lex, no_regexp);

		if (compiler->parser->curr.type != TK_ERROR)
			break;

		uc_compiler_syntax_error(compiler, compiler->parser->curr.pos, "%s",
			json_object_get_string(compiler->parser->curr.val));

		uc_value_put(compiler->parser->curr.val);
		compiler->parser->curr.val = NULL;
	}
}

static void
uc_compiler_parse_consume(uc_compiler *compiler, uc_tokentype_t type)
{
	if (compiler->parser->curr.type == type) {
		uc_compiler_parse_advance(compiler);

		return;
	}

	uc_compiler_syntax_error(compiler, compiler->parser->curr.pos,
		"Unexpected token\nExpecting %s", uc_get_tokenname(type));
}

static bool
uc_compiler_parse_check(uc_compiler *compiler, uc_tokentype_t type)
{
	return (compiler->parser->curr.type == type);
}

static bool
uc_compiler_parse_match(uc_compiler *compiler, uc_tokentype_t type)
{
	if (!uc_compiler_parse_check(compiler, type))
		return false;

	uc_compiler_parse_advance(compiler);

	return true;
}

static void
uc_compiler_parse_synchronize(uc_compiler *compiler)
{
	compiler->parser->synchronizing = false;

	while (compiler->parser->curr.type != TK_EOF) {
		if (compiler->parser->prev.type == TK_SCOL)
			return;

		switch (compiler->parser->curr.type) {
		case TK_IF:
		case TK_FOR:
		case TK_WHILE:
		case TK_SWITCH:
		case TK_FUNC:
		case TK_TRY:
		case TK_RETURN:
		case TK_BREAK:
		case TK_CONTINUE:
		case TK_LOCAL:
			return;

		default:
			break;
		}

		uc_compiler_parse_advance(compiler);
	}
}

static uc_parse_rule *
uc_compiler_parse_rule(uc_tokentype_t type)
{
	return &uc_compiler_parse_rules[type];
}

static bool
uc_compiler_parse_at_assignment_op(uc_compiler *compiler)
{
	switch (compiler->parser->curr.type) {
	case TK_ASBAND:
	case TK_ASBXOR:
	case TK_ASBOR:
	case TK_ASLEFT:
	case TK_ASRIGHT:
	case TK_ASMUL:
	case TK_ASDIV:
	case TK_ASMOD:
	case TK_ASADD:
	case TK_ASSUB:
	case TK_ASSIGN:
		return true;

	default:
		return false;
	}
}

static void
uc_compiler_parse_precedence(uc_compiler *compiler, uc_precedence_t precedence)
{
	uc_parse_rule *rule;
	bool assignable;

	uc_compiler_parse_advance(compiler);

	rule = uc_compiler_parse_rule(compiler->parser->prev.type);

	if (!rule->prefix) {
		uc_compiler_syntax_error(compiler, compiler->parser->prev.pos, "Expecting expression");

		return;
	}

	assignable = (precedence <= P_ASSIGN);
	rule->prefix(compiler, assignable);

	while (precedence <= uc_compiler_parse_rule(compiler->parser->curr.type)->precedence) {
		uc_compiler_parse_advance(compiler);
		uc_compiler_parse_rule(compiler->parser->prev.type)->infix(compiler, assignable);
	}

	if (assignable && uc_compiler_parse_at_assignment_op(compiler))
		uc_compiler_syntax_error(compiler, compiler->parser->prev.pos, "Invalid left-hand side expression for assignment");
}

static size_t
uc_compiler_reladdr(uc_compiler *compiler, size_t from, size_t to)
{
	ssize_t delta = to - from;

	if (delta < -0x7fffffff || delta > 0x7fffffff) {
		uc_compiler_syntax_error(compiler, 0, "Jump address too far");

		return 0;
	}

	return (size_t)(delta + 0x7fffffff);
}

static size_t
uc_compiler_emit_insn(uc_compiler *compiler, size_t srcpos, enum insn_type insn)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t lineoff = uc_compiler_set_srcpos(compiler, srcpos);

	compiler->last_insn = uc_chunk_add(chunk, (uint8_t)insn, lineoff);

	return compiler->last_insn;
}

static size_t
uc_compiler_emit_u8(uc_compiler *compiler, size_t srcpos, uint8_t n)
{
	return uc_chunk_add(
		uc_compiler_current_chunk(compiler),
		n,
		uc_compiler_set_srcpos(compiler, srcpos));
}

static size_t
uc_compiler_emit_s8(uc_compiler *compiler, size_t srcpos, int8_t n)
{
	return uc_chunk_add(
		uc_compiler_current_chunk(compiler),
		n + 0x7f,
		uc_compiler_set_srcpos(compiler, srcpos));
}

static size_t
uc_compiler_emit_u16(uc_compiler *compiler, size_t srcpos, uint16_t n)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t lineoff = uc_compiler_set_srcpos(compiler, srcpos);

	uc_chunk_add(chunk, n / 0x100, lineoff);
	uc_chunk_add(chunk, n % 0x100, 0);

	return chunk->count - 2;
}

static size_t
uc_compiler_emit_s16(uc_compiler *compiler, size_t srcpos, int16_t n)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t lineoff = uc_compiler_set_srcpos(compiler, srcpos);
	uint16_t v = n + 0x7fff;

	uc_chunk_add(chunk, v / 0x100, lineoff);
	uc_chunk_add(chunk, v % 0x100, 0);

	return chunk->count - 2;
}

static size_t
uc_compiler_emit_u32(uc_compiler *compiler, size_t srcpos, uint32_t n)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t lineoff = uc_compiler_set_srcpos(compiler, srcpos);

	uc_chunk_add(chunk, n / 0x1000000, lineoff);
	uc_chunk_add(chunk, (n / 0x10000) % 0x100, 0);
	uc_chunk_add(chunk, (n / 0x100) % 0x100, 0);
	uc_chunk_add(chunk, n % 0x100, 0);

	return chunk->count - 4;
}

static size_t
uc_compiler_emit_s32(uc_compiler *compiler, size_t srcpos, int32_t n)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t lineoff = uc_compiler_set_srcpos(compiler, srcpos);
	uint32_t v = n + 0x7fffffff;

	uc_chunk_add(chunk, v / 0x1000000, lineoff);
	uc_chunk_add(chunk, (v / 0x10000) % 0x100, 0);
	uc_chunk_add(chunk, (v / 0x100) % 0x100, 0);
	uc_chunk_add(chunk, v % 0x100, 0);

	return chunk->count - 4;
}

static uint32_t
uc_compiler_get_u32(uc_compiler *compiler, size_t off)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);

	return chunk->entries[off + 0] * 0x1000000 +
	       chunk->entries[off + 1] * 0x10000 +
	       chunk->entries[off + 2] * 0x100 +
	       chunk->entries[off + 3];
}

static void
uc_compiler_set_u32(uc_compiler *compiler, size_t off, uint32_t n)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);

	chunk->entries[off + 0] = n / 0x1000000;
	chunk->entries[off + 1] = (n / 0x10000) % 0x100;
	chunk->entries[off + 2] = (n / 0x100) % 0x100;
	chunk->entries[off + 3] = n % 0x100;
}

static size_t
uc_compiler_emit_constant(uc_compiler *compiler, size_t srcpos, json_object *val)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t cidx = uc_chunk_add_constant(chunk, val);

	uc_compiler_emit_insn(compiler, srcpos, I_LOAD);
	uc_compiler_emit_u32(compiler, 0, cidx);

	return cidx;
}

static size_t
uc_compiler_emit_regexp(uc_compiler *compiler, size_t srcpos, json_object *val)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t cidx = uc_chunk_add_constant(chunk, val);

	uc_compiler_emit_insn(compiler, srcpos, I_LREXP);
	uc_compiler_emit_u32(compiler, 0, cidx);

	return cidx;
}

static size_t
uc_compiler_emit_jmp(uc_compiler *compiler, size_t srcpos, uint32_t dest)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);

	uc_compiler_emit_insn(compiler, srcpos, I_JMP);
	uc_compiler_emit_u32(compiler, 0, dest ? uc_compiler_reladdr(compiler, chunk->count - 1, dest) : 0);

	return chunk->count - 5;
}

static size_t
uc_compiler_emit_jmpz(uc_compiler *compiler, size_t srcpos, uint32_t dest)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);

	uc_compiler_emit_insn(compiler, srcpos, I_JMPZ);
	uc_compiler_emit_u32(compiler, 0, dest ? uc_compiler_reladdr(compiler, chunk->count - 1, dest) : 0);

	return chunk->count - 5;
}

static ssize_t
uc_compiler_get_jmpaddr(uc_compiler *compiler, size_t off)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);

	assert(chunk->entries[off] == I_JMP || chunk->entries[off] == I_JMPZ);
	assert(off + 4 < chunk->count);

	return (
		chunk->entries[off + 1] * 0x1000000 +
		chunk->entries[off + 2] * 0x10000 +
		chunk->entries[off + 3] * 0x100 +
		chunk->entries[off + 4]
	) - 0x7fffffff;
}

static void
uc_compiler_set_jmpaddr(uc_compiler *compiler, size_t off, uint32_t dest)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t addr = uc_compiler_reladdr(compiler, off, dest);

	assert(chunk->entries[off] == I_JMP || chunk->entries[off] == I_JMPZ);
	assert(off + 4 < chunk->count);

	chunk->entries[off + 1] = addr / 0x1000000;
	chunk->entries[off + 2] = (addr / 0x10000) % 0x100;
	chunk->entries[off + 3] = (addr / 0x100) % 0x100;
	chunk->entries[off + 4] = addr % 0x100;
}

static uc_function *
uc_compiler_finish(uc_compiler *compiler)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	uc_locals *locals = &compiler->locals;
	uc_upvals *upvals = &compiler->upvals;
	size_t i;

	uc_compiler_emit_insn(compiler, 0, I_LNULL);
	uc_compiler_emit_insn(compiler, 0, I_RETURN);

	for (i = 0; i < locals->count; i++) {
		uc_chunk_debug_add_variable(chunk,
			locals->entries[i].from,
			chunk->count,
			i,
			false,
			locals->entries[i].name);

		uc_value_put(locals->entries[i].name);
	}

	for (i = 0; i < upvals->count; i++) {
		uc_chunk_debug_add_variable(chunk,
			0,
			chunk->count,
			i,
			true,
			upvals->entries[i].name);

		uc_value_put(upvals->entries[i].name);
	}

	uc_vector_clear(locals);
	uc_vector_clear(upvals);

	if (compiler->parser->error) {
		uc_value_put(compiler->function->header.jso);

		return NULL;
	}

	return compiler->function;
}

static void
uc_compiler_enter_scope(uc_compiler *compiler)
{
	compiler->scope_depth++;
}

static void
uc_compiler_leave_scope(uc_compiler *compiler)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	uc_locals *locals = &compiler->locals;

	compiler->scope_depth--;

	while (locals->count > 0 && locals->entries[locals->count - 1].depth > compiler->scope_depth) {
		locals->count--;

		uc_chunk_debug_add_variable(chunk,
			locals->entries[locals->count].from,
			chunk->count,
			locals->count,
			false,
			locals->entries[locals->count].name);

		uc_value_put(locals->entries[locals->count].name);
		locals->entries[locals->count].name = NULL;

		uc_compiler_emit_insn(compiler, 0,
			locals->entries[locals->count].captured ? I_CUPV : I_POP);
	}
}

static ssize_t
uc_compiler_declare_local(uc_compiler *compiler, json_object *name)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	uc_locals *locals = &compiler->locals;
	const char *str1, *str2;
	size_t i, len1, len2;

	//if (compiler->scope_depth == 0)
	//	return;

	if (locals->count >= 0x00FFFFFF) {
		uc_compiler_syntax_error(compiler, 0, "Too many local variables");

		return -1;
	}

	str1 = json_object_get_string(name);
	len1 = json_object_get_string_len(name);

	for (i = locals->count; i > 0; i--) {
		if (locals->entries[i - 1].depth != -1 && locals->entries[i - 1].depth < compiler->scope_depth)
			break;

		str2 = json_object_get_string(locals->entries[i - 1].name);
		len2 = json_object_get_string_len(locals->entries[i - 1].name);

		if (len1 == len2 && !strcmp(str1, str2)) {
			if (compiler->parser->config &&
			    compiler->parser->config->strict_declarations) {
				uc_compiler_syntax_error(compiler, 0, "Variable '%s' redeclared", str2);

				return -1;
			}

			return i - 1;
		}
	}

	uc_vector_grow(locals);

	locals->entries[locals->count].name = uc_value_get(name);
	locals->entries[locals->count].depth = -1;
	locals->entries[locals->count].captured = false;
	locals->entries[locals->count].from = chunk->count;
	locals->count++;

	return -1;
}

static ssize_t
uc_compiler_initialize_local(uc_compiler *compiler)
{
	uc_locals *locals = &compiler->locals;

	locals->entries[locals->count - 1].depth = compiler->scope_depth;

	return locals->count - 1;
}

static ssize_t
uc_compiler_resolve_local(uc_compiler *compiler, json_object *name)
{
	uc_locals *locals = &compiler->locals;
	const char *str1, *str2;
	size_t i, len1, len2;

	str1 = json_object_get_string(name);
	len1 = json_object_get_string_len(name);

	for (i = locals->count; i > 0; i--) {
		str2 = json_object_get_string(locals->entries[i - 1].name);
		len2 = json_object_get_string_len(locals->entries[i - 1].name);

		if (len1 != len2 || strcmp(str1, str2))
			continue;

		if (locals->entries[i - 1].depth == -1) {
			uc_compiler_syntax_error(compiler, 0,
				"Can't access lexical declaration '%s' before initialization", str2);

			return -1;
		}

		return i - 1;
	}

	return -1;
}

static ssize_t
uc_compiler_add_upval(uc_compiler *compiler, ssize_t idx, bool local, json_object *name)
{
	uc_function *function = compiler->function;
	uc_upvals *upvals = &compiler->upvals;
	uc_upval *uv;
	size_t i;

	for (i = 0, uv = upvals->entries; i < upvals->count; i++, uv = upvals->entries + i)
		if (uv->index == idx && uv->local == local)
			return i;

	/* XXX: encoding... */
	if (upvals->count >= (2 << 14)) {
		uc_compiler_syntax_error(compiler, 0, "Too many upvalues");

		return -1;
	}

	uc_vector_grow(upvals);

	upvals->entries[upvals->count].local = local;
	upvals->entries[upvals->count].index = idx;
	upvals->entries[upvals->count].name  = uc_value_get(name);

	function->nupvals++;

	return upvals->count++;
}

static ssize_t
uc_compiler_resolve_upval(uc_compiler *compiler, json_object *name)
{
	ssize_t idx;

	if (!compiler->parent)
		return -1;

	idx = uc_compiler_resolve_local(compiler->parent, name);

	if (idx > -1) {
		compiler->parent->locals.entries[idx].captured = true;

		return uc_compiler_add_upval(compiler, idx, true, name);
	}

	idx = uc_compiler_resolve_upval(compiler->parent, name);

	if (idx > -1)
		return uc_compiler_add_upval(compiler, idx, false, name);

	return -1;
}

static void
uc_compiler_backpatch(uc_compiler *compiler, size_t break_addr, size_t next_addr)
{
	uc_patchlist *pl = compiler->patchlist;
	uc_patchlist *pp = pl->parent;
	volatile ssize_t jmpaddr;
	size_t i;

	for (i = 0; i < pl->count; i++) {
		jmpaddr = uc_compiler_get_jmpaddr(compiler, pl->entries[i]);

		switch (jmpaddr) {
		case TK_BREAK:
			/* if we have a break addr, patch instruction */
			if (break_addr) {
				uc_compiler_set_jmpaddr(compiler, pl->entries[i], break_addr);
				continue;
			}

			break;

		case TK_CONTINUE:
			/* if we have a continue addr, patch instruction */
			if (next_addr) {
				uc_compiler_set_jmpaddr(compiler, pl->entries[i], next_addr);
				continue;
			}

			break;
		}

		/* propagate unhandled patch instructions to parent patch list */
		if (pp) {
			uc_vector_grow(pp);
			pp->entries[pp->count++] = pl->entries[i];
		}
	}

	free(pl->entries);

	compiler->patchlist = pl->parent;
}

static void
uc_compiler_emit_inc_dec(uc_compiler *compiler, uc_tokentype_t toktype, bool is_postfix)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	enum insn_type type;
	uint32_t cidx = 0;

	/* determine kind of emitted load instruction and operand value (if any) */
	type = chunk->entries[compiler->last_insn];

	if (type == I_LVAR || type == I_LLOC || type == I_LUPV) {
		cidx = uc_compiler_get_u32(compiler, compiler->last_insn + 1);

		uc_chunk_pop(chunk);
		uc_chunk_pop(chunk);
		uc_chunk_pop(chunk);
		uc_chunk_pop(chunk);
		uc_chunk_pop(chunk);
	}

	/* if we're mutating an object or array field, pop the last lval instruction
	 * to leave object + last field name value on stack */
	else if (type == I_LVAL) {
		uc_chunk_pop(chunk);
	}
	else {
		uc_compiler_syntax_error(compiler, 0, "Invalid increment/decrement operand");

		return;
	}

	/* add / substract 1 */
	uc_compiler_emit_insn(compiler, 0, I_LOAD8);
	uc_compiler_emit_s8(compiler, 0, (toktype == TK_INC) ? 1 : -1);

	/* depending on variable type, emit corresponding increment instruction */
	switch (type) {
	case I_LVAR:
		uc_compiler_emit_insn(compiler, 0, I_UVAR);
		uc_compiler_emit_u32(compiler, 0, (I_PLUS << 24) | cidx);
		break;

	case I_LLOC:
		uc_compiler_emit_insn(compiler, 0, I_ULOC);
		uc_compiler_emit_u32(compiler, 0, (I_PLUS << 24) | cidx);
		break;

	case I_LUPV:
		uc_compiler_emit_insn(compiler, 0, I_UUPV);
		uc_compiler_emit_u32(compiler, 0, (I_PLUS << 24) | cidx);
		break;

	case I_LVAL:
		uc_compiler_emit_insn(compiler, 0, I_UVAL);
		uc_compiler_emit_u8(compiler, 0, I_PLUS);
		break;

	default:
		break;
	}

	/* for post increment or decrement, add/substract 1 to yield final value */
	if (is_postfix) {
		uc_compiler_emit_insn(compiler, 0, I_LOAD8);
		uc_compiler_emit_s8(compiler, 0, 1);

		uc_compiler_emit_insn(compiler, 0, (toktype == TK_INC) ? I_SUB : I_ADD);
	}
}


static void
uc_compiler_compile_unary(uc_compiler *compiler, bool assignable)
{
	uc_tokentype_t type = compiler->parser->prev.type;

	uc_compiler_parse_precedence(compiler, P_UNARY);

	switch (type) {
	case TK_SUB:
		uc_compiler_emit_insn(compiler, 0, I_MINUS);
		break;

	case TK_ADD:
		uc_compiler_emit_insn(compiler, 0, I_PLUS);
		break;

	case TK_NOT:
		uc_compiler_emit_insn(compiler, 0, I_NOT);
		break;

	case TK_COMPL:
		uc_compiler_emit_insn(compiler, 0, I_COMPL);
		break;

	case TK_INC:
	case TK_DEC:
		uc_compiler_emit_inc_dec(compiler, type, false);
		break;

	default:
		return;
	}
}

static void
uc_compiler_compile_binary(uc_compiler *compiler, bool assignable)
{
	uc_tokentype_t type = compiler->parser->prev.type;

	uc_compiler_parse_precedence(compiler, uc_compiler_parse_rule(type)->precedence + 1);

	switch (type) {
	case TK_ADD:    uc_compiler_emit_insn(compiler, 0, I_ADD);    break;
	case TK_SUB:    uc_compiler_emit_insn(compiler, 0, I_SUB);    break;
	case TK_MUL:    uc_compiler_emit_insn(compiler, 0, I_MUL);    break;
	case TK_DIV:    uc_compiler_emit_insn(compiler, 0, I_DIV);    break;
	case TK_MOD:    uc_compiler_emit_insn(compiler, 0, I_MOD);    break;
	case TK_LSHIFT: uc_compiler_emit_insn(compiler, 0, I_LSHIFT); break;
	case TK_RSHIFT: uc_compiler_emit_insn(compiler, 0, I_RSHIFT); break;
	case TK_BAND:   uc_compiler_emit_insn(compiler, 0, I_BAND);   break;
	case TK_BXOR:   uc_compiler_emit_insn(compiler, 0, I_BXOR);   break;
	case TK_BOR:    uc_compiler_emit_insn(compiler, 0, I_BOR);    break;
	case TK_LT:     uc_compiler_emit_insn(compiler, 0, I_LT);     break;
	case TK_LE:
		uc_compiler_emit_insn(compiler, 0, I_GT);
		uc_compiler_emit_insn(compiler, 0, I_NOT);
		break;
	case TK_GT:     uc_compiler_emit_insn(compiler, 0, I_GT);     break;
	case TK_GE:
		uc_compiler_emit_insn(compiler, 0, I_LT);
		uc_compiler_emit_insn(compiler, 0, I_NOT);
		break;
	case TK_EQ:     uc_compiler_emit_insn(compiler, 0, I_EQ);     break;
	case TK_NE:     uc_compiler_emit_insn(compiler, 0, I_NE);     break;
	case TK_EQS:    uc_compiler_emit_insn(compiler, 0, I_EQS);    break;
	case TK_NES:    uc_compiler_emit_insn(compiler, 0, I_NES);    break;
	case TK_IN:     uc_compiler_emit_insn(compiler, 0, I_IN);     break;
	default:
		return;
	}
}

static enum insn_type
uc_compiler_emit_variable_rw(uc_compiler *compiler, json_object *varname, uc_tokentype_t type)
{
	enum insn_type insn;
	uint32_t sub_insn;
	ssize_t idx;

	switch (type) {
	case TK_ASADD:   sub_insn = I_ADD;    break;
	case TK_ASSUB:   sub_insn = I_SUB;    break;
	case TK_ASMUL:   sub_insn = I_MUL;    break;
	case TK_ASDIV:   sub_insn = I_DIV;    break;
	case TK_ASMOD:   sub_insn = I_MOD;    break;
	case TK_ASBAND:  sub_insn = I_BAND;   break;
	case TK_ASBXOR:  sub_insn = I_BXOR;   break;
	case TK_ASBOR:   sub_insn = I_BOR;    break;
	case TK_ASLEFT:  sub_insn = I_LSHIFT; break;
	case TK_ASRIGHT: sub_insn = I_RSHIFT; break;
	default:         sub_insn = 0;        break;
	}

	if (!varname) {
		insn = sub_insn ? I_UVAL : (type ? I_SVAL : I_LVAL);

		uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, insn);

		if (sub_insn)
			uc_compiler_emit_u8(compiler, compiler->parser->prev.pos, sub_insn);
	}
	else if ((idx = uc_compiler_resolve_local(compiler, varname)) > -1) {
		insn = sub_insn ? I_ULOC : (type ? I_SLOC : I_LLOC);

		uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, insn);
		uc_compiler_emit_u32(compiler, compiler->parser->prev.pos,
			((sub_insn & 0xff) << 24) | idx);
	}
	else if ((idx = uc_compiler_resolve_upval(compiler, varname)) > -1) {
		insn = sub_insn ? I_UUPV : (type ? I_SUPV : I_LUPV);

		uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, insn);
		uc_compiler_emit_u32(compiler, compiler->parser->prev.pos,
			((sub_insn & 0xff) << 24) | idx);
	}
	else {
		idx = uc_chunk_add_constant(uc_compiler_current_chunk(compiler), varname);
		insn = sub_insn ? I_UVAR : (type ? I_SVAR : I_LVAR);

		uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, insn);
		uc_compiler_emit_u32(compiler, compiler->parser->prev.pos,
			((sub_insn & 0xff) << 24) | idx);
	}

	return insn;
}

static void
uc_compiler_compile_expression(uc_compiler *compiler)
{
	uc_compiler_parse_precedence(compiler, P_COMMA);
}

static bool
uc_compiler_compile_assignment(uc_compiler *compiler, json_object *var)
{
	uc_tokentype_t type = compiler->parser->curr.type;

	if (uc_compiler_parse_at_assignment_op(compiler)) {
		uc_compiler_parse_advance(compiler);
		uc_compiler_parse_precedence(compiler, P_ASSIGN);
		uc_compiler_emit_variable_rw(compiler, var, type);

		return true;
	}

	return false;
}

static bool
uc_compiler_compile_arrowfn(uc_compiler *compiler, json_object *args, bool restarg)
{
	bool array = json_object_is_type(args, json_type_array);
	uc_compiler fncompiler = {};
	size_t i, pos, load_off;
	uc_function *fn;
	ssize_t slot;

	if (!uc_compiler_parse_match(compiler, TK_ARROW))
		return false;

	pos = compiler->parser->prev.pos;

	uc_compiler_init(&fncompiler, NULL, compiler->parser->prev.pos,
		compiler->function->source);

	fncompiler.parent = compiler;
	fncompiler.parser = compiler->parser;

	fncompiler.function->arrow = true;
	fncompiler.function->vararg = args ? restarg : false;
	fncompiler.function->nargs = array ? json_object_array_length(args) : !!args;

	uc_compiler_enter_scope(&fncompiler);

	/* declare local variables for arguments */
	for (i = 0; i < fncompiler.function->nargs; i++) {
		slot = uc_compiler_declare_local(&fncompiler,
			array ? json_object_array_get_idx(args, i) : args);

		if (slot != -1)
			uc_compiler_syntax_error(&fncompiler, pos,
				"Duplicate argument names are not allowed in this context");

		uc_compiler_initialize_local(&fncompiler);
	}

	/* parse and compile body */
	if (uc_compiler_parse_match(&fncompiler, TK_LBRACE)) {
		while (!uc_compiler_parse_check(&fncompiler, TK_RBRACE) &&
		       !uc_compiler_parse_check(&fncompiler, TK_EOF))
			uc_compiler_compile_declaration(&fncompiler);

		uc_compiler_parse_consume(&fncompiler, TK_RBRACE);

		/* overwrite last pop result with return */
		if (fncompiler.function->chunk.count) {
			uc_chunk_pop(&fncompiler.function->chunk);
			uc_compiler_emit_insn(&fncompiler, 0, I_RETURN);
		}
	}
	else {
		uc_compiler_compile_expression(&fncompiler);
		uc_compiler_emit_insn(&fncompiler, 0, I_RETURN);
	}

	/* emit load instruction for function value */
	uc_compiler_emit_insn(compiler, pos, I_ARFN);
	load_off = uc_compiler_emit_u32(compiler, 0, 0);

	/* encode upvalue information */
	for (i = 0; i < fncompiler.function->nupvals; i++)
		uc_compiler_emit_s32(compiler, 0,
			fncompiler.upvals.entries[i].local
				? -(fncompiler.upvals.entries[i].index + 1)
				: fncompiler.upvals.entries[i].index);

	/* finalize function compiler */
	fn = uc_compiler_finish(&fncompiler);

	if (fn)
		uc_compiler_set_u32(compiler, load_off,
			uc_chunk_add_constant(uc_compiler_current_chunk(compiler),
				fn->header.jso));

	return true;
}

static uc_tokentype_t
uc_compiler_compile_var_or_arrowfn(uc_compiler *compiler, bool assignable, json_object *name)
{
	uc_tokentype_t rv;

	if (assignable && uc_compiler_compile_assignment(compiler, name)) {
		rv = TK_ASSIGN;
	}
	else if (uc_compiler_compile_arrowfn(compiler, name, false)) {
		rv = TK_ARROW;
	}
	else {
		uc_compiler_emit_variable_rw(compiler, name, 0);
		rv = TK_LABEL;
	}

	return rv;
}

static void
uc_compiler_compile_paren(uc_compiler *compiler, bool assignable)
{
	json_object *varnames = NULL, *varname;
	bool maybe_arrowfn = false;
	bool restarg = false;

	/* First try to parse a complete parameter expression and remember the
	 * consumed label tokens as we go. */
	while (true) {
		if (uc_compiler_parse_match(compiler, TK_LABEL)) {
			if (!varnames)
				varnames = xjs_new_array();

			json_object_array_add(varnames, uc_value_get(compiler->parser->prev.val));
		}
		else if (uc_compiler_parse_match(compiler, TK_ELLIP)) {
			uc_compiler_parse_consume(compiler, TK_LABEL);

			if (!varnames)
				varnames = xjs_new_array();

			json_object_array_add(varnames, uc_value_get(compiler->parser->prev.val));

			uc_compiler_parse_consume(compiler, TK_RPAREN);

			maybe_arrowfn = true;
			restarg = true;

			break;
		}
		else if (uc_compiler_parse_check(compiler, TK_COMMA)) {
			/* Reject consecutive commas */
			if (compiler->parser->prev.type == TK_COMMA)
				uc_compiler_syntax_error(compiler, compiler->parser->curr.pos,
					"Expecting expression");

			uc_compiler_parse_advance(compiler);

			continue;
		}
		else {
			maybe_arrowfn = uc_compiler_parse_match(compiler, TK_RPAREN);
			break;
		}
	}

	/* The lhs we parsed so far is elligible for an arrow function arg list,
	 * try to continue compiling into arrow function... */
	if (maybe_arrowfn) {
		/* If we can parse the remainder as arrow function, we're done */
		if (uc_compiler_compile_arrowfn(compiler, varnames, restarg))
			goto out;

		/* ... otherwise disallow the `...` spread operator and empty
		 * parenthesized expressions */
		if (restarg || !varnames) {
			uc_compiler_syntax_error(compiler, compiler->parser->prev.pos,
				"Expecting '=>' after parameter list");

			goto out;
		}
	}

	/* If we reach this, the expression we parsed so far cannot be a parameter
	 * list for an arrow function and we might have consumed one or multiple
	 * consecutive labels. */
	if (varnames) {
		/* Get last variable name */
		varname = json_object_array_get_idx(varnames,
			json_object_array_length(varnames) - 1);

		/* If we consumed the right paren, the expression is complete and we
		 * only need to emit a variable read operation for the last parsed
		 * label since previous read operations are shadowed by subsequent ones
		 * in comma expressions and since pure variable reads are without
		 * side effects. */
		if (maybe_arrowfn) {
			uc_compiler_emit_variable_rw(compiler, varname, 0);

			goto out;
		}

		/* ... otherwise if the last token was a label, try continue parsing as
		 * assignment or arrow function expression and if that fails, as
		 * relational one */
		if (compiler->parser->prev.type == TK_LABEL) {
			if (uc_compiler_compile_var_or_arrowfn(compiler, true, varname) == TK_LABEL) {
				/* parse operand and rhs */
				while (P_TERNARY <= uc_compiler_parse_rule(compiler->parser->curr.type)->precedence) {
					uc_compiler_parse_advance(compiler);
					uc_compiler_parse_rule(compiler->parser->prev.type)->infix(compiler, true);
				}
			}

			/* If we're not at the end of the expression, we require a comma.
			 * Also pop intermediate result in this case. */
			if (!uc_compiler_parse_check(compiler, TK_RPAREN)) {
				uc_compiler_emit_insn(compiler, 0, I_POP);
				uc_compiler_parse_consume(compiler, TK_COMMA);
			}
		}
	}

	/* When we reach this point, all already complete expression possibilities
	 * have been eliminated and we either need to compile the next, non-label
	 * expression or reached the closing paren. If neither applies, we have a
	 * syntax error. */
	if (!uc_compiler_parse_check(compiler, TK_RPAREN))
		uc_compiler_compile_expression(compiler);

	/* At this point we expect the end of the parenthesized expression, anything
	 * else is a syntax error */
	uc_compiler_parse_consume(compiler, TK_RPAREN);

out:
	uc_value_put(varnames);
}

static void
uc_compiler_compile_call(uc_compiler *compiler, bool assignable)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	uc_jmplist spreads = {};
	enum insn_type type;
	size_t i, nargs = 0;

	/* determine the kind of the lhs */
	type = chunk->entries[compiler->last_insn];

	/* if lhs is a dot or bracket expression, pop the LVAL instruction */
	if (type == I_LVAL)
		uc_chunk_pop(chunk);

	/* compile arguments */
	if (!uc_compiler_parse_check(compiler, TK_RPAREN)) {
		do {
			/* if this is a spread arg, remember the argument index */
			if (uc_compiler_parse_match(compiler, TK_ELLIP)) {
				uc_vector_grow(&spreads);
				spreads.entries[spreads.count++] = nargs;
			}

			/* compile argument expression */
			uc_compiler_parse_precedence(compiler, P_ASSIGN);
			nargs++;
		}
		while (uc_compiler_parse_match(compiler, TK_COMMA));
	}

	uc_compiler_parse_consume(compiler, TK_RPAREN);

	/* if lhs is a dot or bracket expression, emit a method call */
	if (type == I_LVAL)
		uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_MCALL);
	/* else ordinary call */
	else
		uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_CALL);

	if (nargs > 0xffff || spreads.count > 0xffff)
		uc_compiler_syntax_error(compiler, compiler->parser->prev.pos,
			"Too many function call arguments");

	/* encode ordinary (low 16 bit) and spread argument (high 16 bit) count */
	uc_compiler_emit_u32(compiler, 0, ((spreads.count & 0xffff) << 16) | nargs);

	/* encode spread arg positions */
	for (i = 0; i < spreads.count; i++)
		uc_compiler_emit_u16(compiler, 0, nargs - spreads.entries[i] - 1);

	uc_vector_clear(&spreads);
}

static void
uc_compiler_compile_post_inc(uc_compiler *compiler, bool assignable)
{
	uc_compiler_emit_inc_dec(compiler, compiler->parser->prev.type, true);
}

static void
uc_compiler_compile_constant(uc_compiler *compiler, bool assignable)
{
	int64_t n;

	switch (compiler->parser->prev.type) {
	case TK_THIS:
		uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_LTHIS);
		break;

	case TK_NULL:
		uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_LNULL);
		break;

	case TK_BOOL:
		uc_compiler_emit_insn(compiler, compiler->parser->prev.pos,
			json_object_get_boolean(compiler->parser->prev.val) ? I_LTRUE : I_LFALSE);
		break;

	case TK_DOUBLE:
	case TK_STRING:
		uc_compiler_emit_constant(compiler, compiler->parser->prev.pos, compiler->parser->prev.val);
		break;

	case TK_REGEXP:
		uc_compiler_emit_regexp(compiler, compiler->parser->prev.pos, compiler->parser->prev.val);
		break;

	case TK_NUMBER:
		n = json_object_get_int64(compiler->parser->prev.val);

		if (n >= -0x7f && n <= 0x7f) {
			uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_LOAD8);
			uc_compiler_emit_s8(compiler, compiler->parser->prev.pos, n);
		}
		else if (n >= -0x7fff && n <= 0x7fff) {
			uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_LOAD16);
			uc_compiler_emit_s16(compiler, compiler->parser->prev.pos, n);
		}
		else if (n >= -0x7fffffff && n <= 0x7fffffff) {
			uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_LOAD32);
			uc_compiler_emit_s32(compiler, compiler->parser->prev.pos, n);
		}
		else {
			uc_compiler_emit_constant(compiler, compiler->parser->prev.pos, compiler->parser->prev.val);
		}

		break;

	default:
		break;
	}
}

static void
uc_compiler_compile_comma(uc_compiler *compiler, bool assignable)
{
	uc_compiler_emit_insn(compiler, 0, I_POP);
	uc_compiler_parse_precedence(compiler, P_ASSIGN);
}

static void
uc_compiler_compile_labelexpr(uc_compiler *compiler, bool assignable)
{
	json_object *label = uc_value_get(compiler->parser->prev.val);

	uc_compiler_compile_var_or_arrowfn(compiler, assignable, label);
	uc_value_put(label);
}

static bool
uc_compiler_compile_delimitted_block(uc_compiler *compiler, uc_tokentype_t endtype)
{
	while (!uc_compiler_parse_check(compiler, endtype) &&
	       !uc_compiler_parse_check(compiler, TK_EOF))
		uc_compiler_compile_declaration(compiler);

	return uc_compiler_parse_check(compiler, endtype);
}

static void
uc_compiler_compile_function(uc_compiler *compiler, bool assignable)
{
	uc_compiler fncompiler = {};
	json_object *name = NULL;
	ssize_t slot = -1, pos;
	uc_tokentype_t type;
	size_t i, load_off;
	uc_function *fn;

	pos = compiler->parser->prev.pos;
	type = compiler->parser->prev.type;

	if (uc_compiler_parse_match(compiler, TK_LABEL)) {
		name = compiler->parser->prev.val;

		/* Named functions are syntactic sugar for local variable declaration
		 * with function value assignment. If a name token was encountered,
		 * initialize a local variable for it... */
		slot = uc_compiler_declare_local(compiler, name);

		if (slot == -1)
			uc_compiler_initialize_local(compiler);
	}

	uc_compiler_init(&fncompiler,
		name ? json_object_get_string(name) : NULL, compiler->parser->prev.pos,
		compiler->function->source);

	fncompiler.parent = compiler;
	fncompiler.parser = compiler->parser;

	uc_compiler_parse_consume(&fncompiler, TK_LPAREN);

	uc_compiler_enter_scope(&fncompiler);

	/* compile argument specification */
	while (true) {
		if (uc_compiler_parse_check(&fncompiler, TK_RPAREN))
			break;

		if (uc_compiler_parse_match(&fncompiler, TK_ELLIP))
			fncompiler.function->vararg = true;

		if (uc_compiler_parse_match(&fncompiler, TK_LABEL)) {
			fncompiler.function->nargs++;

			uc_compiler_declare_local(&fncompiler, fncompiler.parser->prev.val);
			uc_compiler_initialize_local(&fncompiler);

			if (fncompiler.function->vararg ||
			    !uc_compiler_parse_match(&fncompiler, TK_COMMA))
				break;
		}
		else {
			uc_compiler_syntax_error(&fncompiler, fncompiler.parser->curr.pos,
				"Expecting Label");

			return;
		}
	}

	uc_compiler_parse_consume(&fncompiler, TK_RPAREN);

	/* parse and compile function body */
	if (uc_compiler_parse_match(&fncompiler, TK_COLON)) {
		uc_compiler_compile_delimitted_block(&fncompiler, TK_ENDFUNC);
		uc_compiler_parse_consume(&fncompiler, TK_ENDFUNC);
	}
	else if (uc_compiler_parse_match(&fncompiler, TK_LBRACE)) {
		uc_compiler_compile_delimitted_block(&fncompiler, TK_RBRACE);
		uc_compiler_parse_consume(&fncompiler, TK_RBRACE);
	}
	else {
		uc_compiler_syntax_error(&fncompiler, fncompiler.parser->curr.pos,
			"Expecting '{' or ':' after function parameters");
	}

	/* emit load instruction for function value */
	uc_compiler_emit_insn(compiler, pos, (type == TK_ARROW) ? I_ARFN : I_CLFN);
	load_off = uc_compiler_emit_u32(compiler, 0, 0);

	/* encode upvalue information */
	for (i = 0; i < fncompiler.function->nupvals; i++)
		uc_compiler_emit_s32(compiler, 0,
			fncompiler.upvals.entries[i].local
				? -(fncompiler.upvals.entries[i].index + 1)
				: fncompiler.upvals.entries[i].index);

	/* finalize function compiler */
	fn = uc_compiler_finish(&fncompiler);

	if (fn)
		uc_compiler_set_u32(compiler, load_off,
			uc_chunk_add_constant(uc_compiler_current_chunk(compiler),
				fn->header.jso));

	/* if a local variable of the same name already existed, overwrite its value
	 * with the compiled function here */
	if (slot != -1) {
		uc_compiler_emit_insn(compiler, 0, I_SLOC);
		uc_compiler_emit_u32(compiler, 0, slot);
		uc_compiler_emit_insn(compiler, 0, I_POP);
	}
}

static void
uc_compiler_compile_and(uc_compiler *compiler, bool assignable)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t jmpz_off;

	uc_compiler_emit_insn(compiler, 0, I_COPY);
	uc_compiler_emit_u8(compiler, 0, 0);
	jmpz_off = uc_compiler_emit_jmpz(compiler, 0, 0);
	uc_compiler_emit_insn(compiler, 0, I_POP);
	uc_compiler_parse_precedence(compiler, P_AND);
	uc_compiler_set_jmpaddr(compiler, jmpz_off, chunk->count);
}

static void
uc_compiler_compile_or(uc_compiler *compiler, bool assignable)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t jmpz_off, jmp_off;

	uc_compiler_emit_insn(compiler, 0, I_COPY);
	uc_compiler_emit_u8(compiler, 0, 0);
	jmpz_off = uc_compiler_emit_jmpz(compiler, 0, 0);
	jmp_off = uc_compiler_emit_jmp(compiler, 0, 0);
	uc_compiler_set_jmpaddr(compiler, jmpz_off, chunk->count);
	uc_compiler_emit_insn(compiler, 0, I_POP);
	uc_compiler_parse_precedence(compiler, P_OR);
	uc_compiler_set_jmpaddr(compiler, jmp_off, chunk->count);
}

static void
uc_compiler_compile_dot(uc_compiler *compiler, bool assignable)
{
	/* parse label lhs */
	uc_compiler_parse_consume(compiler, TK_LABEL);
	uc_compiler_emit_constant(compiler, compiler->parser->prev.pos, compiler->parser->prev.val);

	/* depending on context, compile into I_UVAL, I_SVAL or I_LVAL operation */
	if (!assignable || !uc_compiler_compile_assignment(compiler, NULL))
		uc_compiler_emit_variable_rw(compiler, NULL, 0);
}

static void
uc_compiler_compile_subscript(uc_compiler *compiler, bool assignable)
{
	/* compile lhs */
	uc_compiler_compile_expression(compiler);
	uc_compiler_parse_consume(compiler, TK_RBRACK);

	/* depending on context, compile into I_UVAL, I_SVAL or I_LVAL operation */
	if (!assignable || !uc_compiler_compile_assignment(compiler, NULL))
		uc_compiler_emit_variable_rw(compiler, NULL, 0);
}

static void
uc_compiler_compile_ternary(uc_compiler *compiler, bool assignable)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t jmpz_off, jmp_off;

	/* jump to false branch */
	jmpz_off = uc_compiler_emit_jmpz(compiler, 0, 0);

	/* compile true branch */
	uc_compiler_parse_precedence(compiler, P_ASSIGN);

	/* jump after false branch */
	jmp_off = uc_compiler_emit_jmp(compiler, 0, 0);

	uc_compiler_parse_consume(compiler, TK_COLON);

	/* compile false branch */
	uc_compiler_set_jmpaddr(compiler, jmpz_off, chunk->count);
	uc_compiler_parse_precedence(compiler, P_TERNARY);
	uc_compiler_set_jmpaddr(compiler, jmp_off, chunk->count);
}

static void
uc_compiler_compile_array(uc_compiler *compiler, bool assignable)
{
	size_t hint_off, hint_count = 0, len = 0;

	/* create empty array on stack */
	uc_compiler_emit_insn(compiler, 0, I_NARR);
	hint_off = uc_compiler_emit_u32(compiler, 0, 0);

	/* parse initializer values */
	do {
		if (uc_compiler_parse_check(compiler, TK_RBRACK)) {
			break;
		}
		else if (uc_compiler_parse_match(compiler, TK_ELLIP)) {
			/* push items on stack so far... */
			if (len > 0) {
				uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_PARR);
				uc_compiler_emit_u32(compiler, 0, len);
				len = 0;
			}

			/* compile spread value expression */
			uc_compiler_parse_precedence(compiler, P_ASSIGN);

			/* emit merge operation */
			uc_compiler_emit_insn(compiler, 0, I_MARR);
		}
		else {
			/* push items on stack so far... */
			if (len >= 0xffffffff) {
				uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_PARR);
				uc_compiler_emit_u32(compiler, 0, len);
				len = 0;
			}

			/* compile item value expression */
			uc_compiler_parse_precedence(compiler, P_ASSIGN);

			hint_count++;
			len++;
		}
	}
	while (uc_compiler_parse_match(compiler, TK_COMMA));

	uc_compiler_parse_consume(compiler, TK_RBRACK);

	/* push items on stack */
	if (len > 0) {
		uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_PARR);
		uc_compiler_emit_u32(compiler, 0, len);
	}

	/* set initial size hint */
	uc_compiler_set_u32(compiler, hint_off, hint_count);
}

static void
uc_compiler_compile_object(uc_compiler *compiler, bool assignable)
{
	size_t hint_off, hint_count = 0, len = 0;

	/* create empty object on stack */
	uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_NOBJ);
	hint_off = uc_compiler_emit_u32(compiler, 0, 0);

	/* parse initializer values */
	do {
		/* End of object literal */
		if (uc_compiler_parse_check(compiler, TK_RBRACE))
			break;

		/* Spread operator */
		if (uc_compiler_parse_match(compiler, TK_ELLIP)) {
			/* set items on stack so far... */
			if (len > 0) {
				uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_SOBJ);
				uc_compiler_emit_u32(compiler, 0, len);
				len = 0;
			}

			/* compile spread value expression */
			uc_compiler_parse_precedence(compiler, P_ASSIGN);

			/* emit merge operation */
			uc_compiler_emit_insn(compiler, 0, I_MOBJ);

			continue;
		}

		/* Computed property name */
		if (uc_compiler_parse_match(compiler, TK_LBRACK)) {
			/* parse property name expression */
			uc_compiler_parse_precedence(compiler, P_ASSIGN);

			/* cosume closing bracket and colon */
			uc_compiler_parse_consume(compiler, TK_RBRACK);
			uc_compiler_parse_consume(compiler, TK_COLON);

			/* parse value expression */
			uc_compiler_parse_precedence(compiler, P_ASSIGN);
		}

		/* Property/value tuple or property shorthand */
		else {
			/* parse key expression */
			if (!uc_compiler_parse_match(compiler, TK_LABEL) &&
			    !uc_compiler_parse_match(compiler, TK_STRING))
				uc_compiler_syntax_error(compiler, compiler->parser->curr.pos,
					"Expecting label");

			/* load label */
			uc_compiler_emit_constant(compiler, compiler->parser->prev.pos,
				compiler->parser->prev.val);

			/* If the property name is a plain label followed by a comma or
			 * closing curly brace, treat it as ES2015 property shorthand
			 * notation... */
			if (compiler->parser->prev.type == TK_LABEL &&
			    (uc_compiler_parse_check(compiler, TK_COMMA) ||
			     uc_compiler_parse_check(compiler, TK_RBRACE))) {
				uc_compiler_emit_variable_rw(compiler,
					compiler->parser->prev.val, 0);
			}

			/* ... otherwise treat it as ordinary `key: value` tuple */
			else {
				uc_compiler_parse_consume(compiler, TK_COLON);

				/* parse value expression */
				uc_compiler_parse_precedence(compiler, P_ASSIGN);
			}
		}

		/* set items on stack so far... */
		if (len >= 0xfffffffe) {
			uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_SOBJ);
			uc_compiler_emit_u32(compiler, 0, len);
			len = 0;
		}

		hint_count += 2;
		len += 2;
	}
	while (uc_compiler_parse_match(compiler, TK_COMMA));

	uc_compiler_parse_consume(compiler, TK_RBRACE);

	/* set items on stack */
	if (len > 0) {
		uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_SOBJ);
		uc_compiler_emit_u32(compiler, 0, len);
		len = 0;
	}

	/* set initial size hint */
	uc_compiler_set_u32(compiler, hint_off, hint_count);
}


static void
uc_compiler_declare_local_null(uc_compiler *compiler, size_t srcpos, json_object *varname)
{
	ssize_t existing_slot = uc_compiler_declare_local(compiler, varname);

	uc_compiler_emit_insn(compiler, srcpos, I_LNULL);

	if (existing_slot == -1) {
		uc_compiler_initialize_local(compiler);
	}
	else {
		uc_compiler_emit_insn(compiler, 0, I_SLOC);
		uc_compiler_emit_u32(compiler, 0, existing_slot);
		uc_compiler_emit_insn(compiler, 0, I_POP);
	}
}

static size_t
uc_compiler_declare_internal(uc_compiler *compiler, size_t srcpos, const char *name)
{
#if 0
	ssize_t existing_slot;
	json_object *n;
	bool strict;

	n = xjs_new_string(name);
	strict = compiler->strict_declarations;
	compiler->strict_declarations = false;
	existing_slot = uc_compiler_declare_local(compiler, n);
	compiler->strict_declarations = strict;

	uc_compiler_emit_insn(compiler, srcpos, I_LNULL);

	if (existing_slot == -1) {
		uc_value_put(n);

		return uc_compiler_initialize_local(compiler);
	}
	else {
		uc_value_put(n);

		uc_compiler_emit_insn(compiler, 0, I_SLOC);
		uc_compiler_emit_u32(compiler, 0, existing_slot);
		uc_compiler_emit_insn(compiler, 0, I_POP);

		return existing_slot;
	}
#else
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	uc_locals *locals = &compiler->locals;

	//uc_compiler_emit_insn(compiler, srcpos, I_LNULL);

	uc_vector_grow(locals);

	locals->entries[locals->count].name = xjs_new_string(name);
	locals->entries[locals->count].depth = compiler->scope_depth;
	locals->entries[locals->count].captured = false;
	locals->entries[locals->count].from = chunk->count;

	return locals->count++;
#endif
}

static void
uc_compiler_compile_local(uc_compiler *compiler)
{
	ssize_t slot;

	do {
		/* parse variable name */
		uc_compiler_parse_consume(compiler, TK_LABEL);

		/* declare local variable */
		slot = uc_compiler_declare_local(compiler, compiler->parser->prev.val);

		/* if followed by '=', parse initializer expression */
		if (uc_compiler_parse_match(compiler, TK_ASSIGN))
			uc_compiler_parse_precedence(compiler, P_ASSIGN);
		/* otherwise load implicit null */
		else
			uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_LNULL);

		/* initialize local */
		if (slot == -1) {
			uc_compiler_initialize_local(compiler);
		}
		/* if the variable was redeclared, overwrite it */
		else {
			uc_compiler_emit_insn(compiler, 0, I_SLOC);
			uc_compiler_emit_u32(compiler, 0, slot);
			uc_compiler_emit_insn(compiler, 0, I_POP);
		}
	}
	while (uc_compiler_parse_match(compiler, TK_COMMA));

	uc_compiler_parse_consume(compiler, TK_SCOL);
}

static uc_tokentype_t
uc_compiler_compile_altifblock(uc_compiler *compiler)
{
	while (true) {
		switch (compiler->parser->curr.type) {
		case TK_ELIF:
		case TK_ELSE:
		case TK_ENDIF:
		case TK_EOF:
			return compiler->parser->curr.type;

		default:
			uc_compiler_compile_declaration(compiler);
			break;
		}
	}

	return 0;
}

static void
uc_compiler_compile_if(uc_compiler *compiler)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t jmpz_off, jmp_off, i;
	bool expect_endif = false;
	uc_jmplist elifs = {};
	uc_tokentype_t type;

	/* parse & compile condition expression */
	uc_compiler_parse_consume(compiler, TK_LPAREN);
	uc_compiler_compile_expression(compiler);
	uc_compiler_parse_consume(compiler, TK_RPAREN);

	/* conditional jump to else/elif branch */
	jmpz_off = uc_compiler_emit_jmpz(compiler, 0, 0);

	if (uc_compiler_parse_match(compiler, TK_COLON)) {
		while (true) {
			/* compile elsif or else branch */
			type = uc_compiler_compile_altifblock(compiler);

			/* we just compiled an elsif block */
			if (!expect_endif && type == TK_ELIF) {
				/* emit jump to skip to the end */
				uc_vector_grow(&elifs);
				elifs.entries[elifs.count++] = uc_compiler_emit_jmp(compiler, 0, 0);

				/* point previous conditional jump to beginning of branch */
				uc_compiler_set_jmpaddr(compiler, jmpz_off, chunk->count);

				/* parse & compile elsif condition */
				uc_compiler_parse_advance(compiler);
				uc_compiler_parse_consume(compiler, TK_LPAREN);
				uc_compiler_compile_expression(compiler);
				uc_compiler_parse_consume(compiler, TK_RPAREN);
				uc_compiler_parse_consume(compiler, TK_COLON);

				/* conditional jump to else/elif branch */
				jmpz_off = uc_compiler_emit_jmpz(compiler, 0, 0);
			}
			else if (!expect_endif && type == TK_ELSE) {
				/* emit jump to skip to the end */
				uc_vector_grow(&elifs);
				elifs.entries[elifs.count++] = uc_compiler_emit_jmp(compiler, 0, 0);

				/* point previous conditional jump to beginning of branch */
				uc_compiler_set_jmpaddr(compiler, jmpz_off, chunk->count);
				jmpz_off = 0;

				/* skip "else" keyword */
				uc_compiler_parse_advance(compiler);

				expect_endif = true;
			}
			else if (type == TK_ENDIF) {
				/* if no else clause, point previous conditional jump after block */
				if (jmpz_off)
					uc_compiler_set_jmpaddr(compiler, jmpz_off, chunk->count);

				/* patch the elif branch jumps to point here after the else */
				for (i = 0; i < elifs.count; i++)
					uc_compiler_set_jmpaddr(compiler, elifs.entries[i],
						chunk->count);

				/* skip the "endif" keyword */
				uc_compiler_parse_advance(compiler);
				break;
			}
			else {
				uc_compiler_syntax_error(compiler, compiler->parser->curr.pos,
					expect_endif
						? "Expecting 'endif'"
						: "Expecting 'elif', 'else' or 'endif'");

				break;
			}
		}

		uc_vector_clear(&elifs);
	}
	else {
		/* compile true branch */
		uc_compiler_compile_statement(compiler);

		/* ... when present, handle false branch */
		if (uc_compiler_parse_match(compiler, TK_ELSE)) {
			/* jump to skip else branch */
			jmp_off = uc_compiler_emit_jmp(compiler, 0, 0);

			/* set conditional jump address */
			uc_compiler_set_jmpaddr(compiler, jmpz_off, chunk->count);

			/* compile false branch */
			uc_compiler_compile_statement(compiler);

			/* set else skip jump address */
			uc_compiler_set_jmpaddr(compiler, jmp_off, chunk->count);
		}
		/* ... otherwise point the conditional jump after the true branch */
		else {
			uc_compiler_set_jmpaddr(compiler, jmpz_off, chunk->count);
		}
	}
}

static void
uc_compiler_compile_while(uc_compiler *compiler)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t cond_off, jmpz_off, end_off;
	uc_patchlist p = {};

	p.parent = compiler->patchlist;
	compiler->patchlist = &p;

	cond_off = chunk->count;

	/* parse & compile loop condition */
	uc_compiler_parse_consume(compiler, TK_LPAREN);
	uc_compiler_compile_expression(compiler);
	uc_compiler_parse_consume(compiler, TK_RPAREN);

	/* conditional jump to end */
	jmpz_off = uc_compiler_emit_jmpz(compiler, 0, 0);

	/* compile loop body */
	if (uc_compiler_parse_match(compiler, TK_COLON)) {
		if (!uc_compiler_compile_delimitted_block(compiler, TK_ENDWHILE))
			uc_compiler_syntax_error(compiler, compiler->parser->curr.pos,
				"Expecting 'endwhile'");
		else
			uc_compiler_parse_advance(compiler);
	}
	else {
		uc_compiler_compile_statement(compiler);
	}

	end_off = chunk->count;

	/* jump back to condition */
	uc_compiler_emit_jmp(compiler, 0, cond_off);

	/* set conditional jump target */
	uc_compiler_set_jmpaddr(compiler, jmpz_off, chunk->count);

	/* patch up break/continue */
	uc_compiler_backpatch(compiler, chunk->count, end_off);
}

static void
uc_compiler_compile_for_in(uc_compiler *compiler, bool local, uc_token *kvar, uc_token *vvar)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t skip_jmp, test_jmp, key_slot, val_slot;
	uc_patchlist p = {};

	p.parent = compiler->patchlist;
	compiler->patchlist = &p;

	uc_compiler_enter_scope(compiler);

	/* declare internal loop variables */
	uc_compiler_emit_insn(compiler, 0, I_LNULL);
	key_slot = uc_compiler_declare_internal(compiler, 0, "(for in key)");

	uc_compiler_emit_insn(compiler, 0, I_LNULL);
	val_slot = uc_compiler_declare_internal(compiler, 0, "(for in value)");

	/* declare loop variables */
	if (local) {
		uc_compiler_declare_local_null(compiler, kvar->pos, kvar->val);

		if (vvar)
			uc_compiler_declare_local_null(compiler, vvar->pos, vvar->val);
	}

	/* value to iterate */
	uc_compiler_compile_expression(compiler);
	uc_compiler_parse_consume(compiler, TK_RPAREN);
	uc_compiler_emit_insn(compiler, 0, I_SLOC);
	uc_compiler_emit_u32(compiler, 0, val_slot);

	/* initial key value */
	uc_compiler_emit_insn(compiler, 0, I_LNULL);
	uc_compiler_emit_insn(compiler, 0, I_SLOC);
	uc_compiler_emit_u32(compiler, 0, key_slot);

	/* jump over variable read for first cycle */
	skip_jmp = uc_compiler_emit_jmp(compiler, 0, 0);

	/* read value */
	uc_compiler_emit_insn(compiler, 0, I_LLOC);
	uc_compiler_emit_u32(compiler, 0, val_slot);

	/* read key */
	uc_compiler_emit_insn(compiler, 0, I_LLOC);
	uc_compiler_emit_u32(compiler, 0, key_slot);

	/* backpatch skip jump */
	uc_compiler_set_jmpaddr(compiler, skip_jmp, chunk->count);

	/* load loop variable and get next key from object */
	uc_compiler_emit_insn(compiler, 0, vvar ? I_NEXTKV : I_NEXTK);

	/* set internal key variable */
	uc_compiler_emit_insn(compiler, 0, I_SLOC);
	uc_compiler_emit_u32(compiler, 0, key_slot);

	/* test for != null */
	uc_compiler_emit_insn(compiler, 0, I_LNULL);
	uc_compiler_emit_insn(compiler, 0, I_NES);

	/* jump after loop body if no next key */
	test_jmp = uc_compiler_emit_jmpz(compiler, 0, 0);

	/* set key and value variables */
	if (vvar) {
		uc_compiler_emit_variable_rw(compiler, vvar->val, TK_ASSIGN);
		uc_compiler_emit_insn(compiler, 0, I_POP);
	}

	/* set key variable */
	uc_compiler_emit_variable_rw(compiler, kvar->val, TK_ASSIGN);
	uc_compiler_emit_insn(compiler, 0, I_POP);

	/* compile loop body */
	if (uc_compiler_parse_match(compiler, TK_COLON)) {
		if (!uc_compiler_compile_delimitted_block(compiler, TK_ENDFOR))
			uc_compiler_syntax_error(compiler, compiler->parser->curr.pos,
				"Expecting 'endfor'");
		else
			uc_compiler_parse_advance(compiler);
	}
	else {
		uc_compiler_compile_statement(compiler);
	}

	/* jump back to retrieve next key */
	uc_compiler_emit_jmp(compiler, 0, skip_jmp + 5);

	/* back patch conditional jump */
	uc_compiler_set_jmpaddr(compiler, test_jmp, chunk->count);

	/* patch up break/continue */
	uc_compiler_backpatch(compiler, chunk->count, skip_jmp + 5);

	/* pop loop variables */
	uc_compiler_emit_insn(compiler, 0, I_POP);

	if (vvar)
		uc_compiler_emit_insn(compiler, 0, I_POP);

	uc_compiler_leave_scope(compiler);
}

static void
uc_compiler_compile_for_count(uc_compiler *compiler, bool local, uc_token *var)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t test_off = 0, incr_off, skip_off, cond_off = 0;
	uc_patchlist p = {};

	p.parent = compiler->patchlist;
	compiler->patchlist = &p;

	uc_compiler_enter_scope(compiler);

	/* Initializer ---------------------------------------------------------- */

	/* We parsed a `local x` or `local x, y` expression, so (re)declare
	 * last label as local initializer variable */
	if (local)
		uc_compiler_declare_local_null(compiler, var->pos, var->val);

	/* If we parsed at least on label, try continue parsing as variable
	 * expression... */
	if (var) {
		uc_compiler_compile_labelexpr(compiler, true);
		uc_compiler_emit_insn(compiler, 0, I_POP);

		/* If followed by a comma, continue parsing expression */
		if (uc_compiler_parse_match(compiler, TK_COMMA)) {
			uc_compiler_compile_expression(compiler);
			uc_compiler_emit_insn(compiler, 0, I_POP);
		}
	}
	/* ... otherwise try parsing an entire expression (which might be absent) */
	else if (!uc_compiler_parse_check(compiler, TK_SCOL)) {
		uc_compiler_compile_expression(compiler);
		uc_compiler_emit_insn(compiler, 0, I_POP);
	}

	uc_compiler_parse_consume(compiler, TK_SCOL);


	/* Condition ------------------------------------------------------------ */
	if (!uc_compiler_parse_check(compiler, TK_SCOL)) {
		cond_off = chunk->count;

		uc_compiler_compile_expression(compiler);

		test_off = uc_compiler_emit_jmpz(compiler, 0, 0);
	}

	uc_compiler_parse_consume(compiler, TK_SCOL);

	/* jump over incrementer */
	skip_off = uc_compiler_emit_jmp(compiler, 0, 0);


	/* Incrementer ---------------------------------------------------------- */
	incr_off = chunk->count;

	if (!uc_compiler_parse_check(compiler, TK_RPAREN)) {
		uc_compiler_compile_expression(compiler);
		uc_compiler_emit_insn(compiler, 0, I_POP);
	}

	uc_compiler_parse_consume(compiler, TK_RPAREN);

	/* if we have a condition, jump back to it, else continue to the loop body */
	if (cond_off)
		uc_compiler_emit_jmp(compiler, 0, cond_off);

	/* back patch skip address */
	uc_compiler_set_jmpaddr(compiler, skip_off, chunk->count);


	/* Body ----------------------------------------------------------------- */
	if (uc_compiler_parse_match(compiler, TK_COLON)) {
		if (!uc_compiler_compile_delimitted_block(compiler, TK_ENDFOR))
			uc_compiler_syntax_error(compiler, compiler->parser->curr.pos,
				"Expecting 'endfor'");
		else
			uc_compiler_parse_advance(compiler);
	}
	else {
		uc_compiler_compile_statement(compiler);
	}

	/* jump back to incrementer */
	uc_compiler_emit_jmp(compiler, 0, incr_off);

	/* back patch conditional jump */
	if (test_off)
		uc_compiler_set_jmpaddr(compiler, test_off, chunk->count);

	/* patch up break/continue */
	uc_compiler_backpatch(compiler, chunk->count, incr_off);

	uc_compiler_leave_scope(compiler);
}

static void
uc_compiler_compile_for(uc_compiler *compiler)
{
	uc_token keyvar = {}, valvar = {};
	bool local;

	uc_compiler_parse_consume(compiler, TK_LPAREN);

	/* check the next few tokens and see if we have either a
	 * `let x in` / `let x, y` expression or an ordinary initializer
	 * statement */

	local = uc_compiler_parse_match(compiler, TK_LOCAL);

	if (local && !uc_compiler_parse_check(compiler, TK_LABEL))
		uc_compiler_syntax_error(compiler, compiler->parser->curr.pos,
			"Expecting label after 'local'");

	if (uc_compiler_parse_match(compiler, TK_LABEL)) {
		keyvar = compiler->parser->prev;
		uc_value_get(keyvar.val);

		if (uc_compiler_parse_match(compiler, TK_COMMA)) {
			uc_compiler_parse_consume(compiler, TK_LABEL);

			valvar = compiler->parser->prev;
			uc_value_get(valvar.val);
		}

		/* is a for-in loop */
		if (uc_compiler_parse_match(compiler, TK_IN)) {
			uc_compiler_compile_for_in(compiler, local, &keyvar,
				valvar.type ? &valvar : NULL);

			goto out;
		}
	}

	/*
	 * The previous expression ruled out a for-in loop, so continue parsing
	 * as counting for loop...
	 */
	uc_compiler_compile_for_count(compiler, local,
		valvar.val ? &valvar : (keyvar.val ? &keyvar : NULL));

out:
	uc_value_put(keyvar.val);
	uc_value_put(valvar.val);
}

static void
uc_compiler_compile_switch(uc_compiler *compiler)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t i, first_jmp, skip_jmp, next_jmp, default_off = 0;
	bool in_case = false;
	uc_jmplist jmps = {};
	uc_patchlist p = {};

	p.parent = compiler->patchlist;
	compiler->patchlist = &p;

	uc_compiler_enter_scope(compiler);

	/* parse and compile match value */
	uc_compiler_parse_consume(compiler, TK_LPAREN);
	uc_compiler_compile_expression(compiler);
	uc_compiler_parse_consume(compiler, TK_RPAREN);
	uc_compiler_parse_consume(compiler, TK_LBRACE);
	uc_compiler_declare_internal(compiler, 0, "(switch value)");

	/* skip over first condition */
	first_jmp = uc_compiler_emit_jmp(compiler, 0, 0);

	/* parse and compile case matches */
	while (!uc_compiler_parse_check(compiler, TK_RBRACE) &&
	       !uc_compiler_parse_check(compiler, TK_EOF)) {
		/* handle `default:` */
		if (uc_compiler_parse_match(compiler, TK_DEFAULT)) {
			if (default_off) {
				uc_compiler_syntax_error(compiler, compiler->parser->prev.pos,
					"more than one switch default case");

				return;
			}

			uc_compiler_parse_consume(compiler, TK_COLON);

			/* remember address of default branch */
			default_off = chunk->count;

			in_case = true;
		}

		/* handle `case …:` */
		else if (uc_compiler_parse_match(compiler, TK_CASE)) {
			/* jump over `case …:` label */
			uc_vector_grow(&jmps);
			jmps.entries[jmps.count++] = uc_compiler_emit_jmp(compiler, 0, 0);

			/* copy condition value */
			uc_compiler_emit_insn(compiler, 0, I_COPY);
			uc_compiler_emit_u8(compiler, 0, 0);

			/* compile case value expression */
			uc_compiler_compile_expression(compiler);
			uc_compiler_parse_consume(compiler, TK_COLON);

			/* strict equality test */
			uc_compiler_emit_insn(compiler, 0, I_EQS);

			/* on inequality, jump to next condition */
			uc_vector_grow(&jmps);
			jmps.entries[jmps.count++] = uc_compiler_emit_jmpz(compiler, 0, 0);

			in_case = true;
		}

		/* handle interleaved statement */
		else if (in_case) {
			uc_compiler_compile_declaration(compiler);
		}

		/* a statement or expression preceeding any `default` or `case` is a
		 * syntax error */
		else {
			uc_compiler_syntax_error(compiler, compiler->parser->curr.pos,
				"Expecting 'case' or 'default'");

			return;
		}
	}

	uc_compiler_parse_consume(compiler, TK_RBRACE);

	/* patch jump targets for cases */
	for (i = 0; i < jmps.count; i += 2) {
		skip_jmp = jmps.entries[i + 0];
		next_jmp = jmps.entries[i + 1];

		uc_compiler_set_jmpaddr(compiler, skip_jmp, next_jmp + 5);

		/* have a subsequent case, patch next jump to it */
		if (i + 2 < jmps.count)
			uc_compiler_set_jmpaddr(compiler, next_jmp, jmps.entries[i + 2] + 5);
		/* case was last in switch, jump to default */
		else if (default_off)
			uc_compiler_set_jmpaddr(compiler, next_jmp, default_off);
		/* if no default, jump to end */
		else
			uc_compiler_set_jmpaddr(compiler, next_jmp, chunk->count);
	}

	/* if we have cases, patch initial jump after the first case condition */
	if (jmps.count)
		uc_compiler_set_jmpaddr(compiler, first_jmp, jmps.entries[0] + 5);
	/* ... otherwise jump into default */
	else if (default_off)
		uc_compiler_set_jmpaddr(compiler, first_jmp, default_off);
	/* ... otherwise if no defualt, turn into no-op */
	else
		uc_compiler_set_jmpaddr(compiler, first_jmp, first_jmp + 5);

	uc_vector_clear(&jmps);

	uc_compiler_leave_scope(compiler);

	uc_compiler_backpatch(compiler, chunk->count, 0);
}

static void
uc_compiler_compile_try(uc_compiler *compiler)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t try_from = 0, try_to = 0, jmp_off = 0, ehvar_slot = 0;
	uc_ehranges *ranges = &chunk->ehranges;

	try_from = chunk->count;
	ehvar_slot = compiler->locals.count;

	/* Try block ------------------------------------------------------------ */
	uc_compiler_enter_scope(compiler);

	uc_compiler_parse_consume(compiler, TK_LBRACE);

	while (!uc_compiler_parse_check(compiler, TK_RBRACE) &&
	       !uc_compiler_parse_check(compiler, TK_EOF))
		uc_compiler_compile_declaration(compiler);

	/* jump beyond catch branch */
	try_to = chunk->count;
	jmp_off = uc_compiler_emit_jmp(compiler, 0, 0);

	uc_compiler_parse_consume(compiler, TK_RBRACE);

	uc_compiler_leave_scope(compiler);


	/* Catch block ---------------------------------------------------------- */
	if (try_to > try_from) {
		uc_vector_grow(ranges);

		ranges->entries[ranges->count].from   = try_from;
		ranges->entries[ranges->count].to     = try_to;
		ranges->entries[ranges->count].target = chunk->count;
		ranges->entries[ranges->count].slot   = ehvar_slot;
		ranges->count++;
	}

	uc_compiler_enter_scope(compiler);

	uc_compiler_parse_consume(compiler, TK_CATCH);

	/* have exception variable */
	if (uc_compiler_parse_match(compiler, TK_LPAREN)) {
		uc_compiler_parse_consume(compiler, TK_LABEL);

		uc_compiler_declare_local(compiler, compiler->parser->prev.val);
		uc_compiler_initialize_local(compiler);

		uc_compiler_parse_consume(compiler, TK_RPAREN);
	}
	/* ... else pop exception object from stack */
	else {
		uc_compiler_emit_insn(compiler, 0, I_POP);
	}

	uc_compiler_parse_consume(compiler, TK_LBRACE);

	while (!uc_compiler_parse_check(compiler, TK_RBRACE) &&
	       !uc_compiler_parse_check(compiler, TK_EOF))
		uc_compiler_compile_declaration(compiler);

	uc_compiler_parse_consume(compiler, TK_RBRACE);

	uc_compiler_leave_scope(compiler);

	uc_compiler_set_jmpaddr(compiler, jmp_off, chunk->count);
}

static void
uc_compiler_compile_control(uc_compiler *compiler)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	uc_tokentype_t type = compiler->parser->prev.type;
	uc_patchlist *p = compiler->patchlist;
	uc_locals *locals = &compiler->locals;
	size_t i, pos = compiler->parser->prev.pos;

	if (!p) {
		uc_compiler_syntax_error(compiler, pos,
			(type == TK_BREAK)
				? "break must be inside loop or switch"
				: "continue must be inside loop");

		return;
	}

	/* pop locals in scope up to this point */
	for (i = locals->count; i > 0 && locals->entries[i - 1].depth == compiler->scope_depth; i--)
		uc_compiler_emit_insn(compiler, 0, I_POP);

	uc_vector_grow(p);

	p->entries[p->count++] =
		uc_compiler_emit_jmp(compiler, pos, chunk->count + type);

	uc_compiler_parse_consume(compiler, TK_SCOL);
}

static void
uc_compiler_compile_return(uc_compiler *compiler)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t off = chunk->count;

	uc_compiler_compile_expstmt(compiler);

	/* if we compiled an empty expression statement (`;`), load implicit null */
	if (chunk->count == off)
		uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_LNULL);
	/* otherwise overwrite the final I_POP instruction with I_RETURN */
	else
		uc_chunk_pop(chunk);

	uc_compiler_emit_insn(compiler, compiler->parser->prev.pos, I_RETURN);
}

static void
uc_compiler_compile_tplexp(uc_compiler *compiler)
{
	uc_chunk *chunk = uc_compiler_current_chunk(compiler);
	size_t off = chunk->count;

	uc_compiler_compile_expression(compiler);

	/* XXX: the lexer currently emits a superfluous trailing semicolon... */
	uc_compiler_parse_match(compiler, TK_SCOL);

	uc_compiler_parse_consume(compiler, TK_REXP);

	if (chunk->count > off)
		uc_compiler_emit_insn(compiler, 0, I_PRINT);
}

static void
uc_compiler_compile_text(uc_compiler *compiler)
{
	uc_compiler_emit_constant(compiler, compiler->parser->prev.pos, compiler->parser->prev.val);
	uc_compiler_emit_insn(compiler, 0, I_PRINT);
}

static void
uc_compiler_compile_block(uc_compiler *compiler)
{
	uc_compiler_enter_scope(compiler);

	while (!uc_compiler_parse_check(compiler, TK_RBRACE) &&
	       !uc_compiler_parse_check(compiler, TK_EOF))
		uc_compiler_compile_declaration(compiler);

	uc_compiler_parse_consume(compiler, TK_RBRACE);

	uc_compiler_leave_scope(compiler);
}

static void
uc_compiler_compile_expstmt(uc_compiler *compiler)
{
	/* empty statement */
	if (uc_compiler_parse_match(compiler, TK_SCOL))
		return;

	uc_compiler_compile_expression(compiler);

	/* allow omitting final semicolon */
	switch (compiler->parser->curr.type) {
	case TK_RBRACE:
	case TK_ELSE:	/* fixme: only in altblockmode */
	case TK_ELIF:
	case TK_ENDIF:
	case TK_ENDFOR:
	case TK_ENDWHILE:
	case TK_ENDFUNC:
	case TK_EOF:
		break;

	default:
		uc_compiler_parse_consume(compiler, TK_SCOL);

		break;
	}

	uc_compiler_emit_insn(compiler, 0, I_POP);
}

static void
uc_compiler_compile_statement(uc_compiler *compiler)
{
	if (uc_compiler_parse_match(compiler, TK_IF))
		uc_compiler_compile_if(compiler);
	else if (uc_compiler_parse_match(compiler, TK_WHILE))
		uc_compiler_compile_while(compiler);
	else if (uc_compiler_parse_match(compiler, TK_FOR))
		uc_compiler_compile_for(compiler);
	else if (uc_compiler_parse_match(compiler, TK_SWITCH))
		uc_compiler_compile_switch(compiler);
	else if (uc_compiler_parse_match(compiler, TK_TRY))
		uc_compiler_compile_try(compiler);
	else if (uc_compiler_parse_match(compiler, TK_FUNC))
		uc_compiler_compile_function(compiler, false);
	else if (uc_compiler_parse_match(compiler, TK_BREAK))
		uc_compiler_compile_control(compiler);
	else if (uc_compiler_parse_match(compiler, TK_CONTINUE))
		uc_compiler_compile_control(compiler);
	else if (uc_compiler_parse_match(compiler, TK_RETURN))
		uc_compiler_compile_return(compiler);
	else if (uc_compiler_parse_match(compiler, TK_TEXT))
		uc_compiler_compile_text(compiler);
	else if (uc_compiler_parse_match(compiler, TK_LEXP))
		uc_compiler_compile_tplexp(compiler);
	else if (uc_compiler_parse_match(compiler, TK_LBRACE))
		uc_compiler_compile_block(compiler);
	else
		uc_compiler_compile_expstmt(compiler);
}

static void
uc_compiler_compile_declaration(uc_compiler *compiler)
{
	if (uc_compiler_parse_match(compiler, TK_LOCAL))
		uc_compiler_compile_local(compiler);
	else
		uc_compiler_compile_statement(compiler);

	if (compiler->parser->synchronizing)
		uc_compiler_parse_synchronize(compiler);
}

uc_function *
uc_compile(uc_parse_config *config, uc_source *source, char **errp)
{
	uc_parser parser = { .config = config };
	uc_compiler compiler = { .parser = &parser };
	uc_function *fn;

	uc_lexer_init(&parser.lex, config, source);
	uc_compiler_init(&compiler, "main", 0, source);

	uc_compiler_parse_advance(&compiler);

	while (!uc_compiler_parse_match(&compiler, TK_EOF))
		uc_compiler_compile_declaration(&compiler);

	fn = uc_compiler_finish(&compiler);

	if (errp)
		*errp = parser.error;

	uc_lexer_free(&parser.lex);

	return fn;
}
