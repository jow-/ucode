#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>

#include "ucode/compiler.h"
#include "ucode/lexer.h"
#include "ucode/util.h"
#include "ucode/lib.h" /* uc_error_context_format() */
#include "ucode/module.h" /* uc_error_context_format() */
#include "ucode/arith.h"

#include "jsdoc.h"
#include "uscope.h"


#define VAR_NAME_AUTO_RETURN ((uc_value_t *)1)

typedef enum {
	TT_NAMESPACE = 0,
	TT_CLASS = 1,
	TT_ENUM = 2,
	TT_INTERFACE = 3,
	TT_STRUCT = 4,
	TT_TYPEPAR = 5,
	TT_TYPE = 6,
	TT_PARAMETER = 7,
	TT_VARIABLE = 8,
	TT_PROPERTY = 9,
	TT_ENUMMEMBER = 10,
	TT_EVENT = 11,
	TT_FUNCTION = 12,
	TT_METHOD = 13,
	TT_MACRO = 14,
	TT_KEYWORD = 15,
	TT_MODIFIER = 16,
	TT_COMMENT = 17,
	TT_STRING = 18,
	TT_NUMBER = 19,
	TT_REGEXP = 20,
	TT_OPERATOR = 21,
	TT_TPLTAG = 22,
	TT_TPLTEXT = 23,
	TT_PUNCT = 24,
	TT_KW_CONTROL = 25,
	TT_BOOLEAN = 26,
	TT_NULL = 27,
	TT_THIS = 28,
	TT_KW_OPERATOR = 29,
} semantic_token_type_t;

static const char *semantic_token_type_names[] = {
	"namespace", "class", "enum", "interface", "struct",
	"typeParameter", "type",  "parameter", "variable", "property",
	"enumMember", "event", "function",  "method", "macro",
	"keyword", "modifier", "comment", "string", "number",
	"regexp", "operator", "ucode-template-tag", "ucode-template-text", "ucode-punctuation",
	"keyword.control", "ucode-boolean", "ucode-null", "ucode-this", "ucode-operator"
};

typedef enum {
	TM_DECLARATION = 0,
	TM_DEFINITION = 1,
	TM_READONLY = 2,
	TM_STATIC = 3,
	TM_DEPRECATED = 4,
	TM_ABSTRACT = 5,
	TM_ASYNC = 6,
	TM_MOD = 7,
	TM_DOC = 8,
	TM_DEFLIB = 9
} semantic_token_modifier_t;

static const char *semantic_token_modifier_names[] = {
	"declaration", "definition", "readonly", "static", "deprecated",
	"abstract", "async", "modification", "documentation", "defaultLibrary"
};

static const char *access_kind_names[] = {
	"declaration",
	"read",
	"write",
	"update",
	"export",
};

typedef struct {
	uc_token_t token;
	semantic_token_type_t sem_type;
	uint32_t sem_modifiers;
} semantic_token_t;

typedef struct {
	uscope_position_t location;
	size_t token_id;
	jsdoc_t *jsdoc;
} undef_t;

typedef struct {
	uscope_position_t start;
	uscope_position_t end;
	struct {
		size_t count;
		uc_value_t **entries;
	} variables;
} scope_t;

typedef struct {
	uc_value_t *name;
	uc_value_t *alias;
	uc_value_t *value;
	uc_value_t *source;
	bool is_default;
	bool is_wildcard;
} xport_item_t;

typedef struct {
	uc_vm_t *vm;
	uc_parser_t parser;
	uc_value_t *global;
	size_t curr_token_offset;
	size_t prev_token_offset;
	struct {
		size_t count;
		struct {
			uc_token_t token;
			size_t offset;
		} *entries;
	} lookahead;
	struct {
		size_t count;
		semantic_token_t *entries;
	} tokens;
	struct {
		size_t count;
		struct {
			uscope_position_t start;
			uscope_position_t end;
			uc_value_t *message;
		} *entries;
	} errors;
	struct {
		size_t count;
		scope_t *entries;
	} scopes;
	struct {
		size_t count;
		size_t *entries;
	} scopechain;
	struct {
		size_t count;
		uc_value_t **entries;
	} thischain;
	struct {
		size_t count;
		xport_item_t *entries;
	} imports;
	struct {
		size_t count;
		xport_item_t *entries;
	} exports;
	struct {
		size_t count;
		jsdoc_t **entries;
	} function_jsdocs;
	struct {
		size_t count;
		jsdoc_t **entries;
	} declaration_jsdocs;
} uscope_parser_t;

typedef struct {
    uc_value_t *(*prefix)(uscope_parser_t *);
    uc_value_t *(*infix)(uscope_parser_t *, uc_value_t *);
    uc_precedence_t precedence;
} parse_rule_t;

typedef struct {
	size_t count;
	struct {
		bool spread;
		uc_value_t *value;
	} *entries;
} callargs_t;

static const semantic_token_type_t type_semtype_map[] = {
	0,
    TT_TPLTAG,		TT_TPLTAG,		TT_TPLTAG,		TT_TPLTAG,
	TT_KW_CONTROL,	TT_KW_CONTROL,	TT_PUNCT,		TT_OPERATOR,
	TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,
    TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,
	TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,	TT_PUNCT,
	TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,
    TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,
	TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,
	TT_OPERATOR,	TT_KW_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,
    TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,
	TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,
	TT_OPERATOR,	TT_OPERATOR,	TT_PUNCT,		TT_PUNCT,
    TT_PUNCT,		TT_PUNCT,		TT_PUNCT,		TT_TPLTEXT,
	TT_PUNCT,		TT_PUNCT,		TT_PUNCT,		TT_KW_CONTROL,
	TT_KW_CONTROL,	TT_KEYWORD,		TT_KEYWORD,		TT_KEYWORD,
    TT_KEYWORD,		TT_KEYWORD,		TT_VARIABLE,	TT_KEYWORD,
	TT_KEYWORD,		TT_KEYWORD,		TT_KEYWORD,		TT_KEYWORD,
	TT_KEYWORD,		TT_PUNCT,		TT_KEYWORD,		TT_KEYWORD,
    TT_KEYWORD,		TT_KEYWORD,		TT_OPERATOR,	TT_BOOLEAN,
	TT_BOOLEAN,		TT_NUMBER,		TT_NUMBER,		TT_STRING,
	TT_REGEXP,		TT_NULL,		TT_THIS,		TT_KEYWORD,
    TT_KEYWORD,		TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,
	TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,	TT_OPERATOR,
	TT_OPERATOR,	TT_PUNCT,		TT_STRING,		TT_KEYWORD,
    TT_KEYWORD,		TT_PUNCT,		TT_COMMENT,		TT_PUNCT
};

static void
scope_enter(uscope_parser_t *usp)
{
	scope_t *scope;

	uc_vector_grow(&usp->scopes);

	scope = &usp->scopes.entries[usp->scopes.count];
	scope->start.offset = usp->parser.prev.pos;
	scope->start.column = scope->start.offset;
	scope->start.line = uc_source_get_line(usp->parser.lex.source, &scope->start.column);

	uc_vector_push(&usp->scopechain, usp->scopes.count++);
}

static void
scope_leave(uscope_parser_t *usp)
{
	size_t curr_scope_id = usp->scopechain.entries[--usp->scopechain.count];
	scope_t *scope = &usp->scopes.entries[curr_scope_id];

	scope->end.offset = usp->parser.prev.pos;
	scope->end.column = scope->end.offset;
	scope->end.line = uc_source_get_line(usp->parser.lex.source, &scope->end.column);

	uc_vector_foreach(&scope->variables, var) {
		uscope_variable_t *spec = ucv_resource_data(*var, "uscope.variable");

		if (!spec->superseded)
			spec->range.end = scope->end;
	}
}

static uc_value_t *
comment_capture(uscope_parser_t *usp, size_t offset)
{
	struct { size_t count; uc_value_t **entries; } comments = { 0 };
	uscope_position_t pos = { 0 }, end = { 0 }, prev = { 0 };
	uc_value_t *rv = NULL;

	for (size_t i = offset; i > 0; i--) {
		uc_token_t *tok = &usp->tokens.entries[i-1].token;

		if (tok->type != TK_COMMENT)
			break;

		pos.column = tok->pos;
		pos.line = uc_source_get_line(usp->parser.lex.source, &pos.column);

		end.column = tok->end;
		end.line = uc_source_get_line(usp->parser.lex.source, &end.column);

		char *s = ucv_string_get(tok->uv);

		if (!s)
			break;

		if (comments.count > 0 && (end.line != prev.line ||
		                           pos.column != prev.column ||
		                           strncmp(s, "//", 2) != 0))
			break;

		prev = pos;
		uc_vector_push(&comments, tok->uv);

		usp->tokens.entries[i-1].sem_modifiers |= (1u << TM_DOC);
	}

	if (comments.count > 1) {
		uc_stringbuf_t *sbuf = ucv_stringbuf_new();

		for (size_t i = comments.count; i > 0; i--) {
			uc_value_t *s = comments.entries[i - 1];
			ucv_stringbuf_addstr(sbuf, ucv_string_get(s), ucv_string_length(s));
		}

		rv = ucv_stringbuf_finish(sbuf);
	}
	else if (comments.count > 0) {
		rv = ucv_get(comments.entries[0]);
	}

	uc_vector_clear(&comments);

	return rv;
}


static bool
is_undef(uc_value_t *uv)
{
	return (ucv_resource_dataptr(uv, "uscope.undefined") != NULL);
}

static uc_value_t *
undef_new(uscope_parser_t *usp, ssize_t token_num, jsdoc_t *jsdoc)
{
	undef_t *undef = xalloc(sizeof(undef_t));
	semantic_token_t *stok = &usp->tokens.entries[token_num];

	undef->token_id = token_num;
	undef->location.offset = stok->token.pos;
	undef->location.column = undef->location.offset;
	undef->location.line =
		uc_source_get_line(usp->parser.lex.source, &undef->location.column);

	undef->jsdoc = jsdoc;

	return uc_resource_new(
		ucv_resource_type_lookup(usp->vm, "uscope.undefined"),
		undef);
}

static uscope_variable_t *
variable_check(uc_value_t *uv)
{
	return ucv_resource_data(uv, "uscope.variable");
}

static jsdoc_t *
variable_get_jsdoc(uc_value_t *uv)
{
	uscope_variable_t *var = ucv_resource_data(uv, "uscope.variable");

	if (var)
		return var->jsdoc;

	undef_t *undef = ucv_resource_data(uv, "uscope.undefined");

	if (undef)
		return undef->jsdoc;

	return NULL;
}

static jsdoc_t *
variable_upsert_jsdoc(uc_value_t *uv, jsdoc_kind_t kind)
{
	uscope_variable_t *var = ucv_resource_data(uv, "uscope.variable");

	if (!var)
		return NULL;

	if (!var->jsdoc) {
		var->jsdoc = xalloc(sizeof(jsdoc_t));
		var->jsdoc->kind = kind;
	}

	return var->jsdoc;
}

static uscope_reference_t *
variable_get_reference(uc_value_t *uv, ssize_t index)
{
	uscope_variable_t *var = ucv_resource_data(uv, "uscope.variable");

	if (!var || var->references.count == 0)
		return NULL;

	if (index < 0)
		index += var->references.count;

	if (index < 0)
		return NULL;

	return uscope_vector_get(&var->references, (size_t)index);
}

static jsdoc_t *
jsdoc_derive(uc_value_t *comment, uc_value_t *value, bool constant)
{
	const char *comment_str = comment ? ucv_string_get(comment) : "";
	size_t comment_len = comment ? ucv_string_length(comment) : 0;
	jsdoc_t *dst_jsdoc = jsdoc_parse(comment_str, comment_len, NULL);
	jsdoc_t *src_jsdoc = variable_get_jsdoc(value);

	/* NB: if an expression is preceeded by a @typedef jsdoc, then do not
	       consider that comment to be documentation for our expression */
	if (dst_jsdoc->kind == KIND_TYPEDEF)
		jsdoc_reset(dst_jsdoc);

	if (src_jsdoc) {
		jsdoc_typedef_merge(&dst_jsdoc->type, src_jsdoc->type, 0);
	}
	else if (value && !is_undef(value)) {
		jsdoc_typedef_t *def = jsdoc_typedef_from_uv(NULL, value);

		if (def) {
			jsdoc_typedef_merge(&dst_jsdoc->type, def, 0);
			jsdoc_typedef_free(def);
		}
	}

	dst_jsdoc->constant = constant;

	return dst_jsdoc;
}

static jsdoc_t *
jsdoc_capture(uscope_parser_t *usp, size_t token_id, uc_value_t *uv)
{
	uc_value_t *doc = comment_capture(usp, token_id);
	jsdoc_t *jsdoc = jsdoc_derive(doc, uv, false);

	ucv_put(doc);

	return jsdoc;
}

__attribute__((format(printf, 1, 0)))
static uc_value_t *
ucv_asprintf(const char *fmt, ...)
{
	uc_value_t *res = NULL;
	char *s = NULL;
	int len = 0;
	va_list ap;

	va_start(ap, fmt);
	len = xvasprintf(&s, fmt, ap);
	va_end(ap);

	if (len > 0)
		res = ucv_string_new_length(s, len);

	free(s);

	return res;
}

static jsdoc_type_t
jsdoc_get_type(const jsdoc_t *jsdoc)
{
	if (!jsdoc || !jsdoc->type)
		return TYPE_UNSPEC;

	return jsdoc->type->type;
}

static void
jsdoc_merge_function_details(uscope_variable_t *var)
{
	if (!var || jsdoc_get_type(var->jsdoc) != TYPE_FUNCTION)
		return;

	uscope_variable_t *val = variable_check(var->value);

	if (!val || jsdoc_get_type(val->jsdoc) != TYPE_FUNCTION)
		return;

	jsdoc_t *new_var_jsdoc = jsdoc_merge(val->jsdoc, var->jsdoc, MERGE_UNION);
	jsdoc_t *new_val_jsdoc = jsdoc_merge(var->jsdoc, val->jsdoc, MERGE_UNION);

	jsdoc_free(var->jsdoc);
	jsdoc_free(val->jsdoc);

	val->jsdoc = new_val_jsdoc;
	var->jsdoc = new_var_jsdoc;
}

static uc_value_t *
variable_new(uscope_parser_t *usp, size_t token_id, uc_value_t *name,
             uc_value_t **initval, jsdoc_t *jsdoc,
             bool constant, bool global)
{
	size_t scope_idx = global ? 0 : usp->scopechain.count - 1;
	size_t scope_id = usp->scopechain.entries[scope_idx];
	scope_t *scope = &usp->scopes.entries[scope_id];

	uscope_variable_t *var = xalloc(sizeof(uscope_variable_t));

	uc_value_t *uv = ucv_resource_new(
		ucv_resource_type_lookup(usp->vm, "uscope.variable"),
		var);

	semantic_token_t *stok = &usp->tokens.entries[token_id];

	if (name == VAR_NAME_AUTO_RETURN)
		var->name = ucv_asprintf(".return.%p", var);
	else if (name == NULL)
		var->name = ucv_get(stok->token.uv);
	else
		var->name = name;

	var->value = initval ? ucv_get(*initval) : NULL;
	var->global = global;
	var->constant = constant;
	var->initialized = (initval != NULL);
	var->jsdoc = jsdoc;

	jsdoc_merge_function_details(var);

	if (constant)
		variable_upsert_jsdoc(uv, KIND_MEMBER)->constant = true;

	uc_vector_grow(&var->references);

	uscope_reference_t *ref = &var->references.entries[var->references.count++];

	ref->access_kind = ACCESS_DECLARATION;
	ref->token_id = token_id;
	ref->location.offset = stok->token.pos;
	ref->location.column = ref->location.offset;
	ref->location.line = uc_source_get_line(usp->parser.lex.source, &ref->location.column);

	var->range.start = ref->location;

	stok->sem_modifiers |= (1u << TM_DECLARATION);

	if (var->initialized)
		stok->sem_modifiers |= (1u << TM_DEFINITION);

	if (!global) {
		uc_vector_foreach(&scope->variables, uv_old) {
			uscope_variable_t *var_old =
				ucv_resource_data(*uv_old, "uscope.variable");

			if (var_old->property || var_old->superseded)
				continue;

			if (!ucv_is_equal(var_old->name, var->name))
				continue;

			fprintf(stderr, "Superseding variable '%s' due to redeclaration\n",
				ucv_string_get(var_old->name));

			var_old->range.end = var->range.start;
			var_old->superseded = true;
		}
	}

	uc_vector_push(&scope->variables, ucv_get(uv));

	return uv;
}

static uc_value_t *
property_new(uscope_parser_t *usp, size_t token_id, uc_value_t *name,
             uc_value_t **initval, jsdoc_t *jsdoc, uc_value_t *base)
{
	size_t scope_id = usp->scopechain.entries[usp->scopechain.count - 1];
	scope_t *scope = &usp->scopes.entries[scope_id];

	uc_vector_grow(&scope->variables);

	uscope_variable_t *var = xalloc(sizeof(uscope_variable_t));

	uc_value_t *uv = ucv_resource_new(
		ucv_resource_type_lookup(usp->vm, "uscope.variable"),
		var);

	semantic_token_t *stok = &usp->tokens.entries[token_id];

	var->base = ucv_get(base);
	var->name = name ? name : ucv_get(stok->token.uv);
	var->value = initval ? ucv_get(*initval) : NULL;
	var->property = true;
	var->initialized = (initval != NULL);
	var->jsdoc = jsdoc;

	var->range.start.offset = stok->token.pos;
	var->range.start.column = var->range.start.offset;
	var->range.start.line = uc_source_get_line(usp->parser.lex.source, &var->range.start.column);

	uscope_reference_t *ref = uc_vector_push(&var->references, {
		.access_kind = ACCESS_DECLARATION
	});

	if (usp->parser.prev.type == TK_LABEL &&
	    (stok->token.type == TK_DOT || stok->token.type == TK_QDOT))
	{
		ref->token_id = usp->prev_token_offset;
		ref->location.offset = usp->parser.prev.pos;
		ref->location.column = ref->location.offset;
		ref->location.line = uc_source_get_line(usp->parser.lex.source, &ref->location.line);
	}
	else {
		ref->token_id = token_id;
		ref->location = var->range.start;
	}

	scope->variables.entries[scope->variables.count++] = ucv_get(uv);

	return uv;
}

static void
reference_add(uscope_parser_t *usp, uc_value_t *uv, size_t token_id, uscope_access_kind_t access)
{
	uscope_variable_t *var = ucv_resource_data(uv, "uscope.variable");

	uc_vector_grow(&var->references);

	semantic_token_t *stok = &usp->tokens.entries[token_id];
	uscope_reference_t *ref = &var->references.entries[var->references.count++];

	ref->access_kind = access;
	ref->token_id = token_id;
	ref->location.offset = stok->token.pos;
	ref->location.column = ref->location.offset;
	ref->location.line =
		uc_source_get_line(usp->parser.lex.source, &ref->location.column);
}

static uc_value_t *
variable_lookup(uscope_parser_t *usp, uc_value_t *name)
{
	uc_value_t *uv = NULL;

	for (size_t i = usp->scopechain.count; i > 0 && uv == NULL; i--) {
		size_t scope_id = usp->scopechain.entries[i - 1];
		scope_t *scope = &usp->scopes.entries[scope_id];

		for (size_t j = 0; j < scope->variables.count; j++) {
			uscope_variable_t *var = ucv_resource_data(scope->variables.entries[j], "uscope.variable");

			if (var->property || var->superseded)
				continue;

			if (!ucv_is_equal(name, var->name))
				continue;

			uv = scope->variables.entries[j];
		}
	}

	return uv;
}

static void
variable_supersede(uscope_parser_t *usp, uc_value_t *name, size_t token_id)
{
	size_t scope_id = *uc_vector_last(&usp->scopechain);
	scope_t *scope = &usp->scopes.entries[scope_id];
	semantic_token_t *stok = uscope_vector_get(&usp->tokens, token_id);

	assert(stok);

	uc_vector_foreach(&scope->variables, uv) {
		uscope_variable_t *var = ucv_resource_data(*uv, "uscope.variable");

		if (var->property || var->superseded)
			continue;

		if (!ucv_is_equal(name, var->name))
			continue;

		var->superseded = true;
		var->range.end.offset = stok->token.pos;
		var->range.end.column = var->range.end.offset;
		var->range.end.line = uc_source_get_line(usp->parser.lex.source, &var->range.end.column);
	}
}

static uc_value_t *
variable_access(uscope_parser_t *usp, jsdoc_t *jsdoc, uscope_access_kind_t access)
{
	size_t token_id = usp->prev_token_offset;
	uc_value_t *name = usp->tokens.entries[token_id].token.uv;
	uc_value_t *uv = variable_lookup(usp, name);

	if (uv) {
		/* if this variable access is annotated with a jsdoc and if the jsdoc
		   type differs from the one already set on the variable, then treat
		   the referenced variable as new one from now on, otherwise simply
		   update the jsdoc type which also retroactively applies to earlier
		   variable accesses */


		// FIXME: jsdoc change -> update variable semantics
		jsdoc_free(jsdoc);

		reference_add(usp, uv, token_id, access);

		return ucv_get(uv);
	}

	fprintf(stderr, "IMPLICIT-VAR '%s'\n", ucv_string_get(name));

	// FIXME: strict mode here
	uc_value_t *new_var = variable_new(usp, token_id,
		ucv_get(name), NULL, jsdoc, false, true);

	variable_get_reference(new_var, 0)->access_kind  = access;

	return new_var;
}

static bool
member_lookup(const jsdoc_t *jsdoc, uc_value_t *key,
              uc_value_t **descp, jsdoc_typedef_t **typep)
{
	if (descp) *descp = NULL;
	if (typep) *typep = NULL;

	if (!jsdoc || !jsdoc->type)
		return false;

	if (jsdoc->type->type == TYPE_OBJECT) {
		uc_vector_foreach(&jsdoc->type->details.object.properties, prop) {
			if (prop->name && ucv_is_equal(prop->name, key)) {
				if (descp) *descp = prop->description;
				if (typep) *typep = prop->type;

				return true;
			}
		}

		if (jsdoc->type->details.object.val_type) {
			if (descp) *descp = NULL;
			if (typep) *typep = jsdoc->type->details.object.val_type;

			return true;
		}
	}
	else if (jsdoc->type->type == TYPE_ARRAY) {
		int64_t index = ucv_to_integer(key);

		if (index < 0)
			index += jsdoc->type->details.array.elements.count;

		jsdoc_element_t *elem = (index >= 0) ? uscope_vector_get(
			&jsdoc->type->details.array.elements,
			(size_t)index) : NULL;

		if (elem) {
			if (descp) *descp = elem->description;
			if (typep) *typep = elem->type;

			return true;
		}
		else if (jsdoc->type->details.array.item_type) {
			if (descp) *descp = NULL;
			if (typep) *typep = jsdoc->type->details.array.item_type;

			return true;
		}
	}

	return false;
}

uc_value_t *
uscope_resolve_variable(uc_vm_t *vm, uc_value_t *uv, bool recursive)
{
	struct { size_t count; uc_value_t **entries; } seen = { 0 };
	uscope_variable_t *var;

	while ((var = ucv_resource_data(uv, "uscope.variable")) != NULL) {
		jsdoc_typedef_t *def;

		uv = NULL;

		if ((def = var->jsdoc ? var->jsdoc->type : NULL) != NULL) {
			if (def->type == TYPE_OBJECT || def->type == TYPE_ARRAY)
				uv = var->value;
			else
				uv = def->value;
		}

		if (!recursive)
			break;

		for (size_t i = 0; i < seen.count; i++) {
			if (seen.entries[i] == uv) {
				uv = NULL;
				break;
			}
		}

		uc_vector_push(&seen, uv);
	}

	uc_vector_clear(&seen);

	return ucv_get(uv);
}

static uc_value_t *
ucv_replace(uc_value_t **dest, uc_value_t *val)
{
	ucv_put(*dest);

	*dest = val;

	return *dest;
}

static bool
member_upsert(const jsdoc_t *jsdoc, uc_value_t *key,
              uc_value_t ***descp, jsdoc_typedef_t ***typep)
{
	if (descp) *descp = NULL;
	if (typep) *typep = NULL;

	if (!jsdoc || !jsdoc->type)
		return false;

	if (jsdoc->type->type == TYPE_OBJECT) {
		uc_vector_foreach(&jsdoc->type->details.object.properties, prop) {
			if (prop->name && ucv_is_equal(prop->name, key)) {
				if (descp) *descp = &prop->description;
				if (typep) *typep = &prop->type;

				return true;
			}
		}

		jsdoc_property_t *pp = uc_vector_push(&jsdoc->type->details.object.properties, {
			.name = ucv_get(key)
		});

		if (descp) *descp = &pp->description;
		if (typep) *typep = &pp->type;

		return true;

	}
	else if (jsdoc->type->type == TYPE_ARRAY) {
		int64_t index = ucv_to_integer(key);

		if (index < 0)
			index += jsdoc->type->details.array.elements.count;

		if (index < 0)
			return false;

		jsdoc_element_t *elem = uscope_vector_get(
			&jsdoc->type->details.array.elements,
			(size_t)index);

		if (!elem)
			while ((size_t)index >= jsdoc->type->details.array.elements.count)
				elem = uc_vector_push(&jsdoc->type->details.array.elements, { 0 });

		if (descp) *descp = &elem->description;
		if (typep) *typep = &elem->type;

		return true;
	}

	return false;
}

static uc_value_t *
update_variable(uscope_parser_t *usp, uc_value_t *uv, uscope_access_kind_t access,
                uc_value_t *value, jsdoc_t *user_jsdoc)
{
	uscope_variable_t *var = variable_check(uv);

	if (!var) {
		jsdoc_free(user_jsdoc);

		return NULL;
	}

	uscope_reference_t *ref = uc_vector_last(&var->references);

	jsdoc_t *val_jsdoc = variable_get_jsdoc(value);
	jsdoc_t *new_jsdoc;

	if (val_jsdoc) {
		new_jsdoc = jsdoc_merge(val_jsdoc, user_jsdoc, 0);
	}
	else if (user_jsdoc) {
		val_jsdoc = jsdoc_from_uv(usp->vm, value, NULL);
		new_jsdoc = jsdoc_merge(val_jsdoc, user_jsdoc, 0);
		jsdoc_free(val_jsdoc);
	}
	else {
		new_jsdoc = jsdoc_from_uv(usp->vm, value, NULL);
	}

	jsdoc_type_t new_type = jsdoc_get_type(new_jsdoc);
	jsdoc_type_t old_type = jsdoc_get_type(var->jsdoc);

	bool is_type_change = var->initialized &&
		((new_type != old_type) ||
		 (new_type == TYPE_OBJECT && value != var->value) ||
		 (new_type == TYPE_ARRAY && value != var->value));

	if (var->property) {
		uscope_variable_t *basevar = variable_check(var->base);
		jsdoc_typedef_t **type = NULL;
		uc_value_t **desc = NULL;

		if (basevar && member_upsert(basevar->jsdoc, var->name, &desc, &type)) {
			jsdoc_typedef_free(*type); *type = NULL;
			jsdoc_typedef_merge(type, new_jsdoc->type, 0);

			// FIXME: do we want to copy the assigned values subject as
			//        property description?
			if (!*desc && new_jsdoc->subject)
				*desc = ucv_get(new_jsdoc->subject);

			if (*type)
				ucv_replace(&(*type)->value,
					ucv_is_scalar(value) ? ucv_get(value) : NULL);

			usp->tokens.entries[ref->token_id].sem_modifiers |= (1u << TM_MOD);
		}
	}
	else if (is_type_change) {
		size_t token_id = uc_vector_last(&var->references)->token_id;
		uc_value_t *new_var = variable_new(usp, token_id,
			ucv_get(var->name), &value,
			jsdoc_merge(var->jsdoc, new_jsdoc, 0),
			var->constant, var->global);

		variable_get_reference(new_var, 0)->access_kind = access;

		var->range.end = uc_vector_last(&var->references)->location;
		var->superseded = true;
		var->references.count--;

		ucv_put(new_var);

		usp->tokens.entries[ref->token_id].sem_modifiers |= (1u << TM_MOD);
	}
	else {
		jsdoc_t *old_jsdoc = var->jsdoc;

		if (!var->initialized)
			usp->tokens.entries[ref->token_id].sem_modifiers |= (1u << TM_DEFINITION);
		else
			usp->tokens.entries[ref->token_id].sem_modifiers |= (1u << TM_MOD);

		var->initialized = true;
		var->jsdoc = jsdoc_merge(old_jsdoc, new_jsdoc, 0);

		jsdoc_free(old_jsdoc);
	}

	ref->access_kind = access;

	jsdoc_free(user_jsdoc);
	jsdoc_free(new_jsdoc);

	return value;
}

static uc_value_t *parse_declaration(uscope_parser_t *);
static uc_value_t *parse_paren(uscope_parser_t *);
static uc_value_t *parse_unary(uscope_parser_t *);
static uc_value_t *parse_delete(uscope_parser_t *);
static uc_value_t *parse_constant(uscope_parser_t *);
static uc_value_t *parse_template(uscope_parser_t *);
static uc_value_t *parse_labelexpr(uscope_parser_t *);
static uc_value_t *parse_funcexpr(uscope_parser_t *);
static uc_value_t *parse_array(uscope_parser_t *);
static uc_value_t *parse_object(uscope_parser_t *);

static uc_value_t *parse_call(uscope_parser_t *, uc_value_t *);
static uc_value_t *parse_binary(uscope_parser_t *, uc_value_t *);
static uc_value_t *parse_post_inc(uscope_parser_t *, uc_value_t *);
static uc_value_t *parse_comma(uscope_parser_t *, uc_value_t *);
static uc_value_t *parse_and(uscope_parser_t *, uc_value_t *);
static uc_value_t *parse_or(uscope_parser_t *, uc_value_t *);
static uc_value_t *parse_nullish(uscope_parser_t *, uc_value_t *);
static uc_value_t *parse_dot(uscope_parser_t *, uc_value_t *);
static uc_value_t *parse_subscript(uscope_parser_t *, uc_value_t *);
static uc_value_t *parse_ternary(uscope_parser_t *, uc_value_t *);

static parse_rule_t
parse_rules[TK_ERROR + 1] = {
	[TK_LPAREN]		= { parse_paren, parse_call, P_CALL },
	[TK_QLPAREN]	= { NULL, parse_call, P_CALL },
	[TK_SUB]		= { parse_unary, parse_binary, P_ADD },
	[TK_ADD]		= { parse_unary, parse_binary, P_ADD },
	[TK_COMPL]		= { parse_unary, NULL, P_UNARY },
	[TK_NOT]		= { parse_unary, NULL, P_UNARY },
	[TK_DELETE]		= { parse_delete, NULL, P_UNARY },
	[TK_INC]		= { parse_unary, parse_post_inc, P_INC },
	[TK_DEC]		= { parse_unary, parse_post_inc, P_INC },
	[TK_DIV]		= { NULL, parse_binary, P_MUL },
	[TK_MUL]		= { NULL, parse_binary, P_MUL },
	[TK_MOD]		= { NULL, parse_binary, P_MUL },
	[TK_EXP]		= { NULL, parse_binary, P_EXP },
	[TK_NUMBER]		= { parse_constant, NULL, P_NONE },
	[TK_DOUBLE]		= { parse_constant, NULL, P_NONE },
	[TK_STRING]		= { parse_constant, NULL, P_NONE },
	[TK_TRUE]		= { parse_constant, NULL, P_NONE },
	[TK_FALSE]		= { parse_constant, NULL, P_NONE },
	[TK_NULL]		= { parse_constant, NULL, P_NONE },
	[TK_THIS]		= { parse_constant, NULL, P_NONE },
	[TK_REGEXP]		= { parse_constant, NULL, P_NONE },
	[TK_TEMPLATE]	= { parse_template, NULL, P_NONE },
	[TK_COMMA]		= { NULL, parse_comma, P_COMMA },
	[TK_LABEL]		= { parse_labelexpr, NULL, P_NONE },
	[TK_FUNC]		= { parse_funcexpr, NULL, P_NONE },
	[TK_AND]		= { NULL, parse_and, P_AND },
	[TK_OR]			= { NULL, parse_or, P_OR },
	[TK_NULLISH]	= { NULL, parse_nullish, P_OR },
	[TK_BOR]		= { NULL, parse_binary, P_BOR },
	[TK_BXOR]		= { NULL, parse_binary, P_BXOR },
	[TK_BAND]		= { NULL, parse_binary, P_BAND },
	[TK_EQ]			= { NULL, parse_binary, P_EQUAL },
	[TK_EQS]		= { NULL, parse_binary, P_EQUAL },
	[TK_NE]			= { NULL, parse_binary, P_EQUAL },
	[TK_NES]		= { NULL, parse_binary, P_EQUAL },
	[TK_LT]			= { NULL, parse_binary, P_COMPARE },
	[TK_LE]			= { NULL, parse_binary, P_COMPARE },
	[TK_GT]			= { NULL, parse_binary, P_COMPARE },
	[TK_GE]			= { NULL, parse_binary, P_COMPARE },
	[TK_IN]			= { NULL, parse_binary, P_COMPARE },
	[TK_LSHIFT]		= { NULL, parse_binary, P_SHIFT },
	[TK_RSHIFT]		= { NULL, parse_binary, P_SHIFT },
	[TK_DOT]		= { NULL, parse_dot, P_CALL },
	[TK_QDOT]		= { NULL, parse_dot, P_CALL },
	[TK_LBRACK]		= { parse_array, parse_subscript, P_CALL },
	[TK_QLBRACK]	= { NULL, parse_subscript, P_CALL },
	[TK_QMARK]		= { NULL, parse_ternary, P_TERNARY },
	[TK_LBRACE]		= { parse_object, NULL, P_NONE },
};

static parse_rule_t *parse_rule_select(uc_tokentype_t type) {
    return &parse_rules[type];
}

__attribute__((format(printf, 3, 0))) static void
parse_syntax_error(uscope_parser_t *usp, size_t off, const char *fmt, ...)
{
	uc_source_t *source = usp->parser.lex.source;
	size_t len = 0;
	va_list ap;
	char *s;

	if (usp->parser.synchronizing)
		return;

	usp->parser.synchronizing = true;

	va_start(ap, fmt);
	len = xvasprintf(&s, fmt, ap);
	va_end(ap);

	uc_vector_grow(&usp->errors);

	uscope_position_t *sp = &usp->errors.entries[usp->errors.count].start;
	uscope_position_t *ep = &usp->errors.entries[usp->errors.count].end;

	sp->offset  = off;
	sp->column  = off;
	sp->line    = uc_source_get_line(source, &sp->column);

	ep->offset  = sp->offset;
	ep->column  = sp->column;
	ep->line    = sp->line;

	usp->errors.entries[usp->errors.count].message = ucv_string_new_length(s, len);
	usp->errors.count++;

	free(s);
}

static uc_token_t *
parse_next_token(uscope_parser_t *usp)
{
	uc_token_t *tok = NULL;

	while (true) {
		tok = uc_lexer_next_token(&usp->parser.lex);

		uc_vector_grow(&usp->tokens);
		usp->tokens.entries[usp->tokens.count].token.type = tok->type;
		usp->tokens.entries[usp->tokens.count].token.pos = tok->pos;
		usp->tokens.entries[usp->tokens.count].token.end = tok->end;
		usp->tokens.entries[usp->tokens.count].token.uv = ucv_get(tok->uv);
		usp->tokens.entries[usp->tokens.count].sem_type = type_semtype_map[tok->type];
		usp->tokens.count++;

		if (tok->type == TK_LSTM || tok->type == TK_COMMENT) {
			ucv_put(tok->uv);
			continue;
		}

		if (tok->type == TK_RSTM)
			tok->type = TK_SCOL;

		break;
	}

	return tok;
}

static void
token_set_sem_type(uscope_parser_t *usp, semantic_token_type_t sem_type)
{
	usp->tokens.entries[usp->prev_token_offset].sem_type = sem_type;
}

static void
token_set_sem_modifier(uscope_parser_t *usp, semantic_token_modifier_t sem_modifier)
{
	usp->tokens.entries[usp->prev_token_offset].sem_modifiers |= (1u << sem_modifier);
}

static void
parse_advance(uscope_parser_t *usp)
{
	ucv_put(usp->parser.prev.uv);

	usp->parser.prev = usp->parser.curr;
	usp->prev_token_offset = usp->curr_token_offset;

	if (usp->lookahead.count > 0) {
		for (size_t i = 0; i < usp->lookahead.count; i++) {
			if (i == 0) {
				usp->parser.curr = usp->lookahead.entries[i].token;
				usp->curr_token_offset = usp->lookahead.entries[i].offset;
			}
			else {
				usp->lookahead.entries[i-1] = usp->lookahead.entries[i];
			}
		}

		usp->lookahead.count--;
	}
	else {
		usp->parser.curr = *parse_next_token(usp);
		usp->curr_token_offset = usp->tokens.count - 1;
	}
}

static uc_token_t *
parse_peek(uscope_parser_t *usp)
{
	uc_vector_grow(&usp->lookahead);

	usp->lookahead.entries[usp->lookahead.count].token = *parse_next_token(usp);
	usp->lookahead.entries[usp->lookahead.count].offset = usp->tokens.count - 1;

	return &usp->lookahead.entries[usp->lookahead.count++].token;
}

static void
parse_consume(uscope_parser_t *usp, uc_tokentype_t type)
{
	if (usp->parser.curr.type == type) {
		parse_advance(usp);

		return;
	}

	parse_syntax_error(usp, usp->parser.curr.pos,
		"Unexpected token\nExpecting %s", uc_tokenname(type));
}

static bool
parse_check(uscope_parser_t *usp, uc_tokentype_t type)
{
	return (usp->parser.curr.type == type);
}

static bool
token_match(uscope_parser_t *usp, uc_tokentype_t type)
{
	if (!parse_check(usp, type))
		return false;

	parse_advance(usp);

	return true;
}

static bool
keyword_check(uscope_parser_t *usp, const char *keyword)
{
	size_t keywordlen = strlen(keyword);

	return (usp->parser.curr.type == TK_LABEL &&
	        ucv_string_length(usp->parser.curr.uv) == keywordlen &&
	        strcmp(ucv_string_get(usp->parser.curr.uv), keyword) == 0);
}

static bool
keyword_match(uscope_parser_t *usp, const char *keyword)
{
	if (!keyword_check(usp, keyword))
		return false;

	parse_advance(usp);

	return true;
}

static void
keyword_consume(uscope_parser_t *usp, const char *keyword)
{
	if (keyword_check(usp, keyword)) {
		parse_advance(usp);

		return;
	}

	parse_syntax_error(usp, usp->parser.curr.pos,
		"Unexpected token\nExpecting '%s'", keyword);
}

static bool
parse_is_at_assignment(uscope_parser_t *usp)
{
	switch (usp->parser.curr.type) {
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
	case TK_ASAND:
	case TK_ASOR:
	case TK_ASEXP:
	case TK_ASNULLISH:
	case TK_ASSIGN:
		return true;

	default:
		return false;
	}
}

static uc_value_t *
parse_precedence(uscope_parser_t *usp, uc_precedence_t precedence)
{
	uc_value_t *result = NULL;
	parse_rule_t *rule = parse_rule_select(usp->parser.curr.type);

	if (!rule->prefix) {
		parse_syntax_error(usp, usp->parser.curr.pos, "Expecting expression");
		parse_advance(usp);

		return NULL;
	}

	/* allow reserved words as property names in object literals */
	if (rule->prefix == parse_object)
		usp->parser.lex.no_keyword = true;

	/* unless a sub-expression follows, treat subsequent slash as division
		* operator and not as beginning of regexp literal */
	if (rule->prefix != parse_paren &&
		rule->prefix != parse_unary &&
		rule->prefix != parse_array)
		usp->parser.lex.no_regexp = true;

	parse_advance(usp);

	result = rule->prefix(usp);

	while (precedence <= parse_rule_select(usp->parser.curr.type)->precedence) {
		rule = parse_rule_select(usp->parser.curr.type);

		if (!rule->infix) {
			parse_syntax_error(usp, usp->parser.curr.pos, "Expecting ';' or binary operator");
			parse_advance(usp);
			ucv_put(result);

			return NULL;
		}

		/* allow reserved words in property accessors */
		if (rule->infix == parse_dot)
			usp->parser.lex.no_keyword = true;

		parse_advance(usp);

		result = rule->infix(usp, result);
	}

	return result;
}

static uc_value_t *
calculate_binary_result(uc_vm_t *vm, uc_tokentype_t operator, uc_value_t *operand, uc_value_t *value)
{
	uc_value_t *v1 = uscope_resolve_variable(vm, operand, true);
	uc_value_t *v2 = uscope_resolve_variable(vm, value, true);

	if (is_undef(v1)) {
		ucv_put(v2);

		return v1;
	}

	if (is_undef(v2)) {
		ucv_put(v1);

		return v2;
	}

	uc_value_t *result = ucv_arith_binary(vm, operator, v1, v2);

	ucv_put(v1);
	ucv_put(v2);

	return result;
}

static uc_value_t *
calculate_unary_result(uc_vm_t *vm, uc_tokentype_t operator, uc_value_t *operand)
{
	uc_value_t *v1 = uscope_resolve_variable(vm, operand, true);
	uc_value_t *nv, *zv, *result;
	int64_t n;

	if (is_undef(v1))
		return v1;

	switch (operator) {
	case TK_SUB:
		nv = ucv_to_number(v1);
		zv = ucv_uint64_new(0);
		result = ucv_arith_binary(vm, TK_SUB, zv, nv);
		ucv_put(nv);
		ucv_put(zv);
		break;

	case TK_ADD:
		result = ucv_to_number(v1);
		break;

	case TK_COMPL:
		nv = ucv_to_number(v1);
		n = ucv_int64_get(nv);
		result = (n < 0) ? ucv_int64_new(~n) : ucv_uint64_new(~ucv_uint64_get(nv));
		ucv_put(nv);
		break;

	case TK_NOT:
		result = ucv_boolean_new(ucv_is_truish(v1) == false);
		break;

	case TK_INC:
		nv = ucv_to_number(v1);
		zv = ucv_uint64_new(1);
		result = ucv_arith_binary(vm, TK_ADD, nv, zv);
		ucv_put(nv);
		ucv_put(zv);
		break;

	case TK_DEC:
		nv = ucv_to_number(v1);
		zv = ucv_uint64_new(1);
		result = ucv_arith_binary(vm, TK_SUB, nv, zv);
		ucv_put(nv);
		ucv_put(zv);
		break;

	default:
		result = NULL;
		break;
	}

	ucv_put(v1);

	return result;
}

static int
is_truish(uc_vm_t *vm, uc_value_t *uv)
{
	uc_value_t *v = uscope_resolve_variable(vm, uv, true);

	if (is_undef(v)) {
		ucv_put(v);

		return -1;
	}

	bool rv = ucv_is_truish(v);

	ucv_put(v);

	return rv;
}


static uc_value_t *
parse_text(uscope_parser_t *usp)
{
    return ucv_get(usp->parser.prev.uv);
}

static uc_value_t *
parse_post_inc(uscope_parser_t *usp, uc_value_t *operand)
{
	uscope_variable_t *var = ucv_resource_data(operand, "uscope.variable");
	uc_value_t *res = NULL;

	if (var) {
		res = uscope_resolve_variable(usp->vm, operand, true);

		uc_value_t *inc = is_undef(res)
			? ucv_get(res) : ucv_arith_binary(usp->vm,
				usp->parser.prev.type == TK_INC ? TK_ADD : TK_SUB,
				res, ucv_uint64_new(1));

		update_variable(usp, operand, ACCESS_UPDATE, inc, NULL);
		ucv_put(inc);
	}

	ucv_put(operand);

	return res;
}

static uc_value_t *
parse_delete(uscope_parser_t *usp)
{
	uc_value_t *operand = parse_precedence(usp, P_UNARY);
	uscope_variable_t *var = ucv_resource_data(operand, "uscope.variable");

	ucv_replace(&operand,
		ucv_boolean_new(var ? var->initialized : false));

	return operand;
}

static uc_value_t *
parse_comma(uscope_parser_t *usp, uc_value_t *left)
{
	ucv_put(left);

	return parse_precedence(usp, P_ASSIGN);
}

static uc_value_t *
parse_unary(uscope_parser_t *usp)
{
	uc_tokentype_t operator = usp->parser.prev.type;
	uc_value_t *operand = parse_precedence(usp, P_UNARY);
	uc_value_t *result = NULL;

	result = calculate_unary_result(usp->vm, operator, operand);

	ucv_put(operand);

	return result;
}

static uc_value_t *
parse_binary(uscope_parser_t *usp, uc_value_t *left)
{
    uc_tokentype_t operator = usp->parser.prev.type;
    parse_rule_t *rule = parse_rule_select(operator);
    uc_value_t *right = parse_precedence(usp, rule->precedence + 1);
	uc_value_t *result = NULL;

	result = calculate_binary_result(usp->vm, operator, left, right);

	ucv_put(left);
	ucv_put(right);

    return result;
}

static uc_value_t *
parse_assignment(uscope_parser_t *usp, uc_value_t *left, jsdoc_t *jsdoc)
{
	uc_tokentype_t operator = usp->parser.curr.type;
	uc_value_t *result = NULL;

	parse_advance(usp);

	uc_value_t *right = parse_precedence(usp, P_ASSIGN);
	uc_tokentype_t op = TK_ASSIGN;

	switch (operator) {
	case TK_ASBAND:    op = TK_BAND;    break;
	case TK_ASBXOR:    op = TK_BXOR;    break;
	case TK_ASBOR:     op = TK_BOR;     break;
	case TK_ASLEFT:    op = TK_LSHIFT;  break;
	case TK_ASRIGHT:   op = TK_RSHIFT;  break;
	case TK_ASMUL:     op = TK_MUL;     break;
	case TK_ASDIV:     op = TK_DIV;     break;
	case TK_ASMOD:     op = TK_MOD;     break;
	case TK_ASADD:     op = TK_ADD;     break;
	case TK_ASSUB:     op = TK_SUB;     break;
	case TK_ASAND:     op = TK_AND;     break;
	case TK_ASOR:      op = TK_OR;      break;
	case TK_ASEXP:     op = TK_EXP;     break;
	case TK_ASNULLISH: op = TK_NULLISH; break;
	default:                            break;
	}

	if (right) {
		if (op != TK_ASSIGN)
			result = calculate_binary_result(usp->vm, op, left, right);
		else
			result = ucv_get(right);
	}

	update_variable(usp, left,
		(op == TK_ASSIGN) ? ACCESS_WRITE : ACCESS_UPDATE,
		right, jsdoc);

	ucv_put(left);
	ucv_put(right);

	return result;
}

static uc_value_t *
parse_dot(uscope_parser_t *usp, uc_value_t *left)
{
	bool optional_chaining = (usp->parser.prev.type == TK_QDOT);
	uscope_variable_t *var = variable_check(left);
	uc_value_t *key = ucv_get(usp->parser.curr.uv);
	size_t token_id = usp->prev_token_offset;
	uc_value_t *prop = NULL;
	jsdoc_t *jsdoc = NULL;

	usp->parser.lex.no_regexp = true;
	parse_consume(usp, TK_LABEL);
	token_set_sem_type(usp, TT_PROPERTY);

	if (var && var->jsdoc && jsdoc_get_type(var->jsdoc) == TYPE_OBJECT) {
		for (size_t i = 0; i < ucv_array_length(var->value); i++) {
			uscope_variable_t *pvar =
				variable_check(ucv_array_get(var->value, i));

			if (!pvar || !pvar->name || !pvar->property)
				continue;

			if (!ucv_is_equal(pvar->name, key))
				continue;

			prop = ucv_get(ucv_array_get(var->value, i));
			break;
		}

		if (!prop) {
			prop = property_new(usp, token_id, ucv_get(key), NULL, NULL, left);
			ucv_array_push(var->value, prop);
		}
		else {
			reference_add(usp, prop, usp->prev_token_offset, ACCESS_READ);
		}
	}
	else {
		// Base value is not an object, creating dangling property reference...
		prop = property_new(usp, token_id, ucv_get(key), NULL, NULL, left);
	}

	if (var) {
		jsdoc_typedef_t *type = NULL;
		uc_value_t *desc = NULL;

		if (member_lookup(var->jsdoc, key, &desc, &type)) {
			jsdoc = variable_upsert_jsdoc(prop, KIND_MEMBER);
			ucv_replace(&jsdoc->description, ucv_get(desc));
			jsdoc_typedef_merge(&jsdoc->type, type, 0);
		}
	}

	ucv_put(left);
	ucv_put(key);

	uscope_reference_t *ref = variable_get_reference(prop, -1);

	if (ref)
		ref->optional = optional_chaining;

	if (parse_is_at_assignment(usp))
		return parse_assignment(usp, prop, NULL);

	return prop;
}

static uc_value_t *
parse_expression(uscope_parser_t *usp)
{
   return parse_precedence(usp, P_COMMA);
}

static uc_value_t *
uscope_resolve_expression(uscope_parser_t *usp, uc_precedence_t precedence)
{
	uc_value_t *expr = parse_precedence(usp, precedence);
	uc_value_t *result = uscope_resolve_variable(usp->vm, expr, true);

	ucv_put(expr);

	return result;
}

static uc_value_t *
parse_subscript(uscope_parser_t *usp, uc_value_t *left)
{
	bool optional_chaining = (usp->parser.prev.type == TK_QLBRACK);
	size_t token_id = usp->prev_token_offset;
	uc_value_t *key = uscope_resolve_expression(usp, P_ASSIGN);

	usp->parser.lex.no_regexp = true;
	parse_consume(usp, TK_RBRACK);

	uscope_variable_t *var = variable_check(left);
	uc_value_t *prop = NULL;

	jsdoc_type_t vartype = (var && var->jsdoc)
		? jsdoc_get_type(var->jsdoc) : TYPE_UNSPEC;

	if (vartype == TYPE_ARRAY || vartype == TYPE_OBJECT) {
		for (size_t i = 0; i < ucv_array_length(var->value); i++) {
			uscope_variable_t *pvar =
				variable_check(ucv_array_get(var->value, i));

			if (!pvar || !pvar->name || !pvar->property)
				continue;

			if (!ucv_compare(I_EQ, pvar->name, key, NULL))
				continue;

			prop = ucv_get(ucv_array_get(var->value, i));
			break;
		}

		if (!prop) {
			prop = property_new(usp, token_id, ucv_get(key), NULL, NULL, left);
			ucv_array_push(var->value, prop);
		}
		else {
			reference_add(usp, prop, token_id, ACCESS_READ);
		}
	}
	else {
		// Base value is not an object, creating dangling property reference...
		prop = property_new(usp, token_id, ucv_get(key), NULL, NULL, left);
	}

	if (var && key) {
		jsdoc_typedef_t *type = NULL;
		uc_value_t *desc = NULL;

		if (member_lookup(var->jsdoc, key, &desc, &type)) {
			jsdoc_t *jsdoc = variable_upsert_jsdoc(prop, KIND_MEMBER);
			jsdoc->description = ucv_get(desc);
			jsdoc_typedef_merge(&jsdoc->type, type, 0);
		}
	}

	ucv_put(left);
	ucv_put(key);

	uscope_reference_t *ref = variable_get_reference(prop, -1);

	if (ref)
		ref->optional = optional_chaining;

	if (parse_is_at_assignment(usp))
		return parse_assignment(usp, prop, NULL);

	return prop;
}

static uc_value_t *
parse_and(uscope_parser_t *usp, uc_value_t *left)
{
	uc_value_t *right = parse_precedence(usp, P_AND);
	uc_value_t *result = NULL;

	result = calculate_binary_result(usp->vm, TK_AND, left, right);

	ucv_put(left);
	ucv_put(right);

	return result;
}

static uc_value_t *
parse_or(uscope_parser_t *usp, uc_value_t *left)
{
	uc_value_t *right = parse_precedence(usp, P_OR);
	uc_value_t *result = NULL;

	result = calculate_binary_result(usp->vm, TK_OR, left, right);

	ucv_put(left);
	ucv_put(right);

	return result;
}

static uc_value_t *
parse_nullish(uscope_parser_t *usp, uc_value_t *left)
{
	uc_value_t *right = parse_precedence(usp, P_OR);
	uc_value_t *result = NULL;

	result = calculate_binary_result(usp->vm, TK_NULLISH, left, right);

	ucv_put(left);
	ucv_put(right);

	return result;
}

static uc_value_t *
parse_ternary(uscope_parser_t *usp, uc_value_t *condition)
{
	size_t token_num = usp->prev_token_offset;

	uc_value_t *true_expr = parse_precedence(usp, P_ASSIGN);

	parse_consume(usp, TK_COLON);

	uc_value_t *false_expr = parse_precedence(usp, P_TERNARY);
	uc_value_t *result = NULL;

	switch (is_truish(usp->vm, condition)) {
	case -1:
		result = undef_new(usp, token_num,
			jsdoc_merge(
				variable_get_jsdoc(true_expr),
				variable_get_jsdoc(false_expr),
				MERGE_UNION | MERGE_TYPEONLY));
		break;

	case  0: result = ucv_get(false_expr); break;
	case  1: result = ucv_get(true_expr); break;
	}

	ucv_put(condition);
	ucv_put(true_expr);
	ucv_put(false_expr);

	return result;
}

static void
upsert_element(jsdoc_t *jsdoc, size_t index, const jsdoc_t *elem_jsdoc)
{
	if (jsdoc_get_type(jsdoc) != TYPE_ARRAY)
		return;

	jsdoc_element_t *elem = NULL;

	while (index >= jsdoc->type->details.array.elements.count)
		elem = uc_vector_push(&jsdoc->type->details.array.elements, { 0 });

	if (!elem)
		elem = uscope_vector_get(&jsdoc->type->details.array.elements, index);

	if (!elem->description && elem_jsdoc->description)
		elem->description = ucv_get(elem_jsdoc->description);

	jsdoc_typedef_merge(&elem->type, elem_jsdoc->type, 0);
}

static uc_value_t *
parse_array(uscope_parser_t *usp)
{
	size_t index = 0;
	uc_value_t *av = ucv_array_new(usp->vm);
	uc_value_t *uv;

	/* create anonymous const */
	uscope_variable_t *anon = xalloc(sizeof(uscope_variable_t));
	anon->constant = true;
	anon->initialized = true;
	anon->value = ucv_get(av);
	anon->jsdoc = jsdoc_new(TYPE_ARRAY);
	anon->name = ucv_asprintf(".array.%p", av);

	uc_vector_grow(&anon->references);

	uscope_reference_t *ref = &anon->references.entries[anon->references.count++];

	ref->access_kind = ACCESS_DECLARATION;
	ref->token_id = usp->prev_token_offset;
	ref->value = ucv_get(av);

	size_t scope_id = *uc_vector_last(&usp->scopechain);
	scope_t *scope = uscope_vector_get(&usp->scopes, scope_id);

	uv = ucv_resource_new(
		ucv_resource_type_lookup(usp->vm, "uscope.variable"),
		anon);

	uc_vector_push(&scope->variables, ucv_get(uv));
	uc_vector_push(&usp->thischain, uv);

	do {
		if (parse_check(usp, TK_RBRACK)) {
			break;
		}
		else if (token_match(usp, TK_ELLIP)) {
			size_t token_id = usp->prev_token_offset;
			uc_value_t *src_arr = uscope_resolve_expression(usp, P_ASSIGN);

			if (ucv_type(src_arr) == UC_ARRAY) {
				for (size_t i = 0; i < ucv_array_length(src_arr); i++) {
					uc_value_t *v = ucv_array_get(src_arr, i);
					jsdoc_t *elem_jsdoc = jsdoc_derive(NULL, v, false);

					upsert_element(anon->jsdoc, index++, elem_jsdoc);

					uc_value_t *initval = uscope_resolve_variable(usp->vm, v, true);

					ucv_array_push(av,
						property_new(usp, token_id,
							ucv_uint64_new(ucv_array_length(av)),
							&initval, elem_jsdoc, uv));

					ucv_put(initval);
				}
			}
			else  {
				ucv_array_push(av, undef_new(usp, token_id, NULL));
			}

			ucv_put(src_arr);
		}
		else {
			size_t token_id = usp->curr_token_offset;
			uc_value_t *expr = parse_precedence(usp, P_ASSIGN);
			jsdoc_t *elem_jsdoc = jsdoc_capture(usp, token_id, expr);

			upsert_element(anon->jsdoc, index++, elem_jsdoc);

			uc_value_t *initval = uscope_resolve_variable(usp->vm, expr, true);

			ucv_array_push(av,
				property_new(usp, token_id,
					ucv_uint64_new(ucv_array_length(av)), &initval,
					elem_jsdoc, uv));

			ucv_put(initval);
			ucv_put(expr);
		}
	} while (token_match(usp, TK_COMMA));

	usp->parser.lex.no_regexp = true;
	parse_consume(usp, TK_RBRACK);

	usp->thischain.count--;

	ucv_put(av);

	return uv;
}

static void
upsert_property(jsdoc_t *jsdoc, uc_value_t *name, const jsdoc_t *prop_jsdoc)
{
	if (jsdoc_get_type(jsdoc) != TYPE_OBJECT)
		return;

	jsdoc_property_t *prop = NULL;

	uc_vector_foreach(&jsdoc->type->details.object.properties, pp) {
		if (pp->name && ucv_is_equal(pp->name, name)) {
			prop = pp;
			break;
		}
	}

	if (!prop) {
		prop = uc_vector_push(&jsdoc->type->details.object.properties, {
			.name = ucv_get(name)
		});
	}

	if (!prop->description && prop_jsdoc->description)
		prop->description = ucv_get(prop_jsdoc->description);

	jsdoc_typedef_merge(&prop->type, prop_jsdoc->type, 0);
}

static uc_value_t *
parse_object(uscope_parser_t *usp)
{
	uc_value_t *props = ucv_array_new(usp->vm);
	uc_value_t *uv = NULL;

	/* create anonymous const */
	uscope_variable_t *anon = xalloc(sizeof(uscope_variable_t));
	anon->constant = true;
	anon->initialized = true;
	anon->value = ucv_get(props);
	anon->jsdoc = jsdoc_new(TYPE_OBJECT);
	anon->name = ucv_asprintf(".object.%p", props);

	uc_vector_grow(&anon->references);

	uscope_reference_t *ref = &anon->references.entries[anon->references.count++];

	ref->access_kind = ACCESS_DECLARATION;
	ref->token_id = usp->prev_token_offset;
	ref->value = ucv_get(props);

	size_t scope_id = usp->scopechain.entries[usp->scopechain.count - 1];
	scope_t *scope = &usp->scopes.entries[scope_id];

	uv = ucv_resource_new(
		ucv_resource_type_lookup(usp->vm, "uscope.variable"),
		anon);

	uc_vector_push(&scope->variables, ucv_get(uv));
	uc_vector_push(&usp->thischain, uv);

	while (!parse_check(usp, TK_RBRACE)) {
		if (token_match(usp, TK_ELLIP)) {
			size_t token_id = usp->prev_token_offset;
			uc_value_t *src_obj = uscope_resolve_expression(usp, P_ASSIGN);

			if (ucv_type(src_obj) == UC_OBJECT) {
				ucv_object_foreach(src_obj, k, v) {
					jsdoc_t *prop_jsdoc = jsdoc_derive(NULL, v, false);
					uc_value_t *key = ucv_string_new(k);

					upsert_property(anon->jsdoc, key, prop_jsdoc);
					ucv_put(key);

					uc_value_t *initval = uscope_resolve_variable(usp->vm, v, true);

					ucv_array_push(props,
						property_new(usp, token_id,
							ucv_string_new(k), &initval, prop_jsdoc, uv));

					ucv_put(initval);
				}
			}
			else {
				// FIXME: need any kind of placeholder logic here?
			}

			ucv_put(src_obj);
		}
		else if (token_match(usp, TK_LBRACK)) {
			size_t token_id = usp->prev_token_offset;
			uc_value_t *key = uscope_resolve_expression(usp, P_ASSIGN);

			parse_consume(usp, TK_RBRACK);
			parse_consume(usp, TK_COLON);

			uc_value_t *value = parse_precedence(usp, P_ASSIGN);

			// FIXME: need any kind of placeholder logic here?
			if (!is_undef(key)) {
				jsdoc_t *prop_jsdoc = jsdoc_capture(usp, token_id, value);

				upsert_property(anon->jsdoc, key, prop_jsdoc);

				uc_value_t *prop = property_new(usp, token_id, ucv_get(key),
					NULL, prop_jsdoc, uv);

				uscope_variable_t *pvar = ucv_resource_data(prop, "uscope.variable");
				pvar->value = uscope_resolve_variable(usp->vm, value, true);
				pvar->initialized = true;

				ucv_array_push(props, prop);
			}

			ucv_put(key);
			ucv_put(value);
		}
		else {
			if (token_match(usp, TK_LABEL) || token_match(usp, TK_STRING)) {
				size_t token_id = usp->prev_token_offset;
				if (parse_check(usp, TK_COLON)) {
					uc_value_t *key = ucv_get(usp->parser.prev.uv);

					token_set_sem_type(usp, TT_PROPERTY);
					parse_consume(usp, TK_COLON);

					uc_value_t *value = parse_precedence(usp, P_ASSIGN);
					jsdoc_t *prop_jsdoc = jsdoc_capture(usp, token_id, value);

					upsert_property(anon->jsdoc, key, prop_jsdoc);

					uc_value_t *prop = property_new(usp, token_id, key, NULL, prop_jsdoc, uv);
					uscope_variable_t *pvar = ucv_resource_data(prop, "uscope.variable");

					ucv_array_push(props, prop);

					pvar->value = uscope_resolve_variable(usp->vm, value, true);
					pvar->initialized = true;

					ucv_put(value);
				}
				else {
					uc_value_t *key = ucv_get(usp->parser.prev.uv);
					uc_value_t *value = variable_access(usp, NULL, ACCESS_READ);
					jsdoc_t *prop_jsdoc = jsdoc_capture(usp, token_id, value);

					upsert_property(anon->jsdoc, key, prop_jsdoc);

					uc_value_t *prop = property_new(usp, token_id, ucv_get(key),
						NULL, prop_jsdoc, uv);

					uscope_variable_t *pvar = ucv_resource_data(prop, "uscope.variable");

					ucv_array_push(props, prop)					;

					pvar->value = uscope_resolve_variable(usp->vm, value, true);
					pvar->initialized = true;

					ucv_put(value);
					ucv_put(key);
				}
			}
			else {
				parse_syntax_error(usp, usp->parser.curr.pos, "Expecting property name");
				goto out;
			}
		}

		usp->parser.lex.no_keyword = true;

		if (!token_match(usp, TK_COMMA))
			break;
	}

	usp->parser.lex.no_regexp = true;
	parse_consume(usp, TK_RBRACE);

out:
	usp->thischain.count--;

	ucv_put(props);

	return uv;
}

static uc_value_t *
parse_template(uscope_parser_t *usp)
{
	uc_value_t *text = parse_constant(usp);
	uc_value_t *tmp, *result = text;

	while (true) {
		if (token_match(usp, TK_TEMPLATE)) {
			text = parse_constant(usp);

			tmp = calculate_binary_result(usp->vm, TK_ADD, result, text);

			ucv_put(text);
			ucv_replace(&result, tmp);
		}
		else if (token_match(usp, TK_PLACEH)) {
			uc_value_t *expr = parse_precedence(usp, P_ASSIGN);

			parse_consume(usp, TK_RBRACE);

			tmp = calculate_binary_result(usp->vm, TK_ADD, result, expr);

			ucv_put(expr);
			ucv_replace(&result, tmp);
		}
		else {
			break;
		}
	}

	return result;
}

static bool
is_global_function(uscope_variable_t *var, const char *name)
{
	if (!var || !var->global || !name || ucv_type(var->name) != UC_STRING)
		return false;

	return (strcmp(ucv_string_get(var->name), name) == 0);
}

static bool
apply_function_side_effects(uscope_parser_t *usp, size_t token_num,
                            uscope_variable_t *var, callargs_t *args,
                            uc_value_t **retval)
{
	if (is_global_function(var, "push") || is_global_function(var, "unshift")) {
		/* need non-spread subject as first arg and at least one member */
		if (args->count < 2 || args->entries[0].spread == true)
			return false;

		jsdoc_typedef_t **arr_defp = NULL;

		uc_vector_foreach(args, arg) {
			if (!arr_defp) {
				jsdoc_t *jsdoc = variable_get_jsdoc(arg->value);

				if (jsdoc_get_type(jsdoc) != TYPE_ARRAY)
					break;

				arr_defp = &jsdoc->type->details.array.item_type;
				continue;
			}

			jsdoc_typedef_t *arg_def = jsdoc_typedef_from_uv(usp->vm, arg->value);

			jsdoc_t js1 = { .type = *arr_defp }, js2 = { .type = arg_def };
			uc_value_t *jsu1, *jsu2;
			char *jss1, *jss2;

			jsu1 = jsdoc_to_uv(usp->vm, &js1);
			jss1 = ucv_to_string(usp->vm, jsu1);
			jsu2 = jsdoc_to_uv(usp->vm, &js2);
			jss2 = ucv_to_string(usp->vm, jsu1);

			fprintf(stderr, "ARRAY TYPE MERGE: %s + %s\n", jss1, jss2);

			ucv_put(jsu1);
			ucv_put(jsu2);
			free(jss1);
			free(jss2);

			if (arg->spread) {
				if (arg_def->type == TYPE_ARRAY) {
					jsdoc_typedef_merge(arr_defp,
						arg_def->details.array.item_type,
						MERGE_UNION | MERGE_TYPEONLY);
				}
			}
			else {
				jsdoc_typedef_merge(arr_defp, arg_def,
					MERGE_UNION | MERGE_TYPEONLY);
			}

			jsdoc_typedef_free(arg_def);
		}

		if (args->entries[args->count - 1].spread)
			*retval = undef_new(usp, token_num,
				jsdoc_derive(NULL, args->entries[args->count - 1].value, false));
		else
			*retval = ucv_get(args->entries[args->count - 1].value);

		return true;
	}
	else if (is_global_function(var, "sort")) {
		/* need non-spread subject as first arg */
		if (args->count < 1 || args->entries[0].spread == true)
			return false;

		jsdoc_t *src_jsdoc = variable_get_jsdoc(args->entries[0].value);

		/* clear elements from typedef as the sorting will alter indexes */
		if (jsdoc_get_type(src_jsdoc) == TYPE_ARRAY) {
			jsdoc_t *dst_jsdoc = xalloc(sizeof(jsdoc_t));

			jsdoc_typedef_merge(&dst_jsdoc->type, src_jsdoc->type,
				MERGE_TYPEONLY | MERGE_NOELEMS);

			*retval = undef_new(usp, token_num, dst_jsdoc);
		}
		else if (jsdoc_get_type(src_jsdoc) == TYPE_OBJECT) {
			*retval = ucv_get(args->entries[0].value);
		}
		else {
			*retval = NULL;
		}

		return true;
	}
	else if (is_global_function(var, "reverse")) {
		/* need non-spread subject as first arg */
		if (args->count < 1 || args->entries[0].spread == true)
			return false;

		jsdoc_t *src_jsdoc = variable_get_jsdoc(args->entries[0].value);

		if (jsdoc_get_type(src_jsdoc) == TYPE_ARRAY || jsdoc_get_type(src_jsdoc) == TYPE_STRING) {
			jsdoc_t *dst_jsdoc = xalloc(sizeof(jsdoc_t));

			jsdoc_typedef_merge(&dst_jsdoc->type, src_jsdoc->type,
				MERGE_TYPEONLY | MERGE_NOELEMS);

			*retval = undef_new(usp, token_num, dst_jsdoc);
		}
		else {
			*retval = NULL;
		}

		return true;
	}
	else if (is_global_function(var, "keys")) {
		/* need non-spread subject as first arg */
		if (args->count < 1 || args->entries[0].spread == true)
			return false;

		jsdoc_t *src_jsdoc = variable_get_jsdoc(args->entries[0].value);

		if (jsdoc_get_type(src_jsdoc) == TYPE_OBJECT) {
			jsdoc_t *dst_jsdoc = jsdoc_new(TYPE_ARRAY);

			dst_jsdoc->type->details.array.item_type = jsdoc_typedef_new(TYPE_STRING);

			*retval = undef_new(usp, token_num, dst_jsdoc);
		}
		else {
			*retval = NULL;
		}

		return true;
	}
	else if (is_global_function(var, "proto")) {
		/* we only handle the two argument form here and return a fused
		   placeholder value containing both the subject and the prototype
		   object properties */
		if (args->count < 2 ||
		    args->entries[0].spread == true ||
		    args->entries[1].spread == true)
			return false;

		jsdoc_t *this_jsdoc = jsdoc_derive(NULL, args->entries[0].value, false);
		jsdoc_t *proto_jsdoc = variable_get_jsdoc(args->entries[1].value);

		if (jsdoc_get_type(proto_jsdoc) == TYPE_OBJECT)
			jsdoc_typedef_merge(&this_jsdoc->type, proto_jsdoc->type, MERGE_UNION);

		*retval = undef_new(usp, token_num, this_jsdoc);

		return true;
	}

	return false;
}

static void
token_id_to_position(uscope_parser_t *usp, size_t token_id, bool end,
                     uscope_position_t *position)
{
	semantic_token_t *stok = uscope_vector_get(&usp->tokens, token_id);

	if (!stok)
		return;

	position->offset = end ? stok->token.end : stok->token.pos;
	position->column = position->offset;
	position->line =
		uc_source_get_line(usp->parser.lex.source, &position->column);
}

static uc_value_t *
parse_call(uscope_parser_t *usp, uc_value_t *callee)
{
	size_t token_num = usp->prev_token_offset;
	uscope_variable_t *var = ucv_resource_data(callee, "uscope.variable");

	for (size_t i = 0; var && i < var->references.count; i++)
		usp->tokens.entries[var->references.entries[i].token_id].sem_type = TT_FUNCTION;

	callargs_t args = { 0 };

	if (!parse_check(usp, TK_RPAREN)) {
		do {
			if (token_match(usp, TK_ELLIP)) {
				uc_value_t *arg = parse_precedence(usp, P_ASSIGN);
				uc_vector_push(&args, ((typeof(*args.entries)){ true, arg }));
			}
			else {
				uc_value_t *arg = parse_precedence(usp, P_ASSIGN);
				uc_vector_push(&args, ((typeof(*args.entries)){ false, arg }));
			}
		} while (token_match(usp, TK_COMMA));
	}

	uc_value_t *retval = NULL;
	bool have_retval = false;

	have_retval = apply_function_side_effects(usp, token_num, var, &args, &retval);

	while (args.count > 0)
		ucv_put(args.entries[--args.count].value);

	uc_vector_clear(&args);

	usp->parser.lex.no_regexp = true;
	parse_consume(usp, TK_RPAREN);

	jsdoc_t *result_jsdoc = variable_get_jsdoc(retval);
	jsdoc_t *var_jsdoc = NULL;

	if (var && jsdoc_get_type(var->jsdoc) == TYPE_FUNCTION) {
		jsdoc_typedef_t *fndef = var->jsdoc->type;
		jsdoc_t *return_jsdoc = jsdoc_from_return(KIND_MEMBER, fndef);

		var_jsdoc = jsdoc_merge(result_jsdoc, return_jsdoc, MERGE_UNION);

		jsdoc_free(return_jsdoc);
	}

	if (!have_retval)
		retval = undef_new(usp, token_num, result_jsdoc);

	uc_value_t *retvar = variable_new(usp, token_num,
		VAR_NAME_AUTO_RETURN, &retval, var_jsdoc, false, false);

	uscope_variable_t *retvar_var = variable_check(retvar);

	retvar_var->base = ucv_get(callee);
	retvar_var->superseded = true;
	token_id_to_position(usp, usp->prev_token_offset,
		true, &retvar_var->range.end);

	ucv_put(retval);
	ucv_put(callee);

	return retvar;
}

static uc_value_t *
parse_control(uscope_parser_t *usp)
{
	parse_consume(usp, TK_SCOL);

	return NULL;
}

static uc_value_t *
parse_tplexp(uscope_parser_t *usp)
{
   uc_value_t *expr = parse_precedence(usp, P_ASSIGN);

   token_match(usp, TK_SCOL);
   parse_consume(usp, TK_REXP);

   return expr;
}

static uc_value_t *
parse_expstmt(uscope_parser_t *usp)
{
	if (token_match(usp, TK_SCOL))
		return NULL;

	uc_value_t *expr = parse_expression(usp);

	switch (usp->parser.curr.type) {
	case TK_RBRACE:
	case TK_ELIF:
	case TK_ENDIF:
	case TK_ENDFOR:
	case TK_ENDWHILE:
	case TK_ENDFUNC:
	case TK_EOF:
		break;

	case TK_ELSE:
		// NB: we're lenient here, the ucode compiler has stricter rules
		token_match(usp, TK_SCOL);
		break;

	default:
		parse_consume(usp, TK_SCOL);
		break;
	}

	return expr;
}

static void
jsdoc_merge_return_type(uscope_parser_t *usp, size_t jsdoc_token_id, uc_value_t *uv)
{
	if (!usp->function_jsdocs.count)
		return;

	jsdoc_t *func_jsdoc = *uc_vector_last(&usp->function_jsdocs);
	jsdoc_typedef_t **rt = &func_jsdoc->type->details.function.return_type;
	uc_value_t **rd = &func_jsdoc->type->details.function.return_description;

	if (uv) {
		jsdoc_t *ret_jsdoc = jsdoc_capture(usp, jsdoc_token_id, uv);

		if (!*rd && ret_jsdoc->subject)
			*rd = ucv_get(ret_jsdoc->subject);

		jsdoc_typedef_merge(rt, ret_jsdoc->type, MERGE_UNION);
		jsdoc_free(ret_jsdoc);
	}
	else if (*rt) {
		(*rt)->nullable = true;
	}
}

static uc_value_t *
parse_return(uscope_parser_t *usp)
{
	size_t jsdoc_token_id = usp->prev_token_offset;
   	uc_value_t *retval = parse_expstmt(usp);

	jsdoc_merge_return_type(usp, jsdoc_token_id, retval);
	ucv_put(retval);

	return NULL;
}

static uc_value_t *
parse_declexpr(uscope_parser_t *usp, bool constant)
{
	jsdoc_t *decl_wide_doc = jsdoc_capture(usp, usp->prev_token_offset, NULL);
	uc_value_t *result = ucv_array_new(usp->vm);

	do {
		if (!token_match(usp, TK_LABEL)) {
			parse_syntax_error(usp, usp->parser.curr.pos, "Expecting variable name");
			goto out;
		}

		jsdoc_t *var_specific_doc = jsdoc_capture(usp, usp->prev_token_offset, NULL);
		size_t token_id = usp->prev_token_offset;
		uc_value_t *initval = NULL;

		variable_supersede(usp, usp->parser.prev.uv, token_id);
		token_set_sem_type(usp, TT_VARIABLE);

		jsdoc_t *decl_jsdoc = jsdoc_merge(decl_wide_doc, var_specific_doc, 0);

		if (constant)
			token_set_sem_modifier(usp, TM_READONLY);

		if (token_match(usp, TK_ASSIGN)) {
			uc_vector_push(&usp->declaration_jsdocs, decl_jsdoc);

			initval = parse_precedence(usp, P_ASSIGN);

			usp->declaration_jsdocs.count--;

			jsdoc_typedef_t *valdef = jsdoc_typedef_from_uv(usp->vm, initval);

			jsdoc_typedef_merge(&var_specific_doc->type, valdef, 0);
			jsdoc_typedef_free(valdef);
		}
		else if (constant) {
			parse_syntax_error(usp, usp->parser.prev.pos,
				"Expecting initializer expression");

			jsdoc_free(var_specific_doc);
			goto out;
		}

		ucv_array_push(result,
			variable_new(usp, token_id, NULL, &initval,
				decl_jsdoc, constant, false));

		jsdoc_free(var_specific_doc);
		ucv_put(initval);
	}
	while (token_match(usp, TK_COMMA));

out:
	jsdoc_free(decl_wide_doc);

	return result;
}

static uc_value_t *
parse_local(uscope_parser_t *usp)
{
	ucv_put(parse_declexpr(usp, false));
	parse_consume(usp, TK_SCOL);

	return NULL;
}

static uc_value_t *
parse_const(uscope_parser_t *usp)
{
	ucv_put(parse_declexpr(usp, true));
	parse_consume(usp, TK_SCOL);

	return NULL;
}

static uc_value_t *
parse_block(uscope_parser_t *usp, uc_tokentype_t endtype)
{
	scope_enter(usp);

	while (!parse_check(usp, endtype) &&
			!parse_check(usp, TK_EOF)) {

		ucv_put(parse_declaration(usp));
	}

	parse_consume(usp, endtype);

	scope_leave(usp);

	return NULL;
}

static uc_value_t *
create_function(uscope_parser_t *usp, uc_value_t *name,
                bool arrow, bool vararg, uc_value_t *arglist)
{
	uc_cfn_ptr_t loadstring_fn = uc_stdlib_function("loadstring");

	if (!loadstring_fn)
		return NULL;

	uc_stringbuf_t *sbuf = ucv_stringbuf_new();

	ucv_stringbuf_append(sbuf, "const retval = null, argvals = null; return ");

	if (arrow)
		ucv_stringbuf_append(sbuf, "(");
	else if (name)
		ucv_stringbuf_printf(sbuf, "function %s (", ucv_string_get(name));
	else
		ucv_stringbuf_append(sbuf, "function (");

	for (size_t i = 0; i < ucv_array_length(arglist); i++) {
		if (i > 0)
			ucv_stringbuf_append(sbuf, ", ");

		if (i + 1 == ucv_array_length(arglist) && vararg)
			ucv_stringbuf_append(sbuf, "...args");
		else
			ucv_stringbuf_printf(sbuf, "arg%zu", i);
	}

	if (arrow)
		ucv_stringbuf_append(sbuf, ") => argvals, retval;");
	else
		ucv_stringbuf_append(sbuf, ") { return argvals, retval; };");

	uc_vm_stack_push(usp->vm, ucv_stringbuf_finish(sbuf));

	uc_value_t *fn = loadstring_fn(usp->vm, 1);

	ucv_put(uc_vm_stack_pop(usp->vm));

	if (ucv_type(fn) != UC_CLOSURE) {
		ucv_put(fn);

		return NULL;
	}

	uc_vm_stack_push(usp->vm, fn);

	if (uc_vm_call(usp->vm, false, 0) != EXCEPTION_NONE)
		return NULL;

	fn = uc_vm_stack_pop(usp->vm);

	if (ucv_type(fn) != UC_CLOSURE) {
		ucv_put(fn);

		return NULL;
	}

	uc_upvalref_t **upvals = ((uc_closure_t *)fn)->upvals;

	// FIXME: attach function.return_type to undef jsdoc
	upvals[0]->closed = true;
	upvals[0]->value = undef_new(usp, usp->prev_token_offset, NULL);

	upvals[1]->closed = true;
	upvals[1]->value = arglist;

	return fn;
}

static jsdoc_t *
jsdoc_new_function(uscope_parser_t *usp, size_t jsdoc_token_id)
{
	jsdoc_t *func_jsdoc = jsdoc_capture(usp, jsdoc_token_id, NULL);
	jsdoc_t *decl_jsdoc = usp->declaration_jsdocs.count
		? *uc_vector_last(&usp->declaration_jsdocs) : NULL;

	if (jsdoc_get_type(decl_jsdoc) == TYPE_FUNCTION) {
		jsdoc_t *tmp = jsdoc_merge(decl_jsdoc,
			(jsdoc_get_type(func_jsdoc) == TYPE_FUNCTION) ? func_jsdoc : NULL,
			0);

		jsdoc_free(func_jsdoc);

		uc_vector_push(&usp->function_jsdocs, tmp);

		return tmp;
	}
	else if (jsdoc_get_type(func_jsdoc) == TYPE_FUNCTION) {
		uc_vector_push(&usp->function_jsdocs, func_jsdoc);

		return func_jsdoc;
	}
	else {
		jsdoc_t *tmp = jsdoc_new(TYPE_FUNCTION);

		jsdoc_free(func_jsdoc);

		uc_vector_push(&usp->function_jsdocs, tmp);

		return tmp;
	}
}

static uc_value_t *
parse_funcexpr_common(uscope_parser_t *usp, bool require_name)
{
	size_t keyword_token_id = usp->prev_token_offset;
	size_t declaration_token_id = keyword_token_id;
	uc_value_t *arglist = ucv_array_new(usp->vm);
	uc_value_t *name = NULL;
	bool vararg = false;
	size_t nargs = 0;

	if (token_match(usp, TK_LABEL)) {
		name = ucv_get(usp->parser.prev.uv);
		declaration_token_id = usp->prev_token_offset;
	}
	else if (require_name) {
		parse_syntax_error(usp, usp->parser.curr.pos,
			"Expecting function name");

		return NULL;
	}

	jsdoc_t *func_jsdoc = jsdoc_new_function(usp, keyword_token_id);

	scope_enter(usp);

	parse_consume(usp, TK_LPAREN);

	while (!parse_check(usp, TK_RPAREN)) {
		size_t token_id = usp->prev_token_offset;

		vararg = token_match(usp, TK_ELLIP);

		if (token_match(usp, TK_LABEL)) {
			token_set_sem_type(usp, TT_PARAMETER);

			jsdoc_param_t *param =
				uscope_vector_get(&func_jsdoc->type->details.function.params, nargs);

			if (!param)
				param = uc_vector_push(&func_jsdoc->type->details.function.params, { 0 });

			jsdoc_t *param_jsdoc = jsdoc_capture(usp, token_id, NULL);

			param->name = ucv_get(usp->parser.prev.uv);

			jsdoc_typedef_merge(&param->type, param_jsdoc->type, 0);

			if (param_jsdoc->description && !param->description)
				param->description = ucv_get(param_jsdoc->description);

			jsdoc_free(param_jsdoc);

			uc_value_t *argvar = variable_new(usp, usp->prev_token_offset,
				NULL, NULL, jsdoc_from_param(KIND_MEMBER, param), false, false);

			ucv_array_push(arglist, argvar);

			nargs++;

			if (vararg || !token_match(usp, TK_COMMA))
				break;
		}
		else {
			parse_syntax_error(usp, usp->parser.curr.pos,
				"Expecting Label");

			goto out;
		}
	}

	parse_consume(usp, TK_RPAREN);

	if (token_match(usp, TK_COLON))
		parse_block(usp, TK_ENDFUNC);
	else if (token_match(usp, TK_LBRACE))
		parse_block(usp, TK_RBRACE);
	else
		parse_syntax_error(usp, usp->parser.curr.pos,
			"Expecting '{' or ':' after function parameters");

out:
	scope_leave(usp);

	uc_value_t *initval = create_function(usp, name, false, vararg, arglist);

	uc_value_t *var = variable_new(usp, declaration_token_id, name, &initval,
		func_jsdoc, false, false);

	ucv_put(initval);

	usp->function_jsdocs.count--;

	return var;
}

static uc_value_t *
parse_funcexpr(uscope_parser_t *usp)
{
   	return parse_funcexpr_common(usp, false);
}

static uc_value_t *
parse_funcdecl(uscope_parser_t *usp)
{
	return parse_funcexpr_common(usp, true);
}

static uc_tokentype_t
parse_altifblock(uscope_parser_t *usp)
{
	scope_enter(usp);

	while (true) {
		switch (usp->parser.curr.type) {
		case TK_ELIF:
		case TK_ELSE:
		case TK_ENDIF:
		case TK_EOF:
			scope_leave(usp);

			return usp->parser.curr.type;

		default:
			parse_declaration(usp);
			break;
		}
	}
}

static uc_value_t *
parse_arrowfn(uscope_parser_t *usp)
{
	size_t declaration_token_id = usp->prev_token_offset;
	uc_value_t *arglist = ucv_array_new(usp->vm);
	bool vararg = false;
	size_t nargs = 0;

	jsdoc_t *func_jsdoc = jsdoc_new_function(usp, declaration_token_id);

	scope_enter(usp);

	if (usp->parser.prev.type == TK_LPAREN) {
		while (usp->parser.curr.type != TK_RPAREN) {
			size_t jsdoc_token_id = usp->prev_token_offset;

			vararg = token_match(usp, TK_ELLIP);

			if (token_match(usp, TK_LABEL)) {
				token_set_sem_type(usp, TT_PARAMETER);

				uc_value_t *argvar = variable_new(usp, usp->prev_token_offset,
					NULL, NULL,
					jsdoc_capture(usp, jsdoc_token_id, NULL),
					false, false);

				ucv_array_push(arglist, argvar);

				nargs++;

				if (vararg || !token_match(usp, TK_COMMA))
					break;
			}
			else {
				parse_syntax_error(usp, usp->parser.curr.pos,
					"Expecting Label");

				goto out;
			}
		}

		parse_consume(usp, TK_RPAREN);
	}
	else {
		uc_value_t *argvar = variable_new(usp, usp->prev_token_offset,
			NULL, NULL, NULL, false, false);

		ucv_array_push(arglist, argvar);

		nargs++;
	}

	parse_consume(usp, TK_ARROW);

	if (token_match(usp, TK_LBRACE)) {
		while (!parse_check(usp, TK_RBRACE) &&
				!parse_check(usp, TK_EOF)) {

			parse_declaration(usp);
		}

		parse_consume(usp, TK_RBRACE);
	}
	else {
		size_t jsdoc_token_id = usp->curr_token_offset;
		uc_value_t *expr = parse_precedence(usp, P_ASSIGN);

		jsdoc_merge_return_type(usp, jsdoc_token_id, expr);
		ucv_put(expr);
	}

out:
	scope_leave(usp);

	uc_value_t *initval = create_function(usp, NULL, true, vararg, arglist);

	uc_value_t *var = variable_new(usp, declaration_token_id, NULL, &initval,
		func_jsdoc, false, false);

	ucv_put(initval);

	usp->function_jsdocs.count--;

	return var;
}

static uc_value_t *
parse_paren(uscope_parser_t *usp)
{
	uc_tokentype_t t = usp->parser.curr.type;

	while (t != TK_RPAREN) {
		if (t == TK_LABEL) {
			if (parse_peek(usp)->type == TK_COMMA) {
				t = parse_peek(usp)->type;
				continue;
			}

			t = uc_vector_last(&usp->lookahead)->token.type;
		}

		if (t == TK_ELLIP) {
			if (parse_peek(usp)->type == TK_LABEL &&
			    parse_peek(usp)->type == TK_COMMA) {
				t = parse_peek(usp)->type;
				continue;
			}

			t = uc_vector_last(&usp->lookahead)->token.type;
		}

		break;
	}

	if (t == TK_RPAREN && parse_peek(usp)->type == TK_ARROW)
		return parse_arrowfn(usp);

	uc_value_t *result = NULL;

	if (!parse_check(usp, TK_RPAREN))
		result = parse_expression(usp);

	usp->parser.lex.no_regexp = true;
	parse_consume(usp, TK_RPAREN);

	return result;
}

static uc_value_t *
parse_labelexpr(uscope_parser_t *usp)
{
	if (usp->parser.curr.type == TK_ARROW)
		return parse_arrowfn(usp);

	jsdoc_t *jsdoc = jsdoc_capture(usp, usp->prev_token_offset, NULL);

	if (parse_is_at_assignment(usp))
		return parse_assignment(usp,
			variable_access(usp, NULL, ACCESS_READ), jsdoc);

	return variable_access(usp, jsdoc, ACCESS_READ);
}

static uc_value_t *parse_statement(uscope_parser_t *usp);

static uc_value_t *
parse_if(uscope_parser_t *usp)
{
	parse_consume(usp, TK_LPAREN);
	ucv_put(parse_expression(usp));
	parse_consume(usp, TK_RPAREN);

	if (token_match(usp, TK_COLON)) {
		//usp->parser.exprstack->flags |= F_ALTBLOCKMODE;

		parse_altifblock(usp);

		while (true) {
			uc_tokentype_t block_type = parse_altifblock(usp);

			if (block_type == TK_ELIF) {
				parse_advance(usp);
				parse_consume(usp, TK_LPAREN);
				ucv_put(parse_expression(usp));
				parse_consume(usp, TK_RPAREN);
				parse_consume(usp, TK_COLON);
			}
			else if (block_type == TK_ELSE) {
				parse_advance(usp);
			}
			else if (block_type == TK_ENDIF) {
				parse_advance(usp);
				break;
			}
			else {
				parse_syntax_error(usp, usp->parser.curr.pos,
					"Expecting 'elif', 'else' or 'endif'");
				break;
			}
		}
	}
	else {
		ucv_put(parse_statement(usp));

		if (token_match(usp, TK_ELSE))
			ucv_put(parse_statement(usp));
	}

	return NULL;
}

static uc_value_t *
parse_while(uscope_parser_t *usp)
{
	parse_consume(usp, TK_LPAREN);
	ucv_put(parse_expression(usp));
	parse_consume(usp, TK_RPAREN);

	if (token_match(usp, TK_COLON)) {
		scope_enter(usp);

		ucv_put(parse_block(usp, TK_ENDWHILE));

		scope_leave(usp);
	}
	else {
		ucv_put(parse_statement(usp));
	}

	return NULL;
}

static uc_value_t *
parse_try(uscope_parser_t *usp)
{
	// Try block
	scope_enter(usp);
	parse_consume(usp, TK_LBRACE);
	ucv_put(parse_block(usp, TK_RBRACE));
	scope_leave(usp);

	// Catch block
	parse_consume(usp, TK_CATCH);
	scope_enter(usp);

	// Exception variable (optional)
	if (token_match(usp, TK_LPAREN)) {
		parse_consume(usp, TK_LABEL);

		uc_value_t *initval = ucv_object_new(usp->vm);

		ucv_put(variable_new(usp,
			usp->prev_token_offset, NULL, &initval, NULL, false, false));

		ucv_put(initval);

		parse_consume(usp, TK_RPAREN);
	}

	parse_consume(usp, TK_LBRACE);
	ucv_put(parse_block(usp, TK_RBRACE));

	scope_leave(usp);

	return NULL;
}

static uc_value_t *
parse_switch(uscope_parser_t *usp)
{
	scope_enter(usp);

	parse_consume(usp, TK_LPAREN);
	ucv_put(parse_expression(usp));
	parse_consume(usp, TK_RPAREN);

	parse_consume(usp, TK_LBRACE);

	while (!parse_check(usp, TK_RBRACE) &&
			!parse_check(usp, TK_EOF)) {
		if (token_match(usp, TK_CASE)) {
			ucv_put(parse_expression(usp));
		}
		else if (!token_match(usp, TK_DEFAULT)) {
			parse_syntax_error(usp, usp->parser.curr.pos, "Expecting 'case' or 'default'");
			return NULL;
		}

		parse_consume(usp, TK_COLON);

		while (!parse_check(usp, TK_CASE) &&
				!parse_check(usp, TK_DEFAULT) &&
				!parse_check(usp, TK_RBRACE) &&
				!parse_check(usp, TK_EOF)) {

			parse_declaration(usp);
		}
	}

	parse_consume(usp, TK_RBRACE);

	scope_leave(usp);

	return NULL;
}

static uc_value_t *
parse_for_in(uscope_parser_t *usp, uc_tokentype_t kind, size_t off)
{
	jsdoc_t *doc1 = jsdoc_capture(usp, usp->prev_token_offset, NULL);
	uc_value_t *kv = NULL, *vv = NULL;

	scope_enter(usp);

	if (kind == TK_LOCAL) {
		parse_consume(usp, TK_LOCAL);

		jsdoc_t *doc2 = jsdoc_capture(usp, usp->prev_token_offset, NULL);

		parse_consume(usp, TK_LABEL);

		kv = variable_new(usp, usp->prev_token_offset, NULL, NULL,
			jsdoc_merge(doc1, doc2, 0), false, false);

		jsdoc_free(doc2);

		if (token_match(usp, TK_COMMA)) {
			doc2 = jsdoc_capture(usp, usp->prev_token_offset, NULL);

			parse_consume(usp, TK_LABEL);

			vv = variable_new(usp, usp->prev_token_offset, NULL, NULL,
				jsdoc_merge(doc1, doc2, 0), false, false);

			jsdoc_free(doc2);
		}
	}
	else if (kind == TK_COMMA) {
		parse_consume(usp, TK_LABEL);

		kv = variable_access(usp, jsdoc_merge(doc1, NULL, 0), ACCESS_UPDATE);

		parse_consume(usp, TK_COMMA);

		jsdoc_t *doc2 = jsdoc_capture(usp, usp->prev_token_offset, NULL);

		parse_consume(usp, TK_LABEL);

		vv = variable_access(usp, jsdoc_merge(doc1, doc2, 0), ACCESS_UPDATE);

		jsdoc_free(doc2);
	}
	else {
		parse_consume(usp, TK_LABEL);

		kv = variable_access(usp, jsdoc_merge(doc1, NULL, 0), ACCESS_UPDATE);
	}

	jsdoc_free(doc1);

	parse_consume(usp, TK_IN);

	uc_value_t *iterable = parse_expression(usp);
	uscope_variable_t *iterspec = ucv_resource_data(iterable, "uscope.variable");

	if (iterspec) {
		uscope_variable_t *kvspec = ucv_resource_data(kv, "uscope.variable");

		if (iterspec->type == UC_OBJECT)
			kvspec->type = UC_STRING;
		else if (iterspec->type == UC_ARRAY && vv != NULL)
			kvspec->type = UC_INTEGER;
	}

	ucv_put(iterable);
	ucv_put(kv);
	ucv_put(vv);

	parse_consume(usp, TK_RPAREN);

	if (token_match(usp, TK_COLON)) {
		scope_enter(usp);
		ucv_put(parse_block(usp, TK_ENDFOR));
		scope_leave(usp);
	}
	else {
		ucv_put(parse_statement(usp));
	}


	scope_leave(usp);

	return NULL;
}

static uc_value_t *
parse_for_count(uscope_parser_t *usp, size_t off)
{
	scope_enter(usp);

	// Initializer
	if (token_match(usp, TK_LOCAL))
		ucv_put(parse_declexpr(usp, false));
	else if (!parse_check(usp, TK_SCOL))
		ucv_put(parse_expression(usp));

	parse_consume(usp, TK_SCOL);

	// Condition
	if (!parse_check(usp, TK_SCOL))
		ucv_put(parse_expression(usp));

	parse_consume(usp, TK_SCOL);

	// Increment
	if (!parse_check(usp, TK_RPAREN))
		ucv_put(parse_expression(usp));

	parse_consume(usp, TK_RPAREN);

	// Body
	if (token_match(usp, TK_COLON)) {
		scope_enter(usp);

		ucv_put(parse_block(usp, TK_ENDFOR));
		parse_consume(usp, TK_ENDFOR);

		scope_leave(usp);
	}
	else {
		ucv_put(parse_statement(usp));
	}

	scope_leave(usp);

	return NULL;
}

static uc_value_t *
parse_for(uscope_parser_t *usp)
{
	uc_tokentype_t tokens[5] = { 0 };
	size_t off = usp->parser.prev.pos;

	tokens[0] = parse_peek(usp)->type;
	tokens[1] = parse_peek(usp)->type;
	tokens[2] = parse_peek(usp)->type;
	tokens[3] = parse_peek(usp)->type;
	tokens[4] = parse_peek(usp)->type;

	parse_consume(usp, TK_LPAREN);

#define compare(count, ...) \
	!memcmp(tokens, \
		(uc_tokentype_t[count]){ __VA_ARGS__ }, \
		count * sizeof(uc_tokentype_t))

	if (compare(5, TK_LOCAL, TK_LABEL, TK_COMMA, TK_LABEL, TK_IN) ||
	    compare(3, TK_LOCAL, TK_LABEL, TK_IN))
		return parse_for_in(usp, TK_LOCAL, off);

	if (compare(4, TK_LABEL, TK_COMMA, TK_LABEL, TK_IN) ||
	    compare(2, TK_LABEL, TK_IN))
		return parse_for_in(usp, tokens[1], off);

#undef compare

	return parse_for_count(usp, off);
}

static uc_value_t *
parse_statement(uscope_parser_t *usp)
{
	uc_value_t *result;

	if (token_match(usp, TK_IF))
		result = parse_if(usp);
	else if (token_match(usp, TK_WHILE))
		result = parse_while(usp);
	else if (token_match(usp, TK_FOR))
		result = parse_for(usp);
	else if (token_match(usp, TK_SWITCH))
		result = parse_switch(usp);
	else if (token_match(usp, TK_TRY))
		result = parse_try(usp);
	else if (token_match(usp, TK_FUNC))
		result = parse_funcdecl(usp);
	else if (token_match(usp, TK_BREAK))
		result = parse_control(usp);
	else if (token_match(usp, TK_CONTINUE))
		result = parse_control(usp);
	else if (token_match(usp, TK_RETURN))
		result = parse_return(usp);
	else if (token_match(usp, TK_TEXT))
		result = parse_text(usp);
	else if (token_match(usp, TK_LEXP))
		result = parse_tplexp(usp);
	else if (token_match(usp, TK_LBRACE))
		result = parse_block(usp, TK_RBRACE);
	else
		result = parse_expstmt(usp);

	ucv_put(result);

	return NULL;
}

static uc_value_t *
parse_importlist(uscope_parser_t *usp)
{
	do {
		jsdoc_t *jsdoc = jsdoc_capture(usp, usp->prev_token_offset, NULL);
		xport_item_t *import = uc_vector_push(&usp->imports, { 0 });

		if (token_match(usp, TK_DEFAULT)) {
			keyword_consume(usp, "as");
			token_set_sem_type(usp, TT_KW_OPERATOR);
			parse_consume(usp, TK_LABEL);

			import->is_default = true;
			import->alias = ucv_get(usp->parser.prev.uv);
			import->value = variable_new(usp, usp->prev_token_offset,
				ucv_get(import->alias), NULL, jsdoc, true, true); // FIXME: load actual import

			//usp->imports.count++;
		}
		else if (token_match(usp, TK_STRING)) {
			import->name = ucv_get(usp->parser.prev.uv);

			keyword_consume(usp, "as");
			token_set_sem_type(usp, TT_KW_OPERATOR);
			parse_consume(usp, TK_LABEL);

			import->alias = ucv_get(usp->parser.prev.uv);
			import->value = variable_new(usp, usp->prev_token_offset,
				ucv_get(import->alias), NULL, jsdoc, true, true); // FIXME: load actual import

			//usp->imports.count++;
		}
		else if (token_match(usp, TK_LABEL)) {
			import->name = ucv_get(usp->parser.prev.uv);

			if (keyword_match(usp, "as")) {
				token_set_sem_type(usp, TT_KW_OPERATOR);
				parse_consume(usp, TK_LABEL);

				import->alias = ucv_get(usp->parser.prev.uv);
			}
			else {
				import->alias = ucv_get(import->name);
			}

			import->value = variable_new(usp, usp->prev_token_offset,
				ucv_get(import->alias), NULL, jsdoc, true, true); // FIXME: load actual import

			//usp->imports.count++;
		}
		else {
			jsdoc_free(jsdoc);

			parse_syntax_error(usp, usp->parser.curr.pos,
				"Unexpected token\nExpecting Label, String or 'default'");

			break;
		}

		if (token_match(usp, TK_RBRACE))
			break;

	} while (token_match(usp, TK_COMMA));

	return NULL;
}

static uc_value_t *
parse_import(uscope_parser_t *usp)
{
	size_t jsdoc_token_id = usp->prev_token_offset;
	size_t off = usp->imports.count;

	if (token_match(usp, TK_LBRACE)) {
		ucv_put(parse_importlist(usp));
		keyword_consume(usp, "from");
		token_set_sem_type(usp, TT_KW_OPERATOR);
	}
	else if (token_match(usp, TK_MUL)) {
		//import->value.import_stmt.is_wildcard = true;
		keyword_consume(usp, "as");
		token_set_sem_type(usp, TT_KW_OPERATOR);
		parse_consume(usp, TK_LABEL);

		xport_item_t *import = uc_vector_push(&usp->imports, { 0 });

		import->is_wildcard = true;
		import->alias = ucv_get(usp->parser.prev.uv);

		// FIXME: load actual import
		import->value = variable_new(usp, usp->prev_token_offset,
			ucv_get(import->alias), NULL,
			jsdoc_capture(usp, jsdoc_token_id, NULL), true, true);

		//usp->imports.count++;

		keyword_consume(usp, "from");
		token_set_sem_type(usp, TT_KW_OPERATOR);
	}
	else if (token_match(usp, TK_LABEL)) {
		xport_item_t *default_import = uc_vector_push(&usp->imports, { 0 });

		default_import->is_default = true;
		default_import->alias = ucv_get(usp->parser.prev.uv);

		// FIXME: load actual import
		default_import->value = variable_new(usp, usp->prev_token_offset,
			NULL, NULL, jsdoc_capture(usp, jsdoc_token_id, NULL), true, true);

		//usp->imports.count++;

		if (token_match(usp, TK_COMMA)) {
			jsdoc_token_id = usp->prev_token_offset;

			if (token_match(usp, TK_LBRACE)) {
				ucv_put(parse_importlist(usp));
			}
			else if (token_match(usp, TK_MUL)) {
				xport_item_t *wildcard_import = uc_vector_push(&usp->imports, { 0 });

				keyword_consume(usp, "as");
				token_set_sem_type(usp, TT_KW_OPERATOR);
				parse_consume(usp, TK_LABEL);

				wildcard_import->is_wildcard = true;
				wildcard_import->alias = ucv_get(usp->parser.prev.uv);

				// FIXME: load actual import
				wildcard_import->value = variable_new(usp, usp->prev_token_offset,
					ucv_get(wildcard_import->alias), NULL,
					jsdoc_capture(usp, jsdoc_token_id, NULL), true, true);

				//usp->imports.count++;
			}
			else {
				parse_syntax_error(usp, usp->parser.curr.pos,
					"Unexpected token\nExpecting '{' or '*'");
			}
		}

		keyword_consume(usp, "from");
		token_set_sem_type(usp, TT_KW_OPERATOR);
	}

	parse_consume(usp, TK_STRING);

	while (off < usp->imports.count)
		usp->imports.entries[off++].source = ucv_get(usp->parser.prev.uv);

	parse_consume(usp, TK_SCOL);

	return NULL;
}

static xport_item_t *
add_export(uscope_parser_t *usp, bool is_default, uc_value_t *value)
{
	uc_vector_grow(&usp->exports);

	xport_item_t *export = &usp->exports.entries[usp->exports.count++];
	uscope_variable_t *var = ucv_resource_data(value, "uscope.variable");

	export->is_default = is_default;
	export->value = value;

	if (var)
		export->name = ucv_get(var->name);

	return export;
}

static uc_value_t *
parse_exportlist(uscope_parser_t *usp)
{
	do {
		jsdoc_t *jsdoc = jsdoc_capture(usp, usp->prev_token_offset, NULL);

		parse_consume(usp, TK_LABEL);

		xport_item_t *export = add_export(usp, false,
			variable_access(usp, jsdoc, ACCESS_EXPORT));

		if (keyword_match(usp, "as")) {
			token_set_sem_type(usp, TT_KW_OPERATOR);

			if (token_match(usp, TK_LABEL) || token_match(usp, TK_STRING)) {
				export->alias = ucv_get(usp->parser.prev.uv);
			}
			else if (token_match(usp, TK_DEFAULT)) {
				token_set_sem_type(usp, TT_KW_OPERATOR);
				export->is_default = true;
			}
			else {
				parse_syntax_error(usp, usp->parser.curr.pos,
					"Unexpected token\nExpecting Label, String or 'default'");
				break;
			}
		}

		if (token_match(usp, TK_RBRACE))
			break;

	} while (token_match(usp, TK_COMMA));

	parse_consume(usp, TK_SCOL);

	return NULL;
}

static uc_value_t *
parse_export(uscope_parser_t *usp)
{
	if (token_match(usp, TK_LBRACE)) {
		ucv_put(parse_exportlist(usp));

		return NULL;
	}

	if (token_match(usp, TK_LOCAL)) {
		uc_value_t *decls = parse_declexpr(usp, false);

		for (size_t i = 0; i < ucv_array_length(decls); i++)
			add_export(usp, false, ucv_get(ucv_array_get(decls, i)));

		ucv_put(decls);
	}
	else if (token_match(usp, TK_CONST)) {
		uc_value_t *decls = parse_declexpr(usp, true);

		for (size_t i = 0; i < ucv_array_length(decls); i++)
			add_export(usp, false, ucv_get(ucv_array_get(decls, i)));

		ucv_put(decls);
	}
	else if (token_match(usp, TK_FUNC)) {
		add_export(usp, false, parse_funcdecl(usp));
	}
	else if (token_match(usp, TK_DEFAULT)) {
		add_export(usp, true, parse_expression(usp));
	}
	else {
		parse_syntax_error(usp, usp->parser.curr.pos,
			"Unexpected token\nExpecting 'let', 'const', 'function', 'default' or '{'");

		return NULL;
	}

	parse_consume(usp, TK_SCOL);

	return NULL;
}

static void
parse_source(uscope_parser_t *usp, uc_source_t *source)
{
	uc_lexer_init(&usp->parser.lex, usp->parser.config, source);
	parse_advance(usp);

	scope_enter(usp);

	while (!token_match(usp, TK_EOF))
		ucv_put(parse_declaration(usp));

	scope_leave(usp);

	uc_lexer_free(&usp->parser.lex);

	uc_vector_clear(&usp->lookahead);

	ucv_put(usp->parser.prev.uv);
	ucv_put(usp->parser.curr.uv);
}


// Updated parse_constant function
static uc_value_t *
parse_constant(uscope_parser_t *usp)
{
	switch (usp->parser.prev.type) {
	case TK_THIS:
		return usp->thischain.count
			? ucv_get(usp->thischain.entries[usp->thischain.count - 1])
			: undef_new(usp, usp->prev_token_offset, NULL);

	case TK_NULL:
		return NULL;

	case TK_TRUE:
		return ucv_boolean_new(true);

	case TK_FALSE:
		return ucv_boolean_new(false);

	case TK_STRING:
	case TK_TEMPLATE:
	case TK_DOUBLE:
	case TK_NUMBER:
	case TK_REGEXP:
		return ucv_get(usp->parser.prev.uv);

	default:
		break;
	}

	return NULL;
}

// Implement parsing functions that return AST nodes instead of emitting bytecode
static uc_value_t *
parse_declaration(uscope_parser_t *usp)
{
	uc_value_t *result;

	if (token_match(usp, TK_LOCAL))
		result = parse_local(usp);
	else if (token_match(usp, TK_CONST))
		result = parse_const(usp);
	else if (token_match(usp, TK_EXPORT))
		result = parse_export(usp);
	else if (token_match(usp, TK_IMPORT))
		result = parse_import(usp);
	else
		result = parse_statement(usp);

	ucv_put(result);

	return NULL;
}

// Implement more parsing functions for different constructs

struct keyword {
	unsigned type;
	const char *pat;
	unsigned plen;
};


static const struct keyword reserved_words[] = {
	{ TK_ENDFUNC,	"endfunction", 11 },
	{ TK_CONTINUE,	"continue", 8 },
	{ TK_ENDWHILE,	"endwhile", 8 },
	{ TK_FUNC,		"function", 8 },
	{ TK_DEFAULT,	"default", 7 },
	{ TK_DELETE,	"delete", 6 },
	{ TK_RETURN,	"return", 6 },
	{ TK_ENDFOR,	"endfor", 6 },
	{ TK_SWITCH,	"switch", 6 },
	{ TK_IMPORT,	"import", 6 },
	{ TK_EXPORT,	"export", 6 },
	{ TK_ENDIF,		"endif", 5 },
	{ TK_WHILE,		"while", 5 },
	{ TK_BREAK,		"break", 5 },
	{ TK_CATCH,		"catch", 5 },
	{ TK_CONST,		"const", 5 },
	{ TK_FALSE,		"false", 5 },
	{ TK_TRUE,		"true",  4 },
	{ TK_ELIF,		"elif",  4 },
	{ TK_ELSE,		"else",  4 },
	{ TK_THIS,		"this",  4 },
	{ TK_NULL,		"null",  4 },
	{ TK_CASE,		"case",  4 },
	{ TK_TRY,		"try",   3 },
	{ TK_FOR,		"for",   3 },
	{ TK_LOCAL,		"let",   3 },
	{ TK_IF,		"if",    2 },
	{ TK_IN,		"in",    2 },
};

const char *
uc_tokenname(unsigned type)
{
	static char buf[sizeof("'endfunction'")];
	const char *tokennames[] = {
		[TK_LEXP] = "{{",
		[TK_REXP] = "}}",
		[TK_LSTM] = "{%",
		[TK_RSTM] = "%}",
		[TK_COMMA] = ",",
		[TK_ASSIGN] = "=",
		[TK_ASADD] = "+=",
		[TK_ASSUB] = "-=",
		[TK_ASMUL] = "*=",
		[TK_ASDIV] = "/=",
		[TK_ASMOD] = "%=",
		[TK_ASLEFT] = "<<=",
		[TK_ASRIGHT] = ">>=",
		[TK_ASBAND] = "&=",
		[TK_ASBXOR] = "^=",
		[TK_ASBOR] = "|=",
		[TK_QMARK] = "?",
		[TK_COLON] = ":",
		[TK_OR] = "||",
		[TK_AND] = "&&",
		[TK_BOR] = "|",
		[TK_BXOR] = "^",
		[TK_BAND] = "&",
		[TK_EQS] = "===",
		[TK_NES] = "!==",
		[TK_EQ] = "==",
		[TK_NE] = "!=",
		[TK_LT] = "<",
		[TK_LE] = "<=",
		[TK_GT] = ">",
		[TK_GE] = ">=",
		[TK_LSHIFT] = "<<",
		[TK_RSHIFT] = ">>",
		[TK_ADD] = "+",
		[TK_SUB] = "-",
		[TK_MUL] = "*",
		[TK_DIV] = "/",
		[TK_MOD] = "%",
		[TK_EXP] = "**",
		[TK_NOT] = "!",
		[TK_COMPL] = "~",
		[TK_INC] = "++",
		[TK_DEC] = "--",
		[TK_DOT] = ".",
		[TK_LBRACK] = "[",
		[TK_RBRACK] = "]",
		[TK_LPAREN] = "(",
		[TK_RPAREN] = ")",
		[TK_LBRACE] = "{",
		[TK_RBRACE] = "}",
		[TK_SCOL] = ";",
		[TK_ELLIP] = "...",
		[TK_ARROW] = "=>",
		[TK_QLBRACK] = "?.[",
		[TK_QLPAREN] = "?.(",
		[TK_QDOT] = "?.",
		[TK_ASEXP] = "**=",
		[TK_ASAND] = "&&=",
		[TK_ASOR] = "||=",
		[TK_ASNULLISH] = "\?\?=",
		[TK_NULLISH] = "\?\?",
		[TK_PLACEH] = "${",

		[TK_TEXT] = "Text",
		[TK_LABEL] = "Label",
		[TK_NUMBER] = "Number",
		[TK_DOUBLE] = "Double",
		[TK_STRING] = "String",
		[TK_REGEXP] = "Regexp",
		[TK_TEMPLATE] = "Template",
		[TK_ERROR] = "Error",
		[TK_EOF] = "End of file",
	};

	size_t i;

	for (i = 0; i < ARRAY_SIZE(reserved_words); i++) {
		if (reserved_words[i].type != type)
			continue;

		snprintf(buf, sizeof(buf), "'%s'", reserved_words[i].pat);

		return buf;
	}

	return tokennames[type] ? tokennames[type] : "?";
}

static uc_value_t *
position_to_uv(uc_vm_t *vm, uscope_position_t *pos)
{
	uc_value_t *rv = ucv_object_new(vm);

	ucv_object_add(rv, "offset", ucv_uint64_new(pos->offset));
	ucv_object_add(rv, "character", ucv_uint64_new(pos->column ? pos->column - 1 : 0));
	ucv_object_add(rv, "line", ucv_uint64_new(pos->line ? pos->line - 1 : 0));

	return rv;
}

static void
convert_parse_config(uc_parse_config_t *config, uc_value_t *spec)
{
	uc_value_t *v, *p;
	size_t i, j;
	bool found;

	struct {
		const char *key;
		bool *flag;
		uc_search_path_t *path;
	} fields[] = {
		{ "lstrip_blocks",       &config->lstrip_blocks,       NULL },
		{ "trim_blocks",         &config->trim_blocks,         NULL },
		{ "strict_declarations", &config->strict_declarations, NULL },
		{ "raw_mode",            &config->raw_mode,            NULL },
		{ "module_search_path",  NULL, &config->module_search_path  },
		{ "force_dynlink_list",  NULL, &config->force_dynlink_list  }
	};

	for (i = 0; i < ARRAY_SIZE(fields); i++) {
		v = ucv_object_get(spec, fields[i].key, &found);

		if (!found)
			continue;

		if (fields[i].flag) {
			*fields[i].flag = ucv_is_truish(v);
		}
		else if (fields[i].path) {
			fields[i].path->count = 0;
			fields[i].path->entries = NULL;

			for (j = 0; j < ucv_array_length(v); j++) {
				p = ucv_array_get(v, j);

				if (ucv_type(p) != UC_STRING)
					continue;

				uc_vector_push(fields[i].path, ucv_string_get(p));
			}
		}
	}
}

static void
parse_typedef(uc_vm_t *vm, uc_value_t *typedefs, uc_token_t *tok)
{
	if (tok->type != TK_COMMENT || ucv_type(tok->uv) != UC_STRING)
		return;

	size_t len = ucv_string_length(tok->uv);
	char *str = ucv_string_get(tok->uv);

	if (len < 3 || strncmp(str, "/**", 3) != 0 || !strstr(str, "typedef"))
		return;

	jsdoc_t jsdoc = { 0 };

	jsdoc_parse(str, len, &jsdoc);

	if (jsdoc.kind == KIND_TYPEDEF && jsdoc.name)
		ucv_object_add(typedefs,
			ucv_string_get(jsdoc.name),
			jsdoc_to_uv(vm, &jsdoc));

	jsdoc_reset(&jsdoc);
}

static uc_value_t *
lookup_var_spec(uc_value_t *scopes, uc_value_t *uvar)
{
	for (size_t i = ucv_array_length(scopes); i > 0; i--) {
		uc_value_t *vars = ucv_object_get(
			ucv_array_get(scopes, i - 1), "variables", NULL);

		for (size_t j = ucv_array_length(vars); j > 0; j--) {
			uc_value_t *spec = ucv_array_get(vars, j - 1);
			uc_value_t *other = ucv_object_get(spec, "variable", NULL);

			if (uvar == other)
				return spec;
		}
	}

	return NULL;
}

static uc_value_t *
uc_analyze(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *code = uc_fn_arg(0);
	uc_value_t *spec = uc_fn_arg(1);
	uc_value_t *global = uc_fn_arg(1);
	uc_value_t *rv = NULL;
	uc_source_t *source = NULL;
	size_t len;
	char *s;

	if (ucv_type(code) == UC_STRING) {
		len = ucv_string_length(code);
		s = xalloc(len);
		memcpy(s, ucv_string_get(code), len);
	}
	else {
		s = ucv_to_string(vm, code);
		len = strlen(s);
	}

	if (len >= 4 && *(uint32_t *)s == htobe32(UC_PRECOMPILED_BYTECODE_MAGIC)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			"Cannot parse precompiled source files");

		free(s);

		return NULL;
	}

	source = uc_source_new_buffer("[code argument]", s, len);

	uc_parse_config_t conf = *vm->config;

	convert_parse_config(&conf, spec);

	uscope_parser_t usp = {
		.vm = vm,
		.parser = { .config = &conf },
		.global = global ? global : uc_vm_scope_get(vm)
	};

	parse_source(&usp, source);

	if (!vm->config || conf.module_search_path.entries != vm->config->module_search_path.entries)
		uc_vector_clear(&conf.module_search_path);

	if (!vm->config || conf.force_dynlink_list.entries != vm->config->force_dynlink_list.entries)
		uc_vector_clear(&conf.force_dynlink_list);

	rv = ucv_object_new(vm);

	/* apply token modifiers */
	uc_vector_foreach(&usp.scopes, scope) {
		uc_vector_foreach(&scope->variables, uv) {
			uscope_variable_t *var = ucv_resource_data(*uv, "uscope.variable");

			uc_vector_foreach(&var->references, ref) {
				semantic_token_t *stok = &usp.tokens.entries[ref->token_id];

				if (jsdoc_get_type(var->jsdoc) == TYPE_FUNCTION)
					stok->sem_type = TT_FUNCTION;
				else if (var->property)
					stok->sem_type = TT_PROPERTY;

				if (var->constant)
					stok->sem_modifiers |= (1u << TM_READONLY);
			}
		}
	}

	/* build token array and jsdoc typedef arrays */
	uc_value_t *tokens = ucv_array_new(vm);
	uc_value_t *typedefs = ucv_object_new(vm);

	for (size_t i = 0; i <= usp.curr_token_offset; i++) {
		uscope_position_t start, end;

		start.offset = usp.tokens.entries[i].token.pos;
		start.column = start.offset;
		start.line = uc_source_get_line(source, &start.column);

		end.offset = usp.tokens.entries[i].token.end;
		end.column = end.offset;
		end.line = uc_source_get_line(source, &end.column);

		uc_value_t *entry = ucv_object_new(vm);
		ucv_object_add(entry, "start", position_to_uv(vm, &start));
		ucv_object_add(entry, "end", position_to_uv(vm, &end));
		ucv_object_add(entry, "type", ucv_uint64_new(usp.tokens.entries[i].token.type));
		ucv_object_add(entry, "value", usp.tokens.entries[i].token.uv);
		ucv_object_add(entry, "semanticType", ucv_uint64_new(usp.tokens.entries[i].sem_type));
		ucv_object_add(entry, "semanticModifiers", ucv_uint64_new(usp.tokens.entries[i].sem_modifiers));

		ucv_array_push(tokens, entry);

		parse_typedef(vm, typedefs, &usp.tokens.entries[i].token);
	}

	ucv_object_add(rv, "tokens", tokens);
	ucv_object_add(rv, "typedefs", typedefs);

	uc_source_put(source);

	/* build parse error array */
	uc_value_t *errors = ucv_array_new_length(vm, usp.errors.count);

	for (size_t i = 0; i < usp.errors.count; i++) {
		uscope_position_t *sp = &usp.errors.entries[i].start;
		uscope_position_t *ep = &usp.errors.entries[i].end;

		uc_value_t *entry = ucv_object_new(vm);
		ucv_object_add(entry, "start", position_to_uv(vm, sp));
		ucv_object_add(entry, "end", position_to_uv(vm, ep));
		ucv_object_add(entry, "message", usp.errors.entries[i].message);

		ucv_array_push(errors, entry);
	}

	ucv_object_add(rv, "errors", errors);

	/* build scope array */
	uc_value_t *scopes = ucv_array_new_length(vm, usp.scopes.count);

	for (size_t i = 0; i < usp.scopes.count; i++) {
		scope_t *scope = &usp.scopes.entries[i];

		uscope_position_t *sp = &scope->start;
		uscope_position_t *ep = &scope->end;

		uc_value_t *so = ucv_object_new(vm);
		uc_value_t *vars = ucv_array_new_length(vm, scope->variables.count);

		ucv_object_add(so, "start", position_to_uv(vm, sp));
		ucv_object_add(so, "end", position_to_uv(vm, ep));
		ucv_object_add(so, "variables", vars);

		ucv_array_push(scopes, so);

		for (size_t j = 0; j < scope->variables.count; j++) {
			uc_value_t *var = scope->variables.entries[j];
			uscope_variable_t *varspec = ucv_resource_data(var, "uscope.variable");

			uc_value_t *vo = ucv_object_new(vm);
			uc_value_t *refs = ucv_array_new_length(vm, varspec->references.count);

			for (size_t k = 0; k < varspec->references.count; k++) {
				uscope_reference_t *ref = &varspec->references.entries[k];
				uscope_position_t *loc = &ref->location;

				uc_value_t *ro = ucv_object_new(vm);

				ucv_object_add(ro, "location", position_to_uv(vm, loc));
				ucv_object_add(ro, "token", ucv_get(ucv_array_get(tokens, ref->token_id)));
				ucv_object_add(ro, "access", ucv_string_new(access_kind_names[ref->access_kind]));
				ucv_object_add(ro, "value", ucv_get(ref->value));

				ucv_array_push(refs, ro);
			}

			uc_value_t *range = ucv_object_new(vm);
			ucv_object_add(range, "start", position_to_uv(vm, &varspec->range.start));
			ucv_object_add(range, "end", position_to_uv(vm, &varspec->range.end));

			uc_value_t tuv = { .type = varspec->type };
			ucv_object_add(vo, "name", ucv_get(varspec->name));
			ucv_object_add(vo, "variable", ucv_get(var));

			if (varspec->base)
				ucv_object_add(vo, "base",
					ucv_get(lookup_var_spec(scopes, varspec->base)));

			ucv_object_add(vo, "value", ucv_get(varspec->value));
			ucv_object_add(vo, "jsdoc", jsdoc_to_uv(vm, varspec->jsdoc));
			ucv_object_add(vo, "type", ucv_string_new(ucv_typename(&tuv)));
			ucv_object_add(vo, "initialized", ucv_boolean_new(varspec->initialized));
			ucv_object_add(vo, "constant", ucv_boolean_new(varspec->constant));
			ucv_object_add(vo, "export", ucv_boolean_new(varspec->export));
			ucv_object_add(vo, "property", ucv_boolean_new(varspec->property));
			ucv_object_add(vo, "references", refs);
			ucv_object_add(vo, "range", range);

			ucv_array_push(vars, vo);
			ucv_put(var);
		}

		uc_vector_clear(&scope->variables);
	}

	ucv_object_add(rv, "scopes", scopes);

	uc_value_t *imports = ucv_array_new_length(vm, usp.imports.count);

	uc_vector_foreach(&usp.imports, import) {
		uc_value_t *io = ucv_object_new(vm);

		ucv_object_add(io, "default", ucv_boolean_new(import->is_default));
		ucv_object_add(io, "wildcard", ucv_boolean_new(import->is_wildcard));
		ucv_object_add(io, "name", import->name);
		ucv_object_add(io, "alias", import->alias);
		ucv_object_add(io, "source", import->source);
		ucv_object_add(io, "value", import->value);

		ucv_array_push(imports, io);
	}

	ucv_object_add(rv, "imports", imports);

	uc_value_t *exports = ucv_array_new_length(vm, usp.exports.count);

	uc_vector_foreach(&usp.exports, export) {
		uc_value_t *eo = ucv_object_new(vm);

		ucv_object_add(eo, "default", ucv_boolean_new(export->is_default));
		ucv_object_add(eo, "name", export->name);
		ucv_object_add(eo, "alias", export->alias);
		ucv_object_add(eo, "value", export->value);

		ucv_array_push(exports, eo);
	}

	ucv_object_add(rv, "exports", exports);

	uc_vector_clear(&usp.errors);
	uc_vector_clear(&usp.tokens);
	uc_vector_clear(&usp.scopes);
	uc_vector_clear(&usp.imports);
	uc_vector_clear(&usp.exports);
	uc_vector_clear(&usp.scopechain);
	uc_vector_clear(&usp.thischain);
	uc_vector_clear(&usp.function_jsdocs);
	uc_vector_clear(&usp.declaration_jsdocs);

	return rv;
}

static const uc_function_list_t uscope_fns[] = {
	{ "analyze", uc_analyze },
};


static uc_value_t *
uc_var_tostring(uc_vm_t *vm, size_t nargs)
{
	uscope_variable_t *var = uc_fn_thisval("uscope.variable");
	uscope_position_t *pos = &var->references.entries[0].location;
	uc_stringbuf_t *sbuf = ucv_stringbuf_new();

	if (var->property) {
		ucv_stringbuf_printf(sbuf, "<%sproperty reference ",
			var->initialized ? "" : "uninitialized ");

		ucv_stringbuf_append(sbuf, "<");
		ucv_to_stringbuf(vm, sbuf, var->name, false);
		ucv_stringbuf_printf(sbuf, "> @ %zu:%zu>",
			pos ? pos->line : 0, pos ? pos->column : 0);
	}
	else {
		ucv_stringbuf_printf(sbuf, "<%s%s %s '%s' @ %zu:%zu>",
			var->initialized ? "" : "uninitialized ",
			var->constant ? "const" : "local",
			var->export ? "export" : "variable",
			ucv_string_get(var->name),
			pos ? pos->line : 0, pos ? pos->column : 0);
	}

	return ucv_stringbuf_finish(sbuf);
}

static void
close_var(void *ud)
{
	uscope_variable_t *var = ud;

	while (var->references.count > 0)
		ucv_put(var->references.entries[--var->references.count].value);

	uc_vector_clear(&var->references);

	ucv_put(var->base);
	ucv_put(var->name);
	ucv_put(var->value);

	jsdoc_free(var->jsdoc);

	free(var);
}

static const uc_function_list_t var_fns[] = {
	{ "tostring", uc_var_tostring }
};


static uc_value_t *
uc_und_tostring(uc_vm_t *vm, size_t nargs)
{
	undef_t *undef = uc_fn_thisval("uscope.undefined");
	uc_stringbuf_t *sbuf = ucv_stringbuf_new();

	ucv_stringbuf_printf(sbuf, "<indeterminate @ %zu:%zu>",
		undef->location.line, undef->location.column);

	return ucv_stringbuf_finish(sbuf);
}

static const uc_function_list_t und_fns[] = {
	{ "tostring", uc_und_tostring }
};

static void
close_undef(void *ud)
{
	undef_t *undef = ud;

	jsdoc_free(undef->jsdoc);

	free(undef);
}


void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, uscope_fns);

	uc_type_declare(vm, "uscope.variable", var_fns, close_var);
	uc_type_declare(vm, "uscope.undefined", und_fns, close_undef);

	uc_value_t *tt =
		ucv_array_new_length(vm, ARRAY_SIZE(semantic_token_type_names));

	for (size_t i = 0; i < ARRAY_SIZE(semantic_token_type_names); i++)
		ucv_array_push(tt, ucv_string_new(semantic_token_type_names[i]));

	ucv_object_add(scope, "TOKEN_TYPES", tt);

	uc_value_t *tm =
		ucv_array_new_length(vm, ARRAY_SIZE(semantic_token_modifier_names));

	for (size_t i = 0; i < ARRAY_SIZE(semantic_token_modifier_names); i++)
		ucv_array_push(tm, ucv_string_new(semantic_token_modifier_names[i]));

	ucv_object_add(scope, "TOKEN_MODIFIERS", tm);
}
