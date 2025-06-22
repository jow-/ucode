#include <stdbool.h>
#include <stddef.h>
#include <ctype.h>
#include <string.h>

#include <json-c/json_tokener.h>

#include <ucode/util.h>
#include <ucode/types.h>

#include "jsdoc.h"
#include "uscope.h"


typedef enum {
	T_ERROR,
	T_EOF,
	T_IDENT,
	T_STRING,
	T_ARROW,
	T_ELLIP,
	T_COLON    = ':',
	T_ANGLE_L  = '<',
	T_ANGLE_R  = '>',
	T_COMMA    = ',',
	T_BRACE_L  = '{',
	T_BRACE_R  = '}',
	T_BRACK_L  = '[',
	T_BRACK_R  = ']',
	T_PAREN_L  = '(',
	T_PAREN_R  = ')',
	T_ASTERISK = '*',
	T_DOT      = '.',
	T_QMARK    = '?',
	T_EMARK    = '!',
	T_ALT      = '|',
} jsdoc_token_type_t;

typedef struct {
	jsdoc_token_type_t type;
	struct {
		size_t count;
		char *entries;
	} value;
} jsdoc_token_t;

typedef struct {
	char *input;
	size_t length;
	jsdoc_token_t prev;
	jsdoc_token_t curr;
	struct {
		size_t count;
		jsdoc_token_t *entries;
	} lookahead;
} jsdoc_parser_t;

typedef enum {
	TAG_NONE,
	TAG_UNKNOWN,

	TAG_CLASS,
	TAG_CONSTANT,
	TAG_CONSTRUCTS,
	TAG_ENUM,
	TAG_EVENT,
	TAG_EXTERNAL,
	TAG_FILE,
	TAG_FUNCTION,
	TAG_INTERFACE,
	TAG_KIND,
	TAG_MEMBER,
	TAG_MEMBEROF,
	TAG_MIXIN,
	TAG_MODULE,
	TAG_NAME,
	TAG_NAMESPACE,
	TAG_TYPE,
	TAG_TYPEDEF,
	TAG_RETURNS,
	TAG_PARAM,
	TAG_PROPERTY,
	TAG_THROWS,
	TAG_DEFAULT,
	TAG_DESCRIPTION,
	TAG_FIRES,
	TAG_YIELDS,
	TAG_ELEMENT,
} jsdoc_tag_type_t;

static const struct {
	const char *name;
	jsdoc_tag_type_t type;
} tag_types[] = {
	{ "class",			TAG_CLASS },
	{ "constant",		TAG_CONSTANT },
	{ "constructs",		TAG_CONSTRUCTS },
	{ "enum",			TAG_ENUM },
	{ "event",			TAG_EVENT },
	{ "external",		TAG_EXTERNAL },
	{ "file",			TAG_FILE },
	{ "function",		TAG_FUNCTION },
	{ "interface",		TAG_INTERFACE },
	{ "kind",			TAG_KIND },
	{ "member",			TAG_MEMBER },
	{ "memberof",		TAG_MEMBEROF },
	{ "mixin",			TAG_MIXIN },
	{ "module",			TAG_MODULE },
	{ "name",			TAG_NAME },
	{ "namespace",		TAG_NAMESPACE },
	{ "type",			TAG_TYPE },
	{ "typedef",		TAG_TYPEDEF },
	{ "returns",		TAG_RETURNS },
	{ "param",			TAG_PARAM },
	{ "property",		TAG_PROPERTY },
	{ "throws",			TAG_THROWS },
	{ "element",		TAG_ELEMENT },

	{ "constructor",	TAG_CLASS },
	{ "const",			TAG_CONSTANT },
	{ "prop",			TAG_PROPERTY },
	{ "var",			TAG_MEMBER },
	{ "defaultvalue",	TAG_DEFAULT },
	{ "desc",			TAG_DESCRIPTION },
	{ "fileoverview",	TAG_FILE },
	{ "overview",		TAG_FILE },
	{ "emits",			TAG_FIRES },
	{ "func",			TAG_FUNCTION },
	{ "method",			TAG_FUNCTION },
	{ "arg",			TAG_PARAM },
	{ "argument",		TAG_PARAM },
	{ "return",			TAG_RETURNS },
	{ "exception",		TAG_THROWS },
	{ "yield",			TAG_YIELDS },
	{ "elem",			TAG_ELEMENT },
};

typedef struct {
	jsdoc_tag_type_t type;
	uc_stringbuf_t value;
} jsdoc_tag_t;

static jsdoc_token_t tok = { 0 };

static jsdoc_token_t *
parse_token(char **ptr, size_t *len)
{
	tok.type = 0;
	tok.value.count = 0;
	tok.value.entries = NULL;

	while (*len > 0 && isspace(**ptr))
		(*ptr)++, (*len)--;

	if (*len == 0) {
		tok.type = T_EOF;
	}
	else if (**ptr == '"' || **ptr == '\'') {
		char quot = **ptr;
		bool esc = false;

		tok.type = T_STRING;

		for ((*ptr)++, (*len)--; *len > 0; (*ptr)++, (*len)--) {
			if (esc) {
				switch (**ptr) {
				case 'n': uc_vector_push(&tok.value, '\n'); break;
				case 'r': uc_vector_push(&tok.value, '\r'); break;
				case 't': uc_vector_push(&tok.value, '\t'); break;
				default: uc_vector_push(&tok.value, **ptr); break;
				}

				esc = false;
			}
			else if (**ptr == '\\') {
				esc = true;
			}
			else if (**ptr == quot) {
				break;
			}
			else {
				uc_vector_push(&tok.value, **ptr);
			}
		}

		if (*len == 0) {
			uc_vector_clear(&tok.value);
			tok.type = T_ERROR;
		}

		(*ptr)++, (*len)--;
	}
	else if (isalpha(**ptr) || **ptr == '_') {
		tok.type = T_IDENT;

		while (*len > 0 && (isalnum(**ptr) || **ptr == '_')) {
			uc_vector_push(&tok.value, **ptr);
			(*ptr)++, (*len)--;

			if (*len > 0 && **ptr == ':' && tok.value.count == 6 &&
			    !strncmp(tok.value.entries, "module", 6)) {
				uc_vector_push(&tok.value, ':');
				(*ptr)++, (*len)--;
			}
		}
	}
	else if (*len >= 3 && !strncmp(*ptr, "...", 3)) {
		tok.type = T_ELLIP;
		*ptr += 3; *len -= 3;
	}
	else if (*len >= 2 && !strncmp(*ptr, "=>", 2)) {
		tok.type = T_ARROW;
		*ptr += 2, *len -= 2;
	}
	else if (strchr("<>{}[]().,:*?!|", **ptr)) {
		tok.type = **ptr;
		(*ptr)++, (*len)--;
	}
	else {
		tok.type = T_ERROR;
	}

	return &tok;
}

static jsdoc_token_type_t
skip_token(char **ptr, size_t *len)
{
	jsdoc_token_t *tok = parse_token(ptr, len);

	uc_vector_clear(&tok->value);

	return tok->type;
}

static const struct {
	const char *name;
	jsdoc_type_t type;
} typemap[] = {
	{ "string",		TYPE_STRING },
	{ "integer",	TYPE_INTEGER },
	{ "int",		TYPE_INTEGER },
	{ "number",		TYPE_NUMBER },
	{ "double",		TYPE_DOUBLE },
	{ "float",		TYPE_DOUBLE },
	{ "boolean",	TYPE_BOOLEAN },
	{ "bool",		TYPE_BOOLEAN },
	{ "Array",		TYPE_ARRAY },
	{ "array",		TYPE_ARRAY },
	{ "Object",		TYPE_OBJECT },
	{ "object",		TYPE_OBJECT },
	{ "function",	TYPE_FUNCTION },
	{ "any",		TYPE_ANY },
};

static const struct {
	const char *name;
	jsdoc_kind_t kind;
} kindmap[] = {
	{ "class",		KIND_CLASS },
	{ "constant",	KIND_CONSTANT },
	{ "event",		KIND_EVENT },
	{ "external",	KIND_EXTERNAL },
	{ "file",		KIND_FILE },
	{ "function",	KIND_FUNCTION },
	{ "member",		KIND_MEMBER },
	{ "mixin",		KIND_MIXIN },
	{ "module",		KIND_MODULE },
	{ "namespace",	KIND_NAMESPACE },
	{ "typedef",	KIND_TYPEDEF },
};

static void
ucv_replace(uc_value_t **dest, uc_value_t *src)
{
	ucv_put(*dest);
	*dest = src;
}

static void
ucv_update(uc_value_t **dest, uc_value_t *src)
{
	if (src) {
		ucv_put(*dest);
		*dest = ucv_get(src);
	}
}

static void
ucv_clear(uc_value_t **uv)
{
	ucv_put(*uv);
	*uv = NULL;
}

static void
parse_advance(jsdoc_parser_t *p)
{
	p->prev = p->curr;

	if (p->lookahead.count > 0) {
		for (size_t i = 0; i < p->lookahead.count; i++) {
			if (i == 0)
				p->curr = p->lookahead.entries[i];
			else
				p->lookahead.entries[i - 1] = p->lookahead.entries[i];
		}

		p->lookahead.count--;
	}
	else {
		p->curr = *parse_token(&p->input, &p->length);
	}
}

static bool
parse_consume(jsdoc_parser_t *p, jsdoc_token_type_t type)
{
	if (p->curr.type != type)
		return false;

	parse_advance(p);

	return true;
}

static bool
parse_capture(jsdoc_parser_t *p, jsdoc_token_type_t type, uc_value_t **dest)
{
	if (p->curr.type != type)
		return false;

	ucv_replace(dest,
		ucv_string_new_length(p->curr.value.entries, p->curr.value.count));

	uc_vector_clear(&p->curr.value);
	parse_advance(p);

	return true;
}

static jsdoc_token_type_t
parse_peek(jsdoc_parser_t *p, size_t depth)
{
	while (p->lookahead.count <= depth) {
		jsdoc_token_t *tok = parse_token(&p->input, &p->length);
		uc_vector_push(&p->lookahead, *tok);
	}

	return p->lookahead.entries[depth].type;
}

static jsdoc_typedef_t *
parse_single_type(jsdoc_parser_t *p);

static jsdoc_typedef_t *
parse_union_type(jsdoc_parser_t *p)
{
	jsdoc_typedef_t *spec = NULL, *alt, *tmp;
	size_t alt_count = 0;

	while ((alt = parse_single_type(p)) != NULL) {
		if (alt_count == 0) {
			spec = alt;
		}
		else if (alt_count == 1) {
			tmp = xalloc(sizeof(*tmp));
			tmp->type = TYPE_UNION;

			uc_vector_push(&tmp->details.alternatives, spec);
			uc_vector_push(&tmp->details.alternatives, alt);

			spec = tmp;
		}
		else {
			uc_vector_push(&spec->details.alternatives, alt);
		}

		if (!parse_consume(p, '|'))
			break;

		alt_count++;
	}

	return spec;
}

static jsdoc_type_t
jsdoc_type_lookup(uc_value_t *name)
{
	char *s = ucv_string_get(name);

	for (size_t i = 0; i < ARRAY_SIZE(typemap); i++)
		if (!strcmp(typemap[i].name, s))
			return typemap[i].type;

	return TYPE_UNSPEC;
}

static bool
jsdoc_type_imply(jsdoc_typedef_t **specp, jsdoc_type_t type)
{
	if (!*specp) {
		*specp = xalloc(sizeof(**specp));
		(*specp)->type = type;

		return true;
	}

	return ((*specp)->type == type);
}

static uc_value_t *
parse_dotted_name(jsdoc_parser_t *p, uc_value_t *label)
{
	if (p->curr.type != '.')
		return label;

	uc_stringbuf_t *sbuf = ucv_stringbuf_new();

	printbuf_memappend_fast(sbuf,
		ucv_string_get(label),
		(int)ucv_string_length(label));

	ucv_clear(&label);

	while (p->curr.type == '.' && parse_peek(p, 0) == T_IDENT) {
		parse_consume(p, '.');
		parse_capture(p, T_IDENT, &label);

		printbuf_strappend(sbuf, ".");

		printbuf_memappend_fast(sbuf,
			ucv_string_get(label),
			(int)ucv_string_length(label));

		ucv_clear(&label);
	}

	return ucv_stringbuf_finish(sbuf);
}

static jsdoc_typedef_t *
parse_single_type(jsdoc_parser_t *p)
{
	if (p->curr.type == T_EOF)
		return NULL;

	jsdoc_typedef_t *spec = NULL;

	if (p->curr.type == '(') {
		struct { size_t count; jsdoc_token_type_t *entries; } parens = { 0 };
		size_t lookahead = 0;

		while (true) {
			jsdoc_token_type_t tt = parse_peek(p, lookahead++);

			switch (tt) {
			case '(': uc_vector_push(&parens, ')'); break;
			case '<': uc_vector_push(&parens, '>'); break;
			case '{': uc_vector_push(&parens, '}'); break;
			case '[': uc_vector_push(&parens, ']'); break;
			default: break;
			}

			if (parens.count == 0 && tt == ')')
				break;

			if (parens.count > 0 && tt == parens.entries[parens.count - 1])
				parens.count--;
		}

		uc_vector_clear(&parens);

		if (parse_peek(p, lookahead++) != T_ARROW) {
			parse_consume(p, '(');

			spec = parse_union_type(p);

			if (!parse_consume(p, ')'))
				goto inval;

			return spec;
		}

		jsdoc_type_imply(&spec, TYPE_FUNCTION);
	}
	else if (parse_consume(p, '{')) {
		jsdoc_type_imply(&spec, TYPE_OBJECT);

		jsdoc_property_t prop = { 0 };

		while (parse_capture(p, T_IDENT, &prop.name) || parse_capture(p, T_STRING, &prop.name)) {
			prop.optional = parse_consume(p, '?');

			if (parse_consume(p, ':'))
				prop.type = parse_union_type(p);
			else
				jsdoc_type_imply(&prop.type, TYPE_ANY);

			uc_vector_push(&spec->details.object.properties, prop);
			memset(&prop, 0, sizeof(prop));

			if (!parse_consume(p, ','))
				break;
		}

		if (!parse_consume(p, '}'))
			goto inval;

		return spec;
	}
	else if (parse_consume(p, '[')) {
		jsdoc_type_imply(&spec, TYPE_ARRAY);

		jsdoc_element_t elem = { 0 };

		while (p->curr.type != ']') {
			if ((p->curr.type == T_IDENT || p->curr.type == T_STRING) && parse_peek(p, ':')) {
				parse_capture(p, p->curr.type, &elem.name);
				parse_consume(p, ':');
			}

			elem.type = parse_union_type(p);

			if (!elem.type) {
				ucv_put(elem.name);
				goto inval;
			}

			uc_vector_push(&spec->details.array.elements, elem);
			memset(&elem, 0, sizeof(elem));

			if (!parse_consume(p, ','))
				break;
		}

		if (!parse_consume(p, ']'))
			goto inval;

		return spec;
	}
	else {
		uc_value_t *ident = NULL;

		spec = xalloc(sizeof(*spec));

		if (parse_consume(p, '?'))
			spec->nullable = true;
		else if (parse_consume(p, '!'))
			spec->required = true;

		if (parse_consume(p, '*') || parse_consume(p, '?')) {
			spec->type = TYPE_ANY;
		}
		else if (parse_capture(p, T_IDENT, &ident)) {
			ident = parse_dotted_name(p, ident);
			spec->type = jsdoc_type_lookup(ident);

			if (spec->type == TYPE_UNSPEC) {
				spec->type = TYPE_TYPENAME;
				ucv_replace(&spec->details.typename, ident);
			}
			else {
				ucv_put(ident);
			}
		}
		else {
			goto inval;
		}
	}

	if (spec->type == TYPE_OBJECT) {
		if ((parse_consume(p, '.') && parse_consume(p, '<')) || parse_consume(p, '<')) {
			spec->details.object.val_type = parse_single_type(p);

			if (parse_consume(p, ',')) {
				spec->details.object.key_type = spec->details.object.val_type;
				spec->details.object.val_type = parse_single_type(p);
			}

			if (!parse_consume(p, '>'))
				goto inval;
		}
	}
	else if (spec->type == TYPE_ARRAY) {
		if ((parse_consume(p, '.') && parse_consume(p, '<')) || parse_consume(p, '>')) {
			spec->details.array.item_type = parse_single_type(p);

			if (!parse_consume(p, '>'))
				goto inval;
		}
	}
	else if (spec->type == TYPE_FUNCTION) {
		/* parse arglist */
		if (parse_consume(p, '(')) {
			while (p->curr.type != ')') {
				jsdoc_param_t param = { 0 };

				param.restarg = parse_consume(p, T_ELLIP);

				if (parse_peek(p, 0) == ':') {
					if (!parse_capture(p, T_IDENT, &param.name))
						goto inval;

					parse_consume(p, ':');
				}

				param.type = parse_union_type(p);

				if (param.type) {
					uc_vector_push(&spec->details.function.params, param);
				}
				else {
					free(param.name);
					goto inval;
				}

				if (!parse_consume(p, ','))
					break;
			}

			if (!parse_consume(p, ')'))
				goto inval;
		}

		if (parse_consume(p, ':') || parse_consume(p, T_ARROW)) {
			spec->details.function.return_type = parse_union_type(p);

			if (!spec->details.function.return_type)
				goto inval;
		}
		else {
			jsdoc_type_imply(&spec->details.function.return_type, TYPE_ANY);
		}
	}

	if (parse_consume(p, '[')) {
		if (!parse_consume(p, ']'))
			goto inval;

		jsdoc_typedef_t *arr = xalloc(sizeof(*arr));

		arr->type = TYPE_ARRAY;
		arr->details.array.item_type = spec;

		return arr;
	}

	return spec;

inval:
	jsdoc_typedef_free(spec);

	return NULL;
}

static bool
type_equal(const jsdoc_typedef_t *a, const jsdoc_typedef_t *b)
{
	if (!a || !b)
		return false;

	if (a->type != b->type)
		return false;

	if (a->type == TYPE_TYPENAME) {
		if (!a->details.typename || !b->details.typename)
			return false;

		return ucv_is_equal(a->details.typename, b->details.typename);
	}

	return true;
}

static int
cmp_typedef(const void *a, const void *b)
{
	const jsdoc_typedef_t * const *t1 = a;
	const jsdoc_typedef_t * const *t2 = b;

	return (int)(*t1)->type - (int)(*t2)->type;
}

static jsdoc_typedef_t *
union_typedef_upsert(jsdoc_typedef_t *dst, const jsdoc_typedef_t *src,
                  unsigned int flags)
{
	uc_vector_foreach(&dst->details.alternatives, dst_alt) {
		if (type_equal(src, *dst_alt)) {
			jsdoc_typedef_merge(dst_alt, src, flags);

			return *dst_alt;
		}
	}

	uc_vector_push(&dst->details.alternatives, NULL);

	jsdoc_typedef_t **dst_alt = uc_vector_last(&dst->details.alternatives);

	jsdoc_typedef_merge(dst_alt, src, flags);

	return *dst_alt;
}

static void
union_typedef_sort(jsdoc_typedef_t *dst)
{
	qsort(dst->details.alternatives.entries,
		dst->details.alternatives.count,
		sizeof(dst->details.alternatives.entries[0]),
		cmp_typedef);
}

bool
jsdoc_typedef_merge(jsdoc_typedef_t **dest, const jsdoc_typedef_t *src,
                    unsigned int flags)
{
	if (!src)
		return false;

	jsdoc_type_imply(dest, TYPE_ANY);

	if ((*dest)->type == TYPE_UNION && src->type != TYPE_UNION) {
		union_typedef_upsert(*dest, src, flags);
		union_typedef_sort(*dest);

		return true;
	}

	if ((*dest)->type != TYPE_UNSPEC && (*dest)->type != TYPE_ANY && !type_equal(src, *dest)) {
		if (!(flags & MERGE_UNION) && (*dest)->type != TYPE_UNION)
			return false;

		jsdoc_typedef_t *u = NULL;

		jsdoc_type_imply(&u, TYPE_UNION);

		uc_vector_push(&u->details.alternatives, *dest);

		union_typedef_upsert(u, src, flags & ~MERGE_UNION);
		union_typedef_sort(u);

		*dest = u;

		return true;
	}

	(*dest)->type = src->type;
	(*dest)->nullable |= src->nullable;
	(*dest)->required |= src->required;

	if (!(flags & MERGE_TYPEONLY))
		ucv_update(&(*dest)->value, src->value);

	switch (src->type) {
	case TYPE_FUNCTION:
		jsdoc_typedef_merge(
			&(*dest)->details.function.return_type,
			src->details.function.return_type, flags);

		ucv_update(
			&(*dest)->details.function.return_description,
			src->details.function.return_description);

		for (size_t i = 0; i < src->details.function.params.count; i++) {
			jsdoc_param_t *src_param = uscope_vector_get(&src->details.function.params, i);
			jsdoc_param_t *dst_param = uscope_vector_get(&(*dest)->details.function.params, i);

			if (!dst_param)
				dst_param = uc_vector_push(&(*dest)->details.function.params, { 0 });

			ucv_update(&dst_param->name, src_param->name);
			ucv_update(&dst_param->defval, src_param->defval);
			ucv_update(&dst_param->description, src_param->description);

			dst_param->optional |= src_param->optional;
			dst_param->restarg |= src_param->restarg;

			jsdoc_typedef_merge(&dst_param->type, src_param->type, flags);
		}

		uc_vector_foreach(&src->details.function.throws, src_throw) {
			jsdoc_throws_t *cpy_throw = NULL;

			uc_vector_foreach(&(*dest)->details.function.throws, dst_throw) {
				if (type_equal(dst_throw->type, src_throw->type)) {
					cpy_throw = src_throw;
					break;
				}
			}

			if (!cpy_throw)
				cpy_throw = uc_vector_push(&(*dest)->details.function.throws, { 0 });

			ucv_update(&cpy_throw->description, src_throw->description);

			jsdoc_typedef_merge(&cpy_throw->type, src_throw->type, flags);
		}

		break;

	case TYPE_OBJECT:
		uc_vector_foreach(&src->details.object.properties, src_prop) {
			if (flags & MERGE_NOELEMS)
				continue;

			jsdoc_property_t *cpy_prop = NULL;

			uc_vector_foreach(&(*dest)->details.object.properties, dst_prop) {
				if (!src_prop->name || !dst_prop->name)
					continue;

				if (!ucv_is_equal(src_prop->name, dst_prop->name))
					continue;

				cpy_prop = dst_prop;
				break;
			}

			if (!cpy_prop)
				cpy_prop = uc_vector_push(&(*dest)->details.object.properties, { 0 });

			ucv_update(&cpy_prop->name, src_prop->name);
			ucv_update(&cpy_prop->defval, src_prop->defval);
			ucv_update(&cpy_prop->description, src_prop->description);

			cpy_prop->optional |= src_prop->optional;

			jsdoc_typedef_merge(&cpy_prop->type, src_prop->type, flags);
		}

		jsdoc_typedef_merge(
			&(*dest)->details.object.key_type,
			src->details.object.key_type, flags);

		jsdoc_typedef_merge(
			&(*dest)->details.object.val_type,
			src->details.object.val_type, flags);

		break;

	case TYPE_ARRAY:
		jsdoc_typedef_merge(
			&(*dest)->details.array.item_type,
			src->details.array.item_type, flags);

		for (size_t i = 0; i < src->details.array.elements.count; i++) {
			if (flags & MERGE_NOELEMS)
				continue;

			jsdoc_element_t *src_elem, *dst_elem;

			src_elem = uscope_vector_get(&src->details.array.elements, i);
			dst_elem = (i >= (*dest)->details.array.elements.count)
				? uc_vector_push(&(*dest)->details.array.elements, { 0 })
				: uscope_vector_get(&(*dest)->details.array.elements, i);

			ucv_update(&dst_elem->name, src_elem->name);
			ucv_update(&dst_elem->description, src_elem->description);

			jsdoc_typedef_merge(&dst_elem->type, src_elem->type, flags);
		}

		break;

	case TYPE_UNION:
		uc_vector_foreach(&src->details.alternatives, src_alt)
			union_typedef_upsert(*dest, *src_alt, flags);

		union_typedef_sort(*dest);
		break;

	case TYPE_TYPENAME:
		ucv_update(&(*dest)->details.typename, src->details.typename);
		break;

	default:
		break;
	}

	return true;
}

void
jsdoc_typedef_free(jsdoc_typedef_t *spec)
{
	if (!spec)
		return;

	switch (spec->type) {
	case TYPE_OBJECT:
		jsdoc_typedef_free(spec->details.object.key_type);
		jsdoc_typedef_free(spec->details.object.val_type);

		while (spec->details.object.properties.count > 0) {
			jsdoc_property_t *prop = uc_vector_last(&spec->details.object.properties);

			jsdoc_typedef_free(prop->type);
			ucv_put(prop->name);
			ucv_put(prop->defval);
			ucv_put(prop->description);

			spec->details.object.properties.count--;
		}

		uc_vector_clear(&spec->details.object.properties);
		break;

	case TYPE_ARRAY:
		jsdoc_typedef_free(spec->details.array.item_type);

		while (spec->details.array.elements.count > 0) {
			jsdoc_element_t *elem = uc_vector_last(&spec->details.array.elements);

			jsdoc_typedef_free(elem->type);
			ucv_put(elem->name);
			ucv_put(elem->description);

			spec->details.array.elements.count--;
		}

		uc_vector_clear(&spec->details.array.elements);
		break;

	case TYPE_FUNCTION:
		while (spec->details.function.params.count > 0) {
			jsdoc_param_t *param = uc_vector_last(&spec->details.function.params);

			jsdoc_typedef_free(param->type);
			ucv_put(param->name);
			ucv_put(param->defval);
			ucv_put(param->description);

			spec->details.function.params.count--;
		}

		jsdoc_typedef_free(spec->details.function.return_type);
		ucv_put(spec->details.function.return_description);

		uc_vector_clear(&spec->details.function.params);
		break;

	case TYPE_UNION:
		while (spec->details.alternatives.count > 0)
			jsdoc_typedef_free(spec->details.alternatives.entries[--spec->details.alternatives.count]);

		uc_vector_clear(&spec->details.alternatives);
		break;

	case TYPE_TYPENAME:
		ucv_put(spec->details.typename);
		break;

	default:
		break;
	}

	ucv_put(spec->value);
	free(spec);
}

void
jsdoc_reset(jsdoc_t *js)
{
	js->kind = KIND_UNSPEC;
	js->constant = false;

	ucv_clear(&js->name);
	ucv_clear(&js->defval);
	ucv_clear(&js->subject);
	ucv_clear(&js->description);

	jsdoc_typedef_free(js->type);
	js->type = NULL;
}

void
jsdoc_free(jsdoc_t *js)
{
	if (js) {
		jsdoc_reset(js);
		free(js);
	}
}

static void
parse_init(jsdoc_parser_t *p, char *input, size_t length)
{
	memset(p, 0, sizeof(*p));

	p->input = input;
	p->length = length;

	parse_advance(p);
}

static void
parse_free(jsdoc_parser_t *p)
{
	while (p->lookahead.count > 0) {
		uc_vector_clear(&p->lookahead.entries[p->lookahead.count - 1].value);
		p->lookahead.count--;
	}

	uc_vector_clear(&p->curr.value);
	uc_vector_clear(&p->prev.value);
	uc_vector_clear(&p->lookahead);
}

static bool
skip_char(char **s, size_t *len, char c)
{
	while (*len > 0 && isspace(**s))
		(*s)++, (*len)--;

	if (*len == 0 || **s != c)
		return false;

	(*s)++, (*len)--;

	return true;
}

static size_t
json_parse(json_tokener *jstok, const char *s, size_t len, json_object **res)
{
	enum json_tokener_error err = json_tokener_get_error(jstok);

	if (err != json_tokener_success && err != json_tokener_continue)
		return 0;

	json_object *jso = json_tokener_parse_ex(jstok, s, len);

	if (jso) {
		json_object_put(*res);
		*res = jso;
	}

	return json_tokener_get_parse_end(jstok);
}

static bool
parse_value(uc_vm_t *vm, char **input, size_t *len, uc_value_t **res)
{
	if (skip_char(input, len, '{')) {
		uc_value_t *uv = ucv_object_new(vm);

		while (*len > 0 && !skip_char(input, len, '}')) {
			uc_value_t *key = NULL, *val = NULL;

			if (!parse_value(vm, input, len, &key) ||
			    !skip_char(input, len, ':') || ucv_type(key) != UC_STRING ||
			    !parse_value(vm, input, len, &val)) {

				ucv_put(key);
				ucv_put(val);
				ucv_put(uv);

				return false;
			}

			ucv_object_add(uv, ucv_string_get(key), val);
			ucv_put(key);

			if (!skip_char(input, len, ','))
				break;
		}

		if ((*input)[-1] != '}') {
			ucv_put(uv);

			return false;
		}

		*res = uv;

		return true;
	}
	else if (skip_char(input, len, '[')) {
		uc_value_t *uv = ucv_array_new(vm);

		while (*len > 0 && !skip_char(input, len, ']')) {
			uc_value_t *elem = NULL;

			if (!parse_value(vm, input, len, &elem)) {
				ucv_put(elem);
				ucv_put(uv);

				return false;
			}

			if (!skip_char(input, len, ','))
				break;
		}

		if ((*input)[-1] != ']') {
			ucv_put(uv);

			return false;
		}

		*res = uv;

		return true;
	}

	skip_char(input, len, 0);

	json_tokener *jstok = json_tokener_new();
	char c = *len ? **input : '\0';
	json_object *jso = NULL;
	size_t consumed = 0;

	if (c == '\'') {
		bool esc = false;
		char *s = *input + 1;
		size_t l = *len - 1;

		json_parse(jstok, "\"", 1, &jso);

		for (; l > 0; s++, l--) {
			if (esc)
				esc = false;
			else if (*s == '\\')
				esc = true;
			else if (*s == '\'')
				break;
		}

		if (!esc && l > 0 && *s == '\'') {
			consumed = json_parse(jstok, *input, s - *input, &jso) + 1;
			json_parse(jstok, "\"", 1, &jso);
		}
	}
	else if (isalpha(c) || c == '_') {
		char *s = *input;
		size_t l = *len;

		for (; l > 0 && isalnum(*s); s++, l--)
			;

		json_parse(jstok, "\"", 1, &jso);
		consumed = json_parse(jstok, *input, s - *input, &jso);
		json_parse(jstok, "\"", 1, &jso);
	}
	else {
		consumed = json_parse(jstok, *input, *len, &jso);
	}

	*input += consumed;
	*len -= consumed;

	if (json_tokener_get_error(jstok) != json_tokener_success) {
		json_tokener_free(jstok);
		json_object_put(jso);

		*res = NULL;

		return false;
	}

	*res = ucv_from_json(vm, jso);

	json_tokener_free(jstok);
	json_object_put(jso);

	return true;
}

static jsdoc_tag_type_t
find_tag(const char **line, const char *end, char kind)
{
	for (; *line < end && isspace(**line); (*line)++);

	if (kind == '*') {
		if (*line < end && **line == '*') {
			(*line)++;

			if (*line < end && **line == ' ')
				(*line)++;
		}

		const char *lp = *line;

		for (; lp < end && isspace(*lp); lp++);

		if (lp < end && *lp == '@') {
			for (const char *s = ++lp, *p = s; p <= end; p++) {
				if (p == end || isspace(*p)) {
					for (*line = p; *line < end && isspace(**line); (*line)++);

					for (size_t i = 0, taglen = p - s; i < ARRAY_SIZE(tag_types); i++)
						if (strlen(tag_types[i].name) == taglen &&
						    strncmp(tag_types[i].name, s, taglen) == 0)
							return tag_types[i].type;

					return TAG_UNKNOWN;
				}
			}
		}
	}
	else if (kind == '/') {
		if (*line + 1 < end && !strncmp(*line, "//", 2)) {
			*line += 2;

			if (*line < end && **line == ' ')
				(*line)++;
		}
	}

	return TAG_NONE;
}

static bool
parse_tag_type_name(jsdoc_t *js, jsdoc_tag_t *tag)
{
	uc_value_t *ident = NULL;
	jsdoc_typedef_t *tspec;
	jsdoc_parser_t p;

	parse_init(&p, tag->value.buf, tag->value.bpos);

	if (parse_consume(&p, '{')) {
		tspec = parse_union_type(&p);

		if (!tspec || !parse_consume(&p, '}')) {
			jsdoc_typedef_free(tspec);
			parse_free(&p);

			return false;
		}

		jsdoc_typedef_merge(&js->type, tspec, 0);
		jsdoc_typedef_free(tspec);
	}

	if (parse_capture(&p, T_IDENT, &ident))
		ucv_replace(&js->name, parse_dotted_name(&p, ident));

	parse_free(&p);

	return true;
}

static bool
parse_tag_type_description(jsdoc_tag_t *tag, jsdoc_typedef_t **typep, uc_value_t **descp)
{
	jsdoc_typedef_t *tspec;
	jsdoc_parser_t p;

	parse_init(&p, tag->value.buf, tag->value.bpos);

	if (parse_consume(&p, '{')) {
		tspec = parse_union_type(&p);

		if (!tspec || !parse_consume(&p, '}')) {
			jsdoc_typedef_free(tspec);
			parse_free(&p);

			return false;
		}

		jsdoc_typedef_merge(typep, tspec, 0);
		jsdoc_typedef_free(tspec);
	}

	if (p.length > 0 && *p.input == '-')
		for (p.input++, p.length--;
		     p.length > 0 && isspace(*p.input);
		     p.input++, p.length--);

	if (p.length > 0)
		*descp = ucv_string_new_length(p.input, p.length);

	parse_free(&p);

	return true;
}

static void
parse_tag_returns(jsdoc_t *js, jsdoc_tag_t *tag)
{
	jsdoc_typedef_t *spec = NULL;
	uc_value_t *description = NULL;

	if (!jsdoc_type_imply(&js->type, TYPE_FUNCTION))
		return;

	if (!parse_tag_type_description(tag, &spec, &description))
		return;

	if (spec) {
		jsdoc_typedef_merge(&js->type->details.function.return_type, spec, 0);
		jsdoc_typedef_free(spec);
	}
	else {
		jsdoc_type_imply(&js->type->details.function.return_type, TYPE_ANY);
	}

	if (description)
		ucv_replace(&js->type->details.function.return_description,
			description);
}

static void
parse_tag_throws(jsdoc_t *js, jsdoc_tag_t *tag, size_t index)
{
	jsdoc_throws_t throw = { 0 }, *tp;

	if (!jsdoc_type_imply(&js->type, TYPE_FUNCTION))
		return;

	if (!parse_tag_type_description(tag, &throw.type, &throw.description))
		return;

	if (js->type->details.function.throws.count <= index) {
		jsdoc_type_imply(&throw.type, TYPE_ANY);
		uc_vector_push(&js->type->details.function.throws, throw);
	}
	else {
		tp = &js->type->details.function.throws.entries[index];

		if (throw.type) {
			jsdoc_typedef_merge(&tp->type, throw.type, 0);
			jsdoc_typedef_free(throw.type);
		}
		else {
			jsdoc_type_imply(&tp->type, TYPE_ANY);
		}

		if (throw.description)
			ucv_replace(&tp->description, throw.description);
	}
}

static bool
parse_tag_type(jsdoc_typedef_t **typep, jsdoc_tag_t *tag)
{
	jsdoc_typedef_t *tspec;
	jsdoc_parser_t p;

	parse_init(&p, tag->value.buf, tag->value.bpos);

	if (parse_consume(&p, '{')) {
		tspec = parse_union_type(&p);

		if (!tspec || !parse_consume(&p, '}')) {
			jsdoc_typedef_free(tspec);
			parse_free(&p);

			return false;
		}

		jsdoc_typedef_merge(typep, tspec, 0);
		jsdoc_typedef_free(tspec);
	}

	parse_free(&p);

	return true;
}

static bool
skip_until(jsdoc_parser_t *p, jsdoc_token_type_t type)
{
	struct { size_t count; jsdoc_token_type_t *entries; } parens = { 0 };
	size_t old_length = p->length;
	char *old_pos = p->input;

	while (true) {
		jsdoc_token_type_t tt = skip_token(&p->input, &p->length);

		switch (tt) {
		case T_EOF:
			uc_vector_clear(&parens);
			p->length = old_length;
			p->input = old_pos;

			return false;

		case T_ERROR:
			p->length--;
			p->input++;

			break;

		case '(': uc_vector_push(&parens, ')'); break;
		case '[': uc_vector_push(&parens, ']'); break;
		case '{': uc_vector_push(&parens, '}'); break;
		case '<': uc_vector_push(&parens, '>'); break;

		case ')':
		case ']':
		case '}':
		case '>':
			if (parens.count > 0 && parens.entries[parens.count - 1] == tt)
				parens.count--;

			break;

		default:
			break;
		}

		if (tt == type && parens.count == 0)
			break;
	}

	uc_vector_clear(&parens);

	return true;
}

static void
parse_tag_param(jsdoc_t *js, jsdoc_tag_t *tag, size_t index)
{
	jsdoc_param_t param = { 0 };
	jsdoc_parser_t p = { 0 };

	if (!jsdoc_type_imply(&js->type, TYPE_FUNCTION))
		goto out;

	parse_init(&p, tag->value.buf, tag->value.bpos);

	if (!parse_consume(&p, '{'))
		goto out;

	if (parse_consume(&p, T_ELLIP)) {
		param.restarg = true;
		param.type = parse_single_type(&p);
	}
	else {
		param.type = parse_union_type(&p);
	}

	if (!param.type || !parse_consume(&p, '}'))
		goto out;

	if (parse_consume(&p, '[')) {
		param.optional = true;

		if (!parse_capture(&p, T_IDENT, &param.name))
			goto out;

		if (parse_consume(&p, '=')) {
			char *def = p.input;

			if (!skip_until(&p, ']'))
				goto out;

			for (p.input--, p.length++; isspace(*p.input); p.input--, p.length++);

			if (p.input > def) {
				size_t len = p.input - def;
				parse_value(NULL, &def, &len, &param.defval);
			}
		}

		if (!parse_consume(&p, ']'))
			goto out;
	}
	else if (!parse_capture(&p, T_IDENT, &param.name)) {
		goto out;
	}

	if (p.length > 0 && *p.input == '-')
		for (p.input++, p.length--;
		     p.length > 0 && isspace(*p.input);
		     p.input++, p.length--);

	if (p.length > 0)
		param.description = ucv_string_new_length(p.input, p.length);

	if (js->type->details.function.params.count <= index) {
		uc_vector_push(&js->type->details.function.params, param);
		memset(&param, 0, sizeof(param));
	}
	else {
		jsdoc_param_t *exist = &js->type->details.function.params.entries[index];

		ucv_update(&exist->name, param.name);
		ucv_update(&exist->defval, param.defval);
		ucv_update(&exist->description, param.description);

		jsdoc_typedef_free(exist->type);

		exist->type = param.type;
		exist->restarg |= param.restarg;
		exist->optional |= param.optional;

		param.type = NULL;
	}

out:
	ucv_put(param.name);
	ucv_put(param.defval);
	ucv_put(param.description);

	jsdoc_typedef_free(param.type);
	parse_free(&p);
}

static jsdoc_property_t *
upsert_property(jsdoc_typedef_t *obj, uc_value_t *name)
{
	if (!obj || obj->type != TYPE_OBJECT) {
		ucv_put(name);

		return NULL;
	}

	uc_vector_foreach(&obj->details.object.properties, prop) {
		if (ucv_is_equal(prop->name, name)) {
			ucv_put(name);

			return prop;
		}
	}

	return uc_vector_push(&obj->details.object.properties, { .name = name });
}

static jsdoc_property_t *
lookup_property_path(jsdoc_parser_t *p, jsdoc_typedef_t *obj)
{
	jsdoc_property_t *prop = NULL;
	uc_value_t *ident = NULL;

	if (!parse_capture(p, T_IDENT, &ident))
		return NULL;

	if ((prop = upsert_property(obj, ident)) == NULL)
		return NULL;

	obj = prop->type;

	while ((p->curr.type == '.' && parse_peek(p, 0) == T_IDENT) ||
	       (p->curr.type == '[' && parse_peek(p, 0) == ']'))
	{
		if (parse_consume(p, '.') && parse_capture(p, T_IDENT, &ident)) {
			if ((prop = upsert_property(obj, ident)) == NULL)
				return NULL;

			obj = prop->type;
		}
		else if (parse_consume(p, '[') && parse_consume(p, ']')) {
			if (obj->type != TYPE_ARRAY)
				return NULL;

			obj = obj->details.array.item_type;
			prop = NULL;
		}
	}

	return prop;
}

static void
parse_tag_property(jsdoc_t *js, jsdoc_tag_t *tag)
{
	uc_value_t *defval = NULL, *description = NULL;
	jsdoc_property_t *prop = NULL;
	jsdoc_typedef_t *ptype = NULL;
	jsdoc_parser_t p = { 0 };

	if (!jsdoc_type_imply(&js->type, TYPE_OBJECT))
		goto out;

	parse_init(&p, tag->value.buf, tag->value.bpos);

	if (!parse_consume(&p, '{'))
		goto out;

	ptype = parse_union_type(&p);

	if (!ptype || !parse_consume(&p, '}'))
		goto out;

	if (parse_consume(&p, '[')) {
		prop = lookup_property_path(&p, js->type);

		if (!prop)
			goto out;

		prop->optional = true;

		if (parse_consume(&p, '=')) {
			char *def = p.input;

			if (!skip_until(&p, ']'))
				goto out;

			for (p.input--, p.length++; isspace(*p.input); p.input--, p.length++);

			if (p.input > def) {
				size_t len = p.input - def;
				parse_value(NULL, &def, &len, &defval);
			}
		}

		if (!parse_consume(&p, ']'))
			goto out;
	}
	else {
		prop = lookup_property_path(&p, js->type);

		if (!prop)
			goto out;
	}

	if (p.length > 0 && *p.input == '-')
		for (p.input++, p.length--;
		     p.length > 0 && isspace(*p.input);
		     p.input++, p.length--);

	if (p.length > 0)
		description = ucv_string_new_length(p.input, p.length);

	jsdoc_typedef_merge(&prop->type, ptype, 0);

	prop->description = ucv_get(description);
	prop->defval = ucv_get(defval);

out:
	ucv_put(description);
	ucv_put(defval);

	jsdoc_typedef_free(ptype);

	parse_free(&p);
}

static void
parse_tag_element(jsdoc_t *js, jsdoc_tag_t *tag, size_t index)
{
	jsdoc_typedef_t *ptype = NULL;
	jsdoc_element_t *elem = NULL;
	jsdoc_parser_t p = { 0 };

	if (!jsdoc_type_imply(&js->type, TYPE_ARRAY))
		goto out;

	parse_init(&p, tag->value.buf, tag->value.bpos);

	if (!parse_consume(&p, '{'))
		goto out;

	ptype = parse_union_type(&p);

	if (!ptype || !parse_consume(&p, '}'))
		goto out;

	if (index < js->type->details.array.elements.count)
		elem = uscope_vector_get(&js->type->details.array.elements, index);
	else
		elem = uc_vector_push(&js->type->details.array.elements, { 0 });

	/* NB: this may fail, names are not mandatory for array items */
	parse_capture(&p, T_IDENT, &elem->name);

	if (p.length > 0 && *p.input == '-')
		for (p.input++, p.length--;
		     p.length > 0 && isspace(*p.input);
		     p.input++, p.length--);

	if (p.length > 0)
		elem->description = ucv_string_new_length(p.input, p.length);

	jsdoc_typedef_merge(&elem->type, ptype, 0);

out:
	jsdoc_typedef_free(ptype);

	parse_free(&p);
}

static void
parse_tag_args(jsdoc_t *js, jsdoc_tag_t *tag, size_t index)
{
	while (tag->value.bpos > 0 && isspace(tag->value.buf[tag->value.bpos - 1]))
		tag->value.bpos--;

	switch (tag->type) {
	case TAG_KIND:
		for (size_t i = 0; i < ARRAY_SIZE(kindmap); i++) {
			if (!strcmp(kindmap[i].name, tag->value.buf)) {
				js->kind = kindmap[i].kind;
				break;
			}
		}

		break;

	case TAG_CONSTANT:
		js->kind = KIND_CONSTANT;
		js->constant = true;
		parse_tag_type_name(js, tag);
		break;

	case TAG_FUNCTION:
		js->kind = KIND_FUNCTION;

		if (tag->value.bpos) {
			ucv_replace(&js->name,
				ucv_string_new_length(tag->value.buf, tag->value.bpos));
			//move_str(&js->name, &tag->value.buf);
		}

		jsdoc_type_imply(&js->type, TYPE_FUNCTION);
		break;

	case TAG_MEMBER:
		js->kind = KIND_MEMBER;
		parse_tag_type_name(js, tag);
		break;

	case TAG_NAME:
		ucv_replace(&js->name,
			ucv_string_new_length(tag->value.buf, tag->value.bpos));
		//move_str(&js->name, &tag->value.buf);
		break;

	case TAG_TYPE:
		parse_tag_type(&js->type, tag);
		break;

	case TAG_TYPEDEF:
		js->kind = KIND_TYPEDEF;
		parse_tag_type_name(js, tag);
		break;

	case TAG_CONSTRUCTS:
		js->kind = KIND_FUNCTION;
		jsdoc_type_imply(&js->type, TYPE_FUNCTION);

		if (tag->value.bpos > 0) {
			ucv_replace(&js->name,
				ucv_string_new_length(tag->value.buf, tag->value.bpos));
			//move_str(&js->name, &tag->value.buf);
		}

		break;

	case TAG_ENUM:
		js->kind = KIND_ENUM;

		if (jsdoc_type_imply(&js->type, TYPE_OBJECT))
			parse_tag_type(&js->type->details.object.val_type, tag);

		break;

	case TAG_PARAM:
		js->kind = KIND_FUNCTION;
		parse_tag_param(js, tag, index);
		break;

	case TAG_RETURNS:
		js->kind = KIND_FUNCTION;
		parse_tag_returns(js, tag);
		break;

	case TAG_THROWS:
		js->kind = KIND_FUNCTION;
		parse_tag_throws(js, tag, index);
		break;

	case TAG_PROPERTY:
		parse_tag_property(js, tag);
		break;

	case TAG_ELEMENT:
		parse_tag_element(js, tag, index);
		break;

	case TAG_DESCRIPTION:
		if (tag->value.bpos > 0) {
			ucv_replace(&js->description,
				ucv_string_new_length(tag->value.buf, tag->value.bpos));
			//move_str(&js->description, &tag->value.buf);
		}

		break;

	case TAG_DEFAULT:
		if (tag->value.bpos > 0) {
			char *s = tag->value.buf;
			size_t l = tag->value.bpos;

			parse_value(NULL, &s, &l, &js->defval);
		}

		break;

	case TAG_EVENT:
	case TAG_EXTERNAL:
	case TAG_FILE:
	case TAG_CLASS:
	case TAG_MIXIN:
	case TAG_MODULE:
	case TAG_NAMESPACE:
	case TAG_INTERFACE:
	case TAG_MEMBEROF:
	case TAG_FIRES:
	case TAG_YIELDS:
	case TAG_UNKNOWN:
	case TAG_NONE:
		/* not implemented */
		break;
	}
}

static uc_value_t *
extract_subject(uc_value_t *text)
{
	uc_value_t *rv = NULL;

	if (!text)
		return NULL;

	char *s = ucv_string_get(text);
	while (isspace(*s)) s++;

	char *e = strstr(s, "\n\n");
	if (!e) e = s + ucv_string_length(text);

	if (e - s > 128) {
		for (char *p = e; p > s + 1; p--) {
			if (strchr(" \t\n", *p) && p[-1] == '.' && p - s <= 128) {
				rv = ucv_string_new_length(s, p - s);
				break;
			}
		}

		for (char *p = e; !rv && p > s; p--) {
			if (strchr(" \t\n", *p) && p - s <= 128) {
				uc_stringbuf_t *sbuf = ucv_stringbuf_new();
				ucv_stringbuf_addstr(sbuf, s, p - s);
				ucv_stringbuf_append(sbuf, "...");
				rv = ucv_stringbuf_finish(sbuf);
				break;
			}
		}
	}
	else {
		rv = ucv_string_new_length(s, e - s);
	}

	for (char *p = ucv_string_get(rv); p && *p; p++)
		if (isspace(*p))
			*p = ' ';

	return rv;
}

static void
rewrap_text(uc_stringbuf_t *buf)
{
	size_t len = buf->bpos, i = 0, o = 0, nl = 0;

	if (!buf->buf)
		return;

	for (char prev = '\n'; i < len; ) {
		if (buf->buf[i] == '\n') {
			if (++nl >= 2) {
				nl = 0;
				buf->buf[o++] = '\n';
				prev = buf->buf[o++] = '\n';

				while (buf->buf[i] == '\n')
					i++;
			}
			else {
				i++;
			}
		}
		else {
			if (nl == 1 && prev != '\n')
				buf->buf[o++] = ' ';

			nl = 0;
			prev = buf->buf[o++] = buf->buf[i++];
		}
	}

	buf->buf[o] = 0;
	buf->bpos = o;
}

jsdoc_t *
jsdoc_new(jsdoc_type_t type)
{
	jsdoc_t *js = xalloc(sizeof(jsdoc_t));

	js->type = xalloc(sizeof(jsdoc_typedef_t));
	js->type->type = type;

	return js;
}

jsdoc_t *
jsdoc_merge(const jsdoc_t *base, const jsdoc_t *override, unsigned int flags)
{
	jsdoc_t *res = jsdoc_new(TYPE_UNSPEC);

	if (base) {
		res->kind = base->kind;
		res->constant = base->constant;

		res->name = ucv_get(base->name);
		res->defval = ucv_get(base->defval);
		res->subject = ucv_get(base->subject);
		res->description = ucv_get(base->description);

		jsdoc_typedef_merge(&res->type, base->type, flags);
	}

	if (override) {
		res->kind = override->kind;
		res->constant |= override->constant;

		ucv_update(&res->name, override->name);
		ucv_update(&res->defval, override->defval);
		ucv_update(&res->subject, override->subject);
		ucv_update(&res->description, override->description);

		jsdoc_typedef_merge(&res->type, override->type, flags);
	}

	return res;
}

jsdoc_t *
jsdoc_parse(const char *comment, size_t len, jsdoc_t *js)
{
	size_t property_index = 0;
	size_t element_index = 0;
	size_t param_index = 0;
	size_t throw_index = 0;
	uint32_t tags_seen = 0;
	char kind = ' ';

	struct {
		size_t count;
		jsdoc_tag_t *entries;
	} tags = { 0 };

	jsdoc_tag_t *tag = uc_vector_push(&tags, { .type = TAG_DESCRIPTION });

	if (len >= 2 && !strncmp(comment, "/*", 2)) {
		comment += 2, len -= 2;
		kind = '*';

		if (len > 0 && *comment == '*')
			comment++, len--;

		while (len > 0 && isspace(*comment))
			comment++, len--;

		if (len >= 2 && !strncmp(comment + len - 2, "*/", 2))
			len -= 2;
	}
	else if (len >= 2 && !strncmp(comment, "//", 2)) {
		comment += 2, len -= 2;
		kind = '/';
	}

	for (const char *p = comment, *ln = comment; p <= comment + len; p++) {
		if (p == comment + len || *p == '\n') {
			jsdoc_tag_type_t type = find_tag(&ln, p, kind);

			if (type) {
				uc_vector_grow(&tags);
				tag = &tags.entries[tags.count++];
				tag->type = type;

				if (p > ln) {
					fprintf(stderr, "APPEND-FIRST [%.*s]\n",
						(int)(p - ln), ln);

					printbuf_memappend_fast((&tag->value), ln, p - ln);
				}
			}
			else if (tag->value.bpos > 0 || p > ln) {
				fprintf(stderr, "APPEND-CONT [%.*s]\n",
					(int)(p - ln), ln);

				printbuf_strappend((&tag->value), "\n");
				printbuf_memappend_fast((&tag->value), ln, p - ln);
			}

			ln = p + 1;
		}
	}

	if (!js)
		js = xalloc(sizeof(*js));

	for (size_t i = 0; i < tags.count; i++) {
		jsdoc_tag_t *tag = &tags.entries[i];

		rewrap_text(&tag->value);

		/* @param, @throws, @property and @element may be repeated ... */
		if (tag->type == TAG_PARAM)
			parse_tag_args(js, tag, param_index++);
		else if (tag->type == TAG_THROWS)
			parse_tag_args(js, tag, throw_index++);
		else if (tag->type == TAG_PROPERTY)
			parse_tag_args(js, tag, property_index++);
		else if (tag->type == TAG_ELEMENT)
			parse_tag_args(js, tag, element_index++);

		/* ... for all other types only consider the first */
		else if (!(tags_seen & (1u << tag->type)))
			parse_tag_args(js, tag, 0);

		tags_seen |= (1u << tag->type);

		free(tag->value.buf);
	}

	uc_vector_clear(&tags);

	js->subject = extract_subject(js->description);

	return js;
}

jsdoc_typedef_t *
jsdoc_typedef_new(jsdoc_type_t type)
{
	jsdoc_typedef_t *def = xalloc(sizeof(jsdoc_typedef_t));

	def->type = type;

	return def;
}

static uc_value_t *
jsdoc_typedef_to_uv(uc_vm_t *vm, jsdoc_typedef_t *type)
{
	uc_value_t *t = ucv_object_new(vm);
	uc_value_t *uv;

	switch (type ? type->type : TYPE_UNSPEC) {
	case TYPE_FUNCTION:
		uv = ucv_object_new(vm);

		uc_value_t *f_args = ucv_array_new_length(vm, type->details.function.params.count);

		uc_vector_foreach(&type->details.function.params, param) {
			uc_value_t *f_arg = ucv_object_new(vm);

			if (param->name)
				ucv_object_add(f_arg, "name", ucv_get(param->name));

			if (param->description)
				ucv_object_add(f_arg, "description", ucv_get(param->description));

			if (param->defval)
				ucv_object_add(f_arg, "default", ucv_get(param->defval));

			ucv_object_add(f_arg, "type", jsdoc_typedef_to_uv(vm, param->type));

			if (param->restarg)
				ucv_object_add(f_arg, "restarg", ucv_boolean_new(true));

			if (param->optional)
				ucv_object_add(f_arg, "optional", ucv_boolean_new(true));

			ucv_array_push(f_args, f_arg);
		}

		ucv_object_add(uv, "arguments", f_args);

		uc_value_t *f_ret = ucv_object_new(vm);

		ucv_object_add(f_ret, "type",
			jsdoc_typedef_to_uv(vm, type->details.function.return_type));

		if (type->details.function.return_description)
			ucv_object_add(f_ret, "description",
				ucv_get(type->details.function.return_description));

		ucv_object_add(uv, "return", f_ret);

		if (type->details.function.throws.count > 0) {
			uc_value_t *f_throws = ucv_array_new_length(vm, type->details.function.throws.count);

			uc_vector_foreach(&type->details.function.throws, throw) {
				uc_value_t *f_throw = ucv_object_new(vm);

				if (throw->description)
					ucv_object_add(f_throw, "description",
						ucv_get(throw->description));

				ucv_object_add(f_throw, "type",
					jsdoc_typedef_to_uv(vm, throw->type));

				ucv_array_push(f_throws, f_throw);
			}

			ucv_object_add(uv, "throws", f_throws);
		}

		ucv_object_add(t, "type", ucv_string_new("function"));
		ucv_object_add(t, "function", uv);
		break;

	case TYPE_OBJECT:
		uv = ucv_object_new(vm);

		ucv_object_add(uv, "key_type",
			jsdoc_typedef_to_uv(vm, type->details.object.key_type));

		ucv_object_add(uv, "value_type",
			jsdoc_typedef_to_uv(vm, type->details.object.val_type));

		if (type->details.object.properties.count > 0) {
			uc_value_t *o_props = ucv_object_new(vm);

			uc_vector_foreach(&type->details.object.properties, prop) {
				uc_value_t *o_prop = ucv_object_new(vm);

				ucv_object_add(o_prop, "name", ucv_get(prop->name));

				if (prop->description)
					ucv_object_add(o_prop, "description",
						ucv_get(prop->description));

				if (prop->defval)
					ucv_object_add(o_prop, "default",
						ucv_get(prop->defval));

				if (prop->optional)
					ucv_object_add(o_prop, "optional",
						ucv_boolean_new(true));

				ucv_object_add(o_prop, "type",
					jsdoc_typedef_to_uv(vm, prop->type));

				char *pname = ucv_string_get(prop->name);
				char *p = NULL;

				if (!pname) {
					xasprintf(&p, ".property.%p", prop);
					pname = p;
				}

				ucv_object_add(o_props, pname, o_prop);
				free(p);
			}

			ucv_object_add(uv, "properties", o_props);
		}

		ucv_object_add(t, "type", ucv_string_new("object"));
		ucv_object_add(t, "object", uv);
		break;

	case TYPE_ARRAY:
		uv = ucv_object_new(vm);

		ucv_object_add(uv, "item_type",
			jsdoc_typedef_to_uv(vm, type->details.array.item_type));

		if (type->details.array.elements.count > 0) {
			uc_value_t *a_elems = ucv_array_new_length(vm,
				type->details.array.elements.count);

			uc_vector_foreach(&type->details.array.elements, elem) {
				uc_value_t *a_elem = ucv_object_new(vm);

				if (elem->name)
					ucv_object_add(a_elem, "name",
						ucv_get(elem->name));

				if (elem->description)
					ucv_object_add(a_elem, "description",
						ucv_get(elem->description));

				ucv_object_add(a_elem, "type",
					jsdoc_typedef_to_uv(vm, elem->type));

				ucv_array_push(a_elems, a_elem);
			}

			ucv_object_add(uv, "elements", a_elems);
		}

		ucv_object_add(t, "type", ucv_string_new("array"));
		ucv_object_add(t, "array", uv);
		break;

	case TYPE_UNION:
		uv = ucv_array_new_length(vm, type->details.alternatives.count);

		uc_vector_foreach(&type->details.alternatives, subtype)
			ucv_array_push(uv, jsdoc_typedef_to_uv(vm, *subtype));

		ucv_object_add(t, "type", ucv_string_new("union"));
		ucv_object_add(t, "union", uv);
		break;

	case TYPE_TYPENAME:
		ucv_object_add(t, "type", ucv_string_new("typename"));
		ucv_object_add(t, "typename", ucv_get(type->details.typename));
		break;

	case TYPE_UNSPEC:
		ucv_object_add(t, "type", ucv_string_new("unspec"));
		break;

	case TYPE_INTEGER:
		ucv_object_add(t, "type", ucv_string_new("integer"));
		break;

	case TYPE_DOUBLE:
		ucv_object_add(t, "type", ucv_string_new("double"));
		break;

	case TYPE_NUMBER:
		ucv_object_add(t, "type", ucv_string_new("number"));
		break;

	case TYPE_BOOLEAN:
		ucv_object_add(t, "type", ucv_string_new("boolean"));
		break;

	case TYPE_STRING:
		ucv_object_add(t, "type", ucv_string_new("string"));
		break;

	case TYPE_ANY:
		ucv_object_add(t, "type", ucv_string_new("any"));
		break;
	}

	if (type && type->nullable)
		ucv_object_add(t, "nullable", ucv_boolean_new(true));

	if (type && type->required)
		ucv_object_add(t, "required", ucv_boolean_new(true));

	if (type && type->value)
		ucv_object_add(t, "value", ucv_get(type->value));

	return t;
}

uc_value_t *
jsdoc_to_uv(uc_vm_t *vm, const jsdoc_t *js)
{
	if (!js)
		return NULL;

	uc_value_t *uv = ucv_object_new(vm);

	if (js->name)
		ucv_object_add(uv, "name", ucv_get(js->name));

	if (js->subject)
		ucv_object_add(uv, "subject", ucv_get(js->subject));

	if (js->description)
		ucv_object_add(uv, "description", ucv_get(js->description));

	if (js->defval)
		ucv_object_add(uv, "default", ucv_get(js->defval));

	for (size_t i = 0; i < ARRAY_SIZE(kindmap); i++) {
		if (kindmap[i].kind == js->kind) {
			ucv_object_add(uv, "kind", ucv_string_new(kindmap[i].name));
			break;
		}
	}

	ucv_object_add(uv, "type", jsdoc_typedef_to_uv(vm, js->type));

	if (js->constant)
		ucv_object_add(uv, "constant", ucv_boolean_new(true));

	return uv;
}

jsdoc_typedef_t *
jsdoc_typedef_from_uv(uc_vm_t *vm, uc_value_t *uv)
{
	uscope_variable_t *uvar = ucv_resource_data(uv, "uscope.variable");
	jsdoc_typedef_t *t = NULL;

	jsdoc_type_t vartype = (uvar && uvar->jsdoc && uvar->jsdoc->type)
		? uvar->jsdoc->type->type : TYPE_UNSPEC;

	uc_function_t *function;
	uc_closure_t *closure;

	if (vartype == TYPE_ARRAY) {
		jsdoc_type_imply(&t, TYPE_ARRAY);
		jsdoc_type_imply(&t->details.array.item_type, TYPE_ANY);

		for (size_t i = 0; i < ucv_array_length(uvar->value); i++) {
			jsdoc_element_t *elem = uc_vector_push(&t->details.array.elements, { 0 });
			uc_value_t *v = ucv_array_get(uvar->value, i);
			uscope_variable_t *pvar = ucv_resource_data(v, "uscope.variable"), *var2;

			if (ucv_is_marked(v)) {
				jsdoc_type_imply(&elem->type, TYPE_ANY);
				continue;
			}

			if (!pvar || !pvar->property || !pvar->name)
				continue;

			if (ucv_type(pvar->name) == UC_STRING)
				elem->name = ucv_get(pvar->name);
			else if (pvar->jsdoc)
				ucv_update(&elem->name, pvar->jsdoc->name);
			else if ((var2 = ucv_resource_data(pvar->value, "uscope.variable")) != NULL) {
				if (var2->jsdoc)
					ucv_update(&elem->name, var2->jsdoc->name);
			}

			ucv_set_mark(v);

			elem->type = jsdoc_typedef_from_uv(vm, v);

			ucv_clear_mark(v);

			if (pvar->jsdoc) {
				ucv_update(&elem->description, pvar->jsdoc->subject);
				jsdoc_typedef_merge(&elem->type, pvar->jsdoc->type, 0);
			}
		}

		return t;
	}

	if (vartype == TYPE_OBJECT) {
		jsdoc_type_imply(&t, TYPE_OBJECT);
		jsdoc_type_imply(&t->details.object.key_type, TYPE_ANY);
		jsdoc_type_imply(&t->details.object.val_type, TYPE_ANY);

		for (size_t i = 0; i < ucv_array_length(uvar->value); i++) {
			uc_value_t *v = ucv_array_get(uvar->value, i);

			if (ucv_is_marked(v))
				continue;

			uscope_variable_t *pvar = ucv_resource_data(v, "uscope.variable");

			if (!pvar || !pvar->name || !pvar->property)
				continue;

			ucv_set_mark(v);

			jsdoc_property_t *prop = uc_vector_push(&t->details.object.properties, {
				.name = ucv_get(pvar->name),
				.type = jsdoc_typedef_from_uv(vm, v)
			});

			ucv_clear_mark(v);

			if (pvar->jsdoc) {
				ucv_update(&prop->description, pvar->jsdoc->subject);
				jsdoc_typedef_merge(&prop->type, pvar->jsdoc->type, 0);
			}
		}

		return t;
	}

	uv = uscope_resolve_variable(vm, uv, true);

	switch (ucv_type(uv)) {
	case UC_ARRAY:
		jsdoc_type_imply(&t, TYPE_ARRAY);
		jsdoc_type_imply(&t->details.array.item_type, TYPE_ANY);

		for (size_t i = 0; i < ucv_array_length(uv); i++) {
			jsdoc_element_t *elem = uc_vector_push(&t->details.array.elements, { 0 });
			uc_value_t *v = ucv_array_get(uv, i);
			uscope_variable_t *var = ucv_resource_data(v, "uscope.variable"), *var2;

			if (ucv_is_marked(v)) {
				jsdoc_type_imply(&elem->type, TYPE_ANY);
				continue;
			}

			if (var && ucv_type(var->name) == UC_STRING)
				elem->name = ucv_get(var->name);
			else if (var && var->jsdoc)
				ucv_update(&elem->name, var->jsdoc->name);
			else if (var && (var2 = ucv_resource_data(var->value, "uscope.variable")) != NULL) {
				if (var2->jsdoc)
					ucv_update(&elem->name, var2->jsdoc->name);
			}

			ucv_set_mark(v);

			elem->type = jsdoc_typedef_from_uv(vm, v);

			ucv_clear_mark(v);

			if (var && var->jsdoc) {
				ucv_update(&elem->description, var->jsdoc->subject);
				jsdoc_typedef_merge(&elem->type, var->jsdoc->type, 0);
			}
		}
		break;

	case UC_OBJECT:
		jsdoc_type_imply(&t, TYPE_OBJECT);
		jsdoc_type_imply(&t->details.object.key_type, TYPE_ANY);
		jsdoc_type_imply(&t->details.object.val_type, TYPE_ANY);

		ucv_object_foreach(uv, k, v) {
			if (ucv_is_marked(v))
				continue;

			ucv_set_mark(v);

			uscope_variable_t *var = ucv_resource_data(v, "uscope.variable");
			jsdoc_property_t *prop = uc_vector_push(&t->details.object.properties, {
				.name = ucv_string_new(k),
				.type = jsdoc_typedef_from_uv(vm, v)
			});

			ucv_clear_mark(v);

			if (var && var->jsdoc) {
				ucv_update(&prop->description, var->jsdoc->subject);
				jsdoc_typedef_merge(&prop->type, var->jsdoc->type, 0);
			}
		}
		break;

	case UC_CLOSURE:
		closure = (uc_closure_t *)uv;
		function = closure->function;

		jsdoc_type_imply(&t, TYPE_FUNCTION);

		for (size_t i = 0; i < function->nargs; i++) {
			jsdoc_param_t *param = uc_vector_push(&t->details.function.params, {
				.restarg = (function->vararg && i + 1 == function->nargs)
			});

			jsdoc_type_imply(&param->type, TYPE_ANY);
		}

		jsdoc_type_imply(&t->details.function.return_type, TYPE_ANY);
		break;

	case UC_CFUNCTION:
		jsdoc_type_imply(&t, TYPE_FUNCTION);
		jsdoc_type_imply(&t->details.function.return_type, TYPE_ANY);
		break;

	case UC_BOOLEAN: jsdoc_type_imply(&t, TYPE_BOOLEAN); break;
	case UC_DOUBLE:  jsdoc_type_imply(&t, TYPE_DOUBLE);  break;
	case UC_INTEGER: jsdoc_type_imply(&t, TYPE_INTEGER); break;
	case UC_STRING:  jsdoc_type_imply(&t, TYPE_STRING);  break;
	default:         jsdoc_type_imply(&t, TYPE_ANY);     break;
	}

	if (ucv_is_scalar(uv))
		t->value = uv;
	else
		ucv_put(uv);

	return t;
}

jsdoc_t *
jsdoc_from_uv(uc_vm_t *vm, uc_value_t *uv, jsdoc_t *js)
{
	jsdoc_typedef_t *st = jsdoc_typedef_from_uv(vm, uv);
	uc_cfunction_t *cfunction;
	uc_closure_t *closure;

	if (!js)
		js = xalloc(sizeof(*js));

	if (!js->type) {
		js->type = st;
	}
	else {
		jsdoc_typedef_merge(&js->type, st, 0);
		jsdoc_typedef_free(st);
	}

	js->constant |= ucv_is_constant(uv);

	switch (ucv_type(uv)) {
	case UC_CLOSURE:
		closure = (uc_closure_t *)uv;

		if (closure->function->name[0]) {
			ucv_replace(&js->name, ucv_string_new(closure->function->name));
			//update_str(&js->name, closure->function->name);
		}

		if (js->kind == KIND_UNSPEC)
			js->kind = KIND_FUNCTION;

		break;

	case UC_CFUNCTION:
		cfunction = (uc_cfunction_t *)uv;

		if (cfunction->name[0]) {
			ucv_replace(&js->name, ucv_string_new(cfunction->name));
			//update_str(&js->name, cfunction->name);
		}

		if (js->kind == KIND_UNSPEC)
			js->kind = KIND_FUNCTION;

		break;

	default:
		if (js->kind == KIND_UNSPEC)
			js->kind = KIND_MEMBER;

		break;
	}

	return js;
}

jsdoc_t *
jsdoc_from_param(jsdoc_kind_t kind, const jsdoc_param_t *param)
{
	jsdoc_t *js = xalloc(sizeof(jsdoc_t));

	js->kind = kind;
	js->name = ucv_get(param->name);
	js->subject = extract_subject(param->description);
	js->description = ucv_get(param->description);
	js->defval = ucv_get(param->defval);

	if (param->restarg) {
		jsdoc_type_imply(&js->type, TYPE_ARRAY);
		jsdoc_typedef_merge(&js->type->details.array.item_type,
			param->type, MERGE_TYPEONLY);
	}
	else {
		jsdoc_typedef_merge(&js->type, param->type, MERGE_TYPEONLY);
	}

	return js;
}

jsdoc_t *
jsdoc_from_property(jsdoc_kind_t kind, const jsdoc_property_t *prop)
{
	jsdoc_t *js = xalloc(sizeof(jsdoc_t));

	js->kind = kind;
	js->name = ucv_get(prop->name);
	js->subject = extract_subject(prop->description);
	js->description = ucv_get(prop->description);
	js->defval = ucv_get(prop->defval);

	jsdoc_typedef_merge(&js->type, prop->type, MERGE_TYPEONLY);

	return js;
}

jsdoc_t *
jsdoc_from_element(jsdoc_kind_t kind, const jsdoc_element_t *elem)
{
	jsdoc_t *js = xalloc(sizeof(jsdoc_t));

	js->kind = kind;
	js->name = ucv_get(elem->name);
	js->subject = extract_subject(elem->description);
	js->description = ucv_get(elem->description);

	jsdoc_typedef_merge(&js->type, elem->type, MERGE_TYPEONLY);

	return js;
}

jsdoc_t *
jsdoc_from_return(jsdoc_kind_t kind, const jsdoc_typedef_t *fnspec)
{
	jsdoc_t *js = xalloc(sizeof(jsdoc_t));

	js->kind = kind;

	if (fnspec->type == TYPE_FUNCTION) {
		js->subject = extract_subject(fnspec->details.function.return_description);
		js->description = ucv_get(fnspec->details.function.return_description);

		jsdoc_typedef_merge(&js->type,
			fnspec->details.function.return_type, MERGE_TYPEONLY);
	}
	else {
		jsdoc_type_imply(&js->type, TYPE_ANY);
	}

	return js;
}
