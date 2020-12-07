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

#include "lexer.h"
#include "parser.h"
#include "eval.h"
#include "lib.h"

#include <math.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <regex.h>

bool
uc_val_is_truish(struct json_object *val)
{
	struct uc_op *tag = json_object_get_userdata(val);
	double d;

	switch (tag ? tag->type : 0) {
	case T_EXCEPTION:
		return false;

	default:
		switch (json_object_get_type(val)) {
		case json_type_int:
			return (json_object_get_int64(val) != 0);

		case json_type_double:
			d = json_object_get_double(val);

			return (d != 0 && !isnan(d));

		case json_type_boolean:
			return (json_object_get_boolean(val) != false);

		case json_type_string:
			return (json_object_get_string_len(val) > 0);

		case json_type_array:
		case json_type_object:
			return true;

		default:
			return false;
		}
	}
}

enum json_type
uc_cast_number(struct json_object *v, int64_t *n, double *d)
{
	bool is_double = false;
	const char *s;
	char *e;

	*d = 0.0;
	*n = 0;

	switch (json_object_get_type(v)) {
	case json_type_int:
		*n = json_object_get_int64(v);

		return json_type_int;

	case json_type_double:
		*d = json_object_get_double(v);

		return json_type_double;

	case json_type_null:
		return json_type_int;

	case json_type_boolean:
		*n = json_object_get_boolean(v) ? 1 : 0;

		return json_type_int;

	case json_type_string:
		s = json_object_get_string(v);

		while (isspace(*s))
			s++;

		if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X') && isxdigit(s[2])) {
			*n = strtoll(s, &e, 16);
		}
		else if (s[0] == '0' && isdigit(s[2])) {
			*n = strtoll(s, &e, 8);
		}
		else {
			*n = strtoll(s, &e, 10);

			if (*e == '.') {
				*d = strtod(s, &e);
				is_double = (e > s);
			}
		}

		while (isspace(*e))
			e++;

		if (*e) {
			*d = NAN;

			return json_type_double;
		}

		if (is_double)
			return json_type_double;

		return json_type_int;

	default:
		*d = NAN;

		return json_type_double;
	}
}

static struct json_object *
uc_execute_op(struct uc_state *state, uint32_t off);

static struct json_object *
uc_execute_op_sequence(struct uc_state *state, uint32_t off);

static struct json_object *
uc_execute_list(struct uc_state *state, uint32_t off);

static char *
uc_ref_to_str(struct uc_state *state, uint32_t off)
{
	int child_type = OPn_TYPE(off, 1);
	int op_type = OP_TYPE(off);
	const char *l;
	char *s, *p;

	switch (op_type) {
	case T_DOT:
		s = uc_ref_to_str(state, OPn(off, 0));
		l = (child_type == T_LABEL) ? json_object_get_string(OPn_VAL(off, 1)) : "???";

		if (asprintf(&p, "%s.%s", s ? s : "(...)", l) == -1)
			p = NULL;

		free(s);

		return p;

	case T_LBRACK:
		if (!OP_IS_POSTFIX(off))
			return NULL;

		/* fall through */

	case T_LPAREN:
		s = uc_ref_to_str(state, OPn(off, 0));

		switch (child_type) {
		case T_STRING:
			l = json_object_to_json_string_ext(OPn_VAL(off, 1), JSON_C_TO_STRING_NOSLASHESCAPE);
			break;

		case T_NUMBER:
		case T_LABEL:
		case T_BOOL:
			l = json_object_get_string(OPn_VAL(off, 1));
			break;

		default:
			l = "...";
		}

		if (asprintf(&p, "%s%c%s%c", s ? s : "(...)",
		             (op_type == T_LPAREN) ? '(' : '[', l,
		             (op_type == T_LPAREN) ? ')' : ']') == -1)
			p = NULL;

		free(s);

		return p;

	case T_LABEL:
		return strdup(json_object_get_string(OP_VAL(off)));

	default:
		return NULL;
	}
}

static struct json_object *
uc_getref(struct uc_state *state, uint32_t off, struct json_object **key)
{
	uint32_t off1 = OPn(off, 0);
	uint32_t off2 = OPn(off, 1);
	int type = OP_TYPE(off);
	struct uc_scope *sc, *next;
	struct json_object *val;

	if (key)
		*key = NULL;

	if (type == T_DOT) {
		if (key)
			*key = off2 ? json_object_get(OP_VAL(off2)) : NULL;

		return uc_execute_op_sequence(state, off1);
	}
	else if (type == T_LBRACK && OP_IS_POSTFIX(off)) {
		if (key) {
			val = off2 ? uc_execute_op_sequence(state, off2) : NULL;

			if (uc_is_type(val, T_EXCEPTION))
				return val;

			*key = val;
		}

		return uc_execute_op_sequence(state, off1);
	}
	else if (type == T_LABEL) {
		sc = state->scope;

		while (true) {
			if (json_object_object_get_ex(sc->scope, json_object_get_string(OP_VAL(off)), NULL))
				break;

			next = uc_parent_scope(sc);

			if (!next) {
				if (state->strict_declarations) {
					return uc_new_exception(state, OP_POS(off),
					                        "Reference error: access to undeclared variable %s",
					                        json_object_get_string(OP_VAL(off)));
				}

				break;
			}

			sc = next;
		}

		if (key)
			*key = json_object_get(OP_VAL(off));

		return json_object_get(sc->scope);
	}
	else {
		if (key)
			*key = NULL;

		return NULL;
	}
}

static struct json_object *
uc_getref_required(struct uc_state *state, uint32_t off, struct json_object **key)
{
	uint32_t child_off = OPn(off, 0);
	struct json_object *scope, *skey, *rv;
	char *lhs;

	scope = uc_getref(state, off, &skey);

	if (!json_object_is_type(scope, json_type_array) &&
		!json_object_is_type(scope, json_type_object)) {
		if (!uc_is_type(scope, T_EXCEPTION)) {
			lhs = child_off ? uc_ref_to_str(state, child_off) : NULL;

			if (lhs) {
				rv = uc_new_exception(state, OPn_POS(off, 0),
				                      "Type error: `%s` is %s",
				                      lhs, scope ? "not an array or object" : "null");
				free(lhs);
			}
			else {
				rv = uc_new_exception(state, OPn_POS(off, 0),
				                      "Type error: left-hand side is not an array or object");
			}

			json_object_put(scope);
		}
		else {
			rv = scope;
		}

		json_object_put(skey);

		*key = NULL;
		return rv;
	}

	*key = skey;
	return scope;
}

static struct json_object *
uc_getproto(struct json_object *obj)
{
	struct uc_op *tag = json_object_get_userdata(obj);

	if (!tag || (tag->type != T_LBRACE && tag->type <= __T_MAX) || !tag->val)
		return NULL;

	return tag->tag.proto;
}

static struct json_object *
uc_getval(struct json_object *scope, struct json_object *key)
{
	struct json_object *o, *v;
	int64_t idx;
	double d;

	if (!key)
		return NULL;

	if (json_object_is_type(scope, json_type_array)) {
		/* only consider doubles with integer values as array keys */
		if (json_object_is_type(key, json_type_double)) {
			d = json_object_get_double(key);

			if ((double)(int64_t)(d) != d)
				return NULL;

			idx = (int64_t)d;
		}
		else {
			errno = 0;
			idx = json_object_get_int64(key);

			if (errno != 0)
				return NULL;
		}

		return json_object_get(json_object_array_get_idx(scope, idx));
	}

	for (o = scope; o; o = uc_getproto(o)) {
		if (!json_object_is_type(o, json_type_object))
			continue;

		if (json_object_object_get_ex(o, key ? json_object_get_string(key) : "null", &v))
			return json_object_get(v);
	}

	return NULL;
}

static struct json_object *
uc_setval(struct json_object *scope, struct json_object *key, struct json_object *val)
{
	int64_t idx;

	if (!key)
		return NULL;

	if (json_object_is_type(scope, json_type_array)) {
		errno = 0;
		idx = json_object_get_int64(key);

		if (errno != 0)
			return NULL;

		if (json_object_array_put_idx(scope, idx, val))
			return NULL;

		return json_object_get(val);
	}

	if (json_object_object_add(scope, key ? json_object_get_string(key) : "null", val))
		return NULL;

	return json_object_get(val);
}

static struct json_object *
uc_execute_assign(struct uc_state *state, uint32_t off)
{
	uint32_t label_off = OPn(off, 0);
	uint32_t value_off = OPn(off, 1);
	struct json_object *scope, *key, *val;

	scope = uc_getref_required(state, label_off, &key);

	if (!key)
		return scope;

	val = uc_execute_op_sequence(state, value_off);

	if (!uc_is_type(val, T_EXCEPTION))
		uc_setval(scope, key, val);

	json_object_put(scope);
	json_object_put(key);

	return val;
}

static struct json_object *
uc_execute_local(struct uc_state *state, uint32_t off)
{
	struct json_object *val, *rv = NULL;
	uint32_t assign_off, label_off;

	for (assign_off = OPn(off, 0); assign_off != 0; assign_off = OP_NEXT(assign_off)) {
		switch (OP_TYPE(assign_off)) {
		case T_ASSIGN:
			label_off = OPn(assign_off, 0);
			val = uc_execute_op_sequence(state, OPn(assign_off, 1));

			if (uc_is_type(val, T_EXCEPTION))
				return val;

			break;

		case T_LABEL:
			label_off = assign_off;
			val = NULL;
			break;

		default:
			continue;
		}

		if (label_off) {
			json_object_put(rv);
			rv = uc_setval(state->scope->scope, OP_VAL(label_off), val);
		}
	}

	return rv;
}

static struct json_object *
uc_execute_op_sequence(struct uc_state *state, uint32_t off);

static bool
uc_test_condition(struct uc_state *state, uint32_t off)
{
	struct json_object *val = uc_execute_op_sequence(state, off);
	bool istrue = uc_val_is_truish(val);

	json_object_put(val);

	return istrue;
}

static struct json_object *
uc_execute_if(struct uc_state *state, uint32_t off)
{
	uint32_t cond_off = OPn(off, 0);
	uint32_t then_off = OPn(off, 1);
	uint32_t else_off = OPn(off, 2);
	bool res = uc_test_condition(state, cond_off);

	if (state->exception)
		return json_object_get(state->exception);
	else if (res)
		return uc_execute_op_sequence(state, then_off);
	else if (else_off)
		return uc_execute_op_sequence(state, else_off);

	return NULL;
}

static struct json_object *
uc_execute_for(struct uc_state *state, uint32_t off)
{
	struct json_object *kscope, *vscope, *val, *item, *ik, *iv = NULL, *rv = NULL;
	uint32_t init_off = OPn(off, 0);
	uint32_t cond_off = OPn(off, 1);
	uint32_t step_off = OPn(off, 2);
	uint32_t body_off = OPn(off, 3);
	uint32_t ik_off, iv_off;
	size_t arridx, arrlen;
	bool local = false;
	struct uc_op *tag;

	/* for (x in ...) loop variant */
	if (OP_IS_FOR_IN(off)) {
		if (OP_TYPE(init_off) == T_LOCAL) {
			local = true;
			init_off = OPn(init_off, 0);
		}

		ik_off = OPn(init_off, 0);
		ik = OP_VAL(ik_off);
		kscope = local ? state->scope->scope : uc_getref(state, ik_off, NULL);

		if (uc_is_type(kscope, T_EXCEPTION))
			return kscope;

		iv_off = OP_NEXT(ik_off);

		if (iv_off) {
			iv = OP_VAL(iv_off);
			vscope = local ? kscope : uc_getref(state, iv_off, NULL);

			if (uc_is_type(vscope, T_EXCEPTION))
				return vscope;
		}

		val = uc_execute_op_sequence(state, OPn(init_off, 1));

		if (uc_is_type(val, T_EXCEPTION))
			return val;

		if (json_object_is_type(val, json_type_array)) {
			for (arridx = 0, arrlen = json_object_array_length(val);
			     arridx < arrlen; arridx++) {
				item = json_object_array_get_idx(val, arridx);

				if (iv) {
					uc_setval(kscope, ik, xjs_new_int64(arridx));
					uc_setval(vscope, iv, item);
				}
				else {
					uc_setval(kscope, ik, item);
				}

				json_object_put(rv);

				rv = uc_execute_op_sequence(state, body_off);
				tag = json_object_get_userdata(rv);

				switch (tag ? tag->type : 0) {
				case T_RETURN:
				case T_EXCEPTION:
					json_object_put(val);

					return rv;

				case T_BREAK:
					json_object_put(val);
					json_object_put(rv);

					return NULL;
				}
			}
		}
		else if (json_object_is_type(val, json_type_object)) {
			json_object_object_foreach(val, key, item) {
				json_object_put(uc_setval(kscope, ik, xjs_new_string(key)));

				if (iv)
					uc_setval(vscope, iv, item);

				json_object_put(rv);

				rv = uc_execute_op_sequence(state, body_off);
				tag = json_object_get_userdata(rv);

				switch (tag ? tag->type : 0) {
				case T_RETURN:
				case T_EXCEPTION:
					json_object_put(val);

					return rv;

				case T_BREAK:
					json_object_put(val);
					json_object_put(rv);

					return NULL;
				}
			}
		}

		json_object_put(val);
		json_object_put(rv);

		return NULL;
	}

	if (init_off) {
		val = uc_execute_op_sequence(state, init_off);

		if (uc_is_type(val, T_EXCEPTION))
			return val;

		json_object_put(val);
	}

	while (cond_off ? uc_test_condition(state, cond_off) : true) {
		json_object_put(rv);

		rv = uc_execute_op_sequence(state, body_off);
		tag = json_object_get_userdata(rv);

		switch (tag ? tag->type : 0) {
		case T_RETURN:
		case T_EXCEPTION:
			return rv;

		case T_BREAK:
			json_object_put(rv);

			return NULL;
		}

		if (step_off) {
			val = uc_execute_op_sequence(state, step_off);

			if (uc_is_type(val, T_EXCEPTION)) {
				json_object_put(rv);

				return val;
			}

			json_object_put(val);
		}
	}

	json_object_put(rv);

	return NULL;
}

static struct json_object *
uc_execute_while(struct uc_state *state, uint32_t off)
{
	uint32_t test = OPn(off, 0);
	uint32_t body = OPn(off, 1);
	struct json_object *v, *rv = NULL;
	struct uc_op *tag = NULL;
	bool cond;

	while (1) {
		json_object_put(rv);

		v = test ? uc_execute_op_sequence(state, test) : NULL;
		cond = test ? uc_val_is_truish(v) : true;

		if (uc_is_type(v, T_EXCEPTION))
			return v;

		json_object_put(v);

		if (!cond)
			return NULL;

		rv = uc_execute_op_sequence(state, body);
		tag = json_object_get_userdata(rv);

		switch (tag ? tag->type : 0) {
		case T_RETURN:
		case T_EXCEPTION:
			return rv;

		case T_BREAK:
			json_object_put(rv);

			return NULL;
		}
	}

	json_object_put(rv);

	return NULL;
}

static struct json_object *
uc_execute_and_or(struct uc_state *state, uint32_t off)
{
	bool is_or = (OP_TYPE(off) == T_OR);
	struct json_object *val = NULL;
	uint32_t op_off;
	int i = 0;

	for (op_off = OPn(off, 0); op_off != 0 && i < OPn_NUM; op_off = OPn(off, ++i)) {
		json_object_put(val);

		val = uc_execute_op_sequence(state, op_off);

		if (uc_is_type(val, T_EXCEPTION))
			break;

		if (uc_val_is_truish(val) == is_or)
			break;
	}

	return val;
}

bool
uc_cmp(int how, struct json_object *v1, struct json_object *v2)
{
	enum json_type t1 = json_object_get_type(v1);
	enum json_type t2 = json_object_get_type(v2);
	int64_t n1, n2, delta;
	double d1, d2;

	if (t1 == json_type_string && t2 == json_type_string) {
		delta = strcmp(json_object_get_string(v1), json_object_get_string(v2));
	}
	else {
		if ((t1 == json_type_array && t2 == json_type_array) ||
		    (t1 == json_type_object && t2 == json_type_object))	{
			delta = (void *)v1 - (void *)v2;
		}
		else {
			t1 = uc_cast_number(v1, &n1, &d1);
			t2 = uc_cast_number(v2, &n2, &d2);

			if (t1 == json_type_double || t2 == json_type_double) {
				d1 = (t1 == json_type_double) ? d1 : (double)n1;
				d2 = (t2 == json_type_double) ? d2 : (double)n2;

				if (d1 == d2)
					delta = 0;
				else if (d1 < d2)
					delta = -1;
				else
					delta = 1;
			}
			else {
				delta = n1 - n2;
			}
		}
	}

	switch (how) {
	case T_LT:
		return (delta < 0);

	case T_LE:
		return (delta <= 0);

	case T_GT:
		return (delta > 0);

	case T_GE:
		return (delta >= 0);

	case T_EQ:
		return (delta == 0);

	case T_NE:
		return (delta != 0);

	default:
		return false;
	}
}

static struct json_object *
_uc_get_operands(struct uc_state *state, uint32_t op_off, size_t n, struct json_object **v)
{
	struct json_object *ctx = NULL;
	uint32_t child_off;
	size_t i, j;

	for (i = 0; i < n; i++) {
		child_off = OPn(op_off, i);

		if (child_off && OP_IS_LIST(child_off))
			v[i] = uc_execute_list(state, child_off);
		else if (child_off)
			v[i] = uc_execute_op_sequence(state, child_off);
		else
			v[i] = NULL;

		if (i == 0)
			ctx = json_object_get(state->ctx);

		if (uc_is_type(v[i], T_EXCEPTION)) {
			json_object_put(ctx);

			for (j = 0; j < i; j++)
				json_object_put(v[j]);

			return v[i];
		}
	}

	json_object_put(state->ctx);
	state->ctx = ctx;

	return NULL;
}

#define uc_get_operands(state, off, vals) \
	do { \
		struct json_object *ex = _uc_get_operands(state, off, ARRAY_SIZE(vals), vals); \
		if (ex) return ex; \
	} while(0)

static struct json_object *
uc_execute_rel(struct uc_state *state, uint32_t off)
{
	struct json_object *v[2], *rv;

	uc_get_operands(state, off, v);

	rv = xjs_new_boolean(uc_cmp(OP_TYPE(off), v[0], v[1]));

	json_object_put(v[0]);
	json_object_put(v[1]);

	return rv;
}

static bool
uc_eq(struct json_object *v1, struct json_object *v2)
{
	struct uc_op *tag1 = json_object_get_userdata(v1);
	struct uc_op *tag2 = json_object_get_userdata(v2);
	enum json_type t1 = json_object_get_type(v1);
	enum json_type t2 = json_object_get_type(v2);

	if ((tag1 ? tag1->type : 0) != (tag2 ? tag2->type : 0))
		return false;

	if (t1 != t2)
		return false;

	switch (t1) {
	case json_type_array:
	case json_type_object:
		return (v1 == v2);

	case json_type_boolean:
		return (json_object_get_boolean(v1) == json_object_get_boolean(v2));

	case json_type_double:
		if (isnan(json_object_get_double(v1)) || isnan(json_object_get_double(v2)))
			return false;

		return (json_object_get_double(v1) == json_object_get_double(v2));

	case json_type_int:
		return (json_object_get_int64(v1) == json_object_get_int64(v2));

	case json_type_string:
		return !strcmp(json_object_get_string(v1), json_object_get_string(v2));

	case json_type_null:
		return true;
	}

	return false;
}

static struct json_object *
uc_execute_equality(struct uc_state *state, uint32_t off)
{
	struct json_object *v[2], *rv;
	bool equal = false;

	uc_get_operands(state, off, v);

	equal = uc_eq(v[0], v[1]);
	rv = xjs_new_boolean((OP_TYPE(off) == T_EQS) ? equal : !equal);

	json_object_put(v[0]);
	json_object_put(v[1]);

	return rv;
}

static struct json_object *
uc_execute_in(struct uc_state *state, uint32_t off)
{
	struct json_object *v[2], *item;
	size_t arrlen, arridx;
	bool found = false;
	const char *key;

	uc_get_operands(state, off, v);

	if (json_object_is_type(v[1], json_type_array)) {
		for (arridx = 0, arrlen = json_object_array_length(v[1]);
		     arridx < arrlen; arridx++) {
			item = json_object_array_get_idx(v[1], arridx);

			if (uc_cmp(T_EQ, v[0], item)) {
				found = true;
				break;
			}
		}
	}
	else if (json_object_is_type(v[1], json_type_object)) {
		key = v[0] ? json_object_get_string(v[0]) : "null";
		found = json_object_object_get_ex(v[1], key, NULL);
	}

	json_object_put(v[0]);
	json_object_put(v[1]);

	return xjs_new_boolean(found);
}

static struct json_object *
uc_execute_inc_dec(struct uc_state *state, uint32_t off)
{
	bool is_inc = (OP_TYPE(off) == T_INC);
	struct json_object *val, *nval, *scope, *key;
	int64_t n;
	double d;

	scope = uc_getref_required(state, OPn(off, 0), &key);

	if (!key)
		return scope;

	val = uc_getval(scope, key);

	json_object_put(scope);
	json_object_put(key);

	if (uc_cast_number(val, &n, &d) == json_type_double)
		nval = uc_new_double(d + (is_inc ? 1.0 : -1.0));
	else
		nval = xjs_new_int64(n + (is_inc ? 1 : -1));

	json_object_put(uc_setval(scope, key, nval));

	/* postfix inc/dec, return old val */
	if (OP_IS_POSTFIX(off))
		return val;

	json_object_put(val);

	return json_object_get(nval);
}

static struct json_object *
uc_execute_list(struct uc_state *state, uint32_t off)
{
	struct json_object *ex, *val, *arr = xjs_new_array();
	size_t i;

	while (off) {
		val = uc_execute_op(state, off);

		if (uc_is_type(val, T_EXCEPTION)) {
			json_object_put(arr);

			return val;
		}

		if (OP_IS_ELLIP(off)) {
			if (!json_object_is_type(val, json_type_array)) {
				ex = uc_new_exception(state, OP_POS(off),
				                      "Type error: (%s) is not iterable",
				                      json_object_get_string(val));

				json_object_put(arr);
				json_object_put(val);

				return ex;
			}

			for (i = 0; i < json_object_array_length(val); i++)
				json_object_array_add(arr, json_object_get(json_object_array_get_idx(val, i)));

			json_object_put(val);
		}
		else {
			json_object_array_add(arr, val);
		}

		off = OP_NEXT(off);
	}

	return arr;
}

static struct json_object *
uc_execute_object(struct uc_state *state, uint32_t off)
{
	struct json_object *ex, *v, *obj = uc_new_object(NULL);
	uint32_t key_off;
	char *istr;
	size_t i;

	for (key_off = OPn(off, 0); key_off != 0; key_off = OP_NEXT(key_off)) {
		v = uc_execute_op_sequence(state, OPn(key_off, 0));

		if (uc_is_type(v, T_EXCEPTION)) {
			json_object_put(obj);

			return v;
		}

		if (OP_TYPE(key_off) == T_ELLIP) {
			switch (json_object_get_type(v)) {
			case json_type_object:
				; /* a label can only be part of a statement and a declaration is not a statement */
				json_object_object_foreach(v, vk, vv)
					json_object_object_add(obj, vk, json_object_get(vv));

				json_object_put(v);

				break;

			case json_type_array:
				for (i = 0; i < json_object_array_length(v); i++) {
					xasprintf(&istr, "%zu", i);
					json_object_object_add(obj, istr, json_object_get(json_object_array_get_idx(v, i)));
					free(istr);
				}

				json_object_put(v);

				break;

			default:
				ex = uc_new_exception(state, OP_POS(key_off),
				                      "Type error: (%s) is not iterable",
				                      json_object_get_string(v));

				json_object_put(obj);
				json_object_put(v);

				return ex;
			}
		}
		else {
			json_object_object_add(obj, json_object_get_string(OP_VAL(key_off)), v);
		}
	}

	return obj;
}

struct json_object *
uc_invoke(struct uc_state *state, uint32_t off, struct json_object *this,
          struct json_object *func, struct json_object *argvals)
{
	struct uc_op *tag = json_object_get_userdata(func);
	struct json_object *arr, *rv = NULL;
	struct uc_callstack callstack = {};
	struct uc_function *fn, *prev_fn;
	size_t arridx, arglen;
	struct uc_scope *sc;
	uint32_t tag_off;
	uc_c_fn *fptr;
	int tag_type;
	bool rest;

	if (!tag)
		return NULL;

	if (state->calldepth >= 1000)
		return uc_new_exception(state, OP_POS(off), "Runtime error: Too much recursion");

	callstack.next = state->callstack;
	callstack.function = state->function;
	callstack.off = OP_POS(off);

	if (tag->is_arrow)
		callstack.ctx = state->callstack ? json_object_get(state->callstack->ctx) : NULL;
	else
		callstack.ctx = json_object_get(this ? this : state->ctx);

	state->callstack = &callstack;
	state->calldepth++;

	fn = tag->tag.data;

	prev_fn = state->function;
	state->function = fn;

	/* is native function */
	if (tag->type == T_CFUNC) {
		fptr = (uc_c_fn *)fn->cfn;
		rv = fptr ? fptr(state, off, argvals) : NULL;
	}

	/* is ucode function */
	else {
		callstack.scope = uc_new_scope(state, fn->parent_scope);

		sc = state->scope;
		state->scope = uc_acquire_scope(callstack.scope);

		if (fn->args) {
			arglen = json_object_array_length(fn->args);
			rest = (arglen > 1) && json_object_is_type(json_object_array_get_idx(fn->args, arglen - 1), json_type_null);

			for (arridx = 0; arridx < arglen - rest; arridx++) {
				/* if the last argument is a rest one (...arg), put all remaining parameter values in an array */
				if (rest && arridx == arglen - 2) {
					arr = xjs_new_array();

					uc_setval(callstack.scope->scope,
					          json_object_array_get_idx(fn->args, arridx),
					          arr);

					for (; argvals && arridx < json_object_array_length(argvals); arridx++)
						json_object_array_add(arr, json_object_get(json_object_array_get_idx(argvals, arridx)));

					break;
				}

				uc_setval(callstack.scope->scope, json_object_array_get_idx(fn->args, arridx),
				          argvals ? json_object_array_get_idx(argvals, arridx) : NULL);
			}
		}

		rv = uc_execute_op_sequence(state, fn->entry);
		tag = json_object_get_userdata(rv);
		tag_off = tag ? tag->off : 0;
		tag_type = tag ? tag->type : 0;

		switch (tag_type) {
		case T_BREAK:
		case T_CONTINUE:
			json_object_put(rv);
			rv = uc_new_exception(state, OP_POS(tag_off),
			                      "Syntax error: %s statement must be inside loop",
			                      uc_get_tokenname(tag_type));
			break;

		case T_RETURN:
			json_object_put(rv);
			rv = json_object_get(state->rval);
			break;
		}

		/* we left the function, pop the function scope... */
		uc_release_scope(state->scope);
		state->scope = sc;

		/* ... and release it */
		uc_release_scope(callstack.scope);

	}

	state->function = prev_fn;

	json_object_put(callstack.ctx);
	state->callstack = callstack.next;
	state->calldepth--;

	return rv;
}

static struct json_object *
uc_execute_call(struct uc_state *state, uint32_t off)
{
	struct json_object *v[2], *rv;
	struct uc_op *decl;
	char *lhs;

	uc_get_operands(state, off, v);

	decl = json_object_get_userdata(v[0]);

	if (!decl || (decl->type != T_FUNC && decl->type != T_CFUNC)) {
		lhs = uc_ref_to_str(state, OPn(off, 0));

		rv = uc_new_exception(state, OPn_POS(off, 0),
		                      "Type error: %s is not a function",
		                      lhs ? lhs : "left-hand side expression");

		free(lhs);
	}
	else {
		if (v[1] == NULL)
			v[1] = xjs_new_array();

		rv = uc_invoke(state, off, NULL, v[0], v[1]);
	}

	json_object_put(v[0]);
	json_object_put(v[1]);

	return rv;
}

static void
uc_write_str(struct json_object *v)
{
	const char *p;
	size_t len;

	switch (json_object_get_type(v)) {
	case json_type_object:
	case json_type_array:
		p = json_object_to_json_string_ext(v, JSON_C_TO_STRING_NOSLASHESCAPE|JSON_C_TO_STRING_SPACED);
		len = strlen(p);
		break;

	case json_type_string:
		p = json_object_get_string(v);
		len = json_object_get_string_len(v);
		break;

	case json_type_null:
		p = "";
		len = 0;
		break;

	default:
		p = json_object_get_string(v);
		len = strlen(p);
	}

	fwrite(p, 1, len, stdout);
}

static struct json_object *
uc_execute_exp(struct uc_state *state, uint32_t off)
{
	struct json_object *val = uc_execute_op_sequence(state, OPn(off, 0));
	struct uc_op *tag = val ? json_object_get_userdata(val) : NULL;

	switch (tag ? tag->type : 0) {
	case T_EXCEPTION:
		printf("<exception: %s>", json_object_get_string(val));
		break;

	default:
		uc_write_str(val);
		break;
	}

	json_object_put(val);

	return NULL;
}

static struct json_object *
uc_execute_unary_plus_minus(struct uc_state *state, uint32_t off)
{
	bool is_sub = (OP_TYPE(off) == T_SUB);
	struct json_object *v[1];
	enum json_type t;
	int64_t n;
	double d;

	uc_get_operands(state, off, v);

	t = uc_cast_number(v[0], &n, &d);

	json_object_put(v[0]);

	switch (t) {
	case json_type_int:
		if (OPn_IS_OVERFLOW(off, 0))
			return xjs_new_int64(((n >= 0) == is_sub) ? INT64_MIN : INT64_MAX);

		return xjs_new_int64(is_sub ? -n : n);

	default:
		return uc_new_double(is_sub ? -d : d);
	}
}

static struct json_object *
uc_execute_arith(struct uc_state *state, uint32_t off)
{
	int type = OP_TYPE(off);
	struct json_object *v[2], *rv;
	enum json_type t1, t2;
	const char *s1, *s2;
	size_t len1, len2;
	int64_t n1, n2;
	double d1, d2;
	char *s;

	if (!OPn(off, 1))
		return uc_execute_unary_plus_minus(state, off);

	uc_get_operands(state, off, v);

	if (type == T_ADD &&
	    (json_object_is_type(v[0], json_type_string) ||
	     json_object_is_type(v[1], json_type_string))) {
		s1 = v[0] ? json_object_get_string(v[0]) : "null";
		s2 = v[1] ? json_object_get_string(v[1]) : "null";
		len1 = strlen(s1);
		len2 = strlen(s2);
		s = xalloc(len1 + len2 + 1);

		snprintf(s, len1 + len2 + 1, "%s%s", s1, s2);

		rv = xjs_new_string(s);

		json_object_put(v[0]);
		json_object_put(v[1]);
		free(s);

		return rv;
	}

	t1 = uc_cast_number(v[0], &n1, &d1);
	t2 = uc_cast_number(v[1], &n2, &d2);

	json_object_put(v[0]);
	json_object_put(v[1]);

	if (t1 == json_type_double || t2 == json_type_double) {
		d1 = (t1 == json_type_double) ? d1 : (double)n1;
		d2 = (t2 == json_type_double) ? d2 : (double)n2;

		switch (type) {
		case T_ADD:
			return uc_new_double(d1 + d2);

		case T_SUB:
			return uc_new_double(d1 - d2);

		case T_MUL:
			return uc_new_double(d1 * d2);

		case T_DIV:
			if (d2 == 0.0)
				return uc_new_double(INFINITY);
			else if (isnan(d2))
				return uc_new_double(NAN);
			else if (!isfinite(d2))
				return uc_new_double(isfinite(d1) ? 0.0 : NAN);

			return uc_new_double(d1 / d2);

		case T_MOD:
			return uc_new_double(NAN);
		}
	}

	switch (type) {
	case T_ADD:
		return xjs_new_int64(n1 + n2);

	case T_SUB:
		return xjs_new_int64(n1 - n2);

	case T_MUL:
		return xjs_new_int64(n1 * n2);

	case T_DIV:
		if (n2 == 0)
			return uc_new_double(INFINITY);

		return xjs_new_int64(n1 / n2);

	case T_MOD:
		return xjs_new_int64(n1 % n2);
	}

	return uc_new_double(NAN);
}

static struct json_object *
uc_execute_bitop(struct uc_state *state, uint32_t off)
{
	struct json_object *v[2];
	int64_t n1, n2;
	double d;

	uc_get_operands(state, off, v);

	if (uc_cast_number(v[0], &n1, &d) == json_type_double)
		n1 = isnan(d) ? 0 : (int64_t)d;

	if (uc_cast_number(v[1], &n2, &d) == json_type_double)
		n2 = isnan(d) ? 0 : (int64_t)d;

	json_object_put(v[0]);
	json_object_put(v[1]);

	switch (OP_TYPE(off)) {
	case T_LSHIFT:
		return xjs_new_int64(n1 << n2);

	case T_RSHIFT:
		return xjs_new_int64(n1 >> n2);

	case T_BAND:
		return xjs_new_int64(n1 & n2);

	case T_BXOR:
		return xjs_new_int64(n1 ^ n2);

	case T_BOR:
		return xjs_new_int64(n1 | n2);

	default:
		return NULL;
	}
}

static struct json_object *
uc_execute_not(struct uc_state *state, uint32_t off)
{
	return xjs_new_boolean(!uc_test_condition(state, OPn(off, 0)));
}

static struct json_object *
uc_execute_compl(struct uc_state *state, uint32_t off)
{
	struct json_object *v[1];
	int64_t n;
	double d;

	uc_get_operands(state, off, v);

	if (uc_cast_number(v[0], &n, &d) == json_type_double)
		n = isnan(d) ? 0 : (int64_t)d;

	json_object_put(v[0]);

	return xjs_new_int64(~n);
}

static void
uc_free_tag(struct json_object *v, void *ud)
{
	free(ud);
}

static struct json_object *
uc_execute_return(struct uc_state *state, uint32_t off)
{
	struct uc_op *cpy = xalloc(sizeof(*cpy));
	struct json_object *v[1], *rv;

	memcpy(cpy, OP(off), sizeof(*cpy));
	cpy->off = off;

	uc_get_operands(state, off, v);

	json_object_put(state->rval);
	state->rval = v[0];

	rv = xjs_new_boolean(false);

	json_object_set_userdata(rv, cpy, uc_free_tag);

	return rv;
}

static struct json_object *
uc_execute_break_cont(struct uc_state *state, uint32_t off)
{
	struct uc_op *cpy = xalloc(sizeof(*cpy));
	struct json_object *rv = xjs_new_int64(0);

	memcpy(cpy, OP(off), sizeof(*cpy));
	cpy->off = off;

	json_object_set_userdata(rv, cpy, uc_free_tag);

	return rv;
}

static struct json_object *
uc_execute_function(struct uc_state *state, uint32_t off)
{
	struct json_object *obj = uc_new_func(state, off, state->scope);
	struct json_object *val = OPn_VAL(off, 0);

	if (val)
		uc_setval(state->scope->scope, val, obj);

	return obj;
}

static struct json_object *
uc_execute_this(struct uc_state *state, uint32_t off)
{
	return json_object_get(state->callstack->ctx);
}

static struct json_object *
uc_execute_try_catch(struct uc_state *state, uint32_t off)
{
	struct json_object *evar, *rv;
	struct uc_op *tag;

	rv = uc_execute_op_sequence(state, OPn(off, 0));

	if (uc_is_type(rv, T_EXCEPTION)) {
		evar = OPn_VAL(off, 1);

		if (evar) {
			/* remove the T_EXCEPTION type from the object to avoid handling
			 * it as a new exception in the catch block */
			tag = json_object_get_userdata(rv);
			tag->type = T_LBRACE;

			json_object_put(uc_setval(state->scope->scope, evar,
			                json_object_get(rv)));
		}

		json_object_put(state->exception);
		state->exception = NULL;

		json_object_put(rv);
		rv = uc_execute_op_sequence(state, OPn(off, 2));
	}

	return rv;
}

static bool
uc_match_case(struct uc_state *state, struct json_object *v, uint32_t case_off)
{
	struct json_object *caseval = uc_execute_op_sequence(state, OPn(case_off, 0));
	bool rv = uc_eq(v, caseval);

	json_object_put(caseval);
	return rv;
}

static struct json_object *
uc_execute_switch_case(struct uc_state *state, uint32_t off)
{
	uint32_t case_off, default_off = 0, jmp_off = 0;
	struct json_object *v[1], *rv = NULL;

	uc_get_operands(state, off, v);

	/* First try to find matching case... */
	for (case_off = OPn(off, 1); case_off != 0; case_off = OP_NEXT(case_off)) {
		/* remember default case and throw on dupes */
		if (OP_TYPE(case_off) == T_DEFAULT) {
			if (default_off) {
				json_object_put(v[0]);

				return uc_new_exception(state, OP_POS(case_off),
				                        "Syntax error: more than one switch default case");
			}

			default_off = case_off;
			continue;
		}

		/* Found a matching case, remember jump offset */
		if (uc_match_case(state, v[0], case_off)) {
			jmp_off = case_off;
			break;
		}
	}

	/* jump to matching case (or default) and continue until break */
	for (case_off = jmp_off ? jmp_off : default_off; case_off != 0; case_off = OP_NEXT(case_off)) {
		json_object_put(rv);

		if (OP_TYPE(case_off) == T_DEFAULT)
			rv = uc_execute_op_sequence(state, OPn(case_off, 0));
		else
			rv = uc_execute_op_sequence(state, OPn(case_off, 1));

		if (uc_is_type(rv, T_BREAK)) {
			json_object_put(rv);
			rv = NULL;
			break;
		}
		else if (uc_is_type(rv, T_RETURN) || uc_is_type(rv, T_EXCEPTION) || uc_is_type(rv, T_CONTINUE)) {
			break;
		}
	}

	json_object_put(v[0]);

	return rv;
}

static struct json_object *
uc_execute_atom(struct uc_state *state, uint32_t off)
{
	return json_object_get(OP_VAL(off));
}

static struct json_object *
uc_execute_text(struct uc_state *state, uint32_t off)
{
	printf("%s", json_object_get_string(OP_VAL(off)));

	return NULL;
}

static struct json_object *
uc_execute_label(struct uc_state *state, uint32_t off)
{
	struct json_object *scope, *key, *val;

	scope = uc_getref(state, off, &key);

	json_object_put(state->ctx);
	state->ctx = NULL;

	if (state->strict_declarations && scope == NULL) {
		return uc_new_exception(state, OP_POS(off),
		                        "Reference error: %s is not defined",
		                        json_object_get_string(OP_VAL(off)));
	}

	val = uc_getval(scope, key);
	json_object_put(scope);
	json_object_put(key);

	return val;
}

static struct json_object *
uc_execute_dot(struct uc_state *state, uint32_t off)
{
	struct json_object *scope, *key, *val;

	scope = uc_getref_required(state, off, &key);

	json_object_put(state->ctx);
	state->ctx = json_object_get(scope);

	if (!key)
		return scope;

	val = uc_getval(scope, key);
	json_object_put(scope);
	json_object_put(key);

	return val;
}

static struct json_object *
uc_execute_lbrack(struct uc_state *state, uint32_t off)
{
	/* postfix access */
	if (OP_IS_POSTFIX(off))
		return uc_execute_dot(state, off);

	return uc_execute_list(state, OPn(off, 0));
}

static struct json_object *
uc_execute_exp_list(struct uc_state *state, uint32_t off)
{
	return uc_execute_op_sequence(state, OPn(off, 0));
}

static struct json_object *(*fns[__T_MAX])(struct uc_state *, uint32_t) = {
	[T_NUMBER]   = uc_execute_atom,
	[T_DOUBLE]   = uc_execute_atom,
	[T_STRING]   = uc_execute_atom,
	[T_REGEXP]   = uc_execute_atom,
	[T_BOOL]     = uc_execute_atom,
	[T_NULL]     = uc_execute_atom,
	[T_THIS]     = uc_execute_this,
	[T_FUNC]     = uc_execute_function,
	[T_ARROW]    = uc_execute_function,
	[T_TEXT]     = uc_execute_text,
	[T_ASSIGN]   = uc_execute_assign,
	[T_LOCAL]    = uc_execute_local,
	[T_LABEL]    = uc_execute_label,
	[T_DOT]      = uc_execute_dot,
	[T_LBRACK]   = uc_execute_lbrack,
	[T_LBRACE]   = uc_execute_object,
	[T_IF]       = uc_execute_if,
	[T_ELIF]     = uc_execute_if,
	[T_QMARK]    = uc_execute_if,
	[T_FOR]      = uc_execute_for,
	[T_WHILE]    = uc_execute_while,
	[T_AND]      = uc_execute_and_or,
	[T_OR]       = uc_execute_and_or,
	[T_LT]       = uc_execute_rel,
	[T_LE]       = uc_execute_rel,
	[T_GT]       = uc_execute_rel,
	[T_GE]       = uc_execute_rel,
	[T_EQ]       = uc_execute_rel,
	[T_NE]       = uc_execute_rel,
	[T_EQS]      = uc_execute_equality,
	[T_NES]      = uc_execute_equality,
	[T_IN]       = uc_execute_in,
	[T_INC]      = uc_execute_inc_dec,
	[T_DEC]      = uc_execute_inc_dec,
	[T_LPAREN]   = uc_execute_call,
	[T_LEXP]     = uc_execute_exp,
	[T_ADD]      = uc_execute_arith,
	[T_SUB]      = uc_execute_arith,
	[T_MUL]      = uc_execute_arith,
	[T_DIV]      = uc_execute_arith,
	[T_MOD]      = uc_execute_arith,
	[T_LSHIFT]   = uc_execute_bitop,
	[T_RSHIFT]   = uc_execute_bitop,
	[T_BAND]     = uc_execute_bitop,
	[T_BXOR]     = uc_execute_bitop,
	[T_BOR]      = uc_execute_bitop,
	[T_COMPL]    = uc_execute_compl,
	[T_NOT]      = uc_execute_not,
	[T_RETURN]   = uc_execute_return,
	[T_BREAK]    = uc_execute_break_cont,
	[T_CONTINUE] = uc_execute_break_cont,
	[T_TRY]      = uc_execute_try_catch,
	[T_SWITCH]   = uc_execute_switch_case,
	[T_COMMA]    = uc_execute_exp_list,
};

static struct json_object *
uc_execute_op(struct uc_state *state, uint32_t off)
{
	int type = OP_TYPE(off);

	if (!fns[type])
		return uc_new_exception(state, OP_POS(off),
		                        "Runtime error: Unrecognized opcode %d", type);

	return fns[type](state, off);
}

static struct json_object *
uc_execute_op_sequence(struct uc_state *state, uint32_t off)
{
	struct json_object *v = NULL;
	struct uc_op *tag = NULL;

	while (off) {
		json_object_put(v);

		v = uc_execute_op(state, off);
		tag = v ? json_object_get_userdata(v) : NULL;

		switch (tag ? tag->type : 0) {
		case T_BREAK:
		case T_CONTINUE:
		case T_RETURN:
		case T_EXCEPTION:
			return v;
		}

		off = OP_NEXT(off);
	}

	return v;
}

static void
uc_globals_init(struct uc_state *state, struct json_object *scope)
{
	struct json_object *arr = xjs_new_array();
	const char *p, *last;

	for (p = last = LIB_SEARCH_PATH;; p++) {
		if (*p == ':' || *p == '\0') {
			json_object_array_add(arr, xjs_new_string_len(last, p - last));

			if (!*p)
				break;

			last = p + 1;
		}
	}

	json_object_object_add(scope, "REQUIRE_SEARCH_PATH", arr);
}

static void
uc_register_variable(struct json_object *scope, const char *key, struct json_object *val)
{
	char *name = strdup(key);
	char *p;

	if (!name)
		return;

	for (p = name; *p; p++)
		if (!isalnum(*p) && *p != '_')
			*p = '_';

	json_object_object_add(scope, name, val);
	free(name);
}

struct json_object *
uc_run(struct uc_state *state, struct json_object *env, struct json_object *modules)
{
	struct json_object *args, *rv;
	struct uc_function fn = {};
	size_t i;

	state->scope = uc_new_scope(state, NULL);
	state->ctx = NULL;

	fn.source = state->source;
	state->function = &fn;

	if (env) {
		json_object_object_foreach(env, key, val)
			uc_register_variable(state->scope->scope, key, json_object_get(val));
	}

	uc_globals_init(state, state->scope->scope);
	uc_lib_init(state, state->scope->scope);

	if (modules) {
		args = xjs_new_array();

		for (i = 0; i < json_object_array_length(modules); i++) {
			json_object_array_put_idx(args, 0, json_object_get(json_object_array_get_idx(modules, i)));

			rv = uc_invoke(state, 0, NULL,
			               json_object_object_get(state->scope->scope, "require"),
			               args);

			if (uc_is_type(rv, T_EXCEPTION))
				goto out;

			uc_register_variable(state->scope->scope,
			                     json_object_get_string(json_object_array_get_idx(modules, i)),
			                     rv);
		}

		json_object_put(args);
	}

	rv = uc_execute_source(state, state->source, state->scope);

out:
	uc_release_scope(state->scope);

	return rv;
}
