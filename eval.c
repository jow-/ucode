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

char exception_tag_space[sizeof(struct ut_op) + sizeof(struct ut_op *)];
static struct ut_op *exception_tag = (struct ut_op *)exception_tag_space;

__attribute__((format(printf, 3, 0))) struct json_object *
ut_exception(struct ut_state *state, uint32_t off, const char *fmt, ...)
{
	struct json_object *msg;
	va_list ap;
	char *s;
	int len;

	va_start(ap, fmt);
	len = vasprintf(&s, fmt, ap);
	va_end(ap);

	if (len < 0) {
		msg = json_object_new_string(UT_ERRMSG_OOM);
	}
	else {
		msg = json_object_new_string_len(s, len);
		free(s);
	}

 	exception_tag->type = T_EXCEPTION;
	exception_tag->tree.operand[0] = off;

	json_object_set_userdata(msg, exception_tag, NULL);

	state->error.code = UT_ERROR_EXCEPTION;
	state->error.info.exception = msg;

	return json_object_get(msg);
}

bool
ut_val_is_truish(struct json_object *val)
{
	struct ut_op *tag = json_object_get_userdata(val);
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
ut_cast_number(struct json_object *v, int64_t *n, double *d)
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
ut_getscope(struct ut_state *state, uint8_t depth)
{
	if (depth >= state->stack.off)
		return NULL;

	return state->stack.scope[state->stack.off - depth - 1];
}

static struct json_object *
ut_addscope(struct ut_state *state, uint32_t decl)
{
	struct json_object *scope, **tmp;

	if (state->stack.off >= 255)
		return ut_exception(state, decl, "Runtime error: Too much recursion");

	if (state->stack.off >= state->stack.size) {
		tmp = realloc(state->stack.scope, (state->stack.size + 1) * sizeof(*state->stack.scope));

		if (!tmp)
			return ut_exception(state, decl, UT_ERRMSG_OOM);

		state->stack.scope = tmp;
		state->stack.size++;
	}

	scope = ut_new_object(state, NULL);

	if (!scope)
		return ut_exception(state, decl, UT_ERRMSG_OOM);

	state->stack.scope[state->stack.off++] = scope;

	return scope;
}

void
ut_putval(struct json_object *val)
{
	struct ut_op *tag = json_object_get_userdata(val);

	if (tag && tag->val != val)
		json_object_put(tag->val);

	json_object_put(val);
}

static struct json_object *
ut_execute_op(struct ut_state *state, uint32_t off);

static char *
ut_ref_to_str(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct ut_op *op2 = ut_get_child(state, off, 1);
	const char *l;
	size_t n1, n2;
	char *s, *p;

	switch (op ? op->type : 0) {
	case T_DOT:
		s = ut_ref_to_str(state, op->tree.operand[0]);
		n1 = strlen(s ? s : "(null)");

		l = ((op2 ? op2->type : 0) == T_LABEL) ? json_object_get_string(op2->val) : "???";
		n2 = strlen(l);

		p = calloc(1, n1 + n2 + 2);

		if (!p)
			return NULL;

		snprintf(p, n1 + n2 + 2, "%s.%s", s ? s : "(null)", l);
		free(s);

		return p;

	case T_LBRACK:
		if (!op->is_postfix)
			return NULL;

		s = ut_ref_to_str(state, op->tree.operand[0]);
		n1 = strlen(s ? s : "(null)");

		l = "...";
		n2 = strlen(l);

		p = calloc(1, n1 + n2 + 3);

		if (!p)
			return NULL;

		snprintf(p, n1 + n2 + 3, "%s[%s]", s, l);
		free(s);

		return p;

	case T_LABEL:
		return strdup(json_object_get_string(op->val));

	default:
		return NULL;
	}
}

static struct json_object *
ut_getref(struct ut_state *state, uint32_t off, struct json_object **key)
{
	struct ut_op *op = ut_get_op(state, off);
	uint32_t off1 = op ? op->tree.operand[0] : 0;
	uint32_t off2 = op ? op->tree.operand[1] : 0;
	struct json_object *scope, *next;
	uint8_t i;

	if (op && op->type == T_DOT) {
		*key = off2 ? ut_get_op(state, off2)->val : NULL;

		return ut_execute_op(state, off1);
	}
	else if (op && op->type == T_LBRACK && op->is_postfix) {
		*key = off2 ? ut_execute_op(state, off2) : NULL;

		return ut_execute_op(state, off1);
	}
	else if (op && op->type == T_LABEL) {
		i = 0;
		scope = ut_getscope(state, i);

		while (true) {
			if (json_object_object_get_ex(scope, json_object_get_string(op->val), NULL))
				break;

			next = ut_getscope(state, ++i);

			if (!next)
				break;

			scope = next;
		}

		*key = op->val;

		return json_object_get(scope);
	}
	else {
		*key = NULL;

		return NULL;
	}
}

static struct json_object *
ut_getref_required(struct ut_state *state, uint32_t off, struct json_object **key)
{
	struct ut_op *op = ut_get_op(state, off);
	uint32_t off1 = op ? op->tree.operand[0] : 0;
	struct json_object *scope, *skey, *rv;
	char *lhs;

	scope = ut_getref(state, off, &skey);

	if (!json_object_is_type(scope, json_type_array) &&
		!json_object_is_type(scope, json_type_object)) {
		lhs = off1 ? ut_ref_to_str(state, off1) : NULL;

		if (lhs) {
			rv = ut_exception(state, off1, "Type error: %s is null", lhs);

			free(lhs);
		}
		else {
			rv = ut_exception(state, off,
				"Syntax error: Invalid left-hand side operand %s", tokennames[op->type]);
		}

		json_object_put(scope);

		*key = NULL;
		return rv;
	}

	*key = skey;
	return scope;
}

static struct json_object *
ut_getproto(struct json_object *obj)
{
	struct ut_op *op = json_object_get_userdata(obj);

	if (!op || (op->type != T_LBRACE && op->type <= __T_MAX) || !op->val)
		return NULL;

	return op->tag.proto;
}

static struct json_object *
ut_getval(struct json_object *scope, struct json_object *key)
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

			if (ceil(d) != d)
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

	for (o = scope; o; o = ut_getproto(o)) {
		if (!json_object_is_type(o, json_type_object))
			continue;

		if (json_object_object_get_ex(o, key ? json_object_get_string(key) : "null", &v))
			return json_object_get(v);
	}

	return NULL;
}

static struct json_object *
ut_setval(struct json_object *scope, struct json_object *key, struct json_object *val)
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
ut_execute_assign(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	uint32_t label = op ? op->tree.operand[0] : 0;
	uint32_t value = op ? op->tree.operand[1] : 0;
	struct json_object *scope, *key, *val;

	scope = ut_getref_required(state, label, &key);

	if (!key)
		return scope;

	val = ut_setval(scope, key, ut_execute_op(state, value));
	ut_putval(scope);

	return val;
}

static struct json_object *
ut_execute_local(struct ut_state *state, uint32_t off)
{
	struct ut_op *as = ut_get_child(state, off, 0);
	struct json_object *rv = NULL;
	struct ut_op *label;

	while (as) {
		label = ut_get_op(state, as->tree.operand[0]);

		if (label)
			rv = ut_setval(
				state->stack.scope[state->stack.off-1], label->val,
				as->tree.operand[1] ? ut_execute_op(state, as->tree.operand[1]) : NULL);

		as = ut_get_op(state, as->tree.next);
	}

	return rv;
}

static struct json_object *
ut_execute_op_sequence(struct ut_state *state, uint32_t off);

static bool
ut_test_condition(struct ut_state *state, uint32_t off)
{
	struct json_object *val = ut_execute_op_sequence(state, off);
	bool istrue = ut_val_is_truish(val);

	ut_putval(val);

	return istrue;
}

static struct json_object *
ut_execute_if(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	uint32_t cond = op ? op->tree.operand[0] : 0;
	uint32_t Then = op ? op->tree.operand[1] : 0;
	uint32_t Else = op ? op->tree.operand[2] : 0;

	if (ut_test_condition(state, cond))
		return ut_execute_op_sequence(state, Then);
	else if (Else)
		return ut_execute_op_sequence(state, Else);

	return NULL;
}

static struct json_object *
ut_execute_for(struct ut_state *state, uint32_t off)
{
	struct json_object *ivar, *val, *item, *rv = NULL;
	struct ut_op *init = ut_get_child(state, off, 0);
	struct ut_op *test = ut_get_child(state, off, 1);
	struct ut_op *incr = ut_get_child(state, off, 2);
	struct ut_op *body = ut_get_child(state, off, 3);
	struct ut_op *tag;
	size_t arridx, arrlen;

	/* for (x in ...) loop variant */
	if (init != NULL && test == NULL && incr == NULL) {
		if (init->type != T_IN)
			return ut_exception(state, ut_get_off(state, init),
			                    "Syntax error: missing ';' after for loop initializer");

		ivar = ut_get_op(state, init->tree.operand[0])->val;
		val = ut_execute_op(state, init->tree.operand[1]);

		if (json_object_is_type(val, json_type_array)) {
			for (arridx = 0, arrlen = json_object_array_length(val);
			     arridx < arrlen; arridx++) {
				item = json_object_array_get_idx(val, arridx);

				ut_setval(ut_getscope(state, 0), ivar, item);
				ut_putval(rv);

				rv = ut_execute_op_sequence(state, ut_get_off(state, body));
				tag = json_object_get_userdata(rv);

				switch (tag ? tag->type : 0) {
				case T_RETURN:
				case T_EXCEPTION:
					ut_putval(val);

					return rv;

				case T_BREAK:
					ut_putval(val);
					ut_putval(rv);

					return NULL;
				}
			}
		}
		else if (json_object_is_type(val, json_type_object)) {
			json_object_object_foreach(val, key, item) {
				ut_setval(ut_getscope(state, 0), ivar, json_object_new_string(key));
				ut_putval(rv);

				rv = ut_execute_op_sequence(state, ut_get_off(state, body));
				tag = json_object_get_userdata(rv);

				switch (tag ? tag->type : 0) {
				case T_RETURN:
				case T_EXCEPTION:
					ut_putval(val);

					return rv;

				case T_BREAK:
					ut_putval(val);
					ut_putval(rv);

					return NULL;
				}
			}
		}

		ut_putval(val);
		ut_putval(rv);

		return NULL;
	}

	if (init)
		ut_putval(ut_execute_op_sequence(state, ut_get_off(state, init)));

	while (test ? ut_test_condition(state, ut_get_off(state, test)) : true) {
		ut_putval(rv);

		rv = ut_execute_op_sequence(state, ut_get_off(state, body));
		tag = json_object_get_userdata(rv);

		switch (tag ? tag->type : 0) {
		case T_RETURN:
		case T_EXCEPTION:
			return rv;

		case T_BREAK:
			ut_putval(rv);

			return NULL;
		}

		if (incr)
			ut_putval(ut_execute_op_sequence(state, ut_get_off(state, incr)));
	}

	ut_putval(rv);

	return NULL;
}

static struct json_object *
ut_execute_while(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	uint32_t test = op ? op->tree.operand[0] : 0;
	uint32_t body = op ? op->tree.operand[1] : 0;
	struct json_object *v, *rv = NULL;
	struct ut_op *tag = NULL;
	bool cond;

	while (1) {
		v = test ? ut_execute_op_sequence(state, test) : NULL;
		cond = test ? ut_val_is_truish(v) : true;

		ut_putval(rv);
		ut_putval(v);

		if (!cond)
			return NULL;

		rv = ut_execute_op_sequence(state, body);
		tag = json_object_get_userdata(rv);

		switch (tag ? tag->type : 0) {
		case T_RETURN:
		case T_EXCEPTION:
			return rv;

		case T_BREAK:
			ut_putval(rv);

			return NULL;
		}
	}

	ut_putval(rv);

	return NULL;
}

static struct json_object *
ut_execute_and_or(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *val = NULL;
	int i;

	for (i = 0; i < ARRAY_SIZE(op->tree.operand) && op->tree.operand[i]; i++) {
		ut_putval(val);

		val = ut_execute_op(state, op->tree.operand[i]);

		if (ut_val_is_truish(val) == (op->type == T_OR))
			break;
	}

	return val;
}

bool
ut_cmp(int how, struct json_object *v1, struct json_object *v2)
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
			t1 = ut_cast_number(v1, &n1, &d1);
			t2 = ut_cast_number(v2, &n2, &d2);

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
ut_execute_rel(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	uint32_t off1 = op ? op->tree.operand[0] : 0;
	uint32_t off2 = op ? op->tree.operand[1] : 0;
	struct json_object *v1 = ut_execute_op(state, off1);
	struct json_object *v2 = ut_execute_op(state, off2);
	struct json_object *rv;

	rv = json_object_new_boolean(ut_cmp(op->type, v1, v2));

	ut_putval(v1);
	ut_putval(v2);

	return rv;
}

static struct json_object *
ut_execute_in(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *op1 = ut_execute_op(state, op ? op->tree.operand[0] : 0);
	struct json_object *op2 = ut_execute_op(state, op ? op->tree.operand[1] : 0);
	struct json_object *item;
	size_t arrlen, arridx;
	bool found = false;
	const char *key;

	if (json_object_is_type(op2, json_type_array)) {
		for (arridx = 0, arrlen = json_object_array_length(op2);
		     arridx < arrlen; arridx++) {
			item = json_object_array_get_idx(op2, arridx);

			if (ut_cmp(T_EQ, op1, item)) {
				found = true;
				break;
			}
		}
	}
	else if (json_object_is_type(op2, json_type_object)) {
		key = op1 ? json_object_get_string(op1) : "null";
		found = json_object_object_get_ex(op2, key, NULL);
	}

	ut_putval(op1);
	ut_putval(op2);

	return json_object_new_boolean(found);
}

static struct json_object *
ut_execute_inc_dec(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *val, *nval, *scope, *key;
	uint32_t label = op ? op->tree.operand[0] : 0;
	int64_t n;
	double d;

	scope = ut_getref_required(state, label, &key);

	if (!key)
		return scope;

	val = ut_getval(scope, key);

	ut_putval(scope);

	if (ut_cast_number(val, &n, &d) == json_type_double)
		nval = ut_new_double(d + (op->type == T_INC ? 1.0 : -1.0));
	else
		nval = json_object_new_int64(n + (op->type == T_INC ? 1 : -1));

	ut_putval(ut_setval(scope, key, nval));

	/* postfix inc/dec, return old val */
	if (op->is_postfix)
		return val;

	ut_putval(val);

	return json_object_get(nval);
}

static struct json_object *
ut_execute_list(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *arr = json_object_new_array();

	if (!arr)
		return ut_exception(state, off, UT_ERRMSG_OOM);

	while (op) {
		json_object_array_add(arr, ut_execute_op(state, ut_get_off(state, op)));
		op = ut_get_op(state, op->tree.next);
	}

	return arr;
}

static struct json_object *
ut_execute_object(struct ut_state *state, uint32_t off)
{
	struct json_object *obj = ut_new_object(state, NULL);
	struct ut_op *key, *val;

	if (!obj)
		return ut_exception(state, off, UT_ERRMSG_OOM);

	for (key = ut_get_child(state, off, 0), val = ut_get_op(state, key ? key->tree.next : 0);
	     key != NULL && val != NULL;
	     key = ut_get_op(state, val->tree.next), val = ut_get_op(state, key ? key->tree.next : 0)) {
		json_object_object_add(obj, json_object_get_string(key->val),
			ut_execute_op(state, ut_get_off(state, val)));
	}

	return obj;
}

struct json_object *
ut_invoke(struct ut_state *state, uint32_t off, struct json_object *scope,
          struct json_object *func, struct json_object *argvals)
{
	struct ut_op *tag = json_object_get_userdata(func);
	struct ut_op *arg, *decl;
	struct json_object *s, *rv = NULL;
	size_t arridx;
	ut_c_fn *cfn;

	if (!tag)
		return NULL;

	/* is native function */
	if (tag->type == T_CFUNC) {
		cfn = (ut_c_fn *)tag->tag.data;

		return cfn ? cfn(state, off, argvals) : NULL;
	}

	decl = tag->tag.data;
	arg = ut_get_op(state, decl ? decl->tree.operand[1] : 0);

	s = scope ? scope : ut_addscope(state, ut_get_off(state, decl));

	if (!json_object_is_type(s, json_type_object))
		return s;

	for (arridx = 0; arg; arridx++, arg = ut_get_op(state, arg->tree.next))
		ut_setval(s, arg->val, argvals ? json_object_array_get_idx(argvals, arridx) : NULL);

	/* store the function "this" context in the proto member of the scope tag structure */
	tag = json_object_get_userdata(s);
	tag->tag.proto = json_object_get(state->ctx);

	rv = ut_execute_op_sequence(state, decl->tree.operand[2]);
	tag = json_object_get_userdata(rv);

	switch (tag ? tag->type : 0) {
	case T_BREAK:
	case T_CONTINUE:
		ut_putval(rv);
		rv = ut_exception(state, ut_get_off(state, tag),
		                  "Syntax error: %s statement must be inside loop",
		                  tokennames[tag->type]);
		break;

	case T_RETURN:
		/* handle magic null */
		if (json_object_is_type(rv, json_type_boolean)) {
			if (!strcmp(json_object_get_string(rv), "null")) {
				ut_putval(rv);
				rv = NULL;
			}
		}

		break;
	}

	/* we left the function, remove the "this" context from the scope tag structure */
	tag = json_object_get_userdata(s);
	json_object_put(tag->tag.proto);
	tag->tag.proto = NULL;

	if (!scope) {
		state->stack.scope[--state->stack.off] = NULL;
		json_object_put(s);
	}

	return rv;
}

static struct json_object *
ut_execute_call(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	uint32_t off1 = op ? op->tree.operand[0] : 0;
	uint32_t off2 = op ? op->tree.operand[1] : 0;
	struct json_object *func = ut_execute_op(state, off1);
	struct ut_op *decl = func ? json_object_get_userdata(func) : NULL;
	struct json_object *argvals = ut_execute_list(state, off2);
	struct json_object *rv;
	char *lhs;

	if (!decl || (decl->type != T_FUNC && decl->type != T_CFUNC)) {
		lhs = ut_ref_to_str(state, off1);
		rv = ut_exception(state, off1,
			"Type error: %s is not a function",
			lhs ? lhs : "left-hand side expression");

		free(lhs);
	}
	else {
		rv = ut_invoke(state, off, NULL, func, argvals);
	}

	ut_putval(argvals);
	ut_putval(func);

	return rv;
}

static void
ut_write_str(struct json_object *v)
{
	const char *p;
	size_t len;

	p = v ? json_object_get_string(v) : "";
	len = json_object_is_type(v, json_type_string) ? json_object_get_string_len(v) : strlen(p);

	fwrite(p, 1, len, stdout);
}

static struct json_object *
ut_execute_exp(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *val = ut_execute_op_sequence(state, op ? op->tree.operand[0] : 0);
	struct ut_op *tag = val ? json_object_get_userdata(val) : NULL;

	switch (tag ? tag->type : 0) {
	case T_RETURN:
		ut_write_str(tag->val);
		break;

	case T_BREAK:
		return val;

	case T_EXCEPTION:
		printf("<exception: %s>", json_object_get_string(val));
		break;

	default:
		ut_write_str(val);
		break;
	}

	ut_putval(val);

	return NULL;
}

static struct json_object *
ut_execute_unary_plus_minus(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct ut_op *op1 = ut_get_child(state, off, 0);
	struct json_object *val = ut_execute_op(state, op ? op->tree.operand[0] : 0);
	enum json_type t;
	int64_t n;
	double d;

	t = ut_cast_number(val, &n, &d);

	ut_putval(val);

	switch (t) {
	case json_type_int:
		if (op1->is_overflow)
			return json_object_new_int64(((n >= 0) == (op->type == T_SUB)) ? INT64_MIN : INT64_MAX);

		return json_object_new_int64((op->type == T_SUB) ? -n : n);

	default:
		return ut_new_double((op->type == T_SUB) ? -d : d);
	}
}

static struct json_object *
ut_execute_arith(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *v1, *v2, *rv;
	enum json_type t1, t2;
	const char *s1, *s2;
	size_t len1, len2;
	int64_t n1, n2;
	double d1, d2;
	char *s;

	if (!op->tree.operand[1])
		return ut_execute_unary_plus_minus(state, off);

	v1 = ut_execute_op(state, op ? op->tree.operand[0] : 0);
	v2 = ut_execute_op(state, op ? op->tree.operand[1] : 0);

	if (op->type == T_ADD &&
	    (json_object_is_type(v1, json_type_string) ||
	     json_object_is_type(v2, json_type_string))) {
		s1 = v1 ? json_object_get_string(v1) : "null";
		s2 = v2 ? json_object_get_string(v2) : "null";
		len1 = strlen(s1);
		len2 = strlen(s2);
		s = calloc(1, len1 + len2 + 1);

		if (!s) {
			ut_putval(v1);
			ut_putval(v2);

			return NULL;
		}

		snprintf(s, len1 + len2 + 1, "%s%s", s1, s2);

		rv = json_object_new_string(s);

		ut_putval(v1);
		ut_putval(v2);
		free(s);

		return rv;
	}

	t1 = ut_cast_number(v1, &n1, &d1);
	t2 = ut_cast_number(v2, &n2, &d2);

	ut_putval(v1);
	ut_putval(v2);

	if (t1 == json_type_double || t2 == json_type_double) {
		d1 = (t1 == json_type_double) ? d1 : (double)n1;
		d2 = (t2 == json_type_double) ? d2 : (double)n2;

		switch (op->type) {
		case T_ADD:
			return ut_new_double(d1 + d2);

		case T_SUB:
			return ut_new_double(d1 - d2);

		case T_MUL:
			return ut_new_double(d1 * d2);

		case T_DIV:
			if (d2 == 0.0)
				return ut_new_double(INFINITY);
			else if (isnan(d2))
				return ut_new_double(NAN);
			else if (!isfinite(d2))
				return ut_new_double(isfinite(d1) ? 0.0 : NAN);

			return ut_new_double(d1 / d2);

		case T_MOD:
			return ut_new_double(NAN);
		}
	}

	switch (op->type) {
	case T_ADD:
		return json_object_new_int64(n1 + n2);

	case T_SUB:
		return json_object_new_int64(n1 - n2);

	case T_MUL:
		return json_object_new_int64(n1 * n2);

	case T_DIV:
		if (n2 == 0)
			return ut_new_double(INFINITY);

		return json_object_new_int64(n1 / n2);

	case T_MOD:
		return json_object_new_int64(n1 % n2);
	}

	return ut_new_double(NAN);
}

static struct json_object *
ut_execute_bitop(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	uint32_t off1 = op ? op->tree.operand[0] : 0;
	uint32_t off2 = op ? op->tree.operand[1] : 0;
	struct json_object *v1, *v2;
	int64_t n1, n2;
	double d;

	v1 = off1 ? ut_execute_op(state, off1) : NULL;
	v2 = off2 ? ut_execute_op(state, off2) : NULL;

	if (ut_cast_number(v1, &n1, &d) == json_type_double)
		n1 = isnan(d) ? 0 : (int64_t)d;

	if (ut_cast_number(v2, &n2, &d) == json_type_double)
		n2 = isnan(d) ? 0 : (int64_t)d;

	ut_putval(v1);
	ut_putval(v2);

	switch (op->type) {
	case T_LSHIFT:
		return json_object_new_int64(n1 << n2);

	case T_RSHIFT:
		return json_object_new_int64(n1 >> n2);

	case T_BAND:
		return json_object_new_int64(n1 & n2);

	case T_BXOR:
		return json_object_new_int64(n1 ^ n2);

	case T_BOR:
		return json_object_new_int64(n1 | n2);

	default:
		return NULL;
	}
}

static struct json_object *
ut_execute_not(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);

	return json_object_new_boolean(!ut_test_condition(state, op ? op->tree.operand[0] : 0));
}

static struct json_object *
ut_execute_compl(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	uint32_t off1 = op ? op->tree.operand[0] : 0;
	struct json_object *val = off1 ? ut_execute_op(state, off1) : NULL;
	int64_t n;
	double d;

	if (ut_cast_number(val, &n, &d) == json_type_double)
		n = isnan(d) ? 0 : (int64_t)d;

	ut_putval(val);

	return json_object_new_int64(~n);
}

static struct json_object *
ut_execute_return(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	uint32_t off1 = op ? op->tree.operand[0] : 0;
	struct json_object *val = off1 ? ut_execute_op(state, off1) : NULL;

	if (!val)
		val = ut_new_null();

	json_object_set_userdata(val, op, NULL);

	return val;
}

static struct json_object *
ut_execute_break_cont(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *rv = json_object_new_int64(0);

	json_object_set_userdata(rv, op, NULL);

	return rv;
}

static struct json_object *
ut_execute_function(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct json_object *obj = ut_new_func(state, op);

	if (!obj)
		return ut_exception(state, off, UT_ERRMSG_OOM);

	return obj;
}

static struct json_object *
ut_execute_this(struct ut_state *state, uint32_t off)
{
	return ut_getproto(ut_getscope(state, 0));
}

static struct json_object *
ut_execute_op(struct ut_state *state, uint32_t off)
{
	struct ut_op *op = ut_get_op(state, off);
	struct ut_op *op1 = ut_get_child(state, off, 0);
	struct json_object *scope, *key, *val;

	switch (op->type) {
	case T_NUMBER:
	case T_DOUBLE:
	case T_BOOL:
	case T_STRING:
	case T_NULL:
		return json_object_get(op->val);

	case T_THIS:
		return ut_execute_this(state, off);

	case T_FUNC:
		val = ut_execute_function(state, off);

		if (op1)
			ut_setval(ut_getscope(state, 0), op1->val, val);

		return val;

	case T_TEXT:
		printf("%s", json_object_get_string(op->val));

		return NULL;

	case T_ASSIGN:
		return ut_execute_assign(state, off);

	case T_LOCAL:
		return ut_execute_local(state, off);

	case T_LABEL:
		scope = ut_getref(state, off, &key);
		state->ctx = scope;

		val = ut_getval(scope, key);
		ut_putval(scope);

		return val;

	case T_DOT:
		scope = ut_getref_required(state, off, &key);
		state->ctx = scope;

		if (!key)
			return scope;

		val = ut_getval(scope, key);
		ut_putval(scope);

		return val;

	case T_LBRACK:
		/* postfix access */
		if (op->is_postfix) {
			scope = ut_getref_required(state, off, &key);
			state->ctx = scope;

			if (!key)
				return scope;

			val = ut_getval(scope, key);
			json_object_put(scope);

			return val;
		}

		return ut_execute_list(state, ut_get_off(state, op1));

	case T_LBRACE:
		return ut_execute_object(state, off);

	case T_IF:
	case T_QMARK:
		return ut_execute_if(state, off);

	case T_FOR:
		return ut_execute_for(state, off);

	case T_WHILE:
		return ut_execute_while(state, off);

	case T_AND:
	case T_OR:
		return ut_execute_and_or(state, off);

	case T_LT:
	case T_LE:
	case T_GT:
	case T_GE:
	case T_EQ:
	case T_NE:
		return ut_execute_rel(state, off);

	case T_IN:
		return ut_execute_in(state, off);

	case T_INC:
	case T_DEC:
		return ut_execute_inc_dec(state, off);

	case T_LPAREN:
		return ut_execute_call(state, off);

	case T_LEXP:
		return ut_execute_exp(state, off);

	case T_ADD:
	case T_SUB:
	case T_MUL:
	case T_DIV:
	case T_MOD:
		return ut_execute_arith(state, off);

	case T_LSHIFT:
	case T_RSHIFT:
	case T_BAND:
	case T_BXOR:
	case T_BOR:
		return ut_execute_bitop(state, off);

	case T_COMPL:
		return ut_execute_compl(state, off);

	case T_NOT:
		return ut_execute_not(state, off);

	case T_RETURN:
		return ut_execute_return(state, off);

	case T_BREAK:
	case T_CONTINUE:
		return ut_execute_break_cont(state, off);

	default:
		return ut_exception(state, off, "Runtime error: Unrecognized opcode %d", op->type);
	}
}

static struct json_object *
ut_execute_op_sequence(struct ut_state *state, uint32_t off)
{
	struct json_object *v = NULL;
	struct ut_op *tag = NULL;
	struct ut_op *op = NULL;

	while (off) {
		ut_putval(v);

		v = ut_execute_op(state, off);
		tag = v ? json_object_get_userdata(v) : NULL;

		switch (tag ? tag->type : 0) {
		case T_BREAK:
		case T_CONTINUE:
		case T_RETURN:
		case T_EXCEPTION:
			return v;
		}

		op = ut_get_op(state, off);
		off = op ? op->tree.next : 0;
	}

	return v;
}

static void
ut_globals_init(struct ut_state *state, struct json_object *scope)
{
	struct json_object *arr = json_object_new_array();
	const char *p, *last;

	if (!arr)
		return;

	for (p = last = LIB_SEARCH_PATH;; p++) {
		if (*p == ':' || *p == '\0') {
			json_object_array_add(arr, json_object_new_string_len(last, p - last));

			if (!*p)
				break;

			last = p + 1;
		}
	}

	json_object_object_add(scope, "REQUIRE_SEARCH_PATH", arr);
}

enum ut_error_type
ut_run(struct ut_state *state)
{
	struct ut_op *op = ut_get_op(state, state->main);
	struct json_object *entry, *scope, *args, *rv;

	if (!op || op->type != T_FUNC) {
		ut_exception(state, state->main, "Runtime error: Invalid root operation in AST");

		return UT_ERROR_EXCEPTION;
	}

	entry = ut_execute_function(state, state->main);

	if (!entry)
		return UT_ERROR_EXCEPTION;

	scope = ut_addscope(state, state->main);

	if (!json_object_is_type(scope, json_type_object))
		return UT_ERROR_EXCEPTION;

	state->ctx = scope;

	ut_globals_init(state, scope);
	ut_lib_init(state, scope);

	args = json_object_new_array();
	rv = ut_invoke(state, state->main, NULL, entry, args);

	json_object_put(entry);
	json_object_put(args);
	json_object_put(rv);

	return state->error.code;
}
