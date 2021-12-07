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

#include <unistd.h>
#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "ucode/module.h"

#define err_return(err) do { last_error = err; return NULL; } while(0)

static enum ubus_msg_status last_error = 0;
static uc_resource_type_t *defer_type;
static uc_resource_type_t *conn_type;

static uc_value_t *cb_registry;
static uint64_t n_cb_active;
static bool have_own_uloop;

typedef struct {
	int timeout;
	struct blob_buf buf;
	struct ubus_context *ctx;
} ubus_connection;

typedef struct {
	struct ubus_context *context;
	struct ubus_request request;
	struct uloop_timeout timeout;
	bool complete;
	uc_vm_t *vm;
	uc_value_t *callback;
	uc_value_t *response;
} ubus_deferred;

static uc_value_t *
uc_ubus_error(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *errmsg;

	if (last_error == 0)
		return NULL;

	errmsg = ucv_string_new(ubus_strerror(last_error));
	last_error = 0;

	return errmsg;
}

static uc_value_t *
uc_blob_to_json(uc_vm_t *vm, struct blob_attr *attr, bool table, const char **name);

static uc_value_t *
uc_blob_array_to_json(uc_vm_t *vm, struct blob_attr *attr, size_t len, bool table)
{
	uc_value_t *o = table ? ucv_object_new(vm) : ucv_array_new(vm);
	uc_value_t *v;
	struct blob_attr *pos;
	size_t rem = len;
	const char *name;

	if (!o)
		return NULL;

	__blob_for_each_attr(pos, attr, rem) {
		name = NULL;
		v = uc_blob_to_json(vm, pos, table, &name);

		if (table && name)
			ucv_object_add(o, name, v);
		else if (!table)
			ucv_array_push(o, v);
		else
			ucv_put(v);
	}

	return o;
}

static uc_value_t *
uc_blob_to_json(uc_vm_t *vm, struct blob_attr *attr, bool table, const char **name)
{
	void *data;
	int len;

	if (!blobmsg_check_attr(attr, false))
		return NULL;

	if (table && blobmsg_name(attr)[0])
		*name = blobmsg_name(attr);

	data = blobmsg_data(attr);
	len = blobmsg_data_len(attr);

	switch (blob_id(attr)) {
	case BLOBMSG_TYPE_BOOL:
		return ucv_boolean_new(*(uint8_t *)data);

	case BLOBMSG_TYPE_INT16:
		return ucv_int64_new((int16_t)be16_to_cpu(*(uint16_t *)data));

	case BLOBMSG_TYPE_INT32:
		return ucv_int64_new((int32_t)be32_to_cpu(*(uint32_t *)data));

	case BLOBMSG_TYPE_INT64:
		return ucv_int64_new((int64_t)be64_to_cpu(*(uint64_t *)data));

	case BLOBMSG_TYPE_DOUBLE:
		;
		union {
			double d;
			uint64_t u64;
		} v;

		v.u64 = be64_to_cpu(*(uint64_t *)data);

		return ucv_double_new(v.d);

	case BLOBMSG_TYPE_STRING:
		return ucv_string_new(data);

	case BLOBMSG_TYPE_ARRAY:
		return uc_blob_array_to_json(vm, data, len, false);

	case BLOBMSG_TYPE_TABLE:
		return uc_blob_array_to_json(vm, data, len, true);

	default:
		return NULL;
	}
}


static uc_value_t *
uc_ubus_connect(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *socket = uc_fn_arg(0);
	uc_value_t *timeout = uc_fn_arg(1);
	uc_value_t *co;
	ubus_connection *c;

	if ((socket && ucv_type(socket) != UC_STRING) ||
	    (timeout && ucv_type(timeout) != UC_INTEGER))
		err_return(UBUS_STATUS_INVALID_ARGUMENT);

	c = calloc(1, sizeof(*c));

	if (!c)
		err_return(UBUS_STATUS_UNKNOWN_ERROR);

	c->ctx = ubus_connect(socket ? ucv_string_get(socket) : NULL);
	c->timeout = timeout ? ucv_int64_get(timeout) : 30;

	if (!c->ctx) {
		free(c);
		err_return(UBUS_STATUS_UNKNOWN_ERROR);
	}

	if (c->timeout < 0)
		c->timeout = 30;

	co = ucv_object_new(vm);

	if (!co) {
		ubus_free(c->ctx);
		free(c);
		err_return(ENOMEM);
	}

	ubus_add_uloop(c->ctx);

	return uc_resource_new(conn_type, c);
}

static void
uc_ubus_signatures_cb(struct ubus_context *c, struct ubus_object_data *o, void *p)
{
	uc_value_t *arr = p;
	uc_value_t *sig;

	if (!o->signature)
		return;

	sig = uc_blob_array_to_json(NULL, blob_data(o->signature), blob_len(o->signature), true);

	if (sig)
		ucv_array_push(arr, sig);
}

static void
uc_ubus_objects_cb(struct ubus_context *c, struct ubus_object_data *o, void *p)
{
	json_object *arr = p;
	json_object *obj;

	obj = json_object_new_string(o->path);

	if (obj)
		json_object_array_add(arr, obj);
}

static uc_value_t *
uc_ubus_list(uc_vm_t *vm, size_t nargs)
{
	ubus_connection **c = uc_fn_this("ubus.connection");
	uc_value_t *objname = uc_fn_arg(0);
	uc_value_t *res = NULL;
	enum ubus_msg_status rv;

	if (!c || !*c || !(*c)->ctx)
		err_return(UBUS_STATUS_CONNECTION_FAILED);

	if (objname && ucv_type(objname) != UC_STRING)
		err_return(UBUS_STATUS_INVALID_ARGUMENT);

	res = ucv_array_new(vm);

	if (!res)
		err_return(UBUS_STATUS_UNKNOWN_ERROR);

	rv = ubus_lookup((*c)->ctx,
	                 objname ? ucv_string_get(objname) : NULL,
	                 objname ? uc_ubus_signatures_cb : uc_ubus_objects_cb,
	                 res);

	if (rv != UBUS_STATUS_OK)
		err_return(rv);

	return res;
}

static void
uc_ubus_call_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	uc_value_t **res = (uc_value_t **)req->priv;

	*res = msg ? uc_blob_array_to_json(NULL, blob_data(msg), blob_len(msg), true) : NULL;
}

static void
uc_ubus_invoke_async_callback(ubus_deferred *defer, int ret, uc_value_t *reply)
{
	uc_resource_t *r;
	size_t i;

	if (defer->callback) {
		uc_vm_stack_push(defer->vm, ucv_get(defer->callback));
		uc_vm_stack_push(defer->vm, ucv_int64_new(ret));
		uc_vm_stack_push(defer->vm, ucv_get(reply));

		if (uc_vm_call(defer->vm, false, 2) == EXCEPTION_NONE)
			ucv_put(uc_vm_stack_pop(defer->vm));

		defer->callback = NULL;
	}

	for (i = 0; i < ucv_array_length(cb_registry); i += 2) {
		r = (uc_resource_t *)ucv_array_get(cb_registry, i);

		if (r && r->data == defer) {
			ucv_array_set(cb_registry, i, NULL);
			ucv_array_set(cb_registry, i + 1, NULL);
			break;
		}
	}

	n_cb_active--;

	if (have_own_uloop && n_cb_active == 0)
		uloop_end();
}

static void
uc_ubus_call_data_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	ubus_deferred *defer = container_of(req, ubus_deferred, request);

	if (defer->response == NULL)
		defer->response = uc_blob_array_to_json(defer->vm, blob_data(msg), blob_len(msg), true);
}

static void
uc_ubus_call_done_cb(struct ubus_request *req, int ret)
{
	ubus_deferred *defer = container_of(req, ubus_deferred, request);

	if (defer->complete)
		return;

	defer->complete = true;
	uloop_timeout_cancel(&defer->timeout);

	uc_ubus_invoke_async_callback(defer, ret, defer->response);
}

static void
uc_ubus_call_timeout_cb(struct uloop_timeout *timeout)
{
	ubus_deferred *defer = container_of(timeout, ubus_deferred, timeout);

	if (defer->complete)
		return;

	defer->complete = true;
	ubus_abort_request(defer->context, &defer->request);

	uc_ubus_invoke_async_callback(defer, UBUS_STATUS_TIMEOUT, NULL);
}

static bool
uc_ubus_have_uloop(void)
{
	bool prev = uloop_cancelled;
	bool active;

	uloop_cancelled = true;
	active = uloop_cancelling();
	uloop_cancelled = prev;

	return active;
}

static uc_value_t *
uc_ubus_call(uc_vm_t *vm, size_t nargs)
{
	ubus_connection **c = uc_fn_this("ubus.connection");
	uc_value_t *objname = uc_fn_arg(0);
	uc_value_t *funname = uc_fn_arg(1);
	uc_value_t *funargs = uc_fn_arg(2);
	uc_value_t *res = NULL;
	enum ubus_msg_status rv;
	json_object *o;
	uint32_t id;

	if (!c || !*c || !(*c)->ctx)
		err_return(UBUS_STATUS_CONNECTION_FAILED);

	if (ucv_type(objname) != UC_STRING ||
	    ucv_type(funname) != UC_STRING ||
	    (funargs && ucv_type(funargs) != UC_OBJECT))
		err_return(UBUS_STATUS_INVALID_ARGUMENT);

	blob_buf_init(&(*c)->buf, 0);

	if (funargs) {
		o = ucv_to_json(funargs);
		rv = blobmsg_add_object(&(*c)->buf, o);
		json_object_put(o);

		if (!rv)
			err_return(UBUS_STATUS_UNKNOWN_ERROR);
	}

	rv = ubus_lookup_id((*c)->ctx, ucv_string_get(objname), &id);

	if (rv != UBUS_STATUS_OK)
		err_return(rv);

	rv = ubus_invoke((*c)->ctx, id, ucv_string_get(funname), (*c)->buf.head,
	                 uc_ubus_call_cb, &res, (*c)->timeout * 1000);

	if (rv != UBUS_STATUS_OK)
		err_return(rv);

	return res;
}

static uc_value_t *
uc_ubus_defer(uc_vm_t *vm, size_t nargs)
{
	ubus_connection **c = uc_fn_this("ubus.connection");
	uc_value_t *objname = uc_fn_arg(0);
	uc_value_t *funname = uc_fn_arg(1);
	uc_value_t *funargs = uc_fn_arg(2);
	uc_value_t *replycb = uc_fn_arg(3);
	uc_value_t *res = NULL;
	enum ubus_msg_status rv;
	ubus_deferred *defer;
	json_object *o;
	uint32_t id;
	size_t i;

	if (!c || !*c || !(*c)->ctx)
		err_return(UBUS_STATUS_CONNECTION_FAILED);

	if (ucv_type(objname) != UC_STRING ||
	    ucv_type(funname) != UC_STRING ||
	    (funargs && ucv_type(funargs) != UC_OBJECT) ||
	    (replycb && !ucv_is_callable(replycb)))
		err_return(UBUS_STATUS_INVALID_ARGUMENT);

	blob_buf_init(&(*c)->buf, 0);

	if (funargs) {
		o = ucv_to_json(funargs);
		rv = blobmsg_add_object(&(*c)->buf, o);
		json_object_put(o);

		if (!rv)
			err_return(UBUS_STATUS_UNKNOWN_ERROR);
	}

	rv = ubus_lookup_id((*c)->ctx, ucv_string_get(objname), &id);

	if (rv != UBUS_STATUS_OK)
		err_return(rv);

	defer = xalloc(sizeof(*defer));

	rv = ubus_invoke_async((*c)->ctx, id, ucv_string_get(funname),
	                       (*c)->buf.head, &defer->request);

	if (rv == UBUS_STATUS_OK) {
		defer->vm = vm;
		defer->context = (*c)->ctx;
		defer->callback = replycb;

		defer->request.data_cb = uc_ubus_call_data_cb;
		defer->request.complete_cb = uc_ubus_call_done_cb;
		ubus_complete_request_async((*c)->ctx, &defer->request);

		defer->timeout.cb = uc_ubus_call_timeout_cb;
		uloop_timeout_set(&defer->timeout, (*c)->timeout * 1000);

		res = uc_resource_new(defer_type, defer);

		for (i = 0;; i += 2) {
			if (ucv_array_get(cb_registry, i) == NULL) {
				ucv_array_set(cb_registry, i, ucv_get(res));
				ucv_array_set(cb_registry, i + 1, ucv_get(replycb));
				n_cb_active++;
				break;
			}
		}

		if (!uc_ubus_have_uloop()) {
			have_own_uloop = true;
			uloop_run();
		}
	}
	else {
		uc_vm_stack_push(vm, ucv_get(replycb));
		uc_vm_stack_push(vm, ucv_int64_new(rv));

		if (uc_vm_call(vm, false, 1) == EXCEPTION_NONE)
			ucv_put(uc_vm_stack_pop(vm));

		free(defer);
	}

	if (rv != UBUS_STATUS_OK)
		err_return(rv);

	return res;
}

static uc_value_t *
uc_ubus_disconnect(uc_vm_t *vm, size_t nargs)
{
	ubus_connection **c = uc_fn_this("ubus.connection");

	if (!c || !*c || !(*c)->ctx)
		err_return(UBUS_STATUS_CONNECTION_FAILED);

	ubus_free((*c)->ctx);
	(*c)->ctx = NULL;

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_ubus_defer_complete(uc_vm_t *vm, size_t nargs)
{
	ubus_deferred **d = uc_fn_this("ubus.deferred");

	if (!d || !*d)
		return NULL;

	return ucv_boolean_new((*d)->complete);
}

static uc_value_t *
uc_ubus_defer_abort(uc_vm_t *vm, size_t nargs)
{
	ubus_deferred **d = uc_fn_this("ubus.deferred");
	uc_resource_t *r;
	size_t i;

	if (!d || !*d)
		return NULL;

	if ((*d)->complete)
		return ucv_boolean_new(false);

	ubus_abort_request((*d)->context, &(*d)->request);
	uloop_timeout_cancel(&(*d)->timeout);

	for (i = 0; i < ucv_array_length(cb_registry); i += 2) {
		r = (uc_resource_t *)ucv_array_get(cb_registry, i);

		if (r && r->data == *d) {
			ucv_array_set(cb_registry, i, NULL);
			ucv_array_set(cb_registry, i + 1, NULL);
			break;
		}
	}

	n_cb_active--;

	if (have_own_uloop && n_cb_active == 0)
		uloop_end();

	(*d)->callback = NULL;
	(*d)->complete = true;

	return ucv_boolean_new(true);
}


static const uc_function_list_t global_fns[] = {
	{ "error",		uc_ubus_error },
	{ "connect",	uc_ubus_connect },
};

static const uc_function_list_t conn_fns[] = {
	{ "list",		uc_ubus_list },
	{ "call",		uc_ubus_call },
	{ "defer",		uc_ubus_defer },
	{ "error",		uc_ubus_error },
	{ "disconnect",	uc_ubus_disconnect },
};

static const uc_function_list_t defer_fns[] = {
	{ "complete",	uc_ubus_defer_complete },
	{ "abort",		uc_ubus_defer_abort },
};


static void close_connection(void *ud) {
	ubus_connection *conn = ud;

	blob_buf_free(&conn->buf);

	if (conn->ctx)
		ubus_free(conn->ctx);

	free(conn);
}

static void close_deferred(void *ud) {
	ubus_deferred *defer = ud;

	uloop_timeout_cancel(&defer->timeout);
	ucv_put(defer->response);
	free(defer);
}

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, global_fns);

	conn_type = uc_type_declare(vm, "ubus.connection", conn_fns, close_connection);
	defer_type = uc_type_declare(vm, "ubus.deferred", defer_fns, close_deferred);
	cb_registry = ucv_array_new(vm);

	uc_vm_registry_set(vm, "ubus.cb_registry", cb_registry);
}
