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

#include "../module.h"

#define err_return(err) do { last_error = err; return NULL; } while(0)

static enum ubus_msg_status last_error = 0;
static uc_ressource_type_t *conn_type;

typedef struct {
	int timeout;
	struct blob_buf buf;
	struct ubus_context *ctx;
} ubus_connection;

static uc_value_t *
uc_ubus_error(uc_vm *vm, size_t nargs)
{
	uc_value_t *errmsg;

	if (last_error == 0)
		return NULL;

	errmsg = ucv_string_new(ubus_strerror(last_error));
	last_error = 0;

	return errmsg;
}

static uc_value_t *
uc_blob_to_json(uc_vm *vm, struct blob_attr *attr, bool table, const char **name);

static uc_value_t *
uc_blob_array_to_json(uc_vm *vm, struct blob_attr *attr, size_t len, bool table)
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
uc_blob_to_json(uc_vm *vm, struct blob_attr *attr, bool table, const char **name)
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
		return ucv_int64_new((int64_t)be16_to_cpu(*(uint16_t *)data));

	case BLOBMSG_TYPE_INT32:
		return ucv_int64_new((int64_t)be32_to_cpu(*(uint32_t *)data));

	case BLOBMSG_TYPE_INT64:
		return ucv_uint64_new(be64_to_cpu(*(uint64_t *)data));

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
uc_ubus_connect(uc_vm *vm, size_t nargs)
{
	uc_value_t *socket = uc_get_arg(0);
	uc_value_t *timeout = uc_get_arg(1);
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

	return uc_alloc_ressource(conn_type, c);
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
uc_ubus_list(uc_vm *vm, size_t nargs)
{
	ubus_connection **c = uc_get_self("ubus.connection");
	uc_value_t *objname = uc_get_arg(0);
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

static uc_value_t *
uc_ubus_call(uc_vm *vm, size_t nargs)
{
	ubus_connection **c = uc_get_self("ubus.connection");
	uc_value_t *objname = uc_get_arg(0);
	uc_value_t *funname = uc_get_arg(1);
	uc_value_t *funargs = uc_get_arg(2);
	uc_value_t *res = NULL;
	json_object *o;
	enum ubus_msg_status rv;
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
uc_ubus_disconnect(uc_vm *vm, size_t nargs)
{
	ubus_connection **c = uc_get_self("ubus.connection");

	if (!c || !*c || !(*c)->ctx)
		err_return(UBUS_STATUS_CONNECTION_FAILED);

	ubus_free((*c)->ctx);
	(*c)->ctx = NULL;

	return ucv_boolean_new(true);
}


static const uc_cfunction_list global_fns[] = {
	{ "error",		uc_ubus_error },
	{ "connect",	uc_ubus_connect },
};

static const uc_cfunction_list conn_fns[] = {
	{ "list",		uc_ubus_list },
	{ "call",		uc_ubus_call },
	{ "error",		uc_ubus_error },
	{ "disconnect",	uc_ubus_disconnect },
};


static void close_connection(void *ud) {
	ubus_connection *conn = ud;

	blob_buf_free(&conn->buf);

	if (conn->ctx)
		ubus_free(conn->ctx);

	free(conn);
}

void uc_module_init(uc_value_t *scope)
{
	uc_add_proto_functions(scope, global_fns);

	conn_type = uc_declare_type("ubus.connection", conn_fns, close_connection);
}
