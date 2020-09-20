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

#include "../module.h"

#include <unistd.h>
#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#define err_return(err) do { last_error = err; return NULL; } while(0)

static const struct ut_ops *ops;

static enum ubus_msg_status last_error = 0;

struct ubus_connection {
	int timeout;
	struct blob_buf buf;
	struct ubus_context *ctx;
};

static struct json_object *
ut_ubus_error(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *errmsg;

	if (last_error == 0)
		return NULL;

	errmsg = json_object_new_string(ubus_strerror(last_error));
	last_error = 0;

	return errmsg;
}

static struct json_object *
ut_blob_to_json(struct blob_attr *attr, bool table, const char **name);

static struct json_object *
ut_blob_array_to_json(struct blob_attr *attr, size_t len, bool table)
{
	struct json_object *o = table ? json_object_new_object() : json_object_new_array();
	struct json_object *v;
	struct blob_attr *pos;
	size_t rem = len;
	const char *name;

	if (!o)
		return NULL;

	__blob_for_each_attr(pos, attr, rem) {
		name = NULL;
		v = ut_blob_to_json(pos, table, &name);

		if (table && name)
			json_object_object_add(o, name, v);
		else if (!table)
			json_object_array_add(o, v);
		else
			json_object_put(v);
	}

	return o;
}

static struct json_object *
ut_blob_to_json(struct blob_attr *attr, bool table, const char **name)
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
		return json_object_new_boolean(*(uint8_t *)data);

	case BLOBMSG_TYPE_INT16:
		return json_object_new_int64((int64_t)be16_to_cpu(*(uint16_t *)data));

	case BLOBMSG_TYPE_INT32:
		return json_object_new_int64((int64_t)be32_to_cpu(*(uint32_t *)data));

	case BLOBMSG_TYPE_INT64:
		return json_object_new_uint64(be64_to_cpu(*(uint64_t *)data));

	case BLOBMSG_TYPE_DOUBLE:
		;
		union {
			double d;
			uint64_t u64;
		} v;

		v.u64 = be64_to_cpu(*(uint64_t *)data);

		return json_object_new_double(v.d);

	case BLOBMSG_TYPE_STRING:
		return json_object_new_string(data);

	case BLOBMSG_TYPE_ARRAY:
		return ut_blob_array_to_json(data, len, false);

	case BLOBMSG_TYPE_TABLE:
		return ut_blob_array_to_json(data, len, true);

	default:
		return NULL;
	}
}


static struct json_object *
ut_ubus_connect(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *socket = json_object_array_get_idx(args, 0);
	struct json_object *timeout = json_object_array_get_idx(args, 1);
	struct json_object *co;
	struct ubus_connection *c;

	if ((socket && !json_object_is_type(socket, json_type_string)) ||
	    (timeout && !json_object_is_type(timeout, json_type_int)))
		err_return(UBUS_STATUS_INVALID_ARGUMENT);

	c = calloc(1, sizeof(*c));

	if (!c)
		err_return(UBUS_STATUS_UNKNOWN_ERROR);

	c->ctx = ubus_connect(socket ? json_object_get_string(socket) : NULL);
	c->timeout = timeout ? json_object_get_int(timeout) : 30;

	if (!c->ctx) {
		free(c);
		err_return(UBUS_STATUS_UNKNOWN_ERROR);
	}

	if (c->timeout < 0)
		c->timeout = 30;

	co = json_object_new_object();

	if (!co) {
		ubus_free(c->ctx);
		free(c);
		err_return(ENOMEM);
	}

	ubus_add_uloop(c->ctx);

	return ops->set_type(co, "ubus.connection", c);
}

static void
ut_ubus_signatures_cb(struct ubus_context *c, struct ubus_object_data *o, void *p)
{
	struct json_object *arr = p;
	struct json_object *sig;

	if (!o->signature)
		return;

	sig = ut_blob_array_to_json(blob_data(o->signature), blob_len(o->signature), true);

	if (sig)
		json_object_array_add(arr, sig);
}

static void
ut_ubus_objects_cb(struct ubus_context *c, struct ubus_object_data *o, void *p)
{
	struct json_object *arr = p;
	struct json_object *obj;

	obj = json_object_new_string(o->path);

	if (obj)
		json_object_array_add(arr, obj);
}

static struct json_object *
ut_ubus_list(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct ubus_connection **c = (struct ubus_connection **)ops->get_type(s->ctx, "ubus.connection");
	struct json_object *objname = json_object_array_get_idx(args, 0);
	struct json_object *res;
	enum ubus_msg_status rv;

	if (!c || !*c || !(*c)->ctx)
		err_return(UBUS_STATUS_CONNECTION_FAILED);

	if (objname && !json_object_is_type(objname, json_type_string))
		err_return(UBUS_STATUS_INVALID_ARGUMENT);

	res = json_object_new_array();

	if (!res)
		err_return(UBUS_STATUS_UNKNOWN_ERROR);

	rv = ubus_lookup((*c)->ctx,
	                 objname ? json_object_get_string(objname) : NULL,
	                 objname ? ut_ubus_signatures_cb : ut_ubus_objects_cb,
	                 res);

	if (rv != UBUS_STATUS_OK)
		err_return(rv);

	return res;
}

static void
ut_ubus_call_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct json_object **res = (struct json_object **)req->priv;

	*res = msg ? ut_blob_array_to_json(blob_data(msg), blob_len(msg), true) : NULL;
}

static struct json_object *
ut_ubus_call(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct ubus_connection **c = (struct ubus_connection **)ops->get_type(s->ctx, "ubus.connection");
	struct json_object *objname = json_object_array_get_idx(args, 0);
	struct json_object *funname = json_object_array_get_idx(args, 1);
	struct json_object *funargs = json_object_array_get_idx(args, 2);
	struct json_object *res;
	enum ubus_msg_status rv;
	uint32_t id;

	if (!c || !*c || !(*c)->ctx)
		err_return(UBUS_STATUS_CONNECTION_FAILED);

	if (!json_object_is_type(objname, json_type_string) ||
	    !json_object_is_type(funname, json_type_string) ||
	    (funargs && !json_object_is_type(funargs, json_type_object)))
		err_return(UBUS_STATUS_INVALID_ARGUMENT);

	blob_buf_init(&(*c)->buf, 0);

	if (funargs && !blobmsg_add_object(&(*c)->buf, funargs))
		err_return(UBUS_STATUS_UNKNOWN_ERROR);

	rv = ubus_lookup_id((*c)->ctx, json_object_get_string(objname), &id);

	if (rv != UBUS_STATUS_OK)
		err_return(rv);

	rv = ubus_invoke((*c)->ctx, id, json_object_get_string(funname), (*c)->buf.head,
	                 ut_ubus_call_cb, &res, (*c)->timeout * 1000);

	if (rv != UBUS_STATUS_OK)
		err_return(rv);

	return res;
}

static struct json_object *
ut_ubus_disconnect(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct ubus_connection **c = (struct ubus_connection **)ops->get_type(s->ctx, "ubus.connection");

	if (!c || !*c || !(*c)->ctx)
		err_return(UBUS_STATUS_CONNECTION_FAILED);

	ubus_free((*c)->ctx);
	(*c)->ctx = NULL;

	return json_object_new_boolean(true);
}


static const struct { const char *name; ut_c_fn *func; } global_fns[] = {
	{ "error",		ut_ubus_error },
	{ "connect",	ut_ubus_connect },
};

static const struct { const char *name; ut_c_fn *func; } conn_fns[] = {
	{ "list",		ut_ubus_list },
	{ "call",		ut_ubus_call },
	{ "disconnect",	ut_ubus_disconnect },
};


static void close_connection(void *ud) {
	struct ubus_connection *conn = ud;

	blob_buf_free(&conn->buf);

	if (conn->ctx)
		ubus_free(conn->ctx);

	free(conn);
}

void ut_module_init(const struct ut_ops *ut, struct ut_state *s, struct json_object *scope)
{
	struct json_object *conn_proto;

	ops = ut;
	conn_proto = ops->new_object(NULL);

	register_functions(ops, global_fns, scope);
	register_functions(ops, conn_fns, conn_proto);

	ops->register_type("ubus.connection", conn_proto, close_connection);
}
