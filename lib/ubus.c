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
#include <limits.h>
#include <libubus.h>
#include <libubox/blobmsg.h>

#include "ucode/module.h"

#define ok_return(expr) do { set_error(0, NULL); return (expr); } while(0)
#define err_return(err, ...) do { set_error(err, __VA_ARGS__); return NULL; } while(0)
#define errval_return(err, ...) do { set_error(err, __VA_ARGS__); return err; } while(0)

#define REQUIRED	0
#define OPTIONAL	1
#define NAMED		2

static struct {
	enum ubus_msg_status code;
	char *msg;
} last_error;

__attribute__((format(printf, 2, 3))) static void
set_error(int errcode, const char *fmt, ...)
{
	va_list ap;

	free(last_error.msg);

	last_error.code = errcode;
	last_error.msg = NULL;

	if (fmt) {
		va_start(ap, fmt);
		xvasprintf(&last_error.msg, fmt, ap);
		va_end(ap);
	}
}

static char *
_arg_type(uc_type_t type)
{
	switch (type) {
	case UC_INTEGER:   return "an integer value";
	case UC_BOOLEAN:   return "a boolean value";
	case UC_STRING:    return "a string value";
	case UC_DOUBLE:    return "a double value";
	case UC_ARRAY:     return "an array";
	case UC_OBJECT:    return "an object";
	case UC_REGEXP:    return "a regular expression";
	case UC_CLOSURE:   return "a function";
	default:           return "the expected type";
	}
}

static bool
_args_get(uc_vm_t *vm, bool named, size_t nargs, ...)
{
	uc_value_t **ptr, *arg, *obj;
	uc_type_t type, t;
	const char *name;
	size_t index = 0;
	va_list ap;
	int opt;

	if (named) {
		obj = uc_fn_arg(0);

		if (nargs != 1 || ucv_type(obj) != UC_OBJECT)
			named = false;
	}

	va_start(ap, nargs);

	while (true) {
		name = va_arg(ap, const char *);

		if (!name)
			break;

		type = va_arg(ap, uc_type_t);
		opt = va_arg(ap, int);
		ptr = va_arg(ap, uc_value_t **);

		if (named)
			arg = ucv_object_get(obj, name, NULL);
		else if (opt != NAMED)
			arg = uc_fn_arg(index++);
		else
			arg = NULL;

		if (opt == REQUIRED && !arg)
			err_return(UBUS_STATUS_INVALID_ARGUMENT, "Argument %s is required", name);

		t = ucv_type(arg);

		if (t == UC_CFUNCTION)
			t = UC_CLOSURE;

		if (arg && type && t != type)
			err_return(UBUS_STATUS_INVALID_ARGUMENT, "Argument %s is not %s", name, _arg_type(type));

		*ptr = arg;
	}

	va_end(ap);

	ok_return(true);
}

#define args_get_named(vm, nargs, ...) do { if (!_args_get(vm, true, nargs, __VA_ARGS__, NULL)) return NULL; } while(0)
#define args_get(vm, nargs, ...) do { if (!_args_get(vm, false, nargs, __VA_ARGS__, NULL)) return NULL; } while(0)

static uc_resource_type_t *subscriber_type;
static uc_resource_type_t *listener_type;
static uc_resource_type_t *request_type;
static uc_resource_type_t *notify_type;
static uc_resource_type_t *object_type;
static uc_resource_type_t *defer_type;
static uc_resource_type_t *conn_type;
static uc_resource_type_t *chan_type;

static uint64_t n_cb_active;
static bool have_own_uloop;

static struct blob_buf buf;

typedef struct {
	struct ubus_context ctx;
	struct blob_buf buf;
	int timeout;

	uc_vm_t *vm;
	int registry_index;
} uc_ubus_connection_t;

typedef struct {
	struct ubus_request request;
	struct uloop_timeout timeout;
	struct ubus_context *ctx;
	size_t registry_index;
	bool complete;
	uc_vm_t *vm;
	uc_value_t *callback;
	uc_value_t *response;
} uc_ubus_deferred_t;

typedef struct {
	struct ubus_object obj;
	struct ubus_context *ctx;
	size_t registry_index;
	uc_vm_t *vm;
} uc_ubus_object_t;

typedef struct {
	struct ubus_request_data req;
	struct uloop_timeout timeout;
	struct ubus_context *ctx;
	size_t registry_index;
	bool deferred;
	bool replied;
	uc_vm_t *vm;
} uc_ubus_request_t;

typedef struct {
	struct ubus_notify_request req;
	struct ubus_context *ctx;
	size_t registry_index;
	bool complete;
	uc_vm_t *vm;
} uc_ubus_notify_t;

typedef struct {
	struct ubus_event_handler ev;
	struct ubus_context *ctx;
	size_t registry_index;
	uc_vm_t *vm;
} uc_ubus_listener_t;

typedef struct {
	struct ubus_subscriber sub;
	struct ubus_context *ctx;
	size_t registry_index;
	uc_vm_t *vm;
} uc_ubus_subscriber_t;

typedef struct {
	bool mret;
	uc_value_t *res;
} uc_ubus_call_res_t;

static uc_value_t *
uc_ubus_error(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *numeric = uc_fn_arg(0), *rv;
	uc_stringbuf_t *buf;
	const char *s;

	if (last_error.code == 0)
		return NULL;

	if (ucv_is_truish(numeric)) {
		rv = ucv_int64_new(last_error.code);
	}
	else {
		buf = ucv_stringbuf_new();

		if (last_error.code == UBUS_STATUS_UNKNOWN_ERROR && last_error.msg) {
			ucv_stringbuf_addstr(buf, last_error.msg, strlen(last_error.msg));
		}
		else {
			s = ubus_strerror(last_error.code);

			ucv_stringbuf_addstr(buf, s, strlen(s));

			if (last_error.msg)
				ucv_stringbuf_printf(buf, ": %s", last_error.msg);
		}

		rv = ucv_stringbuf_finish(buf);
	}

	set_error(0, NULL);

	return rv;
}

static void
_uc_reg_get(uc_vm_t *vm, const char *key, size_t idx, size_t nptrs, ...)
{
	uc_value_t *reg = uc_vm_registry_get(vm, key), **val;
	va_list ap;
	size_t i;

	va_start(ap, nptrs);

	for (i = 0; i < nptrs; i++) {
		val = va_arg(ap, uc_value_t **);

		if (val)
			*val = ucv_array_get(reg, idx + i);
	}

	va_end(ap);
}

static size_t
_uc_reg_add(uc_vm_t *vm, const char *key, size_t nptrs, ...)
{
	uc_value_t *reg = uc_vm_registry_get(vm, key);
	size_t idx, i;
	va_list ap;

	if (!reg) {
		reg = ucv_array_new(vm);
		uc_vm_registry_set(vm, key, reg);
	}

	va_start(ap, nptrs);

	for (idx = 0;; idx += nptrs) {
		if (ucv_array_get(reg, idx) == NULL) {
			for (i = 0; i < nptrs; i++)
				ucv_array_set(reg, idx + i, va_arg(ap, uc_value_t *));

			break;
		}
	}

	va_end(ap);

	return idx;
}

static void
_uc_reg_clear(uc_vm_t *vm, const char *key, size_t idx, size_t nptrs)
{
	uc_value_t *reg = uc_vm_registry_get(vm, key);

	while (nptrs > 0) {
		nptrs--;
		ucv_array_set(reg, idx + nptrs, NULL);
	}
}


#define connection_reg_add(vm, conn, cb, disconnect_cb, fd) \
	_uc_reg_add(vm, "ubus.connections", 4, conn, cb, disconnect_cb, fd)

#define connection_reg_get(vm, idx, conn, cb, disconnect_cb) \
	_uc_reg_get(vm, "ubus.connections", idx, 3, conn, cb, disconnect_cb)

#define connection_reg_clear(vm, idx) \
	_uc_reg_clear(vm, "ubus.connections", idx, 4)


#define request_reg_add(vm, request, cb, datacb, fdcb, conn, fd) \
	_uc_reg_add(vm, "ubus.requests", 6, request, cb, datacb, fdcb, conn, fd)

#define request_reg_get(vm, idx, request, cb, datacb, fdcb) \
	_uc_reg_get(vm, "ubus.requests", idx, 4, request, cb, datacb, fdcb)

#define request_reg_clear(vm, idx) \
	_uc_reg_clear(vm, "ubus.requests", idx, 6)


#define object_reg_add(vm, obj, msg, cb) \
	_uc_reg_add(vm, "ubus.objects", 3, obj, msg, cb)

#define object_reg_get(vm, idx, obj, msg, cb) \
	_uc_reg_get(vm, "ubus.objects", idx, 3, obj, msg, cb)

#define object_reg_clear(vm, idx) \
	_uc_reg_clear(vm, "ubus.objects", idx, 3)


#define notify_reg_add(vm, notify, dcb, scb, ccb) \
	_uc_reg_add(vm, "ubus.notifications", 4, notify, dcb, scb, ccb)

#define notify_reg_get(vm, idx, notify, dcb, scb, ccb) \
	_uc_reg_get(vm, "ubus.notifications", idx, 4, notify, dcb, scb, ccb)

#define notify_reg_clear(vm, idx) \
	_uc_reg_clear(vm, "ubus.notifications", idx, 4)


#define listener_reg_add(vm, listener, cb) \
	_uc_reg_add(vm, "ubus.listeners", 2, listener, cb)

#define listener_reg_get(vm, idx, listener, cb) \
	_uc_reg_get(vm, "ubus.listeners", idx, 2, listener, cb)

#define listener_reg_clear(vm, idx) \
	_uc_reg_clear(vm, "ubus.listeners", idx, 2)


#define subscriber_reg_add(vm, subscriber, ncb, rcb) \
	_uc_reg_add(vm, "ubus.subscribers", 3, subscriber, ncb, rcb)

#define subscriber_reg_get(vm, idx, subscriber, ncb, rcb) \
	_uc_reg_get(vm, "ubus.subscribers", idx, 3, subscriber, ncb, rcb)

#define subscriber_reg_clear(vm, idx) \
	_uc_reg_clear(vm, "ubus.subscribers", idx, 3)


static uc_value_t *
blob_to_ucv(uc_vm_t *vm, struct blob_attr *attr, bool table, const char **name);

static uc_value_t *
blob_array_to_ucv(uc_vm_t *vm, struct blob_attr *attr, size_t len, bool table)
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
		v = blob_to_ucv(vm, pos, table, &name);

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
blob_to_ucv(uc_vm_t *vm, struct blob_attr *attr, bool table, const char **name)
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
		return ucv_string_new_length(data, len - 1);

	case BLOBMSG_TYPE_ARRAY:
		return blob_array_to_ucv(vm, data, len, false);

	case BLOBMSG_TYPE_TABLE:
		return blob_array_to_ucv(vm, data, len, true);

	default:
		return NULL;
	}
}

static void
ucv_array_to_blob(uc_value_t *val, struct blob_buf *blob);

static void
ucv_object_to_blob(uc_value_t *val, struct blob_buf *blob);

static void
ucv_to_blob(const char *name, uc_value_t *val, struct blob_buf *blob)
{
	int64_t n;
	void *c;

	switch (ucv_type(val)) {
	case UC_NULL:
		blobmsg_add_field(blob, BLOBMSG_TYPE_UNSPEC, name, NULL, 0);
		break;

	case UC_BOOLEAN:
		blobmsg_add_u8(blob, name, ucv_boolean_get(val));
		break;

	case UC_INTEGER:
		n = ucv_int64_get(val);

		if (errno == ERANGE)
			blobmsg_add_u64(blob, name, ucv_uint64_get(val));
		else if (n >= INT32_MIN && n <= INT32_MAX)
			blobmsg_add_u32(blob, name, n);
		else
			blobmsg_add_u64(blob, name, n);

		break;

	case UC_DOUBLE:
		blobmsg_add_double(blob, name, ucv_double_get(val));
		break;

	case UC_STRING:
		blobmsg_add_field(blob, BLOBMSG_TYPE_STRING, name,
				  ucv_string_get(val), ucv_string_length(val) + 1);
		break;

	case UC_ARRAY:
		c = blobmsg_open_array(blob, name);
		ucv_array_to_blob(val, blob);
		blobmsg_close_array(blob, c);
		break;

	case UC_OBJECT:
		c = blobmsg_open_table(blob, name);
		ucv_object_to_blob(val, blob);
		blobmsg_close_table(blob, c);
		break;

	default:
		break;
	}
}

static void
ucv_array_to_blob(uc_value_t *val, struct blob_buf *blob)
{
	size_t i;

	for (i = 0; i < ucv_array_length(val); i++)
		ucv_to_blob(NULL, ucv_array_get(val, i), blob);
}

static void
ucv_object_to_blob(uc_value_t *val, struct blob_buf *blob)
{
	ucv_object_foreach(val, k, v)
		ucv_to_blob(k, v, blob);
}


static uc_value_t *
uc_ubus_connect(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *socket, *timeout;
	uc_ubus_connection_t *c;

	args_get(vm, nargs,
	         "socket", UC_STRING, true, &socket,
	         "timeout", UC_INTEGER, true, &timeout);

	c = xalloc(sizeof(*c));
	c->registry_index = -1;
	c->timeout = timeout ? ucv_int64_get(timeout) : 30;

	if (ubus_connect_ctx(&c->ctx, socket ? ucv_string_get(socket) : NULL)) {
		free(c);
		err_return(UBUS_STATUS_UNKNOWN_ERROR, "Unable to connect to ubus socket");
	}

	if (c->timeout < 0)
		c->timeout = 30;

	ubus_add_uloop(&c->ctx);

	ok_return(uc_resource_new(conn_type, c));
}

static void
uc_ubus_signatures_cb(struct ubus_context *c, struct ubus_object_data *o, void *p)
{
	uc_value_t *arr = p;
	uc_value_t *sig;

	if (!o->signature)
		return;

	sig = blob_array_to_ucv(NULL, blob_data(o->signature), blob_len(o->signature), true);

	if (sig)
		ucv_array_push(arr, sig);
}

static void
uc_ubus_objects_cb(struct ubus_context *c, struct ubus_object_data *o, void *p)
{
	uc_value_t *arr = p;

	ucv_array_push(arr, ucv_string_new(o->path));
}

static bool
_conn_get(uc_vm_t *vm, uc_ubus_connection_t **conn)
{
	uc_ubus_connection_t *c = uc_fn_thisval("ubus.connection");

	if (!c)
		c = uc_fn_thisval("ubus.channel");
	if (!c)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid connection context");

	if (c->ctx.sock.fd < 0)
		err_return(UBUS_STATUS_CONNECTION_FAILED, "Connection is closed");

	*conn = c;

	ok_return(true);
}

#define conn_get(vm, ptr) do { if (!_conn_get(vm, ptr)) return NULL; } while(0)

static uc_value_t *
uc_ubus_list(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_connection_t *c;
	uc_value_t *objname, *res = NULL;
	enum ubus_msg_status rv;

	conn_get(vm, &c);

	args_get(vm, nargs,
	         "object name", UC_STRING, true, &objname);

	res = ucv_array_new(vm);

	rv = ubus_lookup(&c->ctx,
	                 objname ? ucv_string_get(objname) : NULL,
	                 objname ? uc_ubus_signatures_cb : uc_ubus_objects_cb,
	                 res);

	if (rv != UBUS_STATUS_OK) {
		ucv_put(res);
		err_return(rv, NULL);
	}

	ok_return(res);
}

static void
uc_ubus_call_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	uc_ubus_call_res_t *res = req->priv;
	uc_value_t *val;

	val = msg ? blob_array_to_ucv(NULL, blob_data(msg), blob_len(msg), true) : NULL;

	if (res->mret) {
		if (!res->res)
			res->res = ucv_array_new(NULL);

		ucv_array_push(res->res, val);
	}
	else if (!res->res) {
		res->res = val;
	}
}

static void
uc_ubus_call_user_cb(uc_ubus_deferred_t *defer, int ret, uc_value_t *reply)
{
	uc_value_t *this, *func;

	request_reg_get(defer->vm, defer->registry_index, &this, &func, NULL, NULL);

	if (ucv_is_callable(func)) {
		uc_vm_stack_push(defer->vm, ucv_get(this));
		uc_vm_stack_push(defer->vm, ucv_get(func));
		uc_vm_stack_push(defer->vm, ucv_int64_new(ret));
		uc_vm_stack_push(defer->vm, ucv_get(reply));

		if (uc_vm_call(defer->vm, true, 2) == EXCEPTION_NONE)
			ucv_put(uc_vm_stack_pop(defer->vm));
	}

	request_reg_clear(defer->vm, defer->registry_index);

	n_cb_active--;

	if (have_own_uloop && n_cb_active == 0)
		uloop_end();
}

static void
uc_ubus_call_data_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	uc_ubus_deferred_t *defer = container_of(req, uc_ubus_deferred_t, request);

	if (defer->response == NULL)
		defer->response = blob_array_to_ucv(defer->vm, blob_data(msg), blob_len(msg), true);
}

static void
uc_ubus_call_data_user_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	uc_ubus_deferred_t *defer = container_of(req, uc_ubus_deferred_t, request);
	uc_value_t *this, *func, *reply;

	request_reg_get(defer->vm, defer->registry_index, &this, NULL, &func, NULL);

	if (ucv_is_callable(func)) {
		reply = blob_array_to_ucv(defer->vm, blob_data(msg), blob_len(msg), true);

		uc_vm_stack_push(defer->vm, ucv_get(this));
		uc_vm_stack_push(defer->vm, ucv_get(func));
		uc_vm_stack_push(defer->vm, ucv_get(reply));

		if (uc_vm_call(defer->vm, true, 1) == EXCEPTION_NONE)
			ucv_put(uc_vm_stack_pop(defer->vm));
		else
			uloop_end();
	}
}

static void
uc_ubus_call_fd_cb(struct ubus_request *req, int fd)
{
	uc_ubus_deferred_t *defer = container_of(req, uc_ubus_deferred_t, request);
	uc_value_t *this, *func;

	if (defer->complete)
		return;

	request_reg_get(defer->vm, defer->registry_index, &this, NULL, NULL, &func);

	if (ucv_is_callable(func)) {
		uc_vm_stack_push(defer->vm, ucv_get(this));
		uc_vm_stack_push(defer->vm, ucv_get(func));
		uc_vm_stack_push(defer->vm, ucv_int64_new(fd));

		if (uc_vm_call(defer->vm, true, 1) == EXCEPTION_NONE)
			ucv_put(uc_vm_stack_pop(defer->vm));
		else
			uloop_end();
	}
}

static void
uc_ubus_call_done_cb(struct ubus_request *req, int ret)
{
	uc_ubus_deferred_t *defer = container_of(req, uc_ubus_deferred_t, request);

	if (defer->complete)
		return;

	defer->complete = true;
	uloop_timeout_cancel(&defer->timeout);

	uc_ubus_call_user_cb(defer, ret, defer->response);
}

static void
uc_ubus_call_timeout_cb(struct uloop_timeout *timeout)
{
	uc_ubus_deferred_t *defer = container_of(timeout, uc_ubus_deferred_t, timeout);

	if (defer->complete)
		return;

	defer->complete = true;
	ubus_abort_request(defer->ctx, &defer->request);

	uc_ubus_call_user_cb(defer, UBUS_STATUS_TIMEOUT, NULL);
}

static bool
uc_ubus_have_uloop(void)
{
	bool prev = uloop_cancelled;
	bool active;

#ifdef HAVE_ULOOP_FD_SET_CB
	if (uloop_fd_set_cb)
		return true;
#endif

	uloop_cancelled = true;
	active = uloop_cancelling();
	uloop_cancelled = prev;

	return active;
}

static int
get_fd(uc_vm_t *vm, uc_value_t *val)
{
	uc_value_t *fn;
	int64_t n;

	fn = ucv_property_get(val, "fileno");

	if (ucv_is_callable(fn)) {
		uc_vm_stack_push(vm, ucv_get(val));
		uc_vm_stack_push(vm, ucv_get(fn));

		if (uc_vm_call(vm, true, 0) != EXCEPTION_NONE)
			return -1;

		val = uc_vm_stack_pop(vm);
		n = ucv_int64_get(val);
		ucv_put(val);
	}
	else {
		n = ucv_int64_get(val);
	}

	if (errno || n < 0 || n > (int64_t)INT_MAX)
		return -1;

	return (int)n;
}

static int
uc_ubus_call_common(uc_vm_t *vm, uc_ubus_connection_t *c, uc_ubus_call_res_t *res,
                    uint32_t id, uc_value_t *funname, uc_value_t *funargs,
                    uc_value_t *fd, uc_value_t *fdcb, uc_value_t *mret)
{
	uc_ubus_deferred_t defer = {};
	enum ubus_msg_status rv;
	int fd_val = -1;

	enum {
		RET_MODE_SINGLE,
		RET_MODE_MULTIPLE,
		RET_MODE_IGNORE,
	} ret_mode = RET_MODE_SINGLE;

	const char * const ret_modes[] = {
		[RET_MODE_SINGLE] = "single",
		[RET_MODE_MULTIPLE] = "multiple",
		[RET_MODE_IGNORE] = "ignore",
	};

	if (ucv_type(mret) == UC_STRING) {
		const char *str = ucv_string_get(mret);
		size_t i;

		for (i = 0; i < ARRAY_SIZE(ret_modes); i++)
			if (!strcmp(str, ret_modes[i]))
				break;

		if (i == ARRAY_SIZE(ret_modes))
			errval_return(UBUS_STATUS_INVALID_ARGUMENT,
			              "Invalid return mode argument");

		ret_mode = i;
	}
	else if (ucv_type(mret) == UC_BOOLEAN) {
		ret_mode = ucv_boolean_get(mret);
	}
	else if (ret_mode) {
		errval_return(UBUS_STATUS_INVALID_ARGUMENT,
		              "Invalid return mode argument");
	}

	blob_buf_init(&c->buf, 0);

	if (funargs)
		ucv_object_to_blob(funargs, &c->buf);

	if (fd) {
		fd_val = get_fd(vm, fd);

		if (fd_val < 0)
			errval_return(UBUS_STATUS_INVALID_ARGUMENT,
			              "Invalid file descriptor argument");
	}

	res->mret = (ret_mode == RET_MODE_MULTIPLE);

	rv = ubus_invoke_async_fd(&c->ctx, id, ucv_string_get(funname),
	                          c->buf.head, &defer.request, fd_val);

	defer.vm = vm;
	defer.ctx = &c->ctx;
	defer.request.data_cb = uc_ubus_call_cb;
	defer.request.priv = res;

	if (ucv_is_callable(fdcb)) {
		defer.request.fd_cb = uc_ubus_call_fd_cb;
		defer.registry_index = request_reg_add(vm, NULL, NULL, NULL, ucv_get(fdcb), NULL, NULL);
	}

	if (rv == UBUS_STATUS_OK) {
		if (ret_mode == RET_MODE_IGNORE)
			ubus_abort_request(&c->ctx, &defer.request);
		else
			rv = ubus_complete_request(&c->ctx, &defer.request, c->timeout * 1000);
	}

	if (defer.request.fd_cb)
		request_reg_clear(vm, defer.registry_index);

	return rv;
}

static uc_value_t *
uc_ubus_call(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *obj, *funname, *funargs, *fd, *fdcb, *mret = NULL;
	uc_ubus_call_res_t res = { 0 };
	uc_ubus_connection_t *c;
	enum ubus_msg_status rv;
	uint32_t id;

	args_get_named(vm, nargs,
	               "object", 0, REQUIRED, &obj,
	               "method", UC_STRING, REQUIRED, &funname,
	               "data", UC_OBJECT, OPTIONAL, &funargs,
	               "return", 0, OPTIONAL, &mret,
	               "fd", 0, NAMED, &fd,
	               "fd_cb", UC_CLOSURE, NAMED, &fdcb);

	conn_get(vm, &c);

	if (ucv_type(obj) == UC_INTEGER) {
		id = ucv_int64_get(obj);
	}
	else if (ucv_type(obj) == UC_STRING) {
		rv = ubus_lookup_id(&c->ctx, ucv_string_get(obj), &id);

		if (rv != UBUS_STATUS_OK)
			err_return(rv, "Failed to resolve object name '%s'",
			           ucv_string_get(obj));
	}
	else {
		err_return(UBUS_STATUS_INVALID_ARGUMENT,
		           "Argument object is not string or integer");
	}

	rv = uc_ubus_call_common(vm, c, &res, id, funname, funargs, fd, fdcb, mret);

	if (rv != UBUS_STATUS_OK) {
		if (ucv_type(obj) == UC_STRING)
			err_return(rv, "Failed to invoke function '%s' on object '%s'",
			           ucv_string_get(funname), ucv_string_get(obj));
		else
			err_return(rv, "Failed to invoke function '%s' on system object %d",
			           ucv_string_get(funname), (int)ucv_int64_get(obj));
	}

	ok_return(res.res);
}

static uc_value_t *
uc_ubus_chan_request(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *funname, *funargs, *fd, *fdcb, *mret = NULL;
	uc_ubus_call_res_t res = { 0 };
	uc_ubus_connection_t *c;
	enum ubus_msg_status rv;

	args_get_named(vm, nargs,
	               "method", UC_STRING, REQUIRED, &funname,
	               "data", UC_OBJECT, OPTIONAL, &funargs,
	               "return", 0, OPTIONAL, &mret,
	               "fd", 0, NAMED, &fd,
	               "fd_cb", UC_CLOSURE, NAMED, &fdcb);

	conn_get(vm, &c);

	rv = uc_ubus_call_common(vm, c, &res, 0, funname, funargs, fd, fdcb, mret);

	if (rv != UBUS_STATUS_OK)
		err_return(rv, "Failed to send request '%s' on channel",
		           ucv_string_get(funname));

	ok_return(res.res);
}

static int
uc_ubus_defer_common(uc_vm_t *vm, uc_ubus_connection_t *c, uc_ubus_call_res_t *res,
                     uint32_t id, uc_value_t *funname, uc_value_t *funargs,
                     uc_value_t *fd, uc_value_t *fdcb, uc_value_t *replycb,
                     uc_value_t *datacb)
{
	uc_ubus_deferred_t *defer;
	enum ubus_msg_status rv;
	uc_callframe_t *frame;
	uc_value_t *conn;
	int fd_val = -1;

	blob_buf_init(&c->buf, 0);

	if (funargs)
		ucv_object_to_blob(funargs, &c->buf);

	if (fd) {
		fd_val = get_fd(vm, fd);

		if (fd_val < 0)
			errval_return(UBUS_STATUS_INVALID_ARGUMENT,
			              "Invalid file descriptor argument");
	}

	defer = xalloc(sizeof(*defer));

	rv = ubus_invoke_async_fd(&c->ctx, id, ucv_string_get(funname),
	                          c->buf.head, &defer->request, fd_val);

	if (rv == UBUS_STATUS_OK) {
		defer->vm = vm;
		defer->ctx = &c->ctx;

		if (ucv_is_callable(datacb))
			defer->request.data_cb = uc_ubus_call_data_user_cb;
		else
			defer->request.data_cb = uc_ubus_call_data_cb;

		if (ucv_is_callable(fdcb))
			defer->request.fd_cb = uc_ubus_call_fd_cb;

		defer->request.complete_cb = uc_ubus_call_done_cb;

		ubus_complete_request_async(&c->ctx, &defer->request);

		defer->timeout.cb = uc_ubus_call_timeout_cb;
		uloop_timeout_set(&defer->timeout, c->timeout * 1000);

		res->res = uc_resource_new(defer_type, defer);
		frame = uc_vector_last(&vm->callframes);
		conn = frame ? frame->ctx : NULL;

		defer->registry_index = request_reg_add(vm, ucv_get(res->res), ucv_get(replycb), ucv_get(datacb),
		                                        ucv_get(fdcb), ucv_get(conn), ucv_get(fd));

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
		else
			uloop_end();

		free(defer);
	}

	return rv;
}

static uc_value_t *
uc_ubus_defer(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *objname, *funname, *funargs, *replycb, *datacb, *fd, *fdcb = NULL;
	uc_ubus_call_res_t res = { 0 };
	uc_ubus_connection_t *c;
	uint32_t id;
	int rv;

	conn_get(vm, &c);

	rv = ubus_lookup_id(&c->ctx, ucv_string_get(objname), &id);

	if (rv != UBUS_STATUS_OK)
		err_return(rv, "Failed to resolve object name '%s'",
		           ucv_string_get(objname));

	args_get_named(vm, nargs,
	               "object", UC_STRING, REQUIRED, &objname,
	               "method", UC_STRING, REQUIRED, &funname,
	               "data", UC_OBJECT, OPTIONAL, &funargs,
	               "cb", UC_CLOSURE, OPTIONAL, &replycb,
	               "data_cb", UC_CLOSURE, OPTIONAL, &datacb,
	               "fd", 0, NAMED, &fd,
	               "fd_cb", UC_CLOSURE, NAMED, &fdcb);

	rv = uc_ubus_defer_common(vm, c, &res, id, funname, funargs, fd, fdcb, replycb, datacb);

	if (rv != UBUS_STATUS_OK)
		err_return(rv, "Failed to invoke function '%s' on object '%s'",
		           ucv_string_get(funname), ucv_string_get(objname));

	ok_return(res.res);
}

static uc_value_t *
uc_ubus_chan_defer(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *funname, *funargs, *replycb, *datacb, *fd, *fdcb = NULL;
	uc_ubus_call_res_t res = { 0 };
	uc_ubus_connection_t *c;
	int rv;

	conn_get(vm, &c);

	args_get_named(vm, nargs,
	               "method", UC_STRING, REQUIRED, &funname,
	               "data", UC_OBJECT, OPTIONAL, &funargs,
	               "cb", UC_CLOSURE, OPTIONAL, &replycb,
	               "data_cb", UC_CLOSURE, OPTIONAL, &datacb,
	               "fd", 0, NAMED, &fd,
	               "fd_cb", UC_CLOSURE, NAMED, &fdcb);

	rv = uc_ubus_defer_common(vm, c, &res, 0, funname, funargs, fd, fdcb, replycb, datacb);

	if (rv != UBUS_STATUS_OK)
		err_return(rv, "Failed to invoke function '%s' on channel",
		           ucv_string_get(funname));

	ok_return(res.res);
}


/*
 * ubus object request context functions
 * --------------------------------------------------------------------------
 */

static void
uc_ubus_request_finish_common(uc_ubus_request_t *callctx, int code)
{
	int fd;

	fd = ubus_request_get_caller_fd(&callctx->req);

	if (fd >= 0)
		close(fd);

	callctx->replied = true;
	ubus_complete_deferred_request(callctx->ctx, &callctx->req, code);
}

static void
uc_ubus_request_finish(uc_ubus_request_t *callctx, int code, uc_value_t *reply)
{
	if (callctx->replied)
		return;

	if (reply) {
		blob_buf_init(&buf, 0);
		ucv_object_to_blob(reply, &buf);
		ubus_send_reply(callctx->ctx, &callctx->req, buf.head);
	}

	uc_ubus_request_finish_common(callctx, code);
	request_reg_clear(callctx->vm, callctx->registry_index);
}

static void
uc_ubus_request_timeout(struct uloop_timeout *timeout)
{
	uc_ubus_request_t *callctx = container_of(timeout, uc_ubus_request_t, timeout);

	uc_ubus_request_finish(callctx, UBUS_STATUS_TIMEOUT, NULL);
}

static uc_value_t *
uc_ubus_request_reply(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_request_t **callctx = uc_fn_this("ubus.request");
	int64_t code = UBUS_STATUS_OK;
	uc_value_t *reply, *rcode;

	if (!callctx || !*callctx)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid call context");

	args_get(vm, nargs,
	         "reply", UC_OBJECT, true, &reply,
	         "rcode", UC_INTEGER, true, &rcode);

	if ((*callctx)->replied)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Reply has already been sent");

	if (rcode) {
		code = ucv_int64_get(rcode);

		if (errno == ERANGE || code < 0 || code > __UBUS_STATUS_LAST)
			code = UBUS_STATUS_UNKNOWN_ERROR;
	}

	uc_ubus_request_finish(*callctx, code, reply);

	ok_return(ucv_boolean_new(true));
}

static uc_value_t *
uc_ubus_request_defer(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_request_t *callctx = uc_fn_thisval("ubus.request");

	if (!callctx)
		return NULL;

	callctx->deferred = true;
	return ucv_boolean_new(true);
}

static uc_value_t *
uc_ubus_request_get_fd(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_request_t *callctx = uc_fn_thisval("ubus.request");

	if (!callctx)
		return NULL;

	return ucv_int64_new(ubus_request_get_caller_fd(&callctx->req));
}

static uc_value_t *
uc_ubus_request_set_fd(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_request_t *callctx = uc_fn_thisval("ubus.request");
	int fd;

	if (!callctx)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid call context");

	fd = get_fd(vm, uc_fn_arg(0));

	if (fd < 0)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid file descriptor");

	ubus_request_set_fd(callctx->ctx, &callctx->req, fd);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_ubus_request_error(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_request_t **callctx = uc_fn_this("ubus.request");
	uc_value_t *rcode = uc_fn_arg(0);
	int64_t code;

	if (!callctx || !*callctx)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid call context");

	args_get(vm, nargs,
	         "rcode", UC_INTEGER, false, &rcode);

	if ((*callctx)->replied)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Reply has already been sent");

	code = ucv_int64_get(rcode);

	if (errno == ERANGE || code < 0 || code > __UBUS_STATUS_LAST)
		code = UBUS_STATUS_UNKNOWN_ERROR;

	uc_ubus_request_finish(*callctx, code, NULL);

	ok_return(ucv_boolean_new(true));
}


/*
 * ubus object notify
 * --------------------------------------------------------------------------
 */

static uc_value_t *
uc_ubus_notify_completed(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_notify_t **notifyctx = uc_fn_this("ubus.notify");

	if (!notifyctx || !*notifyctx)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid notify context");

	ok_return(ucv_boolean_new((*notifyctx)->complete));
}

static uc_value_t *
uc_ubus_notify_abort(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_notify_t **notifyctx = uc_fn_this("ubus.notify");

	if (!notifyctx || !*notifyctx)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid notify context");

	if ((*notifyctx)->complete)
		ok_return(ucv_boolean_new(false));

	ubus_abort_request((*notifyctx)->ctx, &(*notifyctx)->req.req);
	(*notifyctx)->complete = true;

	ok_return(ucv_boolean_new(true));
}

static void
uc_ubus_object_notify_data_cb(struct ubus_notify_request *req, int type, struct blob_attr *msg)
{
	uc_ubus_notify_t *notifyctx = (uc_ubus_notify_t *)req;
	uc_value_t *this, *func;

	notify_reg_get(notifyctx->vm, notifyctx->registry_index, &this, &func, NULL, NULL);

	if (ucv_is_callable(func)) {
		uc_vm_stack_push(notifyctx->vm, ucv_get(this));
		uc_vm_stack_push(notifyctx->vm, ucv_get(func));
		uc_vm_stack_push(notifyctx->vm, ucv_int64_new(type));
		uc_vm_stack_push(notifyctx->vm, blob_array_to_ucv(notifyctx->vm, blob_data(msg), blob_len(msg), true));

		if (uc_vm_call(notifyctx->vm, true, 2) == EXCEPTION_NONE)
			ucv_put(uc_vm_stack_pop(notifyctx->vm));
		else
			uloop_end();
	}
}

static void
uc_ubus_object_notify_status_cb(struct ubus_notify_request *req, int idx, int ret)
{
	uc_ubus_notify_t *notifyctx = (uc_ubus_notify_t *)req;
	uc_value_t *this, *func;

	notify_reg_get(notifyctx->vm, notifyctx->registry_index, &this, NULL, &func, NULL);

	if (ucv_is_callable(func)) {
		uc_vm_stack_push(notifyctx->vm, ucv_get(this));
		uc_vm_stack_push(notifyctx->vm, ucv_get(func));
		uc_vm_stack_push(notifyctx->vm, ucv_int64_new(idx));
		uc_vm_stack_push(notifyctx->vm, ucv_int64_new(ret));

		if (uc_vm_call(notifyctx->vm, true, 2) == EXCEPTION_NONE)
			ucv_put(uc_vm_stack_pop(notifyctx->vm));
		else
			uloop_end();
	}
}

static void
uc_ubus_object_notify_complete_cb(struct ubus_notify_request *req, int idx, int ret)
{
	uc_ubus_notify_t *notifyctx = (uc_ubus_notify_t *)req;
	uc_value_t *this, *func;

	notify_reg_get(notifyctx->vm, notifyctx->registry_index, &this, NULL, NULL, &func);

	if (ucv_is_callable(func)) {
		uc_vm_stack_push(notifyctx->vm, ucv_get(this));
		uc_vm_stack_push(notifyctx->vm, ucv_get(func));
		uc_vm_stack_push(notifyctx->vm, ucv_int64_new(idx));
		uc_vm_stack_push(notifyctx->vm, ucv_int64_new(ret));

		if (uc_vm_call(notifyctx->vm, true, 2) == EXCEPTION_NONE)
			ucv_put(uc_vm_stack_pop(notifyctx->vm));
		else
			uloop_end();
	}

	notifyctx->complete = true;

	notify_reg_clear(notifyctx->vm, notifyctx->registry_index);
}

static uc_value_t *
uc_ubus_object_notify(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *typename, *message, *data_cb, *status_cb, *complete_cb, *timeout;
	uc_ubus_object_t **uuobj = uc_fn_this("ubus.object");
	uc_ubus_notify_t *notifyctx;
	uc_value_t *res;
	int64_t t;
	int rv;

	if (!uuobj || !*uuobj)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid object context");

	args_get_named(vm, nargs,
	              "type", UC_STRING, REQUIRED, &typename,
	              "data", UC_OBJECT, OPTIONAL, &message,
	              "data_cb", UC_CLOSURE, OPTIONAL, &data_cb,
	              "status_cb", UC_CLOSURE, OPTIONAL, &status_cb,
	              "cb", UC_CLOSURE, OPTIONAL, &complete_cb,
	              "timeout", UC_INTEGER, OPTIONAL, &timeout);

	t = timeout ? ucv_int64_get(timeout) : -1;

	if (errno)
		err_return(UBUS_STATUS_INVALID_ARGUMENT,
		           "Invalid timeout value: %s", strerror(errno));

	notifyctx = xalloc(sizeof(*notifyctx));
	notifyctx->vm = vm;
	notifyctx->ctx = (*uuobj)->ctx;

	blob_buf_init(&buf, 0);

	if (message)
		ucv_object_to_blob(message, &buf);

	rv = ubus_notify_async((*uuobj)->ctx, &(*uuobj)->obj,
	                       ucv_string_get(typename), buf.head,
	                       &notifyctx->req);

	if (rv != UBUS_STATUS_OK) {
		free(notifyctx);
		err_return(rv, "Failed to send notification");
	}

	notifyctx->req.data_cb = uc_ubus_object_notify_data_cb;
	notifyctx->req.status_cb = uc_ubus_object_notify_status_cb;
	notifyctx->req.complete_cb = uc_ubus_object_notify_complete_cb;

	res = uc_resource_new(notify_type, notifyctx);

	notifyctx->registry_index = notify_reg_add(vm,
		ucv_get(res), ucv_get(data_cb), ucv_get(status_cb), ucv_get(complete_cb));

	if (t >= 0) {
		rv = ubus_complete_request((*uuobj)->ctx, &notifyctx->req.req, t);

		notify_reg_clear(vm, notifyctx->registry_index);

		ucv_put(res);

		ok_return(ucv_int64_new(rv));
	}

	ubus_complete_request_async((*uuobj)->ctx, &notifyctx->req.req);

	ok_return(res);
}


/*
 * ubus object remove
 * --------------------------------------------------------------------------
 */

static int
uc_ubus_object_remove_common(uc_ubus_object_t *uuobj)
{
	int rv = ubus_remove_object(uuobj->ctx, &uuobj->obj);

	if (rv == UBUS_STATUS_OK)
		object_reg_clear(uuobj->vm, uuobj->registry_index);

	return rv;
}

static uc_value_t *
uc_ubus_object_remove(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_object_t **uuobj = uc_fn_this("ubus.object");
	int rv;

	if (!uuobj || !*uuobj)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid object context");

	rv = uc_ubus_object_remove_common(*uuobj);

	if (rv != UBUS_STATUS_OK)
		err_return(rv, "Failed to remove object");

	ok_return(ucv_boolean_new(true));
}


/*
 * ubus object subscription status
 */

static uc_value_t *
uc_ubus_object_subscribed(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_object_t **uuobj = uc_fn_this("ubus.object");

	if (!uuobj || !*uuobj)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid object context");

	ok_return(ucv_boolean_new((*uuobj)->obj.has_subscribers));
}


/*
 * ubus object method call handling
 * --------------------------------------------------------------------------
 */

static int
uc_ubus_object_call_args(struct ubus_object *obj, const char *ubus_method_name,
                         struct blob_attr *msg, uc_value_t **res)
{
	uc_ubus_object_t *uuobj = (uc_ubus_object_t *)obj;
	const struct ubus_method *method = NULL;
	const struct blobmsg_hdr *hdr;
	struct blob_attr *attr;
	size_t len;
	bool found;
	int i;

	for (i = 0; i < obj->n_methods; i++) {
		if (!strcmp(obj->methods[i].name, ubus_method_name)) {
			method = &obj->methods[i];
			break;
		}
	}

	if (!method)
		return UBUS_STATUS_METHOD_NOT_FOUND;

	len = blob_len(msg);

	__blob_for_each_attr(attr, blob_data(msg), len) {
		if (!blobmsg_check_attr_len(attr, false, len))
			return UBUS_STATUS_INVALID_ARGUMENT;

		if (!blob_is_extended(attr))
			return UBUS_STATUS_INVALID_ARGUMENT;

		hdr = blob_data(attr);
		found = false;

		for (i = 0; i < method->n_policy; i++) {
			if (blobmsg_namelen(hdr) != strlen(method->policy[i].name))
				continue;

			if (strcmp(method->policy[i].name, (char *)hdr->name))
				continue;

			/* named argument found but wrong type */
			if (blob_id(attr) != method->policy[i].type)
				goto inval;

			found = true;
			break;
		}

		/* named argument not found in policy */
		if (!found)
			goto inval;
	}

	*res = blob_array_to_ucv(uuobj->vm, blob_data(msg), blob_len(msg), true);

	return UBUS_STATUS_OK;

inval:
	*res = NULL;

	return UBUS_STATUS_INVALID_ARGUMENT;
}

static uc_value_t *
uc_ubus_object_call_info(uc_vm_t *vm,
                         struct ubus_context *ctx, struct ubus_request_data *req,
                         struct ubus_object *obj, const char *ubus_method_name)
{
	uc_value_t *info, *o;

	info = ucv_object_new(vm);

	o = ucv_object_new(vm);

	ucv_object_add(o, "user", ucv_string_new(req->acl.user));
	ucv_object_add(o, "group", ucv_string_new(req->acl.group));

	if (req->acl.object)
		ucv_object_add(o, "object", ucv_string_new(req->acl.object));

	ucv_object_add(info, "acl", o);

	o = ucv_object_new(vm);

	ucv_object_add(o, "id", ucv_int64_new(obj->id));

	if (obj->name)
		ucv_object_add(o, "name", ucv_string_new(obj->name));

	if (obj->path)
		ucv_object_add(o, "path", ucv_string_new(obj->path));

	ucv_object_add(info, "object", o);

	if (ubus_method_name)
		ucv_object_add(info, "method", ucv_string_new(ubus_method_name));

	return info;
}

static int
uc_ubus_handle_reply_common(struct ubus_context *ctx,
                              struct ubus_request_data *req,
                              uc_vm_t *vm, uc_value_t *this, uc_value_t *func,
                              uc_value_t *reqproto)
{
	uc_ubus_request_t *callctx;
	uc_value_t *reqobj, *res;
	int rv;

	/* allocate deferred method call context */
	callctx = xalloc(sizeof(*callctx));
	callctx->ctx = ctx;
	callctx->vm = vm;

	ubus_defer_request(ctx, req, &callctx->req);

	/* fd is copied to deferred request. ensure it does not get closed early */
	ubus_request_get_caller_fd(req);

	/* create ucode request type object and set properties */
	reqobj = uc_resource_new(request_type, callctx);

	if (reqproto)
		ucv_prototype_set(ucv_prototype_get(reqobj), reqproto);

	/* push object context, handler and request object onto stack */
	uc_vm_stack_push(vm, ucv_get(this));
	uc_vm_stack_push(vm, ucv_get(func));
	uc_vm_stack_push(vm, ucv_get(reqobj));

	/* execute request handler function */
	switch (uc_vm_call(vm, true, 1)) {
	case EXCEPTION_NONE:
		res = uc_vm_stack_pop(vm);

		/* The handler function invoked a nested aync ubus request and returned it */
		if (ucv_resource_dataptr(res, "ubus.deferred")) {
			/* Install guard timer in case the reply callback is never called */
			callctx->timeout.cb = uc_ubus_request_timeout;
			uloop_timeout_set(&callctx->timeout, 10000 /* FIXME */);

			/* Add wrapped request context into registry to prevent GC'ing
			 * until reply or timeout occurred */
			callctx->registry_index = request_reg_add(vm, ucv_get(reqobj), NULL, NULL, NULL, NULL, NULL);
		}

		/* Otherwise, when the function returned an object, treat it as
		* reply data and conclude deferred request immediately */
		else if (ucv_type(res) == UC_OBJECT) {
			blob_buf_init(&buf, 0);
			ucv_object_to_blob(res, &buf);
			ubus_send_reply(ctx, &callctx->req, buf.head);

			uc_ubus_request_finish_common(callctx, UBUS_STATUS_OK);
		}

		/* If neither a deferred ubus request, nor a plain object were
		 * returned and if reqobj.reply() hasn't been called, immediately
		 * finish deferred request with UBUS_STATUS_NO_DATA. */
		else if (!callctx->replied && !callctx->deferred) {
			rv = UBUS_STATUS_NO_DATA;

			if (ucv_type(res) == UC_INTEGER) {
				rv = (int)ucv_int64_get(res);

				if (rv < 0 || rv > __UBUS_STATUS_LAST)
					rv = UBUS_STATUS_UNKNOWN_ERROR;
			}

			uc_ubus_request_finish_common(callctx, rv);
		}

		ucv_put(res);
		break;

	/* if the handler function invoked exit(), forward exit status as ubus
	 * return code, map out of range values to UBUS_STATUS_UNKNOWN_ERROR. */
	case EXCEPTION_EXIT:
		rv = vm->arg.s32;

		if (rv < UBUS_STATUS_OK || rv >= __UBUS_STATUS_LAST)
			rv = UBUS_STATUS_UNKNOWN_ERROR;

		uc_ubus_request_finish_common(callctx, rv);
		break;

	/* treat other exceptions as fatal and halt uloop */
	default:
		uc_ubus_request_finish_common(callctx, UBUS_STATUS_UNKNOWN_ERROR);
		uloop_end();
		break;
	}

	/* release request object */
	ucv_put(reqobj);

	/* garbage collect */
	ucv_gc(vm);

	return UBUS_STATUS_OK;
}

static int
uc_ubus_object_call_cb(struct ubus_context *ctx, struct ubus_object *obj,
                       struct ubus_request_data *req, const char *ubus_method_name,
                       struct blob_attr *msg)
{
	uc_value_t *this, *func, *args = NULL, *reqproto, *methods;
	uc_ubus_object_t *uuobj = (uc_ubus_object_t *)obj;
	int rv;

	object_reg_get(uuobj->vm, uuobj->registry_index, &this, &methods, NULL);

	func = ucv_object_get(ucv_object_get(methods, ubus_method_name, NULL), "call", NULL);

	if (!ucv_is_callable(func))
		return UBUS_STATUS_METHOD_NOT_FOUND;

	rv = uc_ubus_object_call_args(obj, ubus_method_name, msg, &args);

	if (rv != UBUS_STATUS_OK)
		return rv;

	reqproto = ucv_object_new(uuobj->vm);

	ucv_object_add(reqproto, "args", args);
	ucv_object_add(reqproto, "info",
		uc_ubus_object_call_info(uuobj->vm, ctx, req, obj, ubus_method_name));

	return uc_ubus_handle_reply_common(ctx, req, uuobj->vm, this, func, reqproto);
}


/*
 * ubus object registration
 * --------------------------------------------------------------------------
 */

static void
uc_ubus_object_subscribe_cb(struct ubus_context *ctx, struct ubus_object *obj)
{
	uc_ubus_object_t *uuobj = (uc_ubus_object_t *)obj;
	uc_value_t *this, *func;

	object_reg_get(uuobj->vm, uuobj->registry_index, &this, NULL, &func);

	uc_vm_stack_push(uuobj->vm, ucv_get(this));
	uc_vm_stack_push(uuobj->vm, ucv_get(func));

	if (uc_vm_call(uuobj->vm, true, 0) == EXCEPTION_NONE)
		ucv_put(uc_vm_stack_pop(uuobj->vm));
	else
		uloop_end();
}

static bool
uc_ubus_object_methods_validate(uc_value_t *methods)
{
	uc_value_t *func, *args;

	ucv_object_foreach(methods, ubus_method_name, ubus_method_definition) {
		(void)ubus_method_name;

		func = ucv_object_get(ubus_method_definition, "call", NULL);
		args = ucv_object_get(ubus_method_definition, "args", NULL);

		if (!ucv_is_callable(func))
			err_return(UBUS_STATUS_INVALID_ARGUMENT,
			           "Method '%s' field 'call' is not a function value",
			           ubus_method_name);

		if (args) {
			if (ucv_type(args) != UC_OBJECT)
				err_return(UBUS_STATUS_INVALID_ARGUMENT,
				           "Method '%s' field 'args' is not an object value",
				           ubus_method_name);

			ucv_object_foreach(args, ubus_argument_name, ubus_argument_typehint) {
				(void)ubus_argument_name;

				switch (ucv_type(ubus_argument_typehint)) {
				case UC_BOOLEAN:
				case UC_INTEGER:
				case UC_DOUBLE:
				case UC_STRING:
				case UC_ARRAY:
				case UC_OBJECT:
					continue;

				default:
					err_return(UBUS_STATUS_INVALID_ARGUMENT,
					           "Method '%s' field 'args' argument '%s' hint has unsupported type %s",
					           ubus_method_name, ubus_argument_name,
					           ucv_typename(ubus_argument_typehint));
				}
			}
		}
	}

	ok_return(true);
}

static bool
uc_ubus_object_method_register(struct ubus_method *method, const char *ubus_method_name,
                               uc_value_t *ubus_method_arguments)
{
	struct blobmsg_policy *policy;
	enum blobmsg_type type;

	method->name = strdup(ubus_method_name);
	method->policy = calloc(ucv_object_length(ubus_method_arguments), sizeof(*method->policy));
	method->handler = uc_ubus_object_call_cb;

	if (!method->name || !method->policy)
		return false;

	ucv_object_foreach(ubus_method_arguments, ubus_argument_name, ubus_argument_typehint) {
		switch (ucv_type(ubus_argument_typehint)) {
		case UC_BOOLEAN:
			type = BLOBMSG_TYPE_INT8;
			break;

		case UC_INTEGER:
			switch (ucv_int64_get(ubus_argument_typehint)) {
			case 8:
				type = BLOBMSG_TYPE_INT8;
				break;

			case 16:
				type = BLOBMSG_TYPE_INT16;
				break;

			case 64:
				type = BLOBMSG_TYPE_INT64;
				break;

			default:
				type = BLOBMSG_TYPE_INT32;
				break;
			}

			break;

		case UC_DOUBLE:
			type = BLOBMSG_TYPE_DOUBLE;
			break;

		case UC_ARRAY:
			type = BLOBMSG_TYPE_ARRAY;
			break;

		case UC_OBJECT:
			type = BLOBMSG_TYPE_TABLE;
			break;

		default:
			type = BLOBMSG_TYPE_STRING;
			break;
		}

		policy = (struct blobmsg_policy *)&method->policy[method->n_policy++];
		policy->type = type;
		policy->name = strdup(ubus_argument_name);

		if (!policy->name)
			return false;
	}

	return true;
}

static uc_ubus_object_t *
uc_ubus_object_register(struct ubus_context *ctx, const char *ubus_object_name,
                        uc_value_t *ubus_object_methods)
{
	const struct blobmsg_policy *policy;
	uc_ubus_object_t *uuobj = NULL;
	int rv = UBUS_STATUS_UNKNOWN_ERROR;
	char *tptr, *tnptr, *onptr, *mptr;
	struct ubus_method *method;
	struct ubus_object *obj;
	size_t typelen, namelen;
	uc_value_t *args;

	namelen = strlen(ubus_object_name);
	typelen = strlen("ucode-ubus-") + namelen;

	uuobj = calloc_a(sizeof(*uuobj),
	                 &onptr, namelen + 1,
	                 &mptr, ucv_object_length(ubus_object_methods) * sizeof(struct ubus_method),
	                 &tptr, sizeof(struct ubus_object_type),
	                 &tnptr, typelen + 1);

	if (!uuobj)
		err_return(rv, "Out of memory");

	snprintf(tnptr, typelen, "ucode-ubus-%s", ubus_object_name);

	method = (struct ubus_method *)mptr;

	obj = &uuobj->obj;
	obj->name = memcpy(onptr, ubus_object_name, namelen);
	obj->methods = method;

	if (ubus_object_methods) {
		ucv_object_foreach(ubus_object_methods, ubus_method_name, ubus_method_definition) {
			args = ucv_object_get(ubus_method_definition, "args", NULL);

			if (!uc_ubus_object_method_register(&method[obj->n_methods++], ubus_method_name, args))
				goto out;
		}
	}

	obj->type = (struct ubus_object_type *)tptr;
	obj->type->name = tnptr;
	obj->type->methods = obj->methods;
	obj->type->n_methods = obj->n_methods;

	rv = ubus_add_object(ctx, obj);

	if (rv == UBUS_STATUS_OK)
		return uuobj;

out:
	for (; obj->n_methods > 0; method++, obj->n_methods--) {
		for (policy = method->policy; method->n_policy > 0; policy++, method->n_policy--)
			free((char *)policy->name);

		free((char *)method->name);
		free((char *)method->policy);
	}

	free(uuobj);

	err_return(rv, "Unable to add ubus object");
}

static uc_value_t *
uc_ubus_publish(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *objname, *methods, *subscribecb;
	uc_ubus_connection_t *c;
	uc_ubus_object_t *uuobj;
	uc_value_t *res;

	conn_get(vm, &c);

	args_get(vm, nargs,
	         "object name", UC_STRING, false, &objname,
	         "object methods", UC_OBJECT, true, &methods,
	         "subscribe callback", UC_CLOSURE, true, &subscribecb);

	if (!methods && !subscribecb)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Either methods or subscribe callback required");

	if (methods && !uc_ubus_object_methods_validate(methods))
		return NULL;

	uuobj = uc_ubus_object_register(&c->ctx, ucv_string_get(objname), methods);

	if (!uuobj)
		return NULL;

	if (subscribecb)
		uuobj->obj.subscribe_cb = uc_ubus_object_subscribe_cb;

	res = uc_resource_new(object_type, uuobj);

	uuobj->vm = vm;
	uuobj->ctx = &c->ctx;
	uuobj->registry_index = object_reg_add(vm, ucv_get(res), ucv_get(methods), ucv_get(subscribecb));

	ok_return(res);
}


/*
 * ubus events
 * --------------------------------------------------------------------------
 */

static int
uc_ubus_listener_remove_common(uc_ubus_listener_t *uul)
{
	int rv = ubus_unregister_event_handler(uul->ctx, &uul->ev);

	if (rv == UBUS_STATUS_OK)
		listener_reg_clear(uul->vm, uul->registry_index);

	return rv;
}

static uc_value_t *
uc_ubus_listener_remove(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_listener_t **uul = uc_fn_this("ubus.listener");
	int rv;

	if (!uul || !*uul)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid listener context");

	rv = uc_ubus_listener_remove_common(*uul);

	if (rv != UBUS_STATUS_OK)
		err_return(rv, "Failed to remove listener object");

	ok_return(ucv_boolean_new(true));
}

static void
uc_ubus_listener_cb(struct ubus_context *ctx, struct ubus_event_handler *ev,
                    const char *type, struct blob_attr *msg)
{
	uc_ubus_listener_t *uul = (uc_ubus_listener_t *)ev;
	uc_value_t *this, *func;

	listener_reg_get(uul->vm, uul->registry_index, &this, &func);

	uc_vm_stack_push(uul->vm, ucv_get(this));
	uc_vm_stack_push(uul->vm, ucv_get(func));
	uc_vm_stack_push(uul->vm, ucv_string_new(type));
	uc_vm_stack_push(uul->vm, blob_array_to_ucv(uul->vm, blob_data(msg), blob_len(msg), true));

	if (uc_vm_call(uul->vm, true, 2) == EXCEPTION_NONE)
		ucv_put(uc_vm_stack_pop(uul->vm));
	else
		uloop_end();
}

static uc_value_t *
uc_ubus_listener(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *cb, *pattern;
	uc_ubus_connection_t *c;
	uc_ubus_listener_t *uul;
	uc_value_t *res;
	int rv;

	conn_get(vm, &c);

	args_get(vm, nargs,
	         "event type pattern", UC_STRING, false, &pattern,
	         "event callback", UC_CLOSURE, false, &cb);

	uul = xalloc(sizeof(*uul));
	uul->vm = vm;
	uul->ctx = &c->ctx;
	uul->ev.cb = uc_ubus_listener_cb;

	rv = ubus_register_event_handler(&c->ctx, &uul->ev,
	                                 ucv_string_get(pattern));

	if (rv != UBUS_STATUS_OK) {
		free(uul);
		err_return(rv, "Failed to register listener object");
	}

	res = uc_resource_new(listener_type, uul);

	uul->registry_index = listener_reg_add(vm, ucv_get(res), ucv_get(cb));

	ok_return(res);
}

static uc_value_t *
uc_ubus_event(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *eventtype, *eventdata;
	uc_ubus_connection_t *c;
	int rv;

	conn_get(vm, &c);

	args_get(vm, nargs,
	         "event id", UC_STRING, false, &eventtype,
	         "event data", UC_OBJECT, true, &eventdata);

	blob_buf_init(&buf, 0);

	if (eventdata)
		ucv_object_to_blob(eventdata, &buf);

	rv = ubus_send_event(&c->ctx, ucv_string_get(eventtype), buf.head);

	if (rv != UBUS_STATUS_OK)
		err_return(rv, "Unable to send event");

	ok_return(ucv_boolean_new(true));
}


/*
 * ubus subscriptions
 * --------------------------------------------------------------------------
 */

static int
uc_ubus_subscriber_notify_cb(struct ubus_context *ctx, struct ubus_object *obj,
	                         struct ubus_request_data *req, const char *method,
	                         struct blob_attr *msg)
{
	struct ubus_subscriber *sub = container_of(obj, struct ubus_subscriber, obj);
	uc_ubus_subscriber_t *uusub = container_of(sub, uc_ubus_subscriber_t, sub);
	uc_value_t *this, *func, *reqproto;

	subscriber_reg_get(uusub->vm, uusub->registry_index, &this, &func, NULL);

	if (!ucv_is_callable(func))
		return UBUS_STATUS_METHOD_NOT_FOUND;

	reqproto = ucv_object_new(uusub->vm);

	ucv_object_add(reqproto, "type", ucv_string_new(method));

	ucv_object_add(reqproto, "data",
		blob_array_to_ucv(uusub->vm, blob_data(msg), blob_len(msg), true));

	ucv_object_add(reqproto, "info",
		uc_ubus_object_call_info(uusub->vm, ctx, req, obj, NULL));

	return uc_ubus_handle_reply_common(ctx, req, uusub->vm, this, func, reqproto);
}

static void
uc_ubus_subscriber_remove_cb(struct ubus_context *ctx,
                             struct ubus_subscriber *sub, uint32_t id)
{
	uc_ubus_subscriber_t *uusub = container_of(sub, uc_ubus_subscriber_t, sub);
	uc_value_t *this, *func;

	subscriber_reg_get(uusub->vm, uusub->registry_index, &this, NULL, &func);

	if (!ucv_is_callable(func))
		return;

	uc_vm_stack_push(uusub->vm, ucv_get(this));
	uc_vm_stack_push(uusub->vm, ucv_get(func));
	uc_vm_stack_push(uusub->vm, ucv_uint64_new(id));

	if (uc_vm_call(uusub->vm, true, 1) == EXCEPTION_NONE)
		ucv_put(uc_vm_stack_pop(uusub->vm));
	else
		uloop_end();
}

static uc_value_t *
uc_ubus_subscriber_subunsub_common(uc_vm_t *vm, size_t nargs, bool subscribe)
{
	uc_ubus_subscriber_t **uusub = uc_fn_this("ubus.subscriber");
	uc_value_t *objname;
	uint32_t id;
	int rv;

	if (!uusub || !*uusub)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid subscriber context");

	args_get(vm, nargs,
	         "object name", UC_STRING, false, &objname);

	rv = ubus_lookup_id((*uusub)->ctx, ucv_string_get(objname), &id);

	if (rv != UBUS_STATUS_OK)
		err_return(rv, "Failed to resolve object name '%s'",
		           ucv_string_get(objname));

	if (subscribe)
		rv = ubus_subscribe((*uusub)->ctx, &(*uusub)->sub, id);
	else
		rv = ubus_unsubscribe((*uusub)->ctx, &(*uusub)->sub, id);

	if (rv != UBUS_STATUS_OK)
		err_return(rv, "Failed to %s object '%s'",
		           subscribe ? "subscribe" : "unsubscribe",
		           ucv_string_get(objname));

	ok_return(ucv_boolean_new(true));
}

static uc_value_t *
uc_ubus_subscriber_subscribe(uc_vm_t *vm, size_t nargs)
{
	return uc_ubus_subscriber_subunsub_common(vm, nargs, true);
}

static uc_value_t *
uc_ubus_subscriber_unsubscribe(uc_vm_t *vm, size_t nargs)
{
	return uc_ubus_subscriber_subunsub_common(vm, nargs, false);
}

static int
uc_ubus_subscriber_remove_common(uc_ubus_subscriber_t *uusub)
{
	int rv = ubus_unregister_subscriber(uusub->ctx, &uusub->sub);

	if (rv == UBUS_STATUS_OK)
		subscriber_reg_clear(uusub->vm, uusub->registry_index);

	return rv;
}

static uc_value_t *
uc_ubus_subscriber_remove(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_subscriber_t **uusub = uc_fn_this("ubus.subscriber");
	int rv;

	if (!uusub || !*uusub)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid subscriber context");

	rv = uc_ubus_subscriber_remove_common(*uusub);

	if (rv != UBUS_STATUS_OK)
		err_return(rv, "Failed to remove subscriber object");

	ok_return(ucv_boolean_new(true));
}

static uc_value_t *
uc_ubus_subscriber(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *notify_cb, *remove_cb;
	uc_ubus_subscriber_t *uusub;
	uc_ubus_connection_t *c;
	uc_value_t *res;
	int rv;

	conn_get(vm, &c);

	args_get(vm, nargs,
	         "notify callback", UC_CLOSURE, true, &notify_cb,
	         "remove callback", UC_CLOSURE, true, &remove_cb);

	if (!notify_cb && !remove_cb)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Either notify or remove callback required");

	uusub = xalloc(sizeof(*uusub));
	uusub->vm = vm;
	uusub->ctx = &c->ctx;

	rv = ubus_register_subscriber(&c->ctx, &uusub->sub);

	if (rv != UBUS_STATUS_OK) {
		free(uusub);
		err_return(rv, "Failed to register subscriber object");
	}

	if (notify_cb)
		uusub->sub.cb = uc_ubus_subscriber_notify_cb;

	if (remove_cb)
		uusub->sub.remove_cb = uc_ubus_subscriber_remove_cb;

	res = uc_resource_new(subscriber_type, uusub);

	uusub->registry_index = subscriber_reg_add(vm,
		ucv_get(res), ucv_get(notify_cb), ucv_get(remove_cb));

	ok_return(res);
}


/*
 * connection methods
 * --------------------------------------------------------------------------
 */

static uc_value_t *
uc_ubus_remove(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_subscriber_t **uusub;
	uc_ubus_connection_t *c;
	uc_ubus_object_t **uuobj;
	uc_ubus_listener_t **uul;
	int rv;

	conn_get(vm, &c);

	uusub = (uc_ubus_subscriber_t **)ucv_resource_dataptr(uc_fn_arg(0), "ubus.subscriber");
	uuobj = (uc_ubus_object_t **)ucv_resource_dataptr(uc_fn_arg(0), "ubus.object");
	uul = (uc_ubus_listener_t **)ucv_resource_dataptr(uc_fn_arg(0), "ubus.listener");

	if (uusub && *uusub) {
		if ((*uusub)->ctx != &c->ctx)
			err_return(UBUS_STATUS_INVALID_ARGUMENT,
			           "Subscriber belongs to different connection");

		rv = uc_ubus_subscriber_remove_common(*uusub);

		if (rv != UBUS_STATUS_OK)
			err_return(rv, "Unable to remove subscriber");
	}
	else if (uuobj && *uuobj) {
		if ((*uuobj)->ctx != &c->ctx)
			err_return(UBUS_STATUS_INVALID_ARGUMENT,
			           "Object belongs to different connection");

		rv = uc_ubus_object_remove_common(*uuobj);

		if (rv != UBUS_STATUS_OK)
			err_return(rv, "Unable to remove object");
	}
	else if (uul && *uul) {
		if ((*uul)->ctx != &c->ctx)
			err_return(UBUS_STATUS_INVALID_ARGUMENT,
			           "Listener belongs to different connection");

		rv = uc_ubus_listener_remove_common(*uul);

		if (rv != UBUS_STATUS_OK)
			err_return(rv, "Unable to remove listener");
	}
	else {
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Unhandled resource type");
	}

	ok_return(ucv_boolean_new(true));
}


static uc_value_t *
uc_ubus_disconnect(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_connection_t *c;

	conn_get(vm, &c);

	ubus_shutdown(&c->ctx);
	c->ctx.sock.fd = -1;

	ok_return(ucv_boolean_new(true));
}

static uc_value_t *
uc_ubus_defer_completed(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_deferred_t **d = uc_fn_this("ubus.deferred");

	if (!d || !*d)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid deferred context");

	ok_return(ucv_boolean_new((*d)->complete));
}

static uc_value_t *
uc_ubus_defer_await(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_deferred_t *d = uc_fn_thisval("ubus.deferred");
	int64_t remaining;

	if (!d)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid deferred context");

	if (d->complete)
		ok_return(ucv_boolean_new(false));

#ifdef HAVE_ULOOP_TIMEOUT_REMAINING64
	remaining = uloop_timeout_remaining64(&d->timeout);
#else
	remaining = uloop_timeout_remaining(&d->timeout);
#endif

	ubus_complete_request(d->ctx, &d->request, remaining);

	ok_return(ucv_boolean_new(true));
}

static uc_value_t *
uc_ubus_defer_abort(uc_vm_t *vm, size_t nargs)
{
	uc_ubus_deferred_t **d = uc_fn_this("ubus.deferred");

	if (!d || !*d)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid deferred context");

	if ((*d)->complete)
		ok_return(ucv_boolean_new(false));

	ubus_abort_request((*d)->ctx, &(*d)->request);
	uloop_timeout_cancel(&(*d)->timeout);

	request_reg_clear((*d)->vm, (*d)->registry_index);

	n_cb_active--;

	if (have_own_uloop && n_cb_active == 0)
		uloop_end();

	(*d)->complete = true;

	ok_return(ucv_boolean_new(true));
}

/*
 * channel related methods
 * --------------------------------------------------------------------------
 */

#ifdef HAVE_UBUS_CHANNEL_SUPPORT
static int
uc_ubus_channel_req_cb(struct ubus_context *ctx, struct ubus_object *obj,
                       struct ubus_request_data *req, const char *method,
                       struct blob_attr *msg)
{
	uc_ubus_connection_t *c = container_of(ctx, uc_ubus_connection_t, ctx);
	uc_value_t *this, *func, *args, *reqproto;

	connection_reg_get(c->vm, c->registry_index, &this, &func, NULL);

	if (!ucv_is_callable(func))
		return UBUS_STATUS_METHOD_NOT_FOUND;

	args = blob_array_to_ucv(c->vm, blob_data(msg), blob_len(msg), true);
	reqproto = ucv_object_new(c->vm);
	ucv_object_add(reqproto, "args", ucv_get(args));

	if (method)
		ucv_object_add(reqproto, "type", ucv_get(ucv_string_new(method)));

	return uc_ubus_handle_reply_common(ctx, req, c->vm, this, func, reqproto);
}

static void
uc_ubus_channel_disconnect_cb(struct ubus_context *ctx)
{
	uc_ubus_connection_t *c = container_of(ctx, uc_ubus_connection_t, ctx);
	uc_value_t *this, *func;

	connection_reg_get(c->vm, c->registry_index, &this, NULL, &func);

	if (ucv_is_callable(func)) {
		uc_vm_stack_push(c->vm, ucv_get(this));
		uc_vm_stack_push(c->vm, ucv_get(func));

		if (uc_vm_call(c->vm, true, 0) == EXCEPTION_NONE)
			ucv_put(uc_vm_stack_pop(c->vm));
		else
			uloop_end();
	}

	blob_buf_free(&c->buf);

	if (c->registry_index >= 0)
		connection_reg_clear(c->vm, c->registry_index);

	if (c->ctx.sock.fd >= 0) {
		ubus_shutdown(&c->ctx);
		c->ctx.sock.fd = -1;
	}
}

static uc_value_t *
uc_ubus_channel_add(uc_vm_t *vm, uc_ubus_connection_t *c, uc_value_t *cb,
                    uc_value_t *disconnect_cb, uc_value_t *fd)
{
	uc_value_t *chan;

	c->vm = vm;

	if (c->timeout < 0)
		c->timeout = 30;

	chan = uc_resource_new(chan_type, c);
	c->registry_index = connection_reg_add(vm, ucv_get(chan), ucv_get(cb), ucv_get(disconnect_cb), ucv_get(fd));
	c->ctx.connection_lost = uc_ubus_channel_disconnect_cb;
	ubus_add_uloop(&c->ctx);

	ok_return(chan);
}
#endif

static uc_value_t *
uc_ubus_request_new_channel(uc_vm_t *vm, size_t nargs)
{
#ifdef HAVE_UBUS_CHANNEL_SUPPORT
	uc_ubus_request_t *callctx = uc_fn_thisval("ubus.request");
	uc_value_t *cb, *disconnect_cb, *timeout;
	uc_ubus_connection_t *c;
	int fd;

	if (!callctx)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid call context");

	args_get(vm, nargs,
	         "cb", UC_CLOSURE, true, &cb,
	         "disconnect_cb", UC_CLOSURE, true, &disconnect_cb,
	         "timeout", UC_INTEGER, true, &timeout);

	c = xalloc(sizeof(*c));
	c->timeout = timeout ? ucv_int64_get(timeout) : 30;

	if (ubus_channel_create(&c->ctx, &fd, cb ? uc_ubus_channel_req_cb : NULL)) {
		free(c);
		err_return(UBUS_STATUS_UNKNOWN_ERROR, "Unable to create ubus channel");
	}

	ubus_request_set_fd(callctx->ctx, &callctx->req, fd);

	return uc_ubus_channel_add(vm, c, cb, disconnect_cb, NULL);
#else
	err_return(UBUS_STATUS_NOT_SUPPORTED, "No ubus channel support");
#endif
}


static uc_value_t *
uc_ubus_channel_connect(uc_vm_t *vm, size_t nargs)
{
#ifdef HAVE_UBUS_CHANNEL_SUPPORT
	uc_value_t *fd, *cb, *disconnect_cb, *timeout;
	uc_ubus_connection_t *c;
	int fd_val;

	args_get(vm, nargs,
	         "fd", UC_NULL, false, &fd,
	         "cb", UC_CLOSURE, true, &cb,
	         "disconnect_cb", UC_CLOSURE, true, &disconnect_cb,
	         "timeout", UC_INTEGER, true, &timeout);

	fd_val = get_fd(vm, fd);

	if (fd_val < 0)
		err_return(UBUS_STATUS_INVALID_ARGUMENT, "Invalid file descriptor argument");

	c = xalloc(sizeof(*c));
	c->timeout = timeout ? ucv_int64_get(timeout) : 30;

	if (ubus_channel_connect(&c->ctx, fd_val, cb ? uc_ubus_channel_req_cb : NULL)) {
		free(c);
		err_return(UBUS_STATUS_UNKNOWN_ERROR, "Unable to create ubus channel");
	}

	return uc_ubus_channel_add(vm, c, cb, disconnect_cb, fd);
#else
	err_return(UBUS_STATUS_NOT_SUPPORTED, "No ubus channel support");
#endif
}


static const uc_function_list_t global_fns[] = {
	{ "error",			uc_ubus_error },
	{ "connect",		uc_ubus_connect },
	{ "open_channel",	uc_ubus_channel_connect },
};

static const uc_function_list_t conn_fns[] = {
	{ "list",			uc_ubus_list },
	{ "call",			uc_ubus_call },
	{ "defer",			uc_ubus_defer },
	{ "publish",		uc_ubus_publish },
	{ "remove",			uc_ubus_remove },
	{ "listener",		uc_ubus_listener },
	{ "subscriber",		uc_ubus_subscriber },
	{ "event",			uc_ubus_event },
	{ "error",			uc_ubus_error },
	{ "disconnect",		uc_ubus_disconnect },
};

static const uc_function_list_t chan_fns[] = {
	{ "request",		uc_ubus_chan_request },
	{ "defer",			uc_ubus_chan_defer },
	{ "error",			uc_ubus_error },
	{ "disconnect",		uc_ubus_disconnect },
};

static const uc_function_list_t defer_fns[] = {
	{ "await",			uc_ubus_defer_await },
	{ "completed",		uc_ubus_defer_completed },
	{ "abort",			uc_ubus_defer_abort },
};

static const uc_function_list_t object_fns[] = {
	{ "subscribed",		uc_ubus_object_subscribed },
	{ "notify",			uc_ubus_object_notify },
	{ "remove",			uc_ubus_object_remove },
};

static const uc_function_list_t request_fns[] = {
	{ "reply",			uc_ubus_request_reply },
	{ "error",			uc_ubus_request_error },
	{ "defer",			uc_ubus_request_defer },
	{ "get_fd",			uc_ubus_request_get_fd },
	{ "set_fd",			uc_ubus_request_set_fd },
	{ "new_channel",	uc_ubus_request_new_channel },
};

static const uc_function_list_t notify_fns[] = {
	{ "completed",		uc_ubus_notify_completed },
	{ "abort",			uc_ubus_notify_abort },
};

static const uc_function_list_t listener_fns[] = {
	{ "remove",			uc_ubus_listener_remove },
};

static const uc_function_list_t subscriber_fns[] = {
	{ "subscribe",		uc_ubus_subscriber_subscribe },
	{ "unsubscribe",	uc_ubus_subscriber_unsubscribe },
	{ "remove",			uc_ubus_subscriber_remove },
};

static void free_connection(void *ud) {
	uc_ubus_connection_t *conn = ud;

	blob_buf_free(&conn->buf);

	if (conn->ctx.sock.fd >= 0)
		ubus_shutdown(&conn->ctx);
	if (conn->registry_index >= 0)
		connection_reg_clear(conn->vm, conn->registry_index);

	free(conn);
}

static void free_deferred(void *ud) {
	uc_ubus_deferred_t *defer = ud;

	uloop_timeout_cancel(&defer->timeout);
	ucv_put(defer->response);
	free(defer);
}

static void free_object(void *ud) {
	uc_ubus_object_t *uuobj = ud;
	struct ubus_object *obj = &uuobj->obj;
	int i, j;

	for (i = 0; i < obj->n_methods; i++) {
		for (j = 0; j < obj->methods[i].n_policy; j++)
			free((char *)obj->methods[i].policy[j].name);

		free((char *)obj->methods[i].name);
		free((char *)obj->methods[i].policy);
	}

	free(uuobj);
}

static void free_request(void *ud) {
	uc_ubus_request_t *callctx = ud;

	uc_ubus_request_finish(callctx, UBUS_STATUS_TIMEOUT, NULL);
	uloop_timeout_cancel(&callctx->timeout);
	free(callctx);
}

static void free_notify(void *ud) {
	uc_ubus_notify_t *notifyctx = ud;

	free(notifyctx);
}

static void free_listener(void *ud) {
	uc_ubus_listener_t *listener = ud;

	free(listener);
}

static void free_subscriber(void *ud) {
	uc_ubus_subscriber_t *subscriber = ud;

	free(subscriber);
}

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, global_fns);

#define ADD_CONST(x) ucv_object_add(scope, #x, ucv_int64_new(UBUS_##x))
	ADD_CONST(STATUS_OK);
	ADD_CONST(STATUS_INVALID_COMMAND);
	ADD_CONST(STATUS_INVALID_ARGUMENT);
	ADD_CONST(STATUS_METHOD_NOT_FOUND);
	ADD_CONST(STATUS_NOT_FOUND);
	ADD_CONST(STATUS_NO_DATA);
	ADD_CONST(STATUS_PERMISSION_DENIED);
	ADD_CONST(STATUS_TIMEOUT);
	ADD_CONST(STATUS_NOT_SUPPORTED);
	ADD_CONST(STATUS_UNKNOWN_ERROR);
	ADD_CONST(STATUS_CONNECTION_FAILED);

#ifdef HAVE_NEW_UBUS_STATUS_CODES
	ADD_CONST(STATUS_NO_MEMORY);
	ADD_CONST(STATUS_PARSE_ERROR);
	ADD_CONST(STATUS_SYSTEM_ERROR);
#endif

	ADD_CONST(SYSTEM_OBJECT_ACL);

	conn_type = uc_type_declare(vm, "ubus.connection", conn_fns, free_connection);
	chan_type = uc_type_declare(vm, "ubus.channel", chan_fns, free_connection);
	defer_type = uc_type_declare(vm, "ubus.deferred", defer_fns, free_deferred);
	object_type = uc_type_declare(vm, "ubus.object", object_fns, free_object);
	notify_type = uc_type_declare(vm, "ubus.notify", notify_fns, free_notify);
	request_type = uc_type_declare(vm, "ubus.request", request_fns, free_request);
	listener_type = uc_type_declare(vm, "ubus.listener", listener_fns, free_listener);
	subscriber_type = uc_type_declare(vm, "ubus.subscriber", subscriber_fns, free_subscriber);
}
