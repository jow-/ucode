/*
 * Copyright (C) 2022 Jo-Philipp Wich <jo@mein.io>
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

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include <libubox/uloop.h>

#include "ucode/module.h"

#define err_return(err) do { last_error = err; return NULL; } while(0)

static uc_resource_type_t *timer_type, *handle_type, *process_type;
static uc_value_t *object_registry;

static int last_error = 0;

static size_t
uc_uloop_reg_add(uc_value_t *obj, uc_value_t *cb)
{
	size_t i = 0;

	while (ucv_array_get(object_registry, i))
		i += 2;

	ucv_array_set(object_registry, i + 0, ucv_get(obj));
	ucv_array_set(object_registry, i + 1, ucv_get(cb));

	return i;
}

static bool
uc_uloop_reg_remove(size_t i)
{
	if (i + 1 >= ucv_array_length(object_registry))
		return false;

	ucv_array_set(object_registry, i + 0, NULL);
	ucv_array_set(object_registry, i + 1, NULL);

	return true;
}

static bool
uc_uloop_reg_invoke(uc_vm_t *vm, size_t i, uc_value_t *arg)
{
	uc_value_t *obj = ucv_array_get(object_registry, i + 0);
	uc_value_t *cb = ucv_array_get(object_registry, i + 1);

	if (!ucv_is_callable(cb))
		return false;

	uc_vm_stack_push(vm, ucv_get(obj));
	uc_vm_stack_push(vm, ucv_get(cb));
	uc_vm_stack_push(vm, ucv_get(arg));

	if (uc_vm_call(vm, true, 1) != EXCEPTION_NONE) {
		uloop_end();

		return false;
	}

	ucv_put(uc_vm_stack_pop(vm));

	return true;
}

static uc_value_t *
uc_uloop_error(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *errmsg;

	if (last_error == 0)
		return NULL;

	errmsg = ucv_string_new(strerror(last_error));
	last_error = 0;

	return errmsg;
}

static uc_value_t *
uc_uloop_init(uc_vm_t *vm, size_t nargs)
{
	int rv = uloop_init();

	if (rv == -1)
		err_return(errno);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_uloop_run(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *timeout = uc_fn_arg(0);
	int t, rv;

	errno = 0;
	t = timeout ? (int)ucv_int64_get(timeout) : -1;

	if (errno)
		err_return(errno);

	rv = uloop_run_timeout(t);

	return ucv_int64_new(rv);
}

static uc_value_t *
uc_uloop_cancelling(uc_vm_t *vm, size_t nargs)
{
	return ucv_boolean_new(uloop_cancelling());
}

static uc_value_t *
uc_uloop_running(uc_vm_t *vm, size_t nargs)
{
	bool prev = uloop_cancelled;
	bool active;

	uloop_cancelled = true;
	active = uloop_cancelling();
	uloop_cancelled = prev;

	return ucv_boolean_new(active);
}

static uc_value_t *
uc_uloop_end(uc_vm_t *vm, size_t nargs)
{
	uloop_end();

	return NULL;
}

static uc_value_t *
uc_uloop_done(uc_vm_t *vm, size_t nargs)
{
	uloop_done();

	return NULL;
}


typedef struct {
	struct uloop_timeout timeout;
	size_t registry_index;
	uc_vm_t *vm;
} uc_uloop_timer_t;

static void
uc_uloop_timeout_clear(uc_uloop_timer_t **timer)
{
	/* drop registry entries and clear data to prevent reuse */
	uc_uloop_reg_remove((*timer)->registry_index);
	free(*timer);
	*timer = NULL;
}

static uc_value_t *
uc_uloop_timer_set(uc_vm_t *vm, size_t nargs)
{
	uc_uloop_timer_t **timer = uc_fn_this("uloop.timer");
	uc_value_t *timeout = uc_fn_arg(0);
	int t, rv;

	if (!timer || !*timer)
		err_return(EINVAL);

	errno = 0;
	t = timeout ? (int)ucv_int64_get(timeout) : -1;

	if (errno)
		err_return(errno);

	rv = uloop_timeout_set(&(*timer)->timeout, t);

	return ucv_boolean_new(rv == 0);
}

static uc_value_t *
uc_uloop_timer_remaining(uc_vm_t *vm, size_t nargs)
{
	uc_uloop_timer_t **timer = uc_fn_this("uloop.timer");
	int64_t rem;

	if (!timer || !*timer)
		err_return(EINVAL);

#ifdef HAVE_ULOOP_TIMEOUT_REMAINING64
	rem = uloop_timeout_remaining64(&(*timer)->timeout);
#else
	rem = (int64_t)uloop_timeout_remaining(&(*timer)->timeout);
#endif

	return ucv_int64_new(rem);
}

static uc_value_t *
uc_uloop_timer_cancel(uc_vm_t *vm, size_t nargs)
{
	uc_uloop_timer_t **timer = uc_fn_this("uloop.timer");
	int rv;

	if (!timer || !*timer)
		err_return(EINVAL);

	rv = uloop_timeout_cancel(&(*timer)->timeout);

	uc_uloop_timeout_clear(timer);

	return ucv_boolean_new(rv == 0);
}

static void
uc_uloop_timer_cb(struct uloop_timeout *timeout)
{
	uc_uloop_timer_t *timer = (uc_uloop_timer_t *)timeout;

	uc_uloop_reg_invoke(timer->vm, timer->registry_index, NULL);
}

static uc_value_t *
uc_uloop_timer(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *timeout = uc_fn_arg(0);
	uc_value_t *callback = uc_fn_arg(1);
	uc_uloop_timer_t *timer;
	uc_value_t *res;
	int t;

	errno = 0;
	t = timeout ? ucv_int64_get(timeout) : -1;

	if (errno)
		err_return(errno);

	if (!ucv_is_callable(callback))
		err_return(EINVAL);

	timer = xalloc(sizeof(*timer));
	timer->timeout.cb = uc_uloop_timer_cb;
	timer->vm = vm;

	if (t >= 0)
		uloop_timeout_set(&timer->timeout, t);

	res = uc_resource_new(timer_type, timer);

	timer->registry_index = uc_uloop_reg_add(res, callback);

	return res;
}


typedef struct {
	struct uloop_fd fd;
	size_t registry_index;
	uc_value_t *handle;
	uc_vm_t *vm;
} uc_uloop_handle_t;

static void
uc_uloop_handle_clear(uc_uloop_handle_t **handle)
{
	/* drop registry entries and clear data to prevent reuse */
	uc_uloop_reg_remove((*handle)->registry_index);
	ucv_put((*handle)->handle);
	free(*handle);
	*handle = NULL;
}

static uc_value_t *
uc_uloop_handle_fileno(uc_vm_t *vm, size_t nargs)
{
	uc_uloop_handle_t **handle = uc_fn_this("uloop.handle");

	if (!handle || !*handle)
		err_return(EINVAL);

	return ucv_int64_new((*handle)->fd.fd);
}

static uc_value_t *
uc_uloop_handle_handle(uc_vm_t *vm, size_t nargs)
{
	uc_uloop_handle_t **handle = uc_fn_this("uloop.handle");

	if (!handle || !*handle)
		err_return(EINVAL);

	return ucv_get((*handle)->handle);
}

static uc_value_t *
uc_uloop_handle_delete(uc_vm_t *vm, size_t nargs)
{
	uc_uloop_handle_t **handle = uc_fn_this("uloop.handle");
	int rv;

	if (!handle || !*handle)
		err_return(EINVAL);

	rv = uloop_fd_delete(&(*handle)->fd);

	uc_uloop_handle_clear(handle);

	if (rv != 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

static void
uc_uloop_handle_cb(struct uloop_fd *fd, unsigned int flags)
{
	uc_uloop_handle_t *handle = (uc_uloop_handle_t *)fd;
	uc_value_t *f = ucv_uint64_new(flags);

	uc_uloop_reg_invoke(handle->vm, handle->registry_index, f);
	ucv_put(f);
}

static int
get_fd(uc_vm_t *vm, uc_value_t *val)
{
	uc_value_t *fn;
	int64_t n;
	int fd;

	fn = ucv_property_get(val, "fileno");

	if (ucv_is_callable(fn)) {
		uc_vm_stack_push(vm, ucv_get(val));
		uc_vm_stack_push(vm, ucv_get(fn));

		if (uc_vm_call(vm, true, 0) == EXCEPTION_NONE)  {
			val = uc_vm_stack_pop(vm);
		}
		else {
			errno = EBADF;
			val = NULL;
		}
	}
	else {
		ucv_get(val);
	}

	n = ucv_int64_get(val);

	if (errno) {
		fd = -1;
	}
	else if (n < 0 || n > (int64_t)INT_MAX) {
		errno = EBADF;
		fd = -1;
	}
	else {
		fd = (int)n;
	}

	ucv_put(val);

	return fd;
}

static uc_value_t *
uc_uloop_handle(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *fileno = uc_fn_arg(0);
	uc_value_t *callback = uc_fn_arg(1);
	uc_value_t *flags = uc_fn_arg(2);
	uc_uloop_handle_t *handle;
	uc_value_t *res;
	int fd, ret;
	uint64_t f;

	fd = get_fd(vm, fileno);

	if (fd == -1)
		err_return(errno);

	f = ucv_uint64_get(flags);

	if (errno)
		err_return(errno);

	if (f == 0 || f > (uint64_t)UINT_MAX)
		err_return(EINVAL);

	if (!ucv_is_callable(callback))
		err_return(EINVAL);

	handle = xalloc(sizeof(*handle));
	handle->fd.fd = fd;
	handle->fd.cb = uc_uloop_handle_cb;
	handle->handle = ucv_get(fileno);
	handle->vm = vm;

	ret = uloop_fd_add(&handle->fd, (unsigned int)f);

	if (ret != 0) {
		free(handle);
		err_return(errno);
	}

	res = uc_resource_new(handle_type, handle);

	handle->registry_index = uc_uloop_reg_add(res, callback);

	return res;
}


typedef struct {
	struct uloop_process process;
	size_t registry_index;
	uc_vm_t *vm;
} uc_uloop_process_t;

static void
uc_uloop_process_clear(uc_uloop_process_t **process)
{
	/* drop registry entries and clear data to prevent reuse */
	uc_uloop_reg_remove((*process)->registry_index);
	*process = NULL;
}

static uc_value_t *
uc_uloop_process_pid(uc_vm_t *vm, size_t nargs)
{
	uc_uloop_process_t **process = uc_fn_this("uloop.process");

	if (!process || !*process)
		err_return(EINVAL);

	return ucv_int64_new((*process)->process.pid);
}

static uc_value_t *
uc_uloop_process_delete(uc_vm_t *vm, size_t nargs)
{
	uc_uloop_process_t **process = uc_fn_this("uloop.process");
	int rv;

	if (!process || !*process)
		err_return(EINVAL);

	rv = uloop_process_delete(&(*process)->process);

	uc_uloop_process_clear(process);

	if (rv != 0)
		err_return(EINVAL);

	return ucv_boolean_new(true);
}

static void
uc_uloop_process_cb(struct uloop_process *proc, int exitcode)
{
	uc_uloop_process_t *process = (uc_uloop_process_t *)proc;
	uc_value_t *e = ucv_int64_new(exitcode >> 8);

	uc_uloop_reg_invoke(process->vm, process->registry_index, e);
	uc_uloop_process_clear(&process);
	ucv_put(e);
}

static uc_value_t *
uc_uloop_process(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *executable = uc_fn_arg(0);
	uc_value_t *arguments = uc_fn_arg(1);
	uc_value_t *environ = uc_fn_arg(2);
	uc_value_t *callback = uc_fn_arg(3);
	uc_uloop_process_t *process;
	uc_stringbuf_t *buf;
	char **argp, **envp;
	uc_value_t *res;
	pid_t pid;
	size_t i;

	if (ucv_type(executable) != UC_STRING ||
	    (arguments && ucv_type(arguments) != UC_ARRAY) ||
	    (environ && ucv_type(environ) != UC_OBJECT) ||
	    !ucv_is_callable(callback)) {
		err_return(EINVAL);
	}

	pid = fork();

	if (pid == -1)
		err_return(errno);

	if (pid == 0) {
		argp = calloc(ucv_array_length(arguments) + 2, sizeof(char *));
		envp = calloc(ucv_object_length(environ) + 1, sizeof(char *));

		if (!argp || !envp)
			_exit(-1);

		argp[0] = ucv_to_string(vm, executable);

		for (i = 0; i < ucv_array_length(arguments); i++)
			argp[i+1] = ucv_to_string(vm, ucv_array_get(arguments, i));

		i = 0;

		ucv_object_foreach(environ, envk, envv) {
			buf = xprintbuf_new();

			ucv_stringbuf_printf(buf, "%s=", envk);
			ucv_to_stringbuf(vm, buf, envv, false);

			envp[i++] = buf->buf;

			free(buf);
		}

#ifdef __APPLE__
		execve((const char *)ucv_string_get(executable),
		       (char * const *)argp, (char * const *)envp);
#else
		execvpe((const char *)ucv_string_get(executable),
		        (char * const *)argp, (char * const *)envp);
#endif

		_exit(-1);
	}

	process = xalloc(sizeof(*process));
	process->process.pid = pid;
	process->process.cb = uc_uloop_process_cb;
	process->vm = vm;

	uloop_process_add(&process->process);

	res = uc_resource_new(process_type, process);

	process->registry_index = uc_uloop_reg_add(res, callback);

	return res;
}



static const uc_function_list_t timer_fns[] = {
	{ "set",		uc_uloop_timer_set },
	{ "remaining",	uc_uloop_timer_remaining },
	{ "cancel",		uc_uloop_timer_cancel },
};

static const uc_function_list_t handle_fns[] = {
	{ "fileno",		uc_uloop_handle_fileno },
	{ "handle",		uc_uloop_handle_handle },
	{ "delete",		uc_uloop_handle_delete },
};

static const uc_function_list_t process_fns[] = {
	{ "pid",		uc_uloop_process_pid },
	{ "delete",		uc_uloop_process_delete },
};

static const uc_function_list_t global_fns[] = {
	{ "error",		uc_uloop_error },
	{ "init",		uc_uloop_init },
	{ "run",		uc_uloop_run },
	{ "timer",		uc_uloop_timer },
	{ "handle",		uc_uloop_handle },
	{ "process",	uc_uloop_process },
	{ "cancelling",	uc_uloop_cancelling },
	{ "running",	uc_uloop_running },
	{ "done",		uc_uloop_done },
	{ "end",		uc_uloop_end },
};


static void close_timer(void *ud)
{
	uc_uloop_timer_t *timer = ud;

	if (!timer)
		return;

	uloop_timeout_cancel(&timer->timeout);
	free(timer);
}

static void close_handle(void *ud)
{
	uc_uloop_handle_t *handle = ud;

	if (!handle)
		return;

	uloop_fd_delete(&handle->fd);
	ucv_put(handle->handle);
	free(handle);
}

static void close_process(void *ud)
{
	uc_uloop_process_t *process = ud;

	if (!process)
		return;

	uloop_process_delete(&process->process);
	free(process);
}


void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, global_fns);

#define ADD_CONST(x) ucv_object_add(scope, #x, ucv_int64_new(x))

	ADD_CONST(ULOOP_READ);
	ADD_CONST(ULOOP_WRITE);
	ADD_CONST(ULOOP_EDGE_TRIGGER);
	ADD_CONST(ULOOP_BLOCKING);

	timer_type = uc_type_declare(vm, "uloop.timer", timer_fns, close_timer);
	handle_type = uc_type_declare(vm, "uloop.handle", handle_fns, close_handle);
	process_type = uc_type_declare(vm, "uloop.process", process_fns, close_process);

	object_registry = ucv_array_new(vm);

	uc_vm_registry_set(vm, "uloop.registry", object_registry);
}
