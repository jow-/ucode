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
#include <fcntl.h>

#include <libubox/uloop.h>

#include "ucode/module.h"
#include "ucode/platform.h"

#define err_return(err) do { last_error = err; return NULL; } while(0)

static uc_resource_type_t *timer_type, *handle_type, *process_type, *task_type, *pipe_type;
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
	uc_value_t *env_arg = uc_fn_arg(2);
	uc_value_t *callback = uc_fn_arg(3);
	uc_uloop_process_t *process;
	uc_stringbuf_t *buf;
	char **argp, **envp;
	uc_value_t *res;
	pid_t pid;
	size_t i;

	if (ucv_type(executable) != UC_STRING ||
	    (arguments && ucv_type(arguments) != UC_ARRAY) ||
	    (env_arg && ucv_type(env_arg) != UC_OBJECT) ||
	    !ucv_is_callable(callback)) {
		err_return(EINVAL);
	}

	pid = fork();

	if (pid == -1)
		err_return(errno);

	if (pid == 0) {
		argp = calloc(ucv_array_length(arguments) + 2, sizeof(char *));
		envp = calloc(ucv_object_length(env_arg) + 1, sizeof(char *));

		if (!argp || !envp)
			_exit(-1);

		argp[0] = ucv_to_string(vm, executable);

		for (i = 0; i < ucv_array_length(arguments); i++)
			argp[i+1] = ucv_to_string(vm, ucv_array_get(arguments, i));

		i = 0;

		ucv_object_foreach(env_arg, envk, envv) {
			buf = xprintbuf_new();

			ucv_stringbuf_printf(buf, "%s=", envk);
			ucv_to_stringbuf(vm, buf, envv, false);

			envp[i++] = buf->buf;

			free(buf);
		}

		execvpe((const char *)ucv_string_get(executable),
		        (char * const *)argp, (char * const *)envp);

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


static bool
readall(int fd, void *buf, size_t len)
{
	ssize_t rlen;

	while (len > 0) {
		rlen = read(fd, buf, len);

		if (rlen == -1) {
			if (errno == EINTR)
				continue;

			return false;
		}

		if (rlen == 0) {
			errno = EINTR;

			return false;
		}

		buf += rlen;
		len -= rlen;
	}

	return true;
}

static bool
writeall(int fd, void *buf, size_t len)
{
	ssize_t wlen;

	while (len > 0) {
		wlen = write(fd, buf, len);

		if (wlen == -1) {
			if (errno == EINTR)
				continue;

			return false;
		}

		buf += wlen;
		len -= wlen;
	}

	return true;
}

typedef struct {
	int input;
	int output;
	bool has_sender;
	bool has_receiver;
} uc_uloop_pipe_t;

static uc_value_t *
uc_uloop_pipe_send_common(uc_vm_t *vm, uc_value_t *msg, int fd)
{
	uc_stringbuf_t *buf;
	size_t len;
	bool rv;

	buf = xprintbuf_new();

	printbuf_memset(buf, 0, 0, sizeof(len));
	ucv_to_stringbuf(vm, buf, msg, true);

	len = printbuf_length(buf);
	memcpy(buf->buf, &len, sizeof(len));

	rv = writeall(fd, buf->buf, len);

	printbuf_free(buf);

	if (!rv)
		err_return(errno);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_uloop_pipe_send(uc_vm_t *vm, size_t nargs)
{
	uc_uloop_pipe_t **pipe = uc_fn_this("uloop.pipe");
	uc_value_t *msg = uc_fn_arg(0);

	if (!pipe || !*pipe)
		err_return(EINVAL);

	if (!(*pipe)->has_receiver)
		err_return(EPIPE);

	return uc_uloop_pipe_send_common(vm, msg, (*pipe)->output);
}

static bool
uc_uloop_pipe_receive_common(uc_vm_t *vm, int fd, uc_value_t **res, bool skip)
{
	enum json_tokener_error err = json_tokener_error_parse_eof;
	json_tokener *tok = NULL;
	json_object *jso = NULL;
	char buf[1024];
	ssize_t rlen;
	size_t len;

	*res = NULL;

	if (!readall(fd, &len, sizeof(len)))
		err_return(errno);

	/* message length 0 is special, means input requested on other pipe */
	if (len == 0)
		err_return(ENODATA);

	/* valid messages should be at least sizeof(len) plus one byte of payload */
	if (len <= sizeof(len))
		err_return(EINVAL);

	len -= sizeof(len);

	while (len > 0) {
		rlen = read(fd, buf, len < sizeof(buf) ? len : sizeof(buf));

		if (rlen == -1) {
			if (errno == EINTR)
				continue;

			goto read_fail;
		}

		/* premature EOF */
		if (rlen == 0) {
			errno = EPIPE;
			goto read_fail;
		}

		if (!skip) {
			if (!tok)
				tok = xjs_new_tokener();

			jso = json_tokener_parse_ex(tok, buf, rlen);
			err = json_tokener_get_error(tok);
		}

		len -= rlen;
	}

	if (!skip) {
		if (err == json_tokener_continue) {
			jso = json_tokener_parse_ex(tok, "\0", 1);
			err = json_tokener_get_error(tok);
		}

		json_tokener_free(tok);

		if (err != json_tokener_success) {
			errno = EINVAL;
			goto read_fail;
		}

		*res = ucv_from_json(vm, jso);

		json_object_put(jso);
	}

	return true;

read_fail:
	if (tok)
		json_tokener_free(tok);

	json_object_put(jso);
	err_return(errno);
}

static uc_value_t *
uc_uloop_pipe_receive(uc_vm_t *vm, size_t nargs)
{
	uc_uloop_pipe_t **pipe = uc_fn_this("uloop.pipe");
	uc_value_t *rv;
	size_t len = 0;

	if (!pipe || !*pipe)
		err_return(EINVAL);

	if (!(*pipe)->has_sender)
		err_return(EPIPE);

	/* send zero-length message to signal input request */
	writeall((*pipe)->output, &len, sizeof(len));

	/* receive input message */
	uc_uloop_pipe_receive_common(vm, (*pipe)->input, &rv, false);

	return rv;
}

static uc_value_t *
uc_uloop_pipe_sending(uc_vm_t *vm, size_t nargs)
{
	uc_uloop_pipe_t **pipe = uc_fn_this("uloop.pipe");

	if (!pipe || !*pipe)
		err_return(EINVAL);

	return ucv_boolean_new((*pipe)->has_sender);
}

static uc_value_t *
uc_uloop_pipe_receiving(uc_vm_t *vm, size_t nargs)
{
	uc_uloop_pipe_t **pipe = uc_fn_this("uloop.pipe");

	if (!pipe || !*pipe)
		err_return(EINVAL);

	return ucv_boolean_new((*pipe)->has_receiver);
}


typedef struct {
	struct uloop_process process;
	struct uloop_fd output;
	size_t registry_index;
	bool finished;
	int input_fd;
	uc_vm_t *vm;
	uc_value_t *input_cb;
	uc_value_t *output_cb;
} uc_uloop_task_t;

static int
patch_devnull(int fd, bool write)
{
	int devnull = open("/dev/null", write ? O_WRONLY : O_RDONLY);

	if (devnull != -1) {
		dup2(fd, devnull);
		close(fd);
	}

	return devnull;
}

static void
uloop_fd_close(struct uloop_fd *fd) {
	if (fd->fd == -1)
		return;

	close(fd->fd);
	fd->fd = -1;
}

static void
uc_uloop_task_clear(uc_uloop_task_t **task)
{
	/* drop registry entries and clear data to prevent reuse */
	uc_uloop_reg_remove((*task)->registry_index);
	*task = NULL;
}

static uc_value_t *
uc_uloop_task_pid(uc_vm_t *vm, size_t nargs)
{
	uc_uloop_task_t **task = uc_fn_this("uloop.task");

	if (!task || !*task)
		err_return(EINVAL);

	if ((*task)->finished)
		err_return(ESRCH);

	return ucv_int64_new((*task)->process.pid);
}

static uc_value_t *
uc_uloop_task_kill(uc_vm_t *vm, size_t nargs)
{
	uc_uloop_task_t **task = uc_fn_this("uloop.task");
	int rv;

	if (!task || !*task)
		err_return(EINVAL);

	if ((*task)->finished)
		err_return(ESRCH);

	rv = kill((*task)->process.pid, SIGTERM);

	if (rv == -1)
		err_return(errno);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_uloop_task_finished(uc_vm_t *vm, size_t nargs)
{
	uc_uloop_task_t **task = uc_fn_this("uloop.task");

	if (!task || !*task)
		err_return(EINVAL);

	return ucv_boolean_new((*task)->finished);
}

static void
uc_uloop_task_output_cb(struct uloop_fd *fd, unsigned int flags)
{
	uc_uloop_task_t *task = container_of(fd, uc_uloop_task_t, output);
	uc_value_t *obj = ucv_array_get(object_registry, task->registry_index);
	uc_value_t *msg = NULL;

	if (flags & ULOOP_READ) {
		while (true) {
			if (!uc_uloop_pipe_receive_common(task->vm, fd->fd, &msg, !task->output_cb)) {
				/* input requested */
				if (last_error == ENODATA) {
					uc_vm_stack_push(task->vm, ucv_get(obj));
					uc_vm_stack_push(task->vm, ucv_get(task->input_cb));

					if (uc_vm_call(task->vm, true, 0) != EXCEPTION_NONE) {
						uloop_end();

						return;
					}

					msg = uc_vm_stack_pop(task->vm);
					uc_uloop_pipe_send_common(task->vm, msg, task->input_fd);
					ucv_put(msg);

					continue;
				}

				/* error */
				break;
			}

			if (task->output_cb) {
				uc_vm_stack_push(task->vm, ucv_get(obj));
				uc_vm_stack_push(task->vm, ucv_get(task->output_cb));
				uc_vm_stack_push(task->vm, msg);

				if (uc_vm_call(task->vm, true, 1) == EXCEPTION_NONE) {
					ucv_put(uc_vm_stack_pop(task->vm));
				}
				else {
					uloop_end();

					return;
				}
			}
			else {
				ucv_put(msg);
			}
		}
	}

	if (!fd->registered && task->finished) {
		close(task->input_fd);
		task->input_fd = -1;

		uloop_fd_close(&task->output);
		uloop_process_delete(&task->process);

		uc_uloop_task_clear(&task);
	}
}

static void
uc_uloop_task_process_cb(struct uloop_process *proc, int exitcode)
{
	uc_uloop_task_t *task = container_of(proc, uc_uloop_task_t, process);

	task->finished = true;

	uc_uloop_task_output_cb(&task->output, ULOOP_READ);
}

static uc_value_t *
uc_uloop_task(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *func = uc_fn_arg(0);
	uc_value_t *output_cb = uc_fn_arg(1);
	uc_value_t *input_cb = uc_fn_arg(2);
	int outpipe[2] = { -1, -1 };
	int inpipe[2] = { -1, -1 };
	uc_value_t *res, *cbs, *p;
	uc_uloop_pipe_t *tpipe;
	uc_uloop_task_t *task;
	pid_t pid;
	int err;

	if (!ucv_is_callable(func) ||
	    (output_cb && !ucv_is_callable(output_cb)) ||
	    (input_cb && !ucv_is_callable(input_cb)))
	    err_return(EINVAL);

	if (pipe(outpipe) == -1 || pipe(inpipe) == -1) {
		err = errno;

		close(outpipe[0]); close(outpipe[1]);
		close(inpipe[0]); close(inpipe[1]);

		err_return(err);
	}

	pid = fork();

	if (pid == -1)
		err_return(errno);

	if (pid == 0) {
		uloop_done();

		patch_devnull(0, false);
		patch_devnull(1, true);
		patch_devnull(2, true);

		vm->output = fdopen(1, "w");

		close(inpipe[1]);
		close(outpipe[0]);

		tpipe = xalloc(sizeof(*tpipe));
		tpipe->input = inpipe[0];
		tpipe->output = outpipe[1];
		tpipe->has_sender = input_cb;
		tpipe->has_receiver = output_cb;

		p = uc_resource_new(pipe_type, tpipe);

		uc_vm_stack_push(vm, func);
		uc_vm_stack_push(vm, ucv_get(p));

		if (uc_vm_call(vm, false, 1) == EXCEPTION_NONE) {
			res = uc_vm_stack_pop(vm);
			uc_uloop_pipe_send_common(vm, res, tpipe->output);
			ucv_put(res);
		}

		ucv_put(p);

		_exit(0);
	}

	close(inpipe[0]);
	close(outpipe[1]);

	task = xalloc(sizeof(*task));
	task->process.pid = pid;
	task->process.cb = uc_uloop_task_process_cb;

	task->vm = vm;

	task->output.fd = outpipe[0];
	task->output.cb = uc_uloop_task_output_cb;
	task->output_cb = output_cb;
	uloop_fd_add(&task->output, ULOOP_READ);

	if (input_cb) {
		task->input_fd = inpipe[1];
		task->input_cb = input_cb;
	}
	else {
		task->input_fd = -1;
		close(inpipe[1]);
	}

	uloop_process_add(&task->process);

	res = uc_resource_new(task_type, task);

	cbs = ucv_array_new(NULL);
	ucv_array_set(cbs, 0, ucv_get(output_cb));
	ucv_array_set(cbs, 1, ucv_get(input_cb));

	task->registry_index = uc_uloop_reg_add(res, cbs);

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

static const uc_function_list_t task_fns[] = {
	{ "pid",		uc_uloop_task_pid },
	{ "kill",		uc_uloop_task_kill },
	{ "finished",	uc_uloop_task_finished },
};

static const uc_function_list_t pipe_fns[] = {
	{ "send",		uc_uloop_pipe_send },
	{ "receive",	uc_uloop_pipe_receive },
	{ "sending",	uc_uloop_pipe_sending },
	{ "receiving",	uc_uloop_pipe_receiving },
};

static const uc_function_list_t global_fns[] = {
	{ "error",		uc_uloop_error },
	{ "init",		uc_uloop_init },
	{ "run",		uc_uloop_run },
	{ "timer",		uc_uloop_timer },
	{ "handle",		uc_uloop_handle },
	{ "process",	uc_uloop_process },
	{ "task",		uc_uloop_task },
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

static void close_task(void *ud)
{
	uc_uloop_task_t *task = ud;

	if (!task)
		return;

	uloop_process_delete(&task->process);
	uloop_fd_close(&task->output);

	if (task->input_fd != -1)
		close(task->input_fd);

	free(task);
}

static void close_pipe(void *ud)
{
	uc_uloop_pipe_t *pipe = ud;

	if (!pipe)
		return;

	close(pipe->input);
	close(pipe->output);

	free(pipe);
}


static struct {
	struct uloop_fd ufd;
	uc_vm_t *vm;
} signal_handle;

static void
uc_uloop_signal_cb(struct uloop_fd *ufd, unsigned int events)
{
	if (uc_vm_signal_dispatch(signal_handle.vm) != EXCEPTION_NONE)
		uloop_end();
}

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	int signal_fd;

	uc_function_list_register(scope, global_fns);

#define ADD_CONST(x) ucv_object_add(scope, #x, ucv_int64_new(x))

	ADD_CONST(ULOOP_READ);
	ADD_CONST(ULOOP_WRITE);
	ADD_CONST(ULOOP_EDGE_TRIGGER);
	ADD_CONST(ULOOP_BLOCKING);

	timer_type = uc_type_declare(vm, "uloop.timer", timer_fns, close_timer);
	handle_type = uc_type_declare(vm, "uloop.handle", handle_fns, close_handle);
	process_type = uc_type_declare(vm, "uloop.process", process_fns, close_process);
	task_type = uc_type_declare(vm, "uloop.task", task_fns, close_task);
	pipe_type = uc_type_declare(vm, "uloop.pipe", pipe_fns, close_pipe);

	object_registry = ucv_array_new(vm);

	uc_vm_registry_set(vm, "uloop.registry", object_registry);

	signal_fd = uc_vm_signal_notifyfd(vm);

	if (signal_fd != -1 && uloop_init() == 0) {
		signal_handle.vm = vm;
		signal_handle.ufd.cb = uc_uloop_signal_cb;
		signal_handle.ufd.fd = signal_fd;

		uloop_fd_add(&signal_handle.ufd, ULOOP_READ);
	}
}
