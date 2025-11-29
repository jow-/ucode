/*
 * Copyright (C) 2025 Jo-Philipp Wich <jo@mein.io>
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

/**
 * # I/O Operations
 *
 * The `io` module provides object-oriented access to UNIX file descriptors.
 *
 * Functions can be individually imported and directly accessed using the
 * {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import#named_import named import}
 * syntax:
 *
 *   ```
 *   import { open, O_RDWR } from 'io';
 *
 *   let handle = open('/tmp/test.txt', O_RDWR);
 *   handle.write('Hello World\n');
 *   handle.close();
 *   ```
 *
 * Alternatively, the module namespace can be imported
 * using a wildcard import statement:
 *
 *   ```
 *   import * as io from 'io';
 *
 *   let handle = io.open('/tmp/test.txt', io.O_RDWR);
 *   handle.write('Hello World\n');
 *   handle.close();
 *   ```
 *
 * Additionally, the io module namespace may also be imported by invoking
 * the `ucode` interpreter with the `-lio` switch.
 *
 * @module io
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>

#if defined(__linux__)
#define HAS_IOCTL
#endif

#ifdef HAS_IOCTL
#include <sys/ioctl.h>

#define IOC_DIR_NONE	(_IOC_NONE)
#define IOC_DIR_READ	(_IOC_READ)
#define IOC_DIR_WRITE	(_IOC_WRITE)
#define IOC_DIR_RW		(_IOC_READ | _IOC_WRITE)

#endif

#include "ucode/module.h"
#include "ucode/platform.h"

#define err_return(err) do { \
	uc_vm_registry_set(vm, "io.last_error", ucv_int64_new(err)); \
	return NULL; \
} while(0)

typedef struct {
	int fd;
	bool close_on_free;
} uc_io_handle_t;

static bool
get_fd_from_value(uc_vm_t *vm, uc_value_t *val, int *fd)
{
	uc_io_handle_t *handle;
	uc_value_t *fn;
	int64_t n;

	/* Check if it's an io.handle resource */
	handle = ucv_resource_data(val, "io.handle");

	if (handle) {
		if (handle->fd < 0)
			err_return(EBADF);

		*fd = handle->fd;

		return true;
	}

	/* Try calling fileno() method */
	fn = ucv_property_get(val, "fileno");
	errno = 0;

	if (ucv_is_callable(fn)) {
		uc_vm_stack_push(vm, ucv_get(val));
		uc_vm_stack_push(vm, ucv_get(fn));

		if (uc_vm_call(vm, true, 0) != EXCEPTION_NONE)
			err_return(EBADF);

		val = uc_vm_stack_pop(vm);
		n = ucv_int64_get(val);
		ucv_put(val);
	}
	else {
		n = ucv_int64_get(val);
	}

	if (errno || n < 0 || n > (int64_t)INT_MAX)
		err_return(errno ? errno : EBADF);

	*fd = n;

	return true;
}

/**
 * Query error information.
 *
 * Returns a string containing a description of the last occurred error or
 * `null` if there is no error information.
 *
 * @function module:io#error
 *
 * @returns {?string}
 *
 * @example
 * // Trigger an error
 * io.open('/path/does/not/exist');
 *
 * // Print error (should yield "No such file or directory")
 * print(io.error(), "\n");
 */
static uc_value_t *
uc_io_error(uc_vm_t *vm, size_t nargs)
{
	int last_error = ucv_int64_get(uc_vm_registry_get(vm, "io.last_error"));

	if (last_error == 0)
		return NULL;

	uc_vm_registry_set(vm, "io.last_error", ucv_int64_new(0));

	return ucv_string_new(strerror(last_error));
}

/**
 * Represents a handle for interacting with a file descriptor.
 *
 * @class module:io.handle
 * @hideconstructor
 *
 * @borrows module:io#error as module:io.handle#error
 *
 * @see {@link module:io#new|new()}
 * @see {@link module:io#open|open()}
 * @see {@link module:io#from|from()}
 *
 * @example
 *
 * const handle = io.open(…);
 *
 * handle.read(…);
 * handle.write(…);
 *
 * handle.seek(…);
 * handle.tell();
 *
 * handle.fileno();
 *
 * handle.close();
 *
 * handle.error();
 */

/**
 * Reads data from the file descriptor.
 *
 * Reads up to the specified number of bytes from the file descriptor.
 *
 * Returns a string containing the read data.
 *
 * Returns an empty string on EOF.
 *
 * Returns `null` if a read error occurred.
 *
 * @function module:io.handle#read
 *
 * @param {number} length
 * The maximum number of bytes to read.
 *
 * @returns {?string}
 *
 * @example
 * const handle = io.open('/tmp/test.txt', O_RDONLY);
 * const data = handle.read(1024);
 */
static uc_value_t *
uc_io_read(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *limit = uc_fn_arg(0);
	uc_value_t *rv = NULL;
	uc_io_handle_t *handle;
	int fd;
	int64_t len;
	ssize_t rlen;
	char *buf;

	handle = uc_fn_thisval("io.handle");

	if (!handle || handle->fd < 0)
		err_return(EBADF);

	fd = handle->fd;

	if (ucv_type(limit) != UC_INTEGER)
		err_return(EINVAL);

	len = ucv_int64_get(limit);

	if (len <= 0)
		return ucv_string_new_length("", 0);

	if (len > SSIZE_MAX)
		len = SSIZE_MAX;

	buf = xalloc(len);

	rlen = read(fd, buf, len);

	if (rlen < 0) {
		free(buf);
		err_return(errno);
	}

	rv = ucv_string_new_length(buf, rlen);
	free(buf);

	return rv;
}

/**
 * Writes data to the file descriptor.
 *
 * Writes the given data to the file descriptor. Non-string values are
 * converted to strings before being written.
 *
 * Returns the number of bytes written.
 *
 * Returns `null` if a write error occurred.
 *
 * @function module:io.handle#write
 *
 * @param {*} data
 * The data to write.
 *
 * @returns {?number}
 *
 * @example
 * const handle = io.open('/tmp/test.txt', O_WRONLY | O_CREAT);
 * handle.write('Hello World\n');
 */
static uc_value_t *
uc_io_write(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *data = uc_fn_arg(0);
	uc_io_handle_t *handle;
	ssize_t wlen;
	size_t len;
	char *str;
	int fd;

	handle = uc_fn_thisval("io.handle");

	if (!handle || handle->fd < 0)
		err_return(EBADF);

	fd = handle->fd;

	if (ucv_type(data) == UC_STRING) {
		len = ucv_string_length(data);
		wlen = write(fd, ucv_string_get(data), len);
	}
	else {
		str = ucv_to_jsonstring(vm, data);
		len = str ? strlen(str) : 0;
		wlen = write(fd, str, len);
		free(str);
	}

	if (wlen < 0)
		err_return(errno);

	return ucv_int64_new(wlen);
}

/**
 * Sets the file descriptor position.
 *
 * Sets the file position of the descriptor to the given offset and whence.
 *
 * Returns `true` if the position was successfully set.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:io.handle#seek
 *
 * @param {number} [offset=0]
 * The offset in bytes.
 *
 * @param {number} [whence=0]
 * The position reference.
 *
 * | Whence | Description                                                        |
 * |--------|--------------------------------------------------------------------|
 * | `0`    | The offset is relative to the start of the file (SEEK_SET).       |
 * | `1`    | The offset is relative to the current position (SEEK_CUR).        |
 * | `2`    | The offset is relative to the end of the file (SEEK_END).         |
 *
 * @returns {?boolean}
 *
 * @example
 * const handle = io.open('/tmp/test.txt', O_RDONLY);
 * handle.seek(100, 0);  // Seek to byte 100 from start
 */
static uc_value_t *
uc_io_seek(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *ofs = uc_fn_arg(0);
	uc_value_t *how = uc_fn_arg(1);
	uc_io_handle_t *handle;
	int whence;
	off_t offset;
	int fd;

	handle = uc_fn_thisval("io.handle");

	if (!handle || handle->fd < 0)
		err_return(EBADF);

	fd = handle->fd;

	if (!ofs)
		offset = 0;
	else if (ucv_type(ofs) != UC_INTEGER)
		err_return(EINVAL);
	else
		offset = (off_t)ucv_int64_get(ofs);

	if (!how)
		whence = SEEK_SET;
	else if (ucv_type(how) != UC_INTEGER)
		err_return(EINVAL);
	else
		whence = (int)ucv_int64_get(how);

	if (lseek(fd, offset, whence) < 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

/**
 * Gets the current file descriptor position.
 *
 * Returns the current file position as an integer.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:io.handle#tell
 *
 * @returns {?number}
 *
 * @example
 * const handle = io.open('/tmp/test.txt', O_RDONLY);
 * const pos = handle.tell();
 */
static uc_value_t *
uc_io_tell(uc_vm_t *vm, size_t nargs)
{
	uc_io_handle_t *handle;
	off_t offset;
	int fd;

	handle = uc_fn_thisval("io.handle");

	if (!handle || handle->fd < 0)
		err_return(EBADF);

	fd = handle->fd;

	offset = lseek(fd, 0, SEEK_CUR);

	if (offset < 0)
		err_return(errno);

	return ucv_int64_new(offset);
}

/**
 * Duplicates the file descriptor.
 *
 * Creates a duplicate of the file descriptor using dup(2).
 *
 * Returns a new io.handle for the duplicated descriptor.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:io.handle#dup
 *
 * @returns {?module:io.handle}
 *
 * @example
 * const handle = io.open('/tmp/test.txt', O_RDONLY);
 * const dup_handle = handle.dup();
 */
static uc_value_t *
uc_io_dup(uc_vm_t *vm, size_t nargs)
{
	uc_io_handle_t *handle, *new_handle = NULL;
	uc_value_t *res;
	int fd, newfd;

	handle = uc_fn_thisval("io.handle");

	if (!handle || handle->fd < 0)
		err_return(EBADF);

	fd = handle->fd;

	newfd = dup(fd);

	if (newfd < 0)
		err_return(errno);

	res = ucv_resource_create_ex(vm, "io.handle",
	                             (void **)&new_handle, 0, sizeof(*new_handle));

	if (!new_handle)
		err_return(ENOMEM);

	new_handle->fd = newfd;
	new_handle->close_on_free = true;

	return res;
}

/**
 * Duplicates the file descriptor to a specific descriptor number.
 *
 * Creates a duplicate of the file descriptor to the specified descriptor
 * number using dup2(2). If newfd was previously open, it is silently closed.
 *
 * Returns `true` on success.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:io.handle#dup2
 *
 * @param {number} newfd
 * The target file descriptor number.
 *
 * @returns {?boolean}
 *
 * @example
 * const handle = io.open('/tmp/test.txt', O_WRONLY);
 * handle.dup2(2);  // Redirect stderr to the file
 */
static uc_value_t *
uc_io_dup2(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *newfd_arg = uc_fn_arg(0);
	uc_io_handle_t *handle;
	int fd, newfd;

	handle = uc_fn_thisval("io.handle");

	if (!handle || handle->fd < 0)
		err_return(EBADF);

	fd = handle->fd;

	if (!get_fd_from_value(vm, newfd_arg, &newfd))
		return NULL;

	if (dup2(fd, newfd) < 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

/**
 * Gets the file descriptor number.
 *
 * Returns the underlying file descriptor number.
 *
 * Returns `null` if the handle is closed.
 *
 * @function module:io.handle#fileno
 *
 * @returns {?number}
 *
 * @example
 * const handle = io.open('/tmp/test.txt', O_RDONLY);
 * print(handle.fileno(), "\n");
 */
static uc_value_t *
uc_io_fileno(uc_vm_t *vm, size_t nargs)
{
	uc_io_handle_t *handle;

	handle = uc_fn_thisval("io.handle");

	if (!handle || handle->fd < 0)
		err_return(EBADF);

	return ucv_int64_new(handle->fd);
}

/**
 * Performs fcntl() operations on the file descriptor.
 *
 * Performs the specified fcntl() command on the file descriptor with an
 * optional argument.
 *
 * Returns the result of the fcntl() call. For F_DUPFD and F_DUPFD_CLOEXEC,
 * returns a new io.handle wrapping the duplicated descriptor. For other
 * commands, returns a number (interpretation depends on cmd).
 *
 * Returns `null` if an error occurred.
 *
 * @function module:io.handle#fcntl
 *
 * @param {number} cmd
 * The fcntl command (e.g., F_GETFL, F_SETFL, F_GETFD, F_SETFD, F_DUPFD).
 *
 * @param {number} [arg]
 * Optional argument for the command.
 *
 * @returns {?(number|module:io.handle)}
 *
 * @example
 * const handle = io.open('/tmp/test.txt', O_RDONLY);
 * const flags = handle.fcntl(F_GETFL);
 * handle.fcntl(F_SETFL, flags | O_NONBLOCK);
 * const dup_handle = handle.fcntl(F_DUPFD, 10);  // Returns io.handle
 */
static uc_value_t *
uc_io_fcntl(uc_vm_t *vm, size_t nargs)
{
	uc_io_handle_t *handle, *new_handle = NULL;
	uc_value_t *cmd_arg = uc_fn_arg(0);
	uc_value_t *val_arg = uc_fn_arg(1);
	uc_value_t *res;
	int fd, cmd, ret;
	long arg = 0;

	handle = uc_fn_thisval("io.handle");

	if (!handle || handle->fd < 0)
		err_return(EBADF);

	fd = handle->fd;

	if (ucv_type(cmd_arg) != UC_INTEGER)
		err_return(EINVAL);

	cmd = (int)ucv_int64_get(cmd_arg);

	if (val_arg) {
		if (ucv_type(val_arg) != UC_INTEGER)
			err_return(EINVAL);

		arg = (long)ucv_int64_get(val_arg);
	}

	ret = fcntl(fd, cmd, arg);

	if (ret < 0)
		err_return(errno);

	/* F_DUPFD and F_DUPFD_CLOEXEC return a new fd that we own */
	if (cmd == F_DUPFD
#ifdef F_DUPFD_CLOEXEC
	    || cmd == F_DUPFD_CLOEXEC
#endif
	) {
		res = ucv_resource_create_ex(vm, "io.handle", (void **)&new_handle,
		                             0, sizeof(*new_handle));

		if (!new_handle)
			err_return(ENOMEM);

		new_handle->fd = ret;
		new_handle->close_on_free = true;

		return res;
	}

	return ucv_int64_new(ret);
}

#ifdef HAS_IOCTL

/**
 * Performs an ioctl operation on the file descriptor.
 *
 * The direction parameter specifies who is reading and writing,
 * from the user's point of view. It can be one of the following values:
 *
 * | Direction      | Description                                                                       |
 * |----------------|-----------------------------------------------------------------------------------|
 * | IOC_DIR_NONE   | neither userspace nor kernel is writing, ioctl is executed without passing data.  |
 * | IOC_DIR_WRITE  | userspace is writing and kernel is reading.                                       |
 * | IOC_DIR_READ   | kernel is writing and userspace is reading.                                       |
 * | IOC_DIR_RW     | userspace is writing and kernel is writing back into the data structure.          |
 *
 * Returns the result of the ioctl operation; for `IOC_DIR_READ` and
 * `IOC_DIR_RW` this is a string containing the data, otherwise a number as
 * return code.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:io.handle#ioctl
 *
 * @param {number} direction
 * The direction of the ioctl operation. Use constants IOC_DIR_*.
 *
 * @param {number} type
 * The ioctl type (see https://www.kernel.org/doc/html/latest/userspace-api/ioctl/ioctl-number.html)
 *
 * @param {number} num
 * The ioctl sequence number.
 *
 * @param {number|string} [value]
 * The value to pass to the ioctl system call. For `IOC_DIR_NONE`, this argument
 * is ignored. With `IOC_DIR_READ`, the value should be a positive integer
 * specifying the number of bytes to expect from the kernel. For the other
 * directions, `IOC_DIR_WRITE` and `IOC_DIR_RW`, that value parameter must be a
 * string, serving as buffer for the data to send.
 *
 * @returns {?number|?string}
 *
 * @example
 * const handle = io.open('/dev/tty', O_RDWR);
 * const size = handle.ioctl(IOC_DIR_READ, 0x54, 0x13, 8);  // TIOCGWINSZ
 */
static uc_value_t *
uc_io_ioctl(uc_vm_t *vm, size_t nargs)
{
	uc_io_handle_t *handle = uc_fn_thisval("io.handle");
	uc_value_t *direction = uc_fn_arg(0);
	uc_value_t *type = uc_fn_arg(1);
	uc_value_t *num = uc_fn_arg(2);
	uc_value_t *value = uc_fn_arg(3);
	uc_value_t *mem = NULL;
	char *buf = NULL;
	unsigned long req = 0;
	unsigned int dir, ty, nr;
	size_t sz = 0;
	int fd, ret;

	if (!handle || handle->fd < 0)
		err_return(EBADF);

	fd = handle->fd;

	if (ucv_type(direction) != UC_INTEGER || ucv_type(type) != UC_INTEGER ||
	    ucv_type(num) != UC_INTEGER)
		err_return(EINVAL);

	dir = ucv_uint64_get(direction);
	ty = ucv_uint64_get(type);
	nr = ucv_uint64_get(num);

	switch (dir) {
	case IOC_DIR_NONE:
		break;

	case IOC_DIR_WRITE:
		if (ucv_type(value) != UC_STRING)
			err_return(EINVAL);

		sz = ucv_string_length(value);
		buf = ucv_string_get(value);
		break;

	case IOC_DIR_READ:
		if (ucv_type(value) != UC_INTEGER)
			err_return(EINVAL);

		sz = ucv_to_unsigned(value);

		if (errno != 0)
			err_return(errno);

		mem = xalloc(sizeof(uc_string_t) + sz + 1);
		mem->type = UC_STRING;
		mem->refcount = 1;
		buf = ucv_string_get(mem);
		((uc_string_t *)mem)->length = sz;
		break;

	case IOC_DIR_RW:
		if (ucv_type(value) != UC_STRING)
			err_return(EINVAL);

		sz = ucv_string_length(value);
		mem = ucv_string_new_length(ucv_string_get(value), sz);
		buf = ucv_string_get(mem);
		break;

	default:
		err_return(EINVAL);
	}

	req = _IOC(dir, ty, nr, sz);
	ret = ioctl(fd, req, buf);

	if (ret < 0) {
		ucv_put(mem);
		err_return(errno);
	}

	return mem ? mem : ucv_uint64_new(ret);
}

#endif

/**
 * Checks if the file descriptor refers to a terminal.
 *
 * Returns `true` if the descriptor refers to a terminal device.
 *
 * Returns `false` otherwise.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:io.handle#isatty
 *
 * @returns {?boolean}
 *
 * @example
 * const handle = io.new(0);  // stdin
 * if (handle.isatty())
 *     print("Running in a terminal\n");
 */
static uc_value_t *
uc_io_isatty(uc_vm_t *vm, size_t nargs)
{
	uc_io_handle_t *handle;
	int fd;

	handle = uc_fn_thisval("io.handle");

	if (!handle || handle->fd < 0)
		err_return(EBADF);

	fd = handle->fd;

	return ucv_boolean_new(isatty(fd) == 1);
}

/**
 * Closes the file descriptor.
 *
 * Closes the underlying file descriptor. Further operations on this handle
 * will fail.
 *
 * Returns `true` if the descriptor was successfully closed.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:io.handle#close
 *
 * @returns {?boolean}
 *
 * @example
 * const handle = io.open('/tmp/test.txt', O_RDONLY);
 * handle.close();
 */
static uc_value_t *
uc_io_close(uc_vm_t *vm, size_t nargs)
{
	uc_io_handle_t *handle;

	handle = uc_fn_thisval("io.handle");

	if (!handle || handle->fd < 0)
		err_return(EBADF);

	if (close(handle->fd) < 0)
		err_return(errno);

	handle->fd = -1;

	return ucv_boolean_new(true);
}

/**
 * Creates an io.handle from a file descriptor number.
 *
 * Wraps the given file descriptor number in an io.handle object.
 *
 * Returns an io.handle object.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:io#new
 *
 * @param {number} fd
 * The file descriptor number.
 *
 * @returns {?module:io.handle}
 *
 * @example
 * // Wrap stdin
 * const stdin = io.new(0);
 * const data = stdin.read(100);
 */
static uc_value_t *
uc_io_new(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *fdno = uc_fn_arg(0);
	uc_io_handle_t *handle = NULL;
	uc_value_t *res;
	int64_t n;

	if (ucv_type(fdno) != UC_INTEGER)
		err_return(EINVAL);

	n = ucv_int64_get(fdno);

	if (n < 0 || n > INT_MAX)
		err_return(EBADF);

	res = ucv_resource_create_ex(vm, "io.handle",
	                             (void **)&handle, 0, sizeof(*handle));

	if (!handle)
		err_return(ENOMEM);

	handle->fd = (int)n;
	handle->close_on_free = false;  /* Don't own this fd */

	return res;
}

/**
 * Opens a file and returns an io.handle.
 *
 * Opens the specified file with the given flags and mode, returning an
 * io.handle wrapping the resulting file descriptor.
 *
 * Returns an io.handle object.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:io#open
 *
 * @param {string} path
 * The path to the file.
 *
 * @param {number} [flags=O_RDONLY]
 * The open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.).
 *
 * @param {number} [mode=0o666]
 * The file creation mode (used with O_CREAT).
 *
 * @returns {?module:io.handle}
 *
 * @example
 * const handle = io.open('/tmp/test.txt', O_RDWR | O_CREAT, 0o644);
 * handle.write('Hello World\n');
 * handle.close();
 */
static uc_value_t *
uc_io_open(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);
	uc_value_t *flags = uc_fn_arg(1);
	uc_value_t *mode = uc_fn_arg(2);
	uc_io_handle_t *handle = NULL;
	uc_value_t *res;
	int open_flags = O_RDONLY;
	mode_t open_mode = 0666;
	int fd;

	if (ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	if (flags) {
		if (ucv_type(flags) != UC_INTEGER)
			err_return(EINVAL);

		open_flags = (int)ucv_int64_get(flags);
	}

	if (mode) {
		if (ucv_type(mode) != UC_INTEGER)
			err_return(EINVAL);

		open_mode = (mode_t)ucv_int64_get(mode);
	}

	fd = open(ucv_string_get(path), open_flags, open_mode);

	if (fd < 0)
		err_return(errno);

	res = ucv_resource_create_ex(vm, "io.handle",
	                             (void **)&handle, 0, sizeof(*handle));

	if (!handle)
		err_return(ENOMEM);

	handle->fd = fd;
	handle->close_on_free = true;  /* We own this fd */

	return res;
}

/**
 * Creates a pipe.
 *
 * Creates a unidirectional data channel (pipe) that can be used for
 * inter-process communication. Returns an array containing two io.handle
 * objects: the first is the read end of the pipe, the second is the write end.
 *
 * Data written to the write end can be read from the read end.
 *
 * Returns an array `[read_handle, write_handle]` on success.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:io#pipe
 *
 * @returns {?Array<module:io.handle>}
 *
 * @example
 * const [reader, writer] = io.pipe();
 * writer.write('Hello from pipe!');
 * const data = reader.read(100);
 * print(data, "\n");  // Prints: Hello from pipe!
 */
static uc_value_t *
uc_io_pipe(uc_vm_t *vm, size_t nargs)
{
	uc_io_handle_t *read_handle = NULL, *write_handle = NULL;
	uc_value_t *result, *res;
	int fds[2];

	if (pipe(fds) < 0)
		err_return(errno);

	res = ucv_resource_create_ex(vm, "io.handle", (void **)&read_handle, 0,
	                             sizeof(*read_handle));

	if (!read_handle)
		err_return(ENOMEM);

	read_handle->fd = fds[0];
	read_handle->close_on_free = true;

	result = ucv_array_new(vm);
	ucv_array_push(result, res);

	res = ucv_resource_create_ex(vm, "io.handle", (void **)&write_handle, 0,
	                             sizeof(*write_handle));

	if (!write_handle) {
		ucv_put(result);
		err_return(ENOMEM);
	}

	write_handle->fd = fds[1];
	write_handle->close_on_free = true;

	ucv_array_push(result, res);

	return result;
}

/**
 * Creates an io.handle from various value types.
 *
 * Creates an io.handle by extracting the file descriptor from the given value.
 * The value can be:
 * - An integer file descriptor number
 * - An fs.file, fs.proc, or socket resource
 * - Any object/array/resource with a fileno() method
 *
 * Returns an io.handle object.
 *
 * Returns `null` if an error occurred or the value cannot be converted.
 *
 * @function module:io#from
 *
 * @param {*} value
 * The value to convert.
 *
 * @returns {?module:io.handle}
 *
 * @example
 * import { open as fsopen } from 'fs';
 * const fp = fsopen('/tmp/test.txt', 'r');
 * const handle = io.from(fp);
 * const data = handle.read(100);
 */
static uc_value_t *
uc_io_from(uc_vm_t *vm, size_t nargs)
{
	uc_io_handle_t *handle = NULL;
	uc_value_t *val = uc_fn_arg(0);
	uc_value_t *res;
	int fd;

	if (!val)
		err_return(EINVAL);

	if (!get_fd_from_value(vm, val, &fd))
		return NULL;

	res = ucv_resource_create_ex(vm, "io.handle",
	                             (void **)&handle, 0, sizeof(*handle));

	if (!handle)
		err_return(ENOMEM);

	handle->fd = fd;
	handle->close_on_free = false;  /* Don't own this fd, it's from external source */

	return res;
}

static void
uc_io_handle_free(void *ptr)
{
	uc_io_handle_t *handle = ptr;

	if (!handle)
		return;

	if (handle->close_on_free && handle->fd >= 0)
		close(handle->fd);
}

static const uc_function_list_t io_handle_fns[] = {
	{ "read",		uc_io_read },
	{ "write",		uc_io_write },
	{ "seek",		uc_io_seek },
	{ "tell",		uc_io_tell },
	{ "dup",		uc_io_dup },
	{ "dup2",		uc_io_dup2 },
	{ "fileno",		uc_io_fileno },
	{ "fcntl",		uc_io_fcntl },
#ifdef HAS_IOCTL
	{ "ioctl",		uc_io_ioctl },
#endif
	{ "isatty",		uc_io_isatty },
	{ "close",		uc_io_close },
	{ "error",		uc_io_error },
};

static const uc_function_list_t io_fns[] = {
	{ "error",		uc_io_error },
	{ "new",		uc_io_new },
	{ "open",		uc_io_open },
	{ "from",		uc_io_from },
	{ "pipe",		uc_io_pipe },
};

#define ADD_CONST(x) ucv_object_add(scope, #x, ucv_int64_new(x))

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, io_fns);

	ADD_CONST(O_RDONLY);
	ADD_CONST(O_WRONLY);
	ADD_CONST(O_RDWR);
	ADD_CONST(O_CREAT);
	ADD_CONST(O_EXCL);
	ADD_CONST(O_TRUNC);
	ADD_CONST(O_APPEND);
	ADD_CONST(O_NONBLOCK);
	ADD_CONST(O_NOCTTY);
	ADD_CONST(O_SYNC);
	ADD_CONST(O_CLOEXEC);
#ifdef O_DIRECTORY
	ADD_CONST(O_DIRECTORY);
#endif
#ifdef O_NOFOLLOW
	ADD_CONST(O_NOFOLLOW);
#endif

	ADD_CONST(SEEK_SET);
	ADD_CONST(SEEK_CUR);
	ADD_CONST(SEEK_END);

	ADD_CONST(F_DUPFD);
#ifdef F_DUPFD_CLOEXEC
	ADD_CONST(F_DUPFD_CLOEXEC);
#endif
	ADD_CONST(F_GETFD);
	ADD_CONST(F_SETFD);
	ADD_CONST(F_GETFL);
	ADD_CONST(F_SETFL);
	ADD_CONST(F_GETLK);
	ADD_CONST(F_SETLK);
	ADD_CONST(F_SETLKW);
	ADD_CONST(F_GETOWN);
	ADD_CONST(F_SETOWN);

	ADD_CONST(FD_CLOEXEC);

#ifdef HAS_IOCTL
	ADD_CONST(IOC_DIR_NONE);
	ADD_CONST(IOC_DIR_READ);
	ADD_CONST(IOC_DIR_WRITE);
	ADD_CONST(IOC_DIR_RW);
#endif

	uc_type_declare(vm, "io.handle", io_handle_fns, uc_io_handle_free);
}
