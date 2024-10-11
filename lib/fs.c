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

/**
 * # Filesystem Access
 *
 * The `fs` module provides functions for interacting with the file system.
 *
 * Functions can be individually imported and directly accessed using the
 * {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import#named_import named import}
 * syntax:
 *
 *   ```
 *   import { readlink, popen } from 'fs';
 *
 *   let dest = readlink('/sys/class/net/eth0');
 *   let proc = popen('ps ww');
 *   ```
 *
 * Alternatively, the module namespace can be imported
 * using a wildcard import statement:
 *
 *   ```
 *   import * as fs from 'fs';
 *
 *   let dest = fs.readlink('/sys/class/net/eth0');
 *   let proc = fs.popen('ps ww');
 *   ```
 *
 * Additionally, the filesystem module namespace may also be imported by invoking
 * the `ucode` interpreter with the `-lfs` switch.
 *
 * @module fs
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <grp.h>
#include <pwd.h>
#include <glob.h>
#include <fnmatch.h>
#include <limits.h>
#include <fcntl.h>

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

#define err_return(err) do { last_error = err; return NULL; } while(0)

//static const uc_ops *ops;
static uc_resource_type_t *file_type, *proc_type, *dir_type;

static int last_error = 0;

/**
 * Query error information.
 *
 * Returns a string containing a description of the last occurred error or
 * `null` if there is no error information.
 *
 * @function module:fs#error
 *
 *
 * @returns {?string}
 *
 * @example
 * // Trigger file system error
 * unlink('/path/does/not/exist');
 *
 * // Print error (should yield "No such file or directory")
 * print(error(), "\n");
 */
static uc_value_t *
uc_fs_error(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *errmsg;

	if (last_error == 0)
		return NULL;

	errmsg = ucv_string_new(strerror(last_error));
	last_error = 0;

	return errmsg;
}

static uc_value_t *
uc_fs_read_common(uc_vm_t *vm, size_t nargs, const char *type)
{
	uc_value_t *limit = uc_fn_arg(0);
	uc_value_t *rv = NULL;
	char buf[128], *p = NULL, *tmp;
	size_t rlen, len = 0;
	const char *lstr;
	int64_t lsize;
	ssize_t llen;

	FILE **fp = uc_fn_this(type);

	if (!fp || !*fp)
		err_return(EBADF);

	if (ucv_type(limit) == UC_STRING) {
		lstr = ucv_string_get(limit);
		llen = ucv_string_length(limit);

		if (llen == 4 && !strcmp(lstr, "line")) {
			llen = getline(&p, &rlen, *fp);

			if (llen == -1) {
				free(p);
				err_return(errno);
			}

			len = (size_t)llen;
		}
		else if (llen == 3 && !strcmp(lstr, "all")) {
			while (true) {
				rlen = fread(buf, 1, sizeof(buf), *fp);

				tmp = realloc(p, len + rlen);

				if (!tmp) {
					free(p);
					err_return(ENOMEM);
				}

				memcpy(tmp + len, buf, rlen);

				p = tmp;
				len += rlen;

				if (rlen == 0)
					break;
			}
		}
		else if (llen == 1) {
			llen = getdelim(&p, &rlen, *lstr, *fp);

			if (llen == -1) {
				free(p);
				err_return(errno);
			}

			len = (size_t)llen;
		}
		else {
			return NULL;
		}
	}
	else if (ucv_type(limit) == UC_INTEGER) {
		lsize = ucv_int64_get(limit);

		if (lsize <= 0)
			return NULL;

		p = calloc(1, lsize);

		if (!p)
			err_return(ENOMEM);

		len = fread(p, 1, lsize, *fp);

		if (ferror(*fp)) {
			free(p);
			err_return(errno);
		}
	}
	else {
		err_return(EINVAL);
	}

	rv = ucv_string_new_length(p, len);
	free(p);

	return rv;
}

static uc_value_t *
uc_fs_write_common(uc_vm_t *vm, size_t nargs, const char *type)
{
	uc_value_t *data = uc_fn_arg(0);
	size_t len, wsize;
	char *str;

	FILE **fp = uc_fn_this(type);

	if (!fp || !*fp)
		err_return(EBADF);

	if (ucv_type(data) == UC_STRING) {
		len = ucv_string_length(data);
		wsize = fwrite(ucv_string_get(data), 1, len, *fp);
	}
	else {
		str = ucv_to_jsonstring(vm, data);
		len = str ? strlen(str) : 0;
		wsize = fwrite(str, 1, len, *fp);
		free(str);
	}

	if (wsize < len && ferror(*fp))
		err_return(errno);

	return ucv_int64_new(wsize);
}

static uc_value_t *
uc_fs_flush_common(uc_vm_t *vm, size_t nargs, const char *type)
{
	FILE **fp = uc_fn_this(type);

	if (!fp || !*fp)
		err_return(EBADF);

	if (fflush(*fp) != EOF)
		err_return(errno);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_fs_fileno_common(uc_vm_t *vm, size_t nargs, const char *type)
{
	int fd;

	FILE **fp = uc_fn_this(type);

	if (!fp || !*fp)
		err_return(EBADF);

	fd = fileno(*fp);

	if (fd == -1)
		err_return(errno);

	return ucv_int64_new(fd);
}


/**
 * Represents a handle for interacting with a program launched by `popen()`.
 *
 * @class module:fs.proc
 * @hideconstructor
 *
 * @borrows module:fs#error as module:fs.proc#error
 *
 * @see {@link module:fs#popen|popen()}
 *
 * @example
 *
 * const handle = popen(…);
 *
 * handle.read(…);
 * handle.write(…);
 * handle.flush();
 *
 * handle.fileno();
 *
 * handle.close();
 *
 * handle.error();
 */

/**
 * Closes the program handle and awaits program termination.
 *
 * Upon calling `close()` on the handle, the program's input or output stream
 * (depending on the open mode) is closed. Afterwards, the function awaits the
 * termination of the underlying program and returns its exit code.
 *
 * - When the program was terminated by a signal, the return value will be the
 *   negative signal number, e.g. `-9` for SIGKILL.
 *
 * - When the program terminated normally, the return value will be the positive
 *   exit code of the program.
 *
 * Returns a negative signal number if the program was terminated by a signal.
 *
 * Returns a positive exit code if the program terminated normally.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:fs.proc#close
 *
 * @returns {?number}
 */
static uc_value_t *
uc_fs_pclose(uc_vm_t *vm, size_t nargs)
{
	FILE **fp = uc_fn_this("fs.proc");
	int rc;

	if (!fp || !*fp)
		err_return(EBADF);

	rc = pclose(*fp);
	*fp = NULL;

	if (rc == -1)
		err_return(errno);

	if (WIFEXITED(rc))
		return ucv_int64_new(WEXITSTATUS(rc));

	if (WIFSIGNALED(rc))
		return ucv_int64_new(-WTERMSIG(rc));

	return ucv_int64_new(0);
}

/**
 * Reads a chunk of data from the program handle.
 *
 * The length argument may be either a positive number of bytes to read, in
 * which case the read call returns up to that many bytes, or a string to
 * specify a dynamic read size.
 *
 *  - If length is a number, the method will read the specified number of bytes
 *    from the handle. Reading stops after the given amount of bytes or after
 *    encountering EOF, whatever comes first.
 *
 *  - If length is the string "line", the method will read an entire line,
 *    terminated by "\n" (a newline), from the handle. Reading stops at the next
 *    newline or when encountering EOF. The returned data will contain the
 *    terminating newline character if one was read.
 *
 *  - If length is the string "all", the method will read from the handle until
 *    encountering EOF and return the complete contents.
 *
 *  - If length is a single character string, the method will read from the
 *    handle until encountering the specified character or upon encountering
 *    EOF. The returned data will contain the terminating character if one was
 *    read.
 *
 * Returns a string containing the read data.
 *
 * Returns an empty string on EOF.
 *
 * Returns `null` if a read error occurred.
 *
 * @function module:fs.proc#read
 *
 * @param {number|string} length
 * The length of data to read. Can be a number, the string "line", the string
 * "all", or a single character string.
 *
 * @returns {?string}
 *
 * @example
 * const fp = popen("command", "r");
 *
 * // Example 1: Read 10 bytes from the handle
 * const chunk = fp.read(10);
 *
 * // Example 2: Read the handle line by line
 * for (let line = fp.read("line"); length(line); line = fp.read("line"))
 *   print(line);
 *
 * // Example 3: Read the complete contents from the handle
 * const content = fp.read("all");
 *
 * // Example 4: Read until encountering the character ':'
 * const field = fp.read(":");
 */
static uc_value_t *
uc_fs_pread(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_read_common(vm, nargs, "fs.proc");
}

/**
 * Writes a chunk of data to the program handle.
 *
 * In case the given data is not a string, it is converted to a string before
 * being written to the program's stdin. String values are written as-is,
 * integer and double values are written in decimal notation, boolean values are
 * written as `true` or `false` while arrays and objects are converted to their
 * JSON representation before being written. The `null` value is represented by
 * an empty string so `proc.write(null)` would be a no-op. Resource values are
 * written in the form `<type address>`, e.g. `<fs.file 0x7f60f0981760>`.
 *
 * If resource, array or object values contain a `tostring()` function in their
 * prototypes, then this function is invoked to obtain an alternative string
 * representation of the value.
 *
 * Returns the number of bytes written.
 *
 * Returns `null` if a write error occurred.
 *
 * @function module:fs.proc#write
 *
 * @param {*} data
 * The data to be written.
 *
 * @returns {?number}
 *
 * @example
 * const fp = popen("command", "w");
 *
 * fp.write("Hello world!\n");
 */
static uc_value_t *
uc_fs_pwrite(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_write_common(vm, nargs, "fs.proc");
}

/**
 * Forces a write of all buffered data to the underlying handle.
 *
 * Returns `true` if the data was successfully flushed.
 *
 * Returns `null` on error.
 *
 * @function module:fs.proc#flush
 *
 * @returns {?boolean}
 *
 */
static uc_value_t *
uc_fs_pflush(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_flush_common(vm, nargs, "fs.proc");
}

/**
 * Obtains the number of the handle's underlying file descriptor.
 *
 * Returns the descriptor number.
 *
 * Returns `null` on error.
 *
 * @function module:fs.proc#fileno
 *
 * @returns {?number}
 */
static uc_value_t *
uc_fs_pfileno(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_fileno_common(vm, nargs, "fs.proc");
}

/**
 * Starts a process and returns a handle representing the executed process.
 *
 * The handle will be connected to the process stdin or stdout, depending on the
 * value of the mode argument.
 *
 * The mode argument may be either "r" to open the process for reading (connect
 * to its stdin) or "w" to open the process for writing (connect to its stdout).
 *
 * The mode character "r" or "w" may be optionally followed by "e" to apply the
 * FD_CLOEXEC flag onto the open descriptor.
 *
 * Returns a process handle referring to the executed process.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:fs#popen
 *
 * @param {string} command
 * The command to be executed.
 *
 * @param {string} [mode="r"]
 * The open mode of the process handle.
 *
 * @returns {?module:fs.proc}
 *
 * @example
 * // Open a process
 * const process = popen('command', 'r');
 */
static uc_value_t *
uc_fs_popen(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *comm = uc_fn_arg(0);
	uc_value_t *mode = uc_fn_arg(1);
	FILE *fp;

	if (ucv_type(comm) != UC_STRING)
		err_return(EINVAL);

	fp = popen(ucv_string_get(comm),
		ucv_type(mode) == UC_STRING ? ucv_string_get(mode) : "r");

	if (!fp)
		err_return(errno);

	return uc_resource_new(proc_type, fp);
}


/**
 * Represents a handle for interacting with a file opened by one of the file
 * open functions.
 *
 * @class module:fs.file
 * @hideconstructor
 *
 * @borrows module:fs#error as module:fs.file#error
 *
 * @see {@link module:fs#open|open()}
 * @see {@link module:fs#fdopen|fdopen()}
 * @see {@link module:fs#mkstemp|mkstemp()}
 * @see {@link module:fs#pipe|pipe()}
 *
 * @example
 *
 * const handle = open(…);
 *
 * handle.read(…);
 * handle.write(…);
 * handle.flush();
 *
 * handle.seek(…);
 * handle.tell();
 *
 * handle.isatty();
 * handle.fileno();
 *
 * handle.close();
 *
 * handle.error();
 */

/**
 * Closes the file handle.
 *
 * Upon calling `close()` on the handle, buffered data is flushed and the
 * underlying file descriptor is closed.
 *
 * Returns `true` if the handle was properly closed.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:fs.file#close
 *
 * @returns {?boolean}
 */
static uc_value_t *
uc_fs_close(uc_vm_t *vm, size_t nargs)
{
	FILE **fp = uc_fn_this("fs.file");

	if (!fp || !*fp)
		err_return(EBADF);

	fclose(*fp);
	*fp = NULL;

	return ucv_boolean_new(true);
}

/**
 * Reads a chunk of data from the file handle.
 *
 * The length argument may be either a positive number of bytes to read, in
 * which case the read call returns up to that many bytes, or a string to
 * specify a dynamic read size.
 *
 *  - If length is a number, the method will read the specified number of bytes
 *    from the handle. Reading stops after the given amount of bytes or after
 *    encountering EOF, whatever comes first.
 *
 *  - If length is the string "line", the method will read an entire line,
 *    terminated by "\n" (a newline), from the handle. Reading stops at the next
 *    newline or when encountering EOF. The returned data will contain the
 *    terminating newline character if one was read.
 *
 *  - If length is the string "all", the method will read from the handle until
 *    encountering EOF and return the complete contents.
 *
 *  - If length is a single character string, the method will read from the
 *    handle until encountering the specified character or upon encountering
 *    EOF. The returned data will contain the terminating character if one was
 *    read.
 *
 * Returns a string containing the read data.
 *
 * Returns an empty string on EOF.
 *
 * Returns `null` if a read error occurred.
 *
 * @function module:fs.file#read
 *
 * @param {number|string} length
 * The length of data to read. Can be a number, the string "line", the string
 * "all", or a single character string.
 *
 * @returns {?string}
 *
 * @example
 * const fp = open("file.txt", "r");
 *
 * // Example 1: Read 10 bytes from the handle
 * const chunk = fp.read(10);
 *
 * // Example 2: Read the handle line by line
 * for (let line = fp.read("line"); length(line); line = fp.read("line"))
 *   print(line);
 *
 * // Example 3: Read the complete contents from the handle
 * const content = fp.read("all");
 *
 * // Example 4: Read until encountering the character ':'
 * const field = fp.read(":");
 */
static uc_value_t *
uc_fs_read(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_read_common(vm, nargs, "fs.file");
}

/**
 * Writes a chunk of data to the file handle.
 *
 * In case the given data is not a string, it is converted to a string before
 * being written into the file. String values are written as-is, integer and
 * double values are written in decimal notation, boolean values are written as
 * `true` or `false` while arrays and objects are converted to their JSON
 * representation before being written. The `null` value is represented by an
 * empty string so `file.write(null)` would be a no-op. Resource values are
 * written in the form `<type address>`, e.g. `<fs.file 0x7f60f0981760>`.
 *
 * If resource, array or object values contain a `tostring()` function in their
 * prototypes, then this function is invoked to obtain an alternative string
 * representation of the value.
 *
 * Returns the number of bytes written.
 *
 * Returns `null` if a write error occurred.
 *
 * @function module:fs.file#write
 *
 * @param {*} data
 * The data to be written.
 *
 * @returns {?number}
 *
 * @example
 * const fp = open("file.txt", "w");
 *
 * fp.write("Hello world!\n");
 */
static uc_value_t *
uc_fs_write(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_write_common(vm, nargs, "fs.file");
}

/**
 * Set file read position.
 *
 * Set the read position of the open file handle to the given offset and
 * position.
 *
 * Returns `true` if the read position was set.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:fs.file#seek
 *
 * @param {number} [offset=0]
 * The offset in bytes.
 *
 * @param {number} [position=0]
 * The position of the offset.
 *
 * | Position | Description                                                                                  |
 * |----------|----------------------------------------------------------------------------------------------|
 * | `0`      | The given offset is relative to the start of the file. This is the default value if omitted. |
 * | `1`      | The given offset is relative to the current read position.                                   |
 * | `2`      | The given offset is relative to the end of the file.                                         |
 *
 * @returns {?boolean}
 *
 * @example
 * const fp = open("file.txt", "r");
 *
 * print(fp.read(100), "\n");  // read 100 bytes...
 * fp.seek(0, 0);              // ... and reset position to start of file
 * print(fp.read(100), "\n");  // ... read same 100 bytes again
 *
 * fp.seek(10, 1);  // skip 10 bytes forward, relative to current offset ...
 * fp.tell();       // ... position is at 110 now
 *
 * fp.seek(-10, 2);            // set position to ten bytes before EOF ...
 * print(fp.read(100), "\n");  // ... reads 10 bytes at most
 */
static uc_value_t *
uc_fs_seek(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *ofs = uc_fn_arg(0);
	uc_value_t *how = uc_fn_arg(1);
	int whence, res;
	off_t offset;

	FILE **fp = uc_fn_this("fs.file");

	if (!fp || !*fp)
		err_return(EBADF);

	if (!ofs)
		offset = 0;
	else if (ucv_type(ofs) != UC_INTEGER)
		err_return(EINVAL);
	else
		offset = (off_t)ucv_int64_get(ofs);

	if (!how)
		whence = 0;
	else if (ucv_type(how) != UC_INTEGER)
		err_return(EINVAL);
	else
		whence = (int)ucv_int64_get(how);

	res = fseeko(*fp, offset, whence);

	if (res < 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

/**
 * Truncate file to a given size
 *
 * Returns `true` if the file was successfully truncated.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:fs.file#truncate
 *
 * @param {number} [offset=0]
 * The offset in bytes.
 *
 * @returns {?boolean}
 */
static uc_value_t *
uc_fs_truncate(uc_vm_t *vm, size_t nargs)
{
	FILE *fp = uc_fn_thisval("fs.file");
	uc_value_t *ofs = uc_fn_arg(0);
	off_t offset;

	if (!fp)
		err_return(EBADF);

	if (!ofs)
		offset = 0;
	else if (ucv_type(ofs) != UC_INTEGER)
		err_return(EINVAL);
	else
		offset = (off_t)ucv_int64_get(ofs);

	if (ftruncate(fileno(fp), offset) < 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

/**
 * Locks or unlocks a file.
 *
 * The mode argument specifies lock/unlock operation flags.
 *
 * | Flag    | Description                  |
 * |---------|------------------------------|
 * | "s"     | shared lock                  |
 * | "x"     | exclusive lock               |
 * | "n"     | don't block when locking     |
 * | "u"     | unlock                       |
 *
 * Returns `true` if the file was successfully locked/unlocked.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:fs.file#lock
 *
 * @param {string} [op]
 * The lock operation flags
 *
 * @returns {?boolean}
 */
static uc_value_t *
uc_fs_lock(uc_vm_t *vm, size_t nargs)
{
	FILE *fp = uc_fn_thisval("fs.file");
	uc_value_t *mode = uc_fn_arg(0);
	int i, op = 0;
	char *m;

	if (!fp)
		err_return(EBADF);

	if (ucv_type(mode) != UC_STRING)
		err_return(EINVAL);

	m = ucv_string_get(mode);
	for (i = 0; m[i]; i++) {
		switch (m[i]) {
		case 's': op |= LOCK_SH; break;
		case 'x': op |= LOCK_EX; break;
		case 'n': op |= LOCK_NB; break;
		case 'u': op |= LOCK_UN; break;
		default: err_return(EINVAL);
		}
	}

	if (flock(fileno(fp), op) < 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

/**
 * Obtain current read position.
 *
 * Obtains the current, absolute read position of the open file.
 *
 * Returns an integer containing the current read offset in bytes.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:fs.file#tell
 *
 * @returns {?number}
 */
static uc_value_t *
uc_fs_tell(uc_vm_t *vm, size_t nargs)
{
	off_t offset;

	FILE **fp = uc_fn_this("fs.file");

	if (!fp || !*fp)
		err_return(EBADF);

	offset = ftello(*fp);

	if (offset < 0)
		err_return(errno);

	return ucv_int64_new(offset);
}

/**
 * Check for TTY.
 *
 * Checks whether the open file handle refers to a TTY (terminal) device.
 *
 * Returns `true` if the handle refers to a terminal.
 *
 * Returns `false` if the handle refers to another kind of file.
 *
 * Returns `null` on error.
 *
 * @function module:fs.file#isatty
 *
 * @returns {?boolean}
 *
 */
static uc_value_t *
uc_fs_isatty(uc_vm_t *vm, size_t nargs)
{
	FILE **fp = uc_fn_this("fs.file");
	int fd;

	if (!fp || !*fp)
		err_return(EBADF);

	fd = fileno(*fp);

	if (fd == -1)
		err_return(errno);

	return ucv_boolean_new(isatty(fd) == 1);
}

/**
 * Forces a write of all buffered data to the underlying handle.
 *
 * Returns `true` if the data was successfully flushed.
 *
 * Returns `null` on error.
 *
 * @function module:fs.file#flush
 *
 * @returns {?boolean}
 *
 */
static uc_value_t *
uc_fs_flush(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_flush_common(vm, nargs, "fs.file");
}

/**
 * Obtains the number of the handle's underlying file descriptor.
 *
 * Returns the descriptor number.
 *
 * Returns `null` on error.
 *
 * @function module:fs.file#fileno
 *
 * @returns {?number}
 */
static uc_value_t *
uc_fs_fileno(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_fileno_common(vm, nargs, "fs.file");
}

#ifdef HAS_IOCTL

/**
 * Performs an ioctl operation on the file.
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
 * The size parameter has a different purpose depending on the direction parameter:
 * - IOC_DIR_NONE  -> the size parameter is not used
 * - IOC_DIR_WRITE -> size must be the length (in bytes) of argp
 * - IOC_DIR_READ  -> expected length (in bytes) of the data returned by kernel
 * - IOC_DIR_RW    -> size is the length (in bytes) of argp, and the length of the data returned by kernel.
 *
 * The argp parameter should be the data to be written for IOC_DIR_WRITE and IOC_DIR_RW, otherwise null.
 *
 * Returns the result of the ioctl operation; for IOC_DIR_READ and IOC_DIR_RW this is a string containing
 * the data, otherwise a number as return code.
 * In case of an error, null is returned and the error code is available via last_error.
 *
 * @function module:fs.file#ioctl
 *
 * @param {number} direction
 * The direction of the ioctl operation. Use constants IOC_DIR_*.
 *
 * @param {number} type
 * ioctl type (see https://www.kernel.org/doc/html/latest/userspace-api/ioctl/ioctl-number.html)
 *
 * @param {number} num
 * ioctl sequence number.
 *
 * @param {number} size
 * The size of the ioctl operation payload.
 *
 * @param {?string} payload
 * The ioctl payload.
 *
 * @returns {?number|?string}
 */
static uc_value_t *
uc_fs_ioctl(uc_vm_t *vm, size_t nargs)
{
	FILE *fp = uc_fn_thisval("fs.file");
	uc_value_t *direction = uc_fn_arg(0);
	uc_value_t *type = uc_fn_arg(1);
	uc_value_t *num = uc_fn_arg(2);
	uc_value_t *size = uc_fn_arg(3);
	uc_value_t *payload = uc_fn_arg(4);
	uc_string_t *mem = NULL;
	char *buf = NULL;
	unsigned long req = 0;
	unsigned int dir, ty, nr;
	size_t sz;
	int fd, ret;

	if (!fp)
		err_return(EBADF);

	fd = fileno(fp);
	if (fd == -1)
		err_return(EBADF);

	if (ucv_type(direction) != UC_INTEGER || ucv_type(type) != UC_INTEGER ||
	    ucv_type(num) != UC_INTEGER || ucv_type(size) != UC_INTEGER)
		err_return(EINVAL);

	dir = ucv_uint64_get(direction);
	sz = ucv_uint64_get(size);
	ty = ucv_uint64_get(type);
	nr = ucv_uint64_get(num);

	switch (dir) {
	case IOC_DIR_NONE:
		sz = 0;
		break;
	case IOC_DIR_WRITE:
		if (ucv_type(payload) != UC_STRING)
			err_return(EINVAL);

		buf = ucv_string_get(payload);
		break;
	case IOC_DIR_READ:
		mem = xalloc(sizeof(uc_string_t) + sz + 1);
		if (!mem)
			err_return(ENOMEM);

		mem->header.type = UC_STRING;
		mem->header.refcount = 1;
		mem->length = sz;
		buf = mem->str;

		break;
	case IOC_DIR_RW:
		if (ucv_type(payload) != UC_STRING)
			err_return(EINVAL);

		mem = (uc_string_t *)payload;
		buf = mem->str;
		sz = mem->length;

		break;
	default: err_return(EINVAL);
	}

	req = _IOC(dir, ty, nr, sz);
	ret = ioctl(fd, req, buf);
	if (ret < 0) {
		if (dir == IOC_DIR_READ)
			free(mem);

		err_return(errno);
	}

	if (mem) {
		return &mem->header;
	} else {
		return ucv_uint64_new(ret);
	}
}

#endif

/**
 * Opens a file.
 *
 * The mode argument specifies the way the file is opened, it may
 * start with one of the following values:
 *
 * | Mode    | Description                                                                                                   |
 * |---------|---------------------------------------------------------------------------------------------------------------|
 * | "r"     | Opens a file for reading. The file must exist.                                                                 |
 * | "w"     | Opens a file for writing. If the file exists, it is truncated. If the file does not exist, it is created.     |
 * | "a"     | Opens a file for appending. Data is written at the end of the file. If the file does not exist, it is created. |
 * | "r+"    | Opens a file for both reading and writing. The file must exist.                                              |
 * | "w+"    | Opens a file for both reading and writing. If the file exists, it is truncated. If the file does not exist, it is created. |
 * | "a+"    | Opens a file for both reading and appending. Data can be read and written at the end of the file. If the file does not exist, it is created. |
 *
 * Additionally, the following flag characters may be appended to
 * the mode value:
 *
 * | Flag    | Description                                                                                                   |
 * |---------|---------------------------------------------------------------------------------------------------------------|
 * | "x"     | Opens a file for exclusive creation. If the file exists, the `open` call fails.                             |
 * | "e"     | Opens a file with the `O_CLOEXEC` flag set, ensuring that the file descriptor is closed on `exec` calls.      |
 *
 * If the mode is one of `"w…"` or `"a…"`, the permission argument
 * controls the filesystem permissions bits used when creating
 * the file.
 *
 * Returns a file handle object associated with the opened file.
 *
 * @function module:fs#open
 *
 * @param {string} path
 * The path to the file.
 *
 * @param {string} [mode="r"]
 * The file opening mode.
 *
 * @param {number} [perm=0o666]
 * The file creation permissions (for modes `w…` and `a…`)
 *
 * @returns {?module:fs.file}
 *
 * @example
 * // Open a file in read-only mode
 * const fileHandle = open('file.txt', 'r');
 */
static uc_value_t *
uc_fs_open(uc_vm_t *vm, size_t nargs)
{
	int open_mode, open_flags, fd, i;
	uc_value_t *path = uc_fn_arg(0);
	uc_value_t *mode = uc_fn_arg(1);
	uc_value_t *perm = uc_fn_arg(2);
	mode_t open_perm = 0666;
	FILE *fp;
	char *m;

	if (ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	m = (ucv_type(mode) == UC_STRING) ? ucv_string_get(mode) : "r";

	switch (*m) {
	case 'r':
		open_mode = O_RDONLY;
		open_flags = 0;
		break;

	case 'w':
		open_mode = O_WRONLY;
		open_flags = O_CREAT | O_TRUNC;
		break;

	case 'a':
		open_mode = O_WRONLY;
		open_flags = O_CREAT | O_APPEND;
		break;

	default:
		err_return(EINVAL);
	}

	for (i = 1; m[i]; i++) {
		switch (m[i]) {
		case '+': open_mode = O_RDWR;      break;
		case 'x': open_flags |= O_EXCL;    break;
		case 'e': open_flags |= O_CLOEXEC; break;
		}
	}

	if (perm) {
		if (ucv_type(perm) != UC_INTEGER)
			err_return(EINVAL);

		open_perm = ucv_int64_get(perm);
	}

#ifdef O_LARGEFILE
	open_flags |= open_mode | O_LARGEFILE;
#else
	open_flags |= open_mode;
#endif

	fd = open(ucv_string_get(path), open_flags, open_perm);

	if (fd < 0)
		return NULL;

	fp = fdopen(fd, m);

	if (!fp) {
		i = errno;
		close(fd);
		err_return(i);
	}

	return uc_resource_new(file_type, fp);
}

/**
 * Associates a file descriptor number with a file handle object.
 *
 * The mode argument controls how the file handle object is opened
 * and must match the open mode of the underlying descriptor.
 *
 * It may be set to one of the following values:
 *
 * | Mode    | Description                                                                                                  |
 * |---------|--------------------------------------------------------------------------------------------------------------|
 * | "r"     | Opens a file stream for reading. The file descriptor must be valid and opened in read mode.                  |
 * | "w"     | Opens a file stream for writing. The file descriptor must be valid and opened in write mode.                 |
 * | "a"     | Opens a file stream for appending. The file descriptor must be valid and opened in write mode.               |
 * | "r+"    | Opens a file stream for both reading and writing. The file descriptor must be valid and opened in read/write mode. |
 * | "w+"    | Opens a file stream for both reading and writing. The file descriptor must be valid and opened in read/write mode. |
 * | "a+"    | Opens a file stream for both reading and appending. The file descriptor must be valid and opened in read/write mode. |
 *
 * Returns the file handle object associated with the file descriptor.
 *
 * @function module:fs#fdopen
 *
 * @param {number} fd
 * The file descriptor.
 *
 * @param {string} [mode="r"]
 * The open mode.
 *
 * @returns {Object}
 *
 * @example
 * // Associate file descriptors of stdin and stdout with handles
 * const stdinHandle = fdopen(0, 'r');
 * const stdoutHandle = fdopen(1, 'w');
 */
static uc_value_t *
uc_fs_fdopen(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *fdno = uc_fn_arg(0);
	uc_value_t *mode = uc_fn_arg(1);
	int64_t n;
	FILE *fp;

	if (ucv_type(fdno) != UC_INTEGER)
		err_return(EINVAL);

	n = ucv_int64_get(fdno);

	if (n < 0 || n > INT_MAX)
		err_return(EBADF);

	fp = fdopen((int)n,
		ucv_type(mode) == UC_STRING ? ucv_string_get(mode) : "r");

	if (!fp)
		err_return(errno);

	return uc_resource_new(file_type, fp);
}


/**
 * Represents a handle for interacting with a directory opened by `opendir()`.
 *
 * @class module:fs.dir
 * @hideconstructor
 *
 * @borrows module:fs#error as module:fs.dir#error
 *
 * @see {@link module:fs#opendir|opendir()}
 *
 * @example
 *
 * const handle = opendir(…);
 *
 * handle.read();
 *
 * handle.tell();
 * handle.seek(…);
 *
 * handle.close();
 *
 * handle.error();
 */

/**
 * Read the next entry from the open directory.
 *
 * Returns a string containing the entry name.
 *
 * Returns `null` if there are no more entries to read.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:fs.dir#read
 *
 * @returns {?string}
 */
static uc_value_t *
uc_fs_readdir(uc_vm_t *vm, size_t nargs)
{
	DIR **dp = uc_fn_this("fs.dir");
	struct dirent *e;

	if (!dp || !*dp)
		err_return(EINVAL);

	errno = 0;
	e = readdir(*dp);

	if (!e)
		err_return(errno);

	return ucv_string_new(e->d_name);
}

/**
 * Obtain current read position.
 *
 * Returns the current read position in the open directory handle which can be
 * passed back to the `seek()` function to return to this position. This is
 * mainly useful to read an open directory handle (or specific items) multiple
 * times.
 *
 * Returns an integer referring to the current position.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:fs.dir#tell
 *
 * @returns {?number}
 */
static uc_value_t *
uc_fs_telldir(uc_vm_t *vm, size_t nargs)
{
	DIR **dp = uc_fn_this("fs.dir");
	long position;

	if (!dp || !*dp)
		err_return(EBADF);

	position = telldir(*dp);

	if (position == -1)
		err_return(errno);

	return ucv_int64_new((int64_t)position);
}

/**
 * Set read position.
 *
 * Sets the read position within the open directory handle to the given offset
 * value. The offset value should be obtained by a previous call to `tell()` as
 * the specific integer values are implementation defined.
 *
 * Returns `true` if the read position was set.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:fs.dir#seek
 *
 * @param {number} offset
 * Position value obtained by `tell()`.
 *
 * @returns {?boolean}
 *
 * @example
 *
 * const handle = opendir("/tmp");
 * const begin = handle.tell();
 *
 * print(handle.read(), "\n");
 *
 * handle.seek(begin);
 *
 * print(handle.read(), "\n");  // prints the first entry again
 */
static uc_value_t *
uc_fs_seekdir(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *ofs = uc_fn_arg(0);
	DIR **dp = uc_fn_this("fs.dir");
	long position;

	if (ucv_type(ofs) != UC_INTEGER)
		err_return(EINVAL);

	if (!dp || !*dp)
		err_return(EBADF);

	position = (long)ucv_int64_get(ofs);

	seekdir(*dp, position);

	return ucv_boolean_new(true);
}

/**
 * Closes the directory handle.
 *
 * Closes the underlying file descriptor referring to the opened directory.
 *
 * Returns `true` if the handle was properly closed.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:fs.dir#close
 *
 * @returns {?boolean}
 */
static uc_value_t *
uc_fs_closedir(uc_vm_t *vm, size_t nargs)
{
	DIR **dp = uc_fn_this("fs.dir");

	if (!dp || !*dp)
		err_return(EBADF);

	closedir(*dp);
	*dp = NULL;

	return ucv_boolean_new(true);
}

/**
 * Opens a directory and returns a directory handle associated with the open
 * directory descriptor.
 *
 * Returns a director handle referring to the open directory.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:fs#opendir
 *
 * @param {string} path
 * The path to the directory.
 *
 * @returns {?module:fs.dir}
 *
 * @example
 * // Open a directory
 * const directory = opendir('path/to/directory');
 */
static uc_value_t *
uc_fs_opendir(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);
	DIR *dp;

	if (ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	dp = opendir(ucv_string_get(path));

	if (!dp)
		err_return(errno);

	return uc_resource_new(dir_type, dp);
}

/**
 * Reads the target path of a symbolic link.
 *
 * Returns a string containing the target path.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:fs#readlink
 *
 * @param {string} path
 * The path to the symbolic link.
 *
 * @returns {?string}
 *
 * @example
 * // Read the value of a symbolic link
 * const targetPath = readlink('symbolicLink');
 */
static uc_value_t *
uc_fs_readlink(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);
	uc_value_t *res;
	ssize_t buflen = 0, rv;
	char *buf = NULL, *tmp;

	if (ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	do {
		buflen += 128;
		tmp = realloc(buf, buflen);

		if (!tmp) {
			free(buf);
			err_return(ENOMEM);
		}

		buf = tmp;
		rv = readlink(ucv_string_get(path), buf, buflen);

		if (rv == -1) {
			free(buf);
			err_return(errno);
		}

		if (rv < buflen)
			break;
	}
	while (true);

	res = ucv_string_new_length(buf, rv);

	free(buf);

	return res;
}

/**
 * @typedef {Object} module:fs.FileStatResult
 * @property {Object} dev - The device information.
 * @property {number} dev.major - The major device number.
 * @property {number} dev.minor - The minor device number.
 * @property {Object} perm - The file permissions.
 * @property {boolean} perm.setuid - Whether the setuid bit is set.
 * @property {boolean} perm.setgid - Whether the setgid bit is set.
 * @property {boolean} perm.sticky - Whether the sticky bit is set.
 * @property {boolean} perm.user_read - Whether the file is readable by the owner.
 * @property {boolean} perm.user_write - Whether the file is writable by the owner.
 * @property {boolean} perm.user_exec - Whether the file is executable by the owner.
 * @property {boolean} perm.group_read - Whether the file is readable by the group.
 * @property {boolean} perm.group_write - Whether the file is writable by the group.
 * @property {boolean} perm.group_exec - Whether the file is executable by the group.
 * @property {boolean} perm.other_read - Whether the file is readable by others.
 * @property {boolean} perm.other_write - Whether the file is writable by others.
 * @property {boolean} perm.other_exec - Whether the file is executable by others.
 * @property {number} inode - The inode number.
 * @property {number} mode - The file mode.
 * @property {number} nlink - The number of hard links.
 * @property {number} uid - The user ID of the owner.
 * @property {number} gid - The group ID of the owner.
 * @property {number} size - The file size in bytes.
 * @property {number} blksize - The block size for file system I/O.
 * @property {number} blocks - The number of 512-byte blocks allocated for the file.
 * @property {number} atime - The timestamp when the file was last accessed.
 * @property {number} mtime - The timestamp when the file was last modified.
 * @property {number} ctime - The timestamp when the file status was last changed.
 * @property {string} type - The type of the file ("directory", "file", etc.).
 */

static uc_value_t *
uc_fs_stat_common(uc_vm_t *vm, size_t nargs, bool use_lstat)
{
	uc_value_t *path = uc_fn_arg(0);
	uc_value_t *res, *o;
	struct stat st;
	int rv;

	if (ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	rv = (use_lstat ? lstat : stat)(ucv_string_get(path), &st);

	if (rv == -1)
		err_return(errno);

	res = ucv_object_new(vm);

	if (!res)
		err_return(ENOMEM);

	o = ucv_object_new(vm);

	if (o) {
		ucv_object_add(o, "major", ucv_int64_new(major(st.st_dev)));
		ucv_object_add(o, "minor", ucv_int64_new(minor(st.st_dev)));

		ucv_object_add(res, "dev", o);
	}

	o = ucv_object_new(vm);

	if (o) {
		ucv_object_add(o, "setuid", ucv_boolean_new(st.st_mode & S_ISUID));
		ucv_object_add(o, "setgid", ucv_boolean_new(st.st_mode & S_ISGID));
		ucv_object_add(o, "sticky", ucv_boolean_new(st.st_mode & S_ISVTX));

		ucv_object_add(o, "user_read", ucv_boolean_new(st.st_mode & S_IRUSR));
		ucv_object_add(o, "user_write", ucv_boolean_new(st.st_mode & S_IWUSR));
		ucv_object_add(o, "user_exec", ucv_boolean_new(st.st_mode & S_IXUSR));

		ucv_object_add(o, "group_read", ucv_boolean_new(st.st_mode & S_IRGRP));
		ucv_object_add(o, "group_write", ucv_boolean_new(st.st_mode & S_IWGRP));
		ucv_object_add(o, "group_exec", ucv_boolean_new(st.st_mode & S_IXGRP));

		ucv_object_add(o, "other_read", ucv_boolean_new(st.st_mode & S_IROTH));
		ucv_object_add(o, "other_write", ucv_boolean_new(st.st_mode & S_IWOTH));
		ucv_object_add(o, "other_exec", ucv_boolean_new(st.st_mode & S_IXOTH));

		ucv_object_add(res, "perm", o);
	}

	ucv_object_add(res, "inode", ucv_int64_new((int64_t)st.st_ino));
	ucv_object_add(res, "mode", ucv_int64_new((int64_t)st.st_mode & ~S_IFMT));
	ucv_object_add(res, "nlink", ucv_int64_new((int64_t)st.st_nlink));
	ucv_object_add(res, "uid", ucv_int64_new((int64_t)st.st_uid));
	ucv_object_add(res, "gid", ucv_int64_new((int64_t)st.st_gid));
	ucv_object_add(res, "size", ucv_int64_new((int64_t)st.st_size));
	ucv_object_add(res, "blksize", ucv_int64_new((int64_t)st.st_blksize));
	ucv_object_add(res, "blocks", ucv_int64_new((int64_t)st.st_blocks));
	ucv_object_add(res, "atime", ucv_int64_new((int64_t)st.st_atime));
	ucv_object_add(res, "mtime", ucv_int64_new((int64_t)st.st_mtime));
	ucv_object_add(res, "ctime", ucv_int64_new((int64_t)st.st_ctime));

	if (S_ISREG(st.st_mode))
		ucv_object_add(res, "type", ucv_string_new("file"));
	else if (S_ISDIR(st.st_mode))
		ucv_object_add(res, "type", ucv_string_new("directory"));
	else if (S_ISCHR(st.st_mode))
		ucv_object_add(res, "type", ucv_string_new("char"));
	else if (S_ISBLK(st.st_mode))
		ucv_object_add(res, "type", ucv_string_new("block"));
	else if (S_ISFIFO(st.st_mode))
		ucv_object_add(res, "type", ucv_string_new("fifo"));
	else if (S_ISLNK(st.st_mode))
		ucv_object_add(res, "type", ucv_string_new("link"));
	else if (S_ISSOCK(st.st_mode))
		ucv_object_add(res, "type", ucv_string_new("socket"));
	else
		ucv_object_add(res, "type", ucv_string_new("unknown"));

	return res;
}

/**
 * Retrieves information about a file or directory.
 *
 * Returns an object containing information about the file or directory.
 *
 * Returns `null` if an error occurred, e.g. due to insufficient permissions.
 *
 * @function module:fs#stat
 *
 * @param {string} path
 * The path to the file or directory.
 *
 * @returns {?module:fs.FileStatResult}
 *
 * @example
 * // Get information about a file
 * const fileInfo = stat('path/to/file');
 */
static uc_value_t *
uc_fs_stat(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_stat_common(vm, nargs, false);
}

/**
 * Retrieves information about a file or directory, without following symbolic
 * links.
 *
 * Returns an object containing information about the file or directory.
 *
 * Returns `null` if an error occurred, e.g. due to insufficient permissions.
 *
 * @function module:fs#lstat
 *
 * @param {string} path
 * The path to the file or directory.
 *
 * @returns {?module:fs.FileStatResult}
 *
 * @example
 * // Get information about a directory
 * const dirInfo = lstat('path/to/directory');
 */
static uc_value_t *
uc_fs_lstat(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_stat_common(vm, nargs, true);
}

/**
 * Creates a new directory.
 *
 * Returns `true` if the directory was successfully created.
 *
 * Returns `null` if an error occurred, e.g. due to inexistent path.
 *
 * @function module:fs#mkdir
 *
 * @param {string} path
 * The path to the new directory.
 *
 * @returns {?boolean}
 *
 * @example
 * // Create a directory
 * mkdir('path/to/new-directory');
 */
static uc_value_t *
uc_fs_mkdir(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);
	uc_value_t *mode = uc_fn_arg(1);

	if (ucv_type(path) != UC_STRING ||
	    (mode && ucv_type(mode) != UC_INTEGER))
		err_return(EINVAL);

	if (mkdir(ucv_string_get(path), (mode_t)(mode ? ucv_int64_get(mode) : 0777)) == -1)
		err_return(errno);

	return ucv_boolean_new(true);
}

/**
 * Removes the specified directory.
 *
 * Returns `true` if the directory was successfully removed.
 *
 * Returns `null` if an error occurred, e.g. due to inexistent path.
 *
 * @function module:fs#rmdir
 *
 * @param {string} path
 * The path to the directory to be removed.
 *
 * @returns {?boolean}
 *
 * @example
 * // Remove a directory
 * rmdir('path/to/directory');
 */
static uc_value_t *
uc_fs_rmdir(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);

	if (ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	if (rmdir(ucv_string_get(path)) == -1)
		err_return(errno);

	return ucv_boolean_new(true);
}

/**
 * Creates a new symbolic link.
 *
 * Returns `true` if the symlink was successfully created.
 *
 * Returns `null` if an error occurred, e.g. due to inexistent path.
 *
 * @function module:fs#symlink
 *
 * @param {string} target
 * The target of the symbolic link.
 *
 * @param {string} path
 * The path of the symbolic link.
 *
 * @returns {?boolean}
 *
 * @example
 * // Create a symbolic link
 * symlink('target', 'path/to/symlink');
 */
static uc_value_t *
uc_fs_symlink(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *dest = uc_fn_arg(0);
	uc_value_t *path = uc_fn_arg(1);

	if (ucv_type(dest) != UC_STRING ||
	    ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	if (symlink(ucv_string_get(dest), ucv_string_get(path)) == -1)
		err_return(errno);

	return ucv_boolean_new(true);
}

/**
 * Removes the specified file or symbolic link.
 *
 * Returns `true` if the unlink operation was successful.
 *
 * Returns `null` if an error occurred, e.g. due to inexistent path.
 *
 * @function module:fs#unlink
 *
 * @param {string} path
 * The path to the file or symbolic link.
 *
 * @returns {?boolean}
 *
 * @example
 * // Remove a file
 * unlink('path/to/file');
 */
static uc_value_t *
uc_fs_unlink(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);

	if (ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	if (unlink(ucv_string_get(path)) == -1)
		err_return(errno);

	return ucv_boolean_new(true);
}

/**
 * Retrieves the current working directory.
 *
 * Returns a string containing the current working directory path.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:fs#getcwd
 *
 * @returns {?string}
 *
 * @example
 * // Get the current working directory
 * const cwd = getcwd();
 */
static uc_value_t *
uc_fs_getcwd(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *res;
	char *buf = NULL, *tmp;
	size_t buflen = 0;

	do {
		buflen += 128;
		tmp = realloc(buf, buflen);

		if (!tmp) {
			free(buf);
			err_return(ENOMEM);
		}

		buf = tmp;

		if (getcwd(buf, buflen) != NULL)
			break;

		if (errno == ERANGE)
			continue;

		free(buf);
		err_return(errno);
	}
	while (true);

	res = ucv_string_new(buf);

	free(buf);

	return res;
}

/**
 * Changes the current working directory to the specified path.
 *
 * Returns `true` if the permission change was successful.
 *
 * Returns `null` if an error occurred, e.g. due to insufficient permissions or
 * invalid arguments.
 *
 * @function module:fs#chdir
 *
 * @param {string} path
 * The path to the new working directory.
 *
 * @returns {?boolean}
 *
 * @example
 * // Change the current working directory
 * chdir('new-directory');
 */
static uc_value_t *
uc_fs_chdir(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);

	if (ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	if (chdir(ucv_string_get(path)) == -1)
		err_return(errno);

	return ucv_boolean_new(true);
}

/**
 * Changes the permission mode bits of a file or directory.
 *
 * Returns `true` if the permission change was successful.
 *
 * Returns `null` if an error occurred, e.g. due to insufficient permissions or
 * invalid arguments.
 *
 * @function module:fs#chmod
 *
 * @param {string} path
 * The path to the file or directory.
 *
 * @param {number} mode
 * The new mode (permissions).
 *
 * @returns {?boolean}
 *
 * @example
 * // Change the mode of a file
 * chmod('path/to/file', 0o644);
 */
static uc_value_t *
uc_fs_chmod(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);
	uc_value_t *mode = uc_fn_arg(1);

	if (ucv_type(path) != UC_STRING ||
	    ucv_type(mode) != UC_INTEGER)
		err_return(EINVAL);

	if (chmod(ucv_string_get(path), (mode_t)ucv_int64_get(mode)) == -1)
		err_return(errno);

	return ucv_boolean_new(true);
}

static bool
uc_fs_resolve_user(uc_value_t *v, uid_t *uid)
{
	struct passwd *pw = NULL;
	int64_t n;
	char *s;

	*uid = (uid_t)-1;

	switch (ucv_type(v)) {
	case UC_INTEGER:
		n = ucv_int64_get(v);

		if (n < -1) {
			errno = ERANGE;

			return false;
		}

		*uid = (uid_t)n;

		return true;

	case UC_STRING:
		s = ucv_string_get(v);
		pw = getpwnam(s);

		if (!pw) {
			errno = ENOENT;

			return false;
		}

		*uid = pw->pw_uid;

		return true;

	case UC_NULL:
		return true;

	default:
		errno = EINVAL;

		return false;
	}
}

static bool
uc_fs_resolve_group(uc_value_t *v, gid_t *gid)
{
	struct group *gr = NULL;
	int64_t n;
	char *s;

	*gid = (gid_t)-1;

	switch (ucv_type(v)) {
	case UC_INTEGER:
		n = ucv_int64_get(v);

		if (n < -1) {
			errno = ERANGE;

			return false;
		}

		*gid = (gid_t)n;

		return true;

	case UC_STRING:
		s = ucv_string_get(v);
		gr = getgrnam(s);

		if (!gr) {
			errno = ENOENT;

			return false;
		}

		*gid = gr->gr_gid;

		return true;

	case UC_NULL:
		return true;

	default:
		errno = EINVAL;

		return false;
	}
}

/**
 * Changes the owner and group of a file or directory.
 *
 * The user and group may be specified either as uid or gid number respectively,
 * or as a string containing the user or group name, in which case it is
 * resolved to the proper uid/gid first.
 *
 * If either the user or group parameter is omitted or given as `-1`,
 * it is not changed.
 *
 * Returns `true` if the ownership change was successful.
 *
 * Returns `null` if an error occurred or if a user/group name cannot be
 * resolved to a uid/gid value.
 *
 * @function module:fs#chown
 *
 * @param {string} path
 * The path to the file or directory.
 *
 * @param {number|string} [uid=-1]
 * The new owner's user ID. When given as number, it is used as-is, when given
 * as string, the user name is resolved to the corresponding uid first.
 *
 * @param {number|string} [gid=-1]
 * The new group's ID. When given as number, it is used as-is, when given as
 * string, the group name is resolved to the corresponding gid first.
 *
 * @returns {?boolean}
 *
 * @example
 * // Change the owner of a file
 * chown('path/to/file', 1000);
 *
 * // Change the group of a directory
 * chown('/htdocs/', null, 'www-data');
 */
static uc_value_t *
uc_fs_chown(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);
	uc_value_t *user = uc_fn_arg(1);
	uc_value_t *group = uc_fn_arg(2);
	uid_t uid;
	gid_t gid;

	if (ucv_type(path) != UC_STRING)
	    err_return(EINVAL);

	if (!uc_fs_resolve_user(user, &uid) ||
	    !uc_fs_resolve_group(group, &gid))
		err_return(errno);

	if (chown(ucv_string_get(path), uid, gid) == -1)
		err_return(errno);

	return ucv_boolean_new(true);
}

/**
 * Renames or moves a file or directory.
 *
 * Returns `true` if the rename operation was successful.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:fs#rename
 *
 * @param {string} oldPath
 * The current path of the file or directory.
 *
 * @param {string} newPath
 * The new path of the file or directory.
 *
 * @returns {?boolean}
 *
 * @example
 * // Rename a file
 * rename('old-name.txt', 'new-name.txt');
 */
static uc_value_t *
uc_fs_rename(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *oldpath = uc_fn_arg(0);
	uc_value_t *newpath = uc_fn_arg(1);

	if (ucv_type(oldpath) != UC_STRING ||
	    ucv_type(newpath) != UC_STRING)
		err_return(EINVAL);

	if (rename(ucv_string_get(oldpath), ucv_string_get(newpath)))
		err_return(errno);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_fs_glob(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *pat, *arr;
	glob_t gl = { 0 };
	size_t i;

	for (i = 0; i < nargs; i++) {
		pat = uc_fn_arg(i);

		if (ucv_type(pat) != UC_STRING) {
			globfree(&gl);
			err_return(EINVAL);
		}

		glob(ucv_string_get(pat), i ? GLOB_APPEND : 0, NULL, &gl);
	}

	arr = ucv_array_new(vm);

	for (i = 0; i < gl.gl_pathc; i++)
		ucv_array_push(arr, ucv_string_new(gl.gl_pathv[i]));

	globfree(&gl);

	return arr;
}

/**
 * Retrieves the directory name of a path.
 *
 * Returns the directory name component of the specified path.
 *
 * Returns `null` if the path argument is not a string.
 *
 * @function module:fs#dirname
 *
 * @param {string} path
 * The path to extract the directory name from.
 *
 * @returns {?string}
 *
 * @example
 * // Get the directory name of a path
 * const directoryName = dirname('/path/to/file.txt');
 */
static uc_value_t *
uc_fs_dirname(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);
	size_t i;
	char *s;

	if (ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	i = ucv_string_length(path);
	s = ucv_string_get(path);

	if (i == 0)
		return ucv_string_new(".");

	for (i--; s[i] == '/'; i--)
		if (i == 0)
			return ucv_string_new("/");

	for (; s[i] != '/'; i--)
		if (i == 0)
			return ucv_string_new(".");

	for (; s[i] == '/'; i--)
		if (i == 0)
			return ucv_string_new("/");

	return ucv_string_new_length(s, i + 1);
}

/**
 * Retrieves the base name of a path.
 *
 * Returns the base name component of the specified path.
 *
 * Returns `null` if the path argument is not a string.
 *
 * @function module:fs#basename
 *
 * @param {string} path
 * The path to extract the base name from.
 *
 * @returns {?string}
 *
 * @example
 * // Get the base name of a path
 * const baseName = basename('/path/to/file.txt');
 */
static uc_value_t *
uc_fs_basename(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);
	size_t i, len, skip;
	char *s;

	if (ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	len = ucv_string_length(path);
	s = ucv_string_get(path);

	if (len == 0)
		return ucv_string_new(".");

	for (i = len - 1, skip = 0; i > 0 && s[i] == '/'; i--, skip++)
		;

	for (; i > 0 && s[i - 1] != '/'; i--)
		;

	return ucv_string_new_length(s + i, len - i - skip);
}

static int
uc_fs_lsdir_sort_fn(const void *k1, const void *k2)
{
	uc_value_t * const *v1 = k1;
	uc_value_t * const *v2 = k2;

	return strcmp(ucv_string_get(*v1), ucv_string_get(*v2));
}

/**
 * Lists the content of a directory.
 *
 * Returns a sorted array of the names of files and directories in the specified
 * directory.
 *
 * Returns `null` if an error occurred, e.g. if the specified directory cannot
 * be opened.
 *
 * @function module:fs#lsdir
 *
 * @param {string} path
 * The path to the directory.
 *
 * @returns {?string[]}
 *
 * @example
 * // List the content of a directory
 * const fileList = lsdir('/path/to/directory');
 */
static uc_value_t *
uc_fs_lsdir(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);
	uc_value_t *pat = uc_fn_arg(1);
	uc_value_t *res = NULL;
	uc_regexp_t *reg;
	struct dirent *e;
	DIR *d;

	if (ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	switch (ucv_type(pat)) {
	case UC_NULL:
	case UC_STRING:
	case UC_REGEXP:
		break;

	default:
		err_return(EINVAL);
	}

	d = opendir(ucv_string_get(path));

	if (!d)
		err_return(errno);

	res = ucv_array_new(vm);

	while ((e = readdir(d)) != NULL) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;

		if (ucv_type(pat) == UC_REGEXP) {
			reg = (uc_regexp_t *)pat;

			if (regexec(&reg->regexp, e->d_name, 0, NULL, 0) == REG_NOMATCH)
				continue;
		}
		else if (ucv_type(pat) == UC_STRING) {
			if (fnmatch(ucv_string_get(pat), e->d_name, 0) == FNM_NOMATCH)
				continue;
		}

		ucv_array_push(res, ucv_string_new(e->d_name));
	}

	closedir(d);

	ucv_array_sort(res, uc_fs_lsdir_sort_fn);

	return res;
}

/**
 * Creates a unique, ephemeral temporary file.
 *
 * Creates a new temporary file, opens it in read and write mode, unlinks it and
 * returns a file handle object referring to the yet open but deleted file.
 *
 * Upon closing the handle, the associated file will automatically vanish from
 * the system.
 *
 * The optional path template argument may be used to override the path and name
 * chosen for the temporary file. If the path template contains no path element,
 * `/tmp/` is prepended, if it does not end with `XXXXXX`, then  * `.XXXXXX` is
 * appended to it. The `XXXXXX` sequence is replaced with a random value
 * ensuring uniqueness of the temporary file name.
 *
 * Returns a file handle object referring to the ephemeral file on success.
 *
 * Returns `null` if an error occurred, e.g. on insufficient permissions or
 * inaccessible directory.
 *
 * @function module:fs#mkstemp
 *
 * @param {string} [template="/tmp/XXXXXX"]
 * The path template to use when forming the temporary file name.
 *
 * @returns {?module:fs.file}
 *
 * @example
 * // Create a unique temporary file in the current working directory
 * const tempFile = mkstemp('./data-XXXXXX');
 */
static uc_value_t *
uc_fs_mkstemp(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *template = uc_fn_arg(0);
	bool ends_with_template = false;
	char *path, *t;
	FILE *fp;
	size_t l;
	int fd;

	if (template && ucv_type(template) != UC_STRING)
		err_return(EINVAL);

	t = ucv_string_get(template);
	l = ucv_string_length(template);

	ends_with_template = (l >= 6 && strcmp(&t[l - 6], "XXXXXX") == 0);

	if (t && strchr(t, '/')) {
		if (ends_with_template)
			xasprintf(&path, "%s", t);
		else
			xasprintf(&path, "%s.XXXXXX", t);
	}
	else if (t) {
		if (ends_with_template)
			xasprintf(&path, "/tmp/%s", t);
		else
			xasprintf(&path, "/tmp/%s.XXXXXX", t);
	}
	else {
		xasprintf(&path, "/tmp/XXXXXX");
	}

	do {
		fd = mkstemp(path);
	}
	while (fd == -1 && errno == EINTR);

	if (fd == -1) {
		free(path);
		err_return(errno);
	}

	unlink(path);
	free(path);

	fp = fdopen(fd, "r+");

	if (!fp) {
		close(fd);
		err_return(errno);
	}

	return uc_resource_new(file_type, fp);
}

/**
 * Checks the accessibility of a file or directory.
 *
 * The optional modes argument specifies the access modes which should be
 * checked. A file is only considered accessible if all access modes specified
 * in the modes argument are possible.
 *
 * The following modes are recognized:
 *
 * | Mode | Description                           |
 * |------|---------------------------------------|
 * | "r"  | Tests whether the file is readable.   |
 * | "w"  | Tests whether the file is writable.   |
 * | "x"  | Tests whether the file is executable. |
 * | "f"  | Tests whether the file exists.        |
 *
 * Returns `true` if the given path is accessible or `false` when it is not.
 *
 * Returns `null` if an error occurred, e.g. due to inaccessible intermediate
 * path components, invalid path arguments etc.
 *
 * @function module:fs#access
 *
 * @param {string} path
 * The path to the file or directory.
 *
 * @param {number} [mode="f"]
 * Optional access mode.
 *
 * @returns {?boolean}
 *
 * @example
 * // Check file read and write accessibility
 * const isAccessible = access('path/to/file', 'rw');
 *
 * // Check execute permissions
 * const mayExecute = access('/usr/bin/example', 'x');
 */
static uc_value_t *
uc_fs_access(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);
	uc_value_t *test = uc_fn_arg(1);
	int mode = F_OK;
	char *p;

	if (ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	if (test && ucv_type(test) != UC_STRING)
		err_return(EINVAL);

	for (p = ucv_string_get(test); p && *p; p++) {
		switch (*p) {
		case 'r':
			mode |= R_OK;
			break;

		case 'w':
			mode |= W_OK;
			break;

		case 'x':
			mode |= X_OK;
			break;

		case 'f':
			mode |= F_OK;
			break;

		default:
			err_return(EINVAL);
		}
	}

	if (access(ucv_string_get(path), mode) == -1)
		err_return(errno);

	return ucv_boolean_new(true);
}

/**
 * Reads the content of a file, optionally limited to the given amount of bytes.
 *
 * Returns a string containing the file contents.
 *
 * Returns `null` if an error occurred, e.g. due to insufficient permissions.
 *
 * @function module:fs#readfile
 *
 * @param {string} path
 * The path to the file.
 *
 * @param {number} [limit]
 * Number of bytes to limit the result to. When omitted, the entire content is
 * returned.
 *
 * @returns {?string}
 *
 * @example
 * // Read first 100 bytes of content
 * const content = readfile('path/to/file', 100);
 *
 * // Read entire file content
 * const content = readfile('path/to/file');
 */
static uc_value_t *
uc_fs_readfile(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);
	uc_value_t *size = uc_fn_arg(1);
	uc_value_t *res = NULL;
	uc_stringbuf_t *buf;
	ssize_t limit = -1;
	size_t rlen, blen;
	FILE *fp;

	if (ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	if (size) {
		if (ucv_type(size) != UC_INTEGER)
			err_return(EINVAL);

		limit = ucv_int64_get(size);
	}

	fp = fopen(ucv_string_get(path), "r");

	if (!fp)
		err_return(errno);

	buf = ucv_stringbuf_new();

	if (limit > -1 && limit < BUFSIZ)
		setvbuf(fp, NULL, _IONBF, 0);

	while (limit != 0) {
		blen = 1024;

		if (limit > 0 && blen > (size_t)limit)
			blen = (size_t)limit;

		printbuf_memset(buf, printbuf_length(buf) + blen - 1, 0, 1);

		buf->bpos -= blen;
		rlen = fread(buf->buf + buf->bpos, 1, blen, fp);
		buf->bpos += rlen;

		if (rlen < blen)
			break;

		if (limit > 0)
			limit -= rlen;
	}

	if (ferror(fp)) {
		fclose(fp);
		printbuf_free(buf);
		err_return(errno);
	}

	fclose(fp);

	/* add sentinel null byte but don't count it towards the string length */
	printbuf_memappend_fast(buf, "\0", 1);
	res = ucv_stringbuf_finish(buf);
	((uc_string_t *)res)->length--;

	return res;
}

/**
 * Writes the given data to a file, optionally truncated to the given amount
 * of bytes.
 *
 * In case the given data is not a string, it is converted to a string before
 * being written into the file. String values are written as-is, integer and
 * double values are written in decimal notation, boolean values are written as
 * `true` or `false` while arrays and objects are converted to their JSON
 * representation before being written into the file. The `null` value is
 * represented by an empty string so `writefile(…, null)` would write an empty
 * file. Resource values are written in the form `<type address>`, e.g.
 * `<fs.file 0x7f60f0981760>`.
 *
 * If resource, array or object values contain a `tostring()` function in their
 * prototypes, then this function is invoked to obtain an alternative string
 * representation of the value.
 *
 * If a file already exists at the given path, it is truncated. If no file
 * exists, it is created with default permissions 0o666 masked by the currently
 * effective umask.
 *
 * Returns the number of bytes written.
 *
 * Returns `null` if an error occurred, e.g. due to insufficient permissions.
 *
 * @function module:fs#writefile
 *
 * @param {string} path
 * The path to the file.
 *
 * @param {*} data
 * The data to be written.
 *
 * @param {number} [limit]
 * Truncates the amount of data to be written to the specified amount of bytes.
 * When omitted, the entire content is written.
 *
 * @returns {?number}
 *
 * @example
 * // Write string to a file
 * const bytesWritten = writefile('path/to/file', 'Hello, World!');
 *
 * // Write object as JSON to a file and limit to 1024 bytes at most
 * const obj = { foo: "Hello world", bar: true, baz: 123 };
 * const bytesWritten = writefile('debug.txt', obj, 1024);
 */
static uc_value_t *
uc_fs_writefile(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);
	uc_value_t *data = uc_fn_arg(1);
	uc_value_t *size = uc_fn_arg(2);
	uc_stringbuf_t *buf = NULL;
	ssize_t limit = -1;
	size_t wlen = 0;
	int err = 0;
	FILE *fp;

	if (ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	if (size) {
		if (ucv_type(size) != UC_INTEGER)
			err_return(EINVAL);

		limit = ucv_int64_get(size);
	}

	fp = fopen(ucv_string_get(path), "w");

	if (!fp)
		err_return(errno);

	if (data && ucv_type(data) != UC_STRING) {
		buf = xprintbuf_new();
		ucv_to_stringbuf_formatted(vm, buf, data, 0, '\0', 0);

		if (limit < 0 || limit > printbuf_length(buf))
			limit = printbuf_length(buf);

		wlen = fwrite(buf->buf, 1, limit, fp);

		if (wlen < (size_t)limit)
			err = errno;

		printbuf_free(buf);
	}
	else if (data) {
		if (limit < 0 || (size_t)limit > ucv_string_length(data))
			limit = ucv_string_length(data);

		wlen = fwrite(ucv_string_get(data), 1, limit, fp);

		if (wlen < (size_t)limit)
			err = errno;
	}

	fclose(fp);

	if (err)
		err_return(err);

	return ucv_uint64_new(wlen);
}

/**
 * Resolves the absolute path of a file or directory.
 *
 * Returns a string containing the resolved path.
 *
 * Returns `null` if an error occurred, e.g. due to insufficient permissions.
 *
 * @function module:fs#realpath
 *
 * @param {string} path
 * The path to the file or directory.
 *
 * @returns {?string}
 *
 * @example
 * // Resolve the absolute path of a file
 * const absolutePath = realpath('path/to/file', 'utf8');
 */
static uc_value_t *
uc_fs_realpath(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0), *rv;
	char *resolved;

	if (ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	resolved = realpath(ucv_string_get(path), NULL);

	if (!resolved)
		err_return(errno);

	rv = ucv_string_new(resolved);

	free(resolved);

	return rv;
}

/**
 * Creates a pipe and returns file handle objects associated with the read- and
 * write end of the pipe respectively.
 *
 * Returns a two element array containing both a file handle object open in read
 * mode referring to the read end of the pipe and a file handle object open in
 * write mode referring to the write end of the pipe.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:fs#pipe
 *
 * @returns {?module:fs.file[]}
 *
 * @example
 * // Create a pipe
 * const pipeHandles = pipe();
 * pipeHandles[1].write("Hello world\n");
 * print(pipeHandles[0].read("line"));
 */
static uc_value_t *
uc_fs_pipe(uc_vm_t *vm, size_t nargs)
{
	int pfds[2], err;
	FILE *rfp, *wfp;
	uc_value_t *rv;

	if (pipe(pfds) == -1)
		err_return(errno);

	rfp = fdopen(pfds[0], "r");

	if (!rfp) {
		err = errno;
		close(pfds[0]);
		close(pfds[1]);
		err_return(err);
	}

	wfp = fdopen(pfds[1], "w");

	if (!wfp) {
		err = errno;
		fclose(rfp);
		close(pfds[1]);
		err_return(err);
	}

	rv = ucv_array_new_length(vm, 2);

	ucv_array_push(rv, uc_resource_new(file_type, rfp));
	ucv_array_push(rv, uc_resource_new(file_type, wfp));

	return rv;
}


static const uc_function_list_t proc_fns[] = {
	{ "read",		uc_fs_pread },
	{ "write",		uc_fs_pwrite },
	{ "close",		uc_fs_pclose },
	{ "flush",		uc_fs_pflush },
	{ "fileno",		uc_fs_pfileno },
	{ "error",		uc_fs_error },
};

static const uc_function_list_t file_fns[] = {
	{ "read",		uc_fs_read },
	{ "write",		uc_fs_write },
	{ "seek",		uc_fs_seek },
	{ "tell",		uc_fs_tell },
	{ "close",		uc_fs_close },
	{ "flush",		uc_fs_flush },
	{ "fileno",		uc_fs_fileno },
	{ "error",		uc_fs_error },
	{ "isatty",		uc_fs_isatty },
	{ "truncate",	uc_fs_truncate },
	{ "lock",		uc_fs_lock },
#if defined(__linux__)
	{ "ioctl",		uc_fs_ioctl },
#endif
};

static const uc_function_list_t dir_fns[] = {
	{ "read",		uc_fs_readdir },
	{ "seek",		uc_fs_seekdir },
	{ "tell",		uc_fs_telldir },
	{ "close",		uc_fs_closedir },
	{ "error",		uc_fs_error },
};

static const uc_function_list_t global_fns[] = {
	{ "error",		uc_fs_error },
	{ "open",		uc_fs_open },
	{ "fdopen",		uc_fs_fdopen },
	{ "opendir",	uc_fs_opendir },
	{ "popen",		uc_fs_popen },
	{ "readlink",	uc_fs_readlink },
	{ "stat",		uc_fs_stat },
	{ "lstat",		uc_fs_lstat },
	{ "mkdir",		uc_fs_mkdir },
	{ "rmdir",		uc_fs_rmdir },
	{ "symlink",	uc_fs_symlink },
	{ "unlink",		uc_fs_unlink },
	{ "getcwd",		uc_fs_getcwd },
	{ "chdir",		uc_fs_chdir },
	{ "chmod",		uc_fs_chmod },
	{ "chown",		uc_fs_chown },
	{ "rename",		uc_fs_rename },
	{ "glob",		uc_fs_glob },
	{ "dirname",	uc_fs_dirname },
	{ "basename",	uc_fs_basename },
	{ "lsdir",		uc_fs_lsdir },
	{ "mkstemp",	uc_fs_mkstemp },
	{ "access",		uc_fs_access },
	{ "readfile",	uc_fs_readfile },
	{ "writefile",	uc_fs_writefile },
	{ "realpath",	uc_fs_realpath },
	{ "pipe",		uc_fs_pipe },
};


static void close_proc(void *ud)
{
	FILE *fp = ud;

	if (fp)
		pclose(fp);
}

static void close_file(void *ud)
{
	FILE *fp = ud;
	int n;

	n = fp ? fileno(fp) : -1;

	if (n > 2)
		fclose(fp);
}

static void close_dir(void *ud)
{
	DIR *dp = ud;

	if (dp)
		closedir(dp);
}

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, global_fns);

	proc_type = uc_type_declare(vm, "fs.proc", proc_fns, close_proc);
	file_type = uc_type_declare(vm, "fs.file", file_fns, close_file);
	dir_type = uc_type_declare(vm, "fs.dir", dir_fns, close_dir);

	ucv_object_add(scope, "stdin", uc_resource_new(file_type, stdin));
	ucv_object_add(scope, "stdout", uc_resource_new(file_type, stdout));
	ucv_object_add(scope, "stderr", uc_resource_new(file_type, stderr));

#ifdef HAS_IOCTL
#define ADD_CONST(x) ucv_object_add(scope, #x, ucv_int64_new(x))
	ADD_CONST(IOC_DIR_NONE);
	ADD_CONST(IOC_DIR_READ);
	ADD_CONST(IOC_DIR_WRITE);
	ADD_CONST(IOC_DIR_RW);
#endif
}
