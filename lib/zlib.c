/*
 * Copyright (C) 2024 Thibaut VARÈNE <hacks@slashdirt.org>
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
 * # Zlib bindings
 *
 * The `zlib` module provides single-call-oriented functions for interacting with zlib data.
 *
 * @module zlib
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <zlib.h>

#include "ucode/module.h"
#include "ucode/platform.h"

// https://zlib.net/zlib_how.html

/*
 * CHUNK is simply the buffer size for feeding data to and pulling data from
 * the zlib routines. Larger buffer sizes would be more efficient, especially
 * for inflate(). If the memory is available, buffers sizes on the order of
 * 128K or 256K bytes should be used.
 */
#define CHUNK 16384


/* zlib init error message */
static const char * ziniterr(int ret)
{
	const char * msg;

	switch (ret) {
	case Z_ERRNO:
		msg = strerror(errno);
		break;
	case Z_STREAM_ERROR:	// can only happen for deflateInit2() by construction
		msg = "invalid compression level";
		break;
	case Z_MEM_ERROR:
		msg = "out of memory";
		break;
	case Z_VERSION_ERROR:
		msg = "zlib version mismatch!";
		break;
	default:
		msg = "unknown error";
		break;
	}

	return msg;
}

static uc_stringbuf_t *
uc_zlib_def_object(uc_vm_t *vm, uc_value_t *obj, z_stream *strm)
{
	int ret;
	bool eof = false;
	uc_value_t *rfn, *rbuf;
	uc_stringbuf_t *buf = NULL;

	rfn = ucv_property_get(obj, "read");

	if (!ucv_is_callable(rfn)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
				      "Input object does not implement read() method");
		return NULL;
	}

	buf = ucv_stringbuf_new();

	do {
		rbuf = NULL;
		uc_vm_stack_push(vm, ucv_get(obj));
		uc_vm_stack_push(vm, ucv_get(rfn));
		uc_vm_stack_push(vm, ucv_int64_new(CHUNK));

		if (uc_vm_call(vm, true, 1) != EXCEPTION_NONE)
			goto fail;

		rbuf = uc_vm_stack_pop(vm);	// read output chunk

		/* we only accept strings */
		if (rbuf != NULL && ucv_type(rbuf) != UC_STRING) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE,
					      "Input object read() method returned non-string value");
			goto fail;
		}

		/* check EOF */
		eof = (rbuf == NULL || ucv_string_length(rbuf) == 0);

		strm->next_in = (unsigned char *)ucv_string_get(rbuf);
		strm->avail_in = ucv_string_length(rbuf);

		/* run deflate() on input until output buffer not full */
		do {
			// enlarge buf by CHUNK amount as needed
			printbuf_memset(buf, printbuf_length(buf) + CHUNK - 1, 0, 1);
			buf->bpos -= CHUNK;

			strm->avail_out = CHUNK;
			strm->next_out = (unsigned char *)(buf->buf + buf->bpos);;

			ret = deflate(strm, eof ? Z_FINISH : Z_NO_FLUSH);	// no bad return value here
			assert(ret != Z_STREAM_ERROR);				// state never clobbered (would be mem corruption)
			(void)ret;		// XXX make annoying compiler that ignores assert() happy

			// update bpos past data written by deflate()
			buf->bpos += CHUNK - strm->avail_out;
		} while (strm->avail_out == 0);
		assert(strm->avail_in == 0);	// all input will be used

		ucv_put(rbuf);	// release rbuf
	} while (!eof);	// finish compression if all of source has been read in
	assert(ret == Z_STREAM_END);	// stream will be complete

	return buf;

fail:
	ucv_put(rbuf);
	printbuf_free(buf);
	return NULL;
}

static uc_stringbuf_t *
uc_zlib_def_string(uc_vm_t *vm, uc_value_t *str, z_stream *strm)
{
	int ret;
	uc_stringbuf_t *buf = NULL;

	buf = ucv_stringbuf_new();

	strm->next_in = (unsigned char *)ucv_string_get(str);
	strm->avail_in = ucv_string_length(str);

	do {
		printbuf_memset(buf, printbuf_length(buf) + CHUNK - 1, 0, 1);
		buf->bpos -= CHUNK;

		strm->avail_out = CHUNK;
		strm->next_out = (unsigned char *)(buf->buf + buf->bpos);

		ret = deflate(strm, Z_FINISH);
		assert(ret != Z_STREAM_ERROR);

		buf->bpos += CHUNK - strm->avail_out;
	} while (ret != Z_STREAM_END);
	assert(strm->avail_in == 0);

	return buf;
}

/**
 * Compresses data in Zlib or gzip format.
 *
 * If the input argument is a plain string, it is directly compressed.
 *
 * If an array, object or resource value is given, this function will attempt to
 * invoke a `read()` method on it to read chunks of input text to incrementally
 * compress. Reading will stop if the object's `read()` method returns
 * either `null` or an empty string.
 *
 * Throws an exception on errors.
 *
 * Returns the compressed data.
 *
 * @function module:zlib#deflate
 *
 * @param {string} str_or_resource
 * The string or resource object to be parsed as JSON.
 *
 * @param {?boolean} [gzip=false]
 * Add a gzip header if true (creates a gzip-compliant output, otherwise defaults to Zlib)
 *
 * @param {?number} [level=Z_DEFAULT_COMPRESSION]
 * The compression level (0-9).
 *
 * @returns {?string}
 *
 * @example
 * // deflate content using default compression
 * const deflated = deflate(content);
 *
 * // deflate content using fastest compression
 * const deflated = deflate(content, Z_BEST_SPEED);
 */
static uc_value_t *
uc_zlib_deflate(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *rv = NULL;
	uc_value_t *src = uc_fn_arg(0);
	uc_value_t *gzip = uc_fn_arg(1);
	uc_value_t *level = uc_fn_arg(2);
	uc_stringbuf_t *buf = NULL;
	int ret, lvl = Z_DEFAULT_COMPRESSION;
	bool gz = false;
	z_stream strm = {
		.zalloc = Z_NULL,
		.zfree = Z_NULL,
		.opaque = Z_NULL,
	};

	if (gzip) {
		if (ucv_type(gzip) != UC_BOOLEAN) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Passed gzip flag is not a boolean");
			goto out;
		}

		gz = (int)ucv_boolean_get(gzip);
	}

	if (level) {
		if (ucv_type(level) != UC_INTEGER) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Passed level is not a number");
			goto out;
		}

		lvl = (int)ucv_int64_get(level);
	}

	ret = deflateInit2(&strm, lvl,
			   Z_DEFLATED,		// only allowed method
			   gz ? 15+16 : 15,	// 15 Zlib default, +16 for gzip
			   8,			// default value
			   Z_DEFAULT_STRATEGY);	// default value
	if (ret != Z_OK) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Zlib error: %s", ziniterr(ret));
		goto out;
	}

	switch (ucv_type(src)) {
	case UC_STRING:
		buf = uc_zlib_def_string(vm, src, &strm);
		break;

	case UC_RESOURCE:
	case UC_OBJECT:
	case UC_ARRAY:
		buf = uc_zlib_def_object(vm, src, &strm);
		break;

	default:
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
				      "Passed value is neither a string nor an object");
		goto out;
	}

	if (!buf) {
		if (vm->exception.type == EXCEPTION_NONE)	// do not clobber previous exception
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Zlib error: %s", strm.msg);
		goto out;
	}

	rv = ucv_stringbuf_finish(buf);

out:
	(void)deflateEnd(&strm);
	return rv;
}

static uc_stringbuf_t *
uc_zlib_inf_object(uc_vm_t *vm, uc_value_t *obj, z_stream *strm)
{
	int ret = Z_STREAM_ERROR;	// error out if EOF on first loop
	bool eof = false;
	uc_value_t *rfn, *rbuf;
	uc_stringbuf_t *buf = NULL;

	rfn = ucv_property_get(obj, "read");

	if (!ucv_is_callable(rfn)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
				      "Input object does not implement read() method");
		return NULL;
	}

	buf = ucv_stringbuf_new();

	do {
		rbuf = NULL;
		uc_vm_stack_push(vm, ucv_get(obj));
		uc_vm_stack_push(vm, ucv_get(rfn));
		uc_vm_stack_push(vm, ucv_int64_new(CHUNK));

		if (uc_vm_call(vm, true, 1) != EXCEPTION_NONE)
			goto fail;

		rbuf = uc_vm_stack_pop(vm);	// read output chunk

		/* we only accept strings */
		if (rbuf != NULL && ucv_type(rbuf) != UC_STRING) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE,
					      "Input object read() method returned non-string value");
			goto fail;
		}

		/* check EOF */
		eof = (rbuf == NULL || ucv_string_length(rbuf) == 0);
		if (eof)
			break;

		strm->next_in = (unsigned char *)ucv_string_get(rbuf);
		strm->avail_in = ucv_string_length(rbuf);

		/* run deflate() on input until output buffer not full */
		do {
			// enlarge buf by CHUNK amount as needed
			printbuf_memset(buf, printbuf_length(buf) + CHUNK - 1, 0, 1);
			buf->bpos -= CHUNK;

			strm->avail_out = CHUNK;
			strm->next_out = (unsigned char *)(buf->buf + buf->bpos);;

			ret = inflate(strm, Z_NO_FLUSH);
			assert(ret != Z_STREAM_ERROR);		// state never clobbered (would be mem corruption)
			switch (ret) {
			case Z_NEED_DICT:
			case Z_DATA_ERROR:
			case Z_MEM_ERROR:
				goto fail;
			}

			// update bpos past data written by deflate()
			buf->bpos += CHUNK - strm->avail_out;
		} while (strm->avail_out == 0);

		ucv_put(rbuf);	// release rbuf
	} while (ret != Z_STREAM_END);	// done when inflate() says it's done

	if (ret != Z_STREAM_END) {	// data error
		printbuf_free(buf);
		buf = NULL;
	}

	return buf;

fail:
	ucv_put(rbuf);
	printbuf_free(buf);
	return NULL;
}

static uc_stringbuf_t *
uc_zlib_inf_string(uc_vm_t *vm, uc_value_t *str, z_stream *strm)
{
	int ret;
	uc_stringbuf_t *buf = NULL;

	buf = ucv_stringbuf_new();

	strm->next_in = (unsigned char *)ucv_string_get(str);
	strm->avail_in = ucv_string_length(str);

	do {
		printbuf_memset(buf, printbuf_length(buf) + CHUNK - 1, 0, 1);
		buf->bpos -= CHUNK;

		strm->avail_out = CHUNK;
		strm->next_out = (unsigned char *)(buf->buf + buf->bpos);

		ret = inflate(strm, Z_FINISH);
		assert(ret != Z_STREAM_ERROR);
		switch (ret) {
		case Z_NEED_DICT:
		case Z_DATA_ERROR:
		case Z_MEM_ERROR:
			printbuf_free(buf);
			return NULL;
		}

		buf->bpos += CHUNK - strm->avail_out;
	} while (ret != Z_STREAM_END);
	assert(strm->avail_in == 0);

	return buf;
}

/**
 * Decompresses data in Zlib or gzip format.
 *
 * If the input argument is a plain string, it is directly decompressed.
 *
 * If an array, object or resource value is given, this function will attempt to
 * invoke a `read()` method on it to read chunks of input text to incrementally
 * decompress. Reading will stop if the object's `read()` method returns
 * either `null` or an empty string.
 *
 * Throws an exception on errors.
 *
 * Returns the decompressed data.
 *
 * @function module:zlib#inflate
 *
 * @param {string} str_or_resource
 * The string or resource object to be parsed as JSON.
 *
 * @returns {?string}
 */
static uc_value_t *
uc_zlib_inflate(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *rv = NULL;
	uc_value_t *src = uc_fn_arg(0);
	uc_stringbuf_t *buf = NULL;
	int ret;
	z_stream strm = {
		.zalloc = Z_NULL,
		.zfree = Z_NULL,
		.opaque = Z_NULL,
		.avail_in = 0,		// must be initialized before call to inflateInit
		.next_in = Z_NULL,	// must be initialized before call to inflateInit
	};

	/* tell inflateInit2 to perform either zlib or gzip decompression: 15+32 */
	ret = inflateInit2(&strm, 15+32);
	if (ret != Z_OK) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Zlib error: %s", ziniterr(ret));
		goto out;
	}

	switch (ucv_type(src)) {
	case UC_STRING:
		buf = uc_zlib_inf_string(vm, src, &strm);
		break;

	case UC_RESOURCE:
	case UC_OBJECT:
	case UC_ARRAY:
		buf = uc_zlib_inf_object(vm, src, &strm);
		break;

	default:
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
				      "Passed value is neither a string nor an object");
		goto out;
	}

	if (!buf) {
		if (vm->exception.type == EXCEPTION_NONE)	// do not clobber previous exception
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Zlib error: %s", strm.msg);
		goto out;
	}

	rv = ucv_stringbuf_finish(buf);

out:
	(void)inflateEnd(&strm);
	return rv;
}

static const uc_function_list_t global_fns[] = {
	{ "deflate",	uc_zlib_deflate },
	{ "inflate",	uc_zlib_inflate },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, global_fns);

#define ADD_CONST(x) ucv_object_add(scope, #x, ucv_int64_new(x))

	/**
	 * @typedef
	 * @name Compression levels
	 * @description Constants representing predefined compression levels.
	 * @property {number} Z_NO_COMPRESSION.
	 * @property {number} Z_BEST_SPEED.
	 * @property {number} Z_BEST_COMPRESSION.
	 * @property {number} Z_DEFAULT_COMPRESSION - default compromise between speed and compression (currently equivalent to level 6).
	 */
	ADD_CONST(Z_NO_COMPRESSION);
	ADD_CONST(Z_BEST_SPEED);
	ADD_CONST(Z_BEST_COMPRESSION);
	ADD_CONST(Z_DEFAULT_COMPRESSION);
}
