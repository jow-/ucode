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
 * # Curl bindings
 *
 * The `curl` module provides single-call curl bindings through the libcurl-easy API.
 *
 * @module curl
 *
 * @todo
 * add support for returning response headers
 */

#include <stdio.h>
#include <string.h>
#include <curl/curl.h>

#include "ucode/module.h"
#include "ucode/platform.h"


CURL *
uc_curl_initurl(uc_vm_t *vm, const char *url)
{
	CURL *curl = NULL;
	CURLcode res;

	res = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (res != CURLE_OK) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Curl init error");
		goto out;
	}

	curl = curl_easy_init();
	if (!curl) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Curl easy init error");
		goto out;
	}

	res = curl_easy_setopt(curl, CURLOPT_URL, url);
	if (res != CURLE_OK) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Failed to set target URL: %s", curl_easy_strerror(res));
		goto out;
	}
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);		// 10s timeout
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);	// follow redirects

out:
	return curl;
}

/**
 * POST data to remote URL.
 *
 * Throws an exception on errors.
 *
 * Returns true on success.
 *
 * @function module:curl#post
 *
 * @param {string} url
 * Target URL. for the POST
 *
 * @param {string} data
 * POST data
 *
 * @param {?array} headers
 * Optional extra HTTP headers
 *
 * @returns {?boolean}
 *
 * @example
 * const REMOTE_URL = "https://myserver.domain/api/post";
 * const curl = require('curl');
 * let gzipdata = ...
 * let headers = [ "My_Custom_Header:  foobar", "Content_Encoding: gzip" ];
 * curl.post(REMOTE_URL, gzipdata, headers);
 */
static uc_value_t *
uc_curl_post(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *url = uc_fn_arg(0);
	uc_value_t *src = uc_fn_arg(1);
	uc_value_t *hdr = uc_fn_arg(2);
	size_t i, len;
	CURL *curl = NULL;
	CURLcode res;
	struct curl_slist *headers = NULL;
	bool ret = false;

	if (ucv_type(url) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Passed url is not a string");
		goto out;
	}

	curl = uc_curl_initurl(vm, ucv_string_get(url));

	if (hdr) {
		if (ucv_type(hdr) != UC_ARRAY) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Passed headers is not an array");
			goto out;
		}

		len = ucv_array_length(hdr);

		if (len) {
			for (i = 0; i < len; i++) {
				/* XXX curl_slist_append(headers, ucv_string_get(ucv_array_get(hdr, i))); fails with
				 include/ucode/types.h:356:59: error: lvalue required as unary '&' operand
				   356 | #define ucv_string_get(uv) _ucv_string_get((uc_value_t **)&uv)
				       |                                                           ^
				 lib/curl.c:75:70: note: in expansion of macro 'ucv_string_get'
				    75 |                                 headers = curl_slist_append(headers, ucv_string_get(ucv_array_get(hdr, i)));
				       |                                                                      ^~~~~~~~~~~~~~
				*/
				uc_value_t *h = ucv_array_get(hdr, i);
				headers = curl_slist_append(headers, ucv_string_get(h));
				if (!headers) {
					uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Could not append header: %s", ucv_string_get(h));
					goto out;
				}
			}
			res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
			if (res != CURLE_OK) {
				uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Failed to set POST headers: %s", curl_easy_strerror(res));
				goto out;
			}
		}
	}

	switch (ucv_type(src)) {
	case UC_STRING:
		res = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, ucv_string_length(src));
		if (res != CURLE_OK) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Failed to set POST size: %s", curl_easy_strerror(res));
			goto out;
		}
		res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ucv_string_get(src));
		if (res != CURLE_OK) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Failed to set POST data: %s", curl_easy_strerror(res));
			goto out;
		}
		break;

	case UC_RESOURCE:
	case UC_OBJECT:
	case UC_ARRAY:
	default:
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Unsupported data type");
		goto out;
	}

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Curl error: %s", curl_easy_strerror(res));
		goto out;
	}

	ret = true;
out:
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	curl_global_cleanup();
	return ucv_boolean_new(ret);
}

static size_t
recv_data(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	size_t dsize = size * nmemb;
	uc_stringbuf_t *outbuf = userdata;

	printbuf_memset(outbuf, printbuf_length(outbuf) + dsize - 1, 0, 1);
	outbuf->bpos -= dsize;

	memcpy(outbuf->buf + outbuf->bpos, ptr, dsize);
	outbuf->bpos += dsize;

	return dsize;
}

/**
 * GET data from remote URL.
 *
 * Throws an exception on errors.
 *
 * Returns remote content on success.
 *
 * @function module:curl#get
 *
 * @param {string} url
 * Target URL. for the GET
 *
 * @param {?array} headers
 * Optional extra HTTP headers
 *
 * @returns {?string}
 *
 * @example
 * const REMOTE_URL = "https://myserver.domain/";
 * const curl = require('curl');
 * let content = curl.get(REMOTE_URL);
 */
static uc_value_t *
uc_curl_get(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *url = uc_fn_arg(0);
	uc_value_t *hdr = uc_fn_arg(1);
	uc_value_t *rv = NULL;
	uc_stringbuf_t *outbuf;
	size_t i, len;
	CURL *curl = NULL;
	CURLcode res;
	struct curl_slist *headers = NULL;

	if (ucv_type(url) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Passed url is not a string");
		goto out;
	}

	curl = uc_curl_initurl(vm, ucv_string_get(url));

	if (hdr) {
		if (ucv_type(hdr) != UC_ARRAY) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Passed headers is not an array");
			goto out;
		}

		len = ucv_array_length(hdr);

		if (len) {
			for (i = 0; i < len; i++) {
				uc_value_t *h = ucv_array_get(hdr, i);
				headers = curl_slist_append(headers, ucv_string_get(h));
				if (!headers) {
					uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Could not append header: %s", ucv_string_get(h));
					goto out;
				}
			}
			res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
			if (res != CURLE_OK) {
				uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Failed to set GET headers: %s", curl_easy_strerror(res));
				goto out;
			}
		}
	}

	outbuf = ucv_stringbuf_new();
	res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, outbuf);
	if (res != CURLE_OK) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Failed to set output buffer: %s", curl_easy_strerror(res));
		printbuf_free(outbuf);
		goto out;
	}

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, recv_data);

	res = curl_easy_perform(curl);
	if (res != CURLE_OK) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Curl error: %s", curl_easy_strerror(res));
		printbuf_free(outbuf);
		goto out;
	}

	rv = ucv_stringbuf_finish(outbuf);

out:
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	curl_global_cleanup();
	return rv;
}

static const uc_function_list_t global_fns[] = {
	{ "post",	uc_curl_post },
	{ "get",	uc_curl_get },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, global_fns);
}
