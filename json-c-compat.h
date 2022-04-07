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

#ifndef JSON_C_COMPAT_H
#define JSON_C_COMPAT_H

#include <stddef.h>
#include <stdint.h>
#include <json-c/json.h>


/* json-c compat */

#ifndef HAVE_PARSE_END
static inline size_t json_tokener_get_parse_end(struct json_tokener *tok) {
	return (size_t)tok->char_offset;
}
#endif

#ifndef HAVE_ARRAY_EXT
static inline struct json_object *json_object_new_array_ext(int size) {
	(void) size;
	return json_object_new_array();
}
#endif

#ifndef HAVE_JSON_UINT64
static inline struct json_object *json_object_new_uint64(uint64_t i) {
	return json_object_new_int64((int64_t)i);
}

static inline uint64_t json_object_get_uint64(const struct json_object *obj) {
	return (uint64_t)json_object_get_int64(obj);
}
#endif

#endif /* JSON_C_COMPAT_H */
