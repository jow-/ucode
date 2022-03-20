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

#ifndef UCODE_VALUE_H
#define UCODE_VALUE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <json-c/json.h>

#include "types.h"

typedef enum {
	TAG_INVAL = 0,
	TAG_NUM = 1,
	TAG_LNUM = 2,
	TAG_DBL = 3,
	TAG_STR = 4,
	TAG_LSTR = 5
} uc_value_type_t;

uc_value_t *uc_number_parse(const char *buf, char **end);

bool uc_double_pack(double d, char *buf, bool little_endian);
double uc_double_unpack(const char *buf, bool little_endian);

void uc_vallist_init(uc_value_list_t *list);
void uc_vallist_free(uc_value_list_t *list);

ssize_t uc_vallist_add(uc_value_list_t *list, uc_value_t *value);
uc_value_type_t uc_vallist_type(uc_value_list_t *list, size_t idx);
uc_value_t *uc_vallist_get(uc_value_list_t *list, size_t idx);

#endif /* UCODE_VALUE_H */
