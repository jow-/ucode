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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>

#define err_return(err) do { last_error = err; return NULL; } while(0)

static const struct ut_ops *ops;

static struct json_object *file_proto;
static struct json_object *dir_proto;

static int last_error = 0;

static struct json_object *
ut_fs_error(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *errmsg;

	if (last_error == 0)
		return NULL;

	errmsg = json_object_new_string(strerror(last_error));
	last_error = 0;

	return errmsg;
}


static struct json_object *
ut_fs_close(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	FILE **fp = (FILE **)ops->get_type(s->ctx, "fs.file");

	if (!fp || !*fp)
		err_return(EBADF);

	fclose(*fp);
	//*fp = NULL;

	return json_object_new_boolean(true);
}

static struct json_object *
ut_fs_read(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *limit = json_object_array_get_idx(args, 0);
	struct json_object *rv = NULL;
	char buf[128], *p = NULL, *tmp;
	size_t rlen, len = 0;
	const char *lstr;
	int64_t lsize;

	FILE **fp = (FILE **)ops->get_type(s->ctx, "fs.file");

	if (!fp || !*fp)
		err_return(EBADF);

	if (json_object_is_type(limit, json_type_string)) {
		lstr = json_object_get_string(limit);

		if (!strcmp(lstr, "line")) {
			while (true) {
				if (!fgets(buf, sizeof(buf), *fp))
					break;

				rlen = strlen(buf);
				tmp = realloc(p, len + rlen + 1);

				if (!tmp) {
					free(p);
					err_return(ENOMEM);
				}

				snprintf(tmp + len, rlen + 1, "%s", buf);

				p = tmp;
				len += rlen;

				if (rlen > 0 && buf[rlen - 1] == '\n')
					break;
			}
		}
		else if (!strcmp(lstr, "all")) {
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
		else {
			return NULL;
		}
	}
	else if (json_object_is_type(limit, json_type_int)) {
		lsize = json_object_get_int64(limit);

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

	rv = json_object_new_string_len(p, len);
	free(p);

	return rv;
}

static struct json_object *
ut_fs_write(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *data = json_object_array_get_idx(args, 0);
	size_t len, wsize;
	const char *str;

	FILE **fp = (FILE **)ops->get_type(s->ctx, "fs.file");

	if (!fp || !*fp)
		err_return(EBADF);

	if (json_object_is_type(data, json_type_string)) {
		str = json_object_get_string(data);
		len = json_object_get_string_len(data);
	}
	else {
		str = json_object_to_json_string(data);
		len = str ? strlen(str) : 0;
	}

	wsize = fwrite(str, 1, len, *fp);

	if (wsize < len && ferror(*fp))
		err_return(errno);

	return json_object_new_int64(wsize);
}

static struct json_object *
ut_fs_seek(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *off  = json_object_array_get_idx(args, 0);
	struct json_object *how  = json_object_array_get_idx(args, 1);
	int whence, res;
	long offset;

	FILE **fp = (FILE **)ops->get_type(s->ctx, "fs.file");

	if (!fp || !*fp)
		err_return(EBADF);

	if (!off)
		offset = 0;
	else if (!json_object_is_type(off, json_type_int))
		err_return(EINVAL);
	else
		offset = (long)json_object_get_int64(off);

	if (!how)
		whence = 0;
	else if (!json_object_is_type(how, json_type_int))
		err_return(EINVAL);
	else
		whence = (int)json_object_get_int64(how);

	res = fseek(*fp, offset, whence);

	if (res < 0)
		err_return(errno);

	return json_object_new_int64(res);
}

static struct json_object *
ut_fs_tell(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	long offset;

	FILE **fp = (FILE **)ops->get_type(s->ctx, "fs.file");

	if (!fp || !*fp)
		err_return(EBADF);

	offset = ftell(*fp);

	if (offset < 0)
		err_return(errno);

	return json_object_new_int64(offset);
}

static struct json_object *
ut_fs_open(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *path = json_object_array_get_idx(args, 0);
	struct json_object *mode = json_object_array_get_idx(args, 1);
	struct json_object *fo;
	FILE *fp;

	if (!json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	fp = fopen(json_object_get_string(path),
		json_object_is_type(mode, json_type_string) ? json_object_get_string(mode) : "r");

	if (!fp)
		err_return(errno);

	fo = json_object_new_object();

	if (!fo) {
		fclose(fp);
		err_return(ENOMEM);
	}

	return ops->set_type(s, fo, file_proto, "fs.file", fp);
}


static struct json_object *
ut_fs_readdir(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	DIR **dp = (DIR **)ops->get_type(s->ctx, "fs.dir");
	struct dirent *e;

	if (!dp || !*dp)
		err_return(EINVAL);

	errno = 0;
	e = readdir(*dp);

	if (!e)
		err_return(errno);

	return json_object_new_string(e->d_name);
}

static struct json_object *
ut_fs_closedir(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	DIR **dp = (DIR **)ops->get_type(s->ctx, "fs.dir");

	if (!dp || !*dp)
		err_return(EBADF);

	closedir(*dp);
	*dp = NULL;

	return json_object_new_boolean(true);
}

static struct json_object *
ut_fs_opendir(struct ut_state *s, struct ut_opcode *op, struct json_object *args)
{
	struct json_object *path = json_object_array_get_idx(args, 0);
	struct json_object *diro;
	DIR *dp;

	if (!json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	dp = opendir(json_object_get_string(path));

	if (!dp)
		err_return(errno);

	diro = json_object_new_object();

	if (!diro) {
		closedir(dp);
		err_return(ENOMEM);
	}

	return ops->set_type(s, diro, dir_proto, "fs.dir", dp);
}


static const struct { const char *name; ut_c_fn *func; } functions[] = {
	{ "error",		ut_fs_error },
	{ "open",		ut_fs_open },
	{ "opendir",	ut_fs_opendir },
};


static void close_file(void *ud) {
	fclose((FILE *)ud);
}

static void close_dir(void *ud) {
	closedir((DIR *)ud);
}

void ut_module_init(const struct ut_ops *ut, struct ut_state *s, struct json_object *scope)
{
	int i;

	ops = ut;
	ops->register_type("fs.file", close_file);
	ops->register_type("fs.dir", close_dir);

	for (i = 0; i < sizeof(functions) / sizeof(functions[0]); i++)
		ops->register_function(s, scope, functions[i].name, functions[i].func);

	file_proto = ops->new_object(s, NULL);

	if (file_proto) {
		ops->register_function(s, file_proto, "read", ut_fs_read);
		ops->register_function(s, file_proto, "write", ut_fs_write);
		ops->register_function(s, file_proto, "seek", ut_fs_seek);
		ops->register_function(s, file_proto, "tell", ut_fs_tell);
		ops->register_function(s, file_proto, "close", ut_fs_close);
	}

	dir_proto = ops->new_object(s, NULL);

	if (dir_proto) {
		ops->register_function(s, dir_proto, "readdir", ut_fs_readdir);
		ops->register_function(s, dir_proto, "closedir", ut_fs_closedir);
	}
}
