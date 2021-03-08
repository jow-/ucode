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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>

#include "../module.h"

#define err_return(err) do { last_error = err; return NULL; } while(0)

//static const uc_ops *ops;
static uc_ressource_type *file_type, *proc_type, *dir_type;

static int last_error = 0;

static json_object *
uc_fs_error(uc_vm *vm, size_t nargs)
{
	json_object *errmsg;

	if (last_error == 0)
		return NULL;

	errmsg = json_object_new_string(strerror(last_error));
	last_error = 0;

	return errmsg;
}

static json_object *
uc_fs_read_common(uc_vm *vm, size_t nargs, const char *type)
{
	json_object *limit = uc_get_arg(0);
	json_object *rv = NULL;
	char buf[128], *p = NULL, *tmp;
	size_t rlen, len = 0;
	const char *lstr;
	int64_t lsize;

	FILE **fp = uc_get_self(type);

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

static json_object *
uc_fs_write_common(uc_vm *vm, size_t nargs, const char *type)
{
	json_object *data = uc_get_arg(0);
	size_t len, wsize;
	const char *str;

	FILE **fp = uc_get_self(type);

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


static json_object *
uc_fs_pclose(uc_vm *vm, size_t nargs)
{
	FILE **fp = uc_get_self("fs.proc");
	int rc;

	if (!fp || !*fp)
		err_return(EBADF);

	rc = pclose(*fp);
	*fp = NULL;

	if (rc == -1)
		err_return(errno);

	if (WIFEXITED(rc))
		return xjs_new_int64(WEXITSTATUS(rc));

	if (WIFSIGNALED(rc))
		return xjs_new_int64(-WTERMSIG(rc));

	return xjs_new_int64(0);
}

static json_object *
uc_fs_pread(uc_vm *vm, size_t nargs)
{
	return uc_fs_read_common(vm, nargs, "fs.proc");
}

static json_object *
uc_fs_pwrite(uc_vm *vm, size_t nargs)
{
	return uc_fs_write_common(vm, nargs, "fs.proc");
}

static json_object *
uc_fs_popen(uc_vm *vm, size_t nargs)
{
	json_object *comm = uc_get_arg(0);
	json_object *mode = uc_get_arg(1);
	FILE *fp;

	if (!json_object_is_type(comm, json_type_string))
		err_return(EINVAL);

	fp = popen(json_object_get_string(comm),
		json_object_is_type(mode, json_type_string) ? json_object_get_string(mode) : "r");

	if (!fp)
		err_return(errno);

	return uc_alloc_ressource(proc_type, fp);
}


static json_object *
uc_fs_close(uc_vm *vm, size_t nargs)
{
	FILE **fp = uc_get_self("fs.file");

	if (!fp || !*fp)
		err_return(EBADF);

	fclose(*fp);
	*fp = NULL;

	return json_object_new_boolean(true);
}

static json_object *
uc_fs_read(uc_vm *vm, size_t nargs)
{
	return uc_fs_read_common(vm, nargs, "fs.file");
}

static json_object *
uc_fs_write(uc_vm *vm, size_t nargs)
{
	return uc_fs_write_common(vm, nargs, "fs.file");
}

static json_object *
uc_fs_seek(uc_vm *vm, size_t nargs)
{
	json_object *ofs  = uc_get_arg(0);
	json_object *how  = uc_get_arg(1);
	int whence, res;
	long offset;

	FILE **fp = uc_get_self("fs.file");

	if (!fp || !*fp)
		err_return(EBADF);

	if (!ofs)
		offset = 0;
	else if (!json_object_is_type(ofs, json_type_int))
		err_return(EINVAL);
	else
		offset = (long)json_object_get_int64(ofs);

	if (!how)
		whence = 0;
	else if (!json_object_is_type(how, json_type_int))
		err_return(EINVAL);
	else
		whence = (int)json_object_get_int64(how);

	res = fseek(*fp, offset, whence);

	if (res < 0)
		err_return(errno);

	return json_object_new_boolean(true);
}

static json_object *
uc_fs_tell(uc_vm *vm, size_t nargs)
{
	long offset;

	FILE **fp = uc_get_self("fs.file");

	if (!fp || !*fp)
		err_return(EBADF);

	offset = ftell(*fp);

	if (offset < 0)
		err_return(errno);

	return json_object_new_int64(offset);
}

static json_object *
uc_fs_open(uc_vm *vm, size_t nargs)
{
	json_object *path = uc_get_arg(0);
	json_object *mode = uc_get_arg(1);
	FILE *fp;

	if (!json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	fp = fopen(json_object_get_string(path),
		json_object_is_type(mode, json_type_string) ? json_object_get_string(mode) : "r");

	if (!fp)
		err_return(errno);

	return uc_alloc_ressource(file_type, fp);
}


static json_object *
uc_fs_readdir(uc_vm *vm, size_t nargs)
{
	DIR **dp = uc_get_self("fs.dir");
	struct dirent *e;

	if (!dp || !*dp)
		err_return(EINVAL);

	errno = 0;
	e = readdir(*dp);

	if (!e)
		err_return(errno);

	return json_object_new_string(e->d_name);
}

static json_object *
uc_fs_telldir(uc_vm *vm, size_t nargs)
{
	DIR **dp = uc_get_self("fs.dir");
	long position;

	if (!dp || !*dp)
		err_return(EBADF);

	position = telldir(*dp);

	if (position == -1)
		err_return(errno);

	return json_object_new_int64((int64_t)position);
}

static json_object *
uc_fs_seekdir(uc_vm *vm, size_t nargs)
{
	json_object *ofs = uc_get_arg(0);
	DIR **dp = uc_get_self("fs.dir");
	long position;

	if (!json_object_is_type(ofs, json_type_int))
		err_return(EINVAL);

	if (!dp || !*dp)
		err_return(EBADF);

	position = (long)json_object_get_int64(ofs);

	seekdir(*dp, position);

	return json_object_new_boolean(true);
}

static json_object *
uc_fs_closedir(uc_vm *vm, size_t nargs)
{
	DIR **dp = uc_get_self("fs.dir");

	if (!dp || !*dp)
		err_return(EBADF);

	closedir(*dp);
	*dp = NULL;

	return json_object_new_boolean(true);
}

static json_object *
uc_fs_opendir(uc_vm *vm, size_t nargs)
{
	json_object *path = uc_get_arg(0);
	DIR *dp;

	if (!json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	dp = opendir(json_object_get_string(path));

	if (!dp)
		err_return(errno);

	return uc_alloc_ressource(dir_type, dp);
}

static json_object *
uc_fs_readlink(uc_vm *vm, size_t nargs)
{
	json_object *path = uc_get_arg(0);
	json_object *res;
	ssize_t buflen = 0, rv;
	char *buf = NULL, *tmp;

	if (!json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	do {
		buflen += 128;
		tmp = realloc(buf, buflen);

		if (!tmp) {
			free(buf);
			err_return(ENOMEM);
		}

		buf = tmp;
		rv = readlink(json_object_get_string(path), buf, buflen);

		if (rv == -1) {
			free(buf);
			err_return(errno);
		}

		if (rv < buflen)
			break;
	}
	while (true);

	res = json_object_new_string_len(buf, rv);

	free(buf);

	return res;
}

static json_object *
uc_fs_stat_common(uc_vm *vm, size_t nargs, bool use_lstat)
{
	json_object *path = uc_get_arg(0);
	json_object *res, *o;
	struct stat st;
	int rv;

	if (!json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	rv = (use_lstat ? lstat : stat)(json_object_get_string(path), &st);

	if (rv == -1)
		err_return(errno);

	res = json_object_new_object();

	if (!res)
		err_return(ENOMEM);

	o = json_object_new_object();

	if (o) {
		json_object_object_add(o, "major", json_object_new_int64(major(st.st_dev)));
		json_object_object_add(o, "minor", json_object_new_int64(minor(st.st_dev)));

		json_object_object_add(res, "dev", o);
	}

	o = json_object_new_object();

	if (o) {
		json_object_object_add(o, "setuid", json_object_new_boolean(st.st_mode & S_ISUID));
		json_object_object_add(o, "setgid", json_object_new_boolean(st.st_mode & S_ISGID));
		json_object_object_add(o, "sticky", json_object_new_boolean(st.st_mode & S_ISVTX));

		json_object_object_add(o, "user_read", json_object_new_boolean(st.st_mode & S_IRUSR));
		json_object_object_add(o, "user_write", json_object_new_boolean(st.st_mode & S_IWUSR));
		json_object_object_add(o, "user_exec", json_object_new_boolean(st.st_mode & S_IXUSR));

		json_object_object_add(o, "group_read", json_object_new_boolean(st.st_mode & S_IRGRP));
		json_object_object_add(o, "group_write", json_object_new_boolean(st.st_mode & S_IWGRP));
		json_object_object_add(o, "group_exec", json_object_new_boolean(st.st_mode & S_IXGRP));

		json_object_object_add(o, "other_read", json_object_new_boolean(st.st_mode & S_IROTH));
		json_object_object_add(o, "other_write", json_object_new_boolean(st.st_mode & S_IWOTH));
		json_object_object_add(o, "other_exec", json_object_new_boolean(st.st_mode & S_IXOTH));

		json_object_object_add(res, "perm", o);
	}

	json_object_object_add(res, "inode", json_object_new_int64((int64_t)st.st_ino));
	json_object_object_add(res, "mode", json_object_new_int64((int64_t)st.st_mode & ~S_IFMT));
	json_object_object_add(res, "nlink", json_object_new_int64((int64_t)st.st_nlink));
	json_object_object_add(res, "uid", json_object_new_int64((int64_t)st.st_uid));
	json_object_object_add(res, "gid", json_object_new_int64((int64_t)st.st_gid));
	json_object_object_add(res, "size", json_object_new_int64((int64_t)st.st_size));
	json_object_object_add(res, "blksize", json_object_new_int64((int64_t)st.st_blksize));
	json_object_object_add(res, "blocks", json_object_new_int64((int64_t)st.st_blocks));
	json_object_object_add(res, "atime", json_object_new_int64((int64_t)st.st_atime));
	json_object_object_add(res, "mtime", json_object_new_int64((int64_t)st.st_mtime));
	json_object_object_add(res, "ctime", json_object_new_int64((int64_t)st.st_ctime));

	if (S_ISREG(st.st_mode))
		json_object_object_add(res, "type", json_object_new_string("file"));
	else if (S_ISDIR(st.st_mode))
		json_object_object_add(res, "type", json_object_new_string("directory"));
	else if (S_ISCHR(st.st_mode))
		json_object_object_add(res, "type", json_object_new_string("char"));
	else if (S_ISBLK(st.st_mode))
		json_object_object_add(res, "type", json_object_new_string("block"));
	else if (S_ISFIFO(st.st_mode))
		json_object_object_add(res, "type", json_object_new_string("fifo"));
	else if (S_ISLNK(st.st_mode))
		json_object_object_add(res, "type", json_object_new_string("link"));
	else if (S_ISSOCK(st.st_mode))
		json_object_object_add(res, "type", json_object_new_string("socket"));
	else
		json_object_object_add(res, "type", json_object_new_string("unknown"));

	return res;
}

static json_object *
uc_fs_stat(uc_vm *vm, size_t nargs)
{
	return uc_fs_stat_common(vm, nargs, false);
}

static json_object *
uc_fs_lstat(uc_vm *vm, size_t nargs)
{
	return uc_fs_stat_common(vm, nargs, true);
}

static json_object *
uc_fs_mkdir(uc_vm *vm, size_t nargs)
{
	json_object *path = uc_get_arg(0);
	json_object *mode = uc_get_arg(1);

	if (!json_object_is_type(path, json_type_string) ||
	    (mode && !json_object_is_type(mode, json_type_int)))
		err_return(EINVAL);

	if (mkdir(json_object_get_string(path), (mode_t)(mode ? json_object_get_int64(mode) : 0777)) == -1)
		err_return(errno);

	return json_object_new_boolean(true);
}

static json_object *
uc_fs_rmdir(uc_vm *vm, size_t nargs)
{
	json_object *path = uc_get_arg(0);

	if (!json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	if (rmdir(json_object_get_string(path)) == -1)
		err_return(errno);

	return json_object_new_boolean(true);
}

static json_object *
uc_fs_symlink(uc_vm *vm, size_t nargs)
{
	json_object *dest = uc_get_arg(0);
	json_object *path = uc_get_arg(1);

	if (!json_object_is_type(dest, json_type_string) ||
	    !json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	if (symlink(json_object_get_string(dest), json_object_get_string(path)) == -1)
		err_return(errno);

	return json_object_new_boolean(true);
}

static json_object *
uc_fs_unlink(uc_vm *vm, size_t nargs)
{
	json_object *path = uc_get_arg(0);

	if (!json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	if (unlink(json_object_get_string(path)) == -1)
		err_return(errno);

	return json_object_new_boolean(true);
}

static json_object *
uc_fs_getcwd(uc_vm *vm, size_t nargs)
{
	json_object *res;
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

		err_return(errno);
	}
	while (true);

	res = json_object_new_string(buf);

	free(buf);

	return res;
}

static json_object *
uc_fs_chdir(uc_vm *vm, size_t nargs)
{
	json_object *path = uc_get_arg(0);

	if (!json_object_is_type(path, json_type_string))
		err_return(EINVAL);

	if (chdir(json_object_get_string(path)) == -1)
		err_return(errno);

	return json_object_new_boolean(true);
}

static const uc_cfunction_list proc_fns[] = {
	{ "read",		uc_fs_pread },
	{ "write",		uc_fs_pwrite },
	{ "close",		uc_fs_pclose },
	{ "error",		uc_fs_error },
};

static const uc_cfunction_list file_fns[] = {
	{ "read",		uc_fs_read },
	{ "write",		uc_fs_write },
	{ "seek",		uc_fs_seek },
	{ "tell",		uc_fs_tell },
	{ "close",		uc_fs_close },
	{ "error",		uc_fs_error },
};

static const uc_cfunction_list dir_fns[] = {
	{ "read",		uc_fs_readdir },
	{ "seek",		uc_fs_seekdir },
	{ "tell",		uc_fs_telldir },
	{ "close",		uc_fs_closedir },
	{ "error",		uc_fs_error },
};

static const uc_cfunction_list global_fns[] = {
	{ "error",		uc_fs_error },
	{ "open",		uc_fs_open },
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

	if (fp && fp != stdin && fp != stdout && fp != stderr)
		fclose(fp);
}

static void close_dir(void *ud)
{
	DIR *dp = ud;

	if (dp)
		closedir(dp);
}

void uc_module_init(uc_prototype *scope)
{
	uc_add_proto_functions(scope, global_fns);

	proc_type = uc_declare_type("fs.proc", proc_fns, close_proc);
	file_type = uc_declare_type("fs.file", file_fns, close_file);
	dir_type = uc_declare_type("fs.dir", dir_fns, close_dir);

	uc_add_proto_val(scope, "stdin", uc_alloc_ressource(file_type, stdin));
	uc_add_proto_val(scope, "stdout", uc_alloc_ressource(file_type, stdout));
	uc_add_proto_val(scope, "stderr", uc_alloc_ressource(file_type, stderr));
}
