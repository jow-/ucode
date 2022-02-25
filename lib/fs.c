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
#if defined(__APPLE__)
	#include <sys/types.h>
#else
	#include <sys/sysmacros.h>
#endif
#include <grp.h>
#include <pwd.h>
#include <glob.h>
#include <fnmatch.h>
#include <limits.h>

#include "ucode/module.h"

#define err_return(err) do { last_error = err; return NULL; } while(0)

//static const uc_ops *ops;
static uc_resource_type_t *file_type, *proc_type, *dir_type;

static int last_error = 0;

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

	FILE **fp = uc_fn_this(type);

	if (!fp || !*fp)
		err_return(EBADF);

	if (ucv_type(limit) == UC_STRING) {
		lstr = ucv_string_get(limit);

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

static uc_value_t *
uc_fs_pread(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_read_common(vm, nargs, "fs.proc");
}

static uc_value_t *
uc_fs_pwrite(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_write_common(vm, nargs, "fs.proc");
}

static uc_value_t *
uc_fs_pflush(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_flush_common(vm, nargs, "fs.proc");
}

static uc_value_t *
uc_fs_pfileno(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_fileno_common(vm, nargs, "fs.proc");
}

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

static uc_value_t *
uc_fs_read(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_read_common(vm, nargs, "fs.file");
}

static uc_value_t *
uc_fs_write(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_write_common(vm, nargs, "fs.file");
}

static uc_value_t *
uc_fs_seek(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *ofs = uc_fn_arg(0);
	uc_value_t *how = uc_fn_arg(1);
	int whence, res;
	long offset;

	FILE **fp = uc_fn_this("fs.file");

	if (!fp || !*fp)
		err_return(EBADF);

	if (!ofs)
		offset = 0;
	else if (ucv_type(ofs) != UC_INTEGER)
		err_return(EINVAL);
	else
		offset = (long)ucv_int64_get(ofs);

	if (!how)
		whence = 0;
	else if (ucv_type(how) != UC_INTEGER)
		err_return(EINVAL);
	else
		whence = (int)ucv_int64_get(how);

	res = fseek(*fp, offset, whence);

	if (res < 0)
		err_return(errno);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_fs_tell(uc_vm_t *vm, size_t nargs)
{
	long offset;

	FILE **fp = uc_fn_this("fs.file");

	if (!fp || !*fp)
		err_return(EBADF);

	offset = ftell(*fp);

	if (offset < 0)
		err_return(errno);

	return ucv_int64_new(offset);
}

static uc_value_t *
uc_fs_flush(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_flush_common(vm, nargs, "fs.file");
}

static uc_value_t *
uc_fs_fileno(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_fileno_common(vm, nargs, "fs.file");
}

static uc_value_t *
uc_fs_open(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *path = uc_fn_arg(0);
	uc_value_t *mode = uc_fn_arg(1);
	FILE *fp;

	if (ucv_type(path) != UC_STRING)
		err_return(EINVAL);

	fp = fopen(ucv_string_get(path),
		ucv_type(mode) == UC_STRING ? ucv_string_get(mode) : "r");

	if (!fp)
		err_return(errno);

	return uc_resource_new(file_type, fp);
}

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

static uc_value_t *
uc_fs_stat(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_stat_common(vm, nargs, false);
}

static uc_value_t *
uc_fs_lstat(uc_vm_t *vm, size_t nargs)
{
	return uc_fs_stat_common(vm, nargs, true);
}

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

	return ucv_string_new_length(s, i);
}

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
}
