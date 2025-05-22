/*
 * Copyright (C) 2024-2025 Mikael Magnusson <mikma@users.sourceforge.net>
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

#include <stdint.h>
#include <errno.h>
#include <alloca.h>
#include <strings.h>

#include <ucode/module.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

static void __attribute__((constructor)) load();
static void __attribute__((destructor)) unload();

#define PK_TYPE "crypto_openssl.pk"

#define TRUE ucv_boolean_new(true)
#define FALSE ucv_boolean_new(false)

static uc_resource_type_t *pk_type;

static void raise_openssl_exception(uc_vm_t *vm, const char *msg)
{
	unsigned long err = ERR_get_error();
	char buf[120];

	ERR_error_string_n(err, buf, sizeof(buf));
	uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "%s: %s", msg, buf);
}


static uc_value_t *
md_digest(uc_vm_t *vm, size_t nargs)
{
	EVP_MD_CTX *mdctx = NULL;
	uc_value_t *rv = NULL;

	uc_value_t *alg = uc_fn_arg(0);
	uc_value_t *input = uc_fn_arg(1);

	if (ucv_type(alg) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "alg is not a string");
		goto fail;
	}

	if (ucv_type(input) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "input is not a string");
		goto fail;
	}

	const EVP_MD *md = EVP_get_digestbyname(ucv_string_get(alg));

	if (!md) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "unknown MD algorithm");
		goto fail;
	}

	mdctx = EVP_MD_CTX_create();

	if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "EVP_DigestInit_ex failed");
		goto fail;
	}

	if (1 != EVP_DigestUpdate(mdctx, ucv_string_get(input), ucv_string_length(input))) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "EVP_DigestUpdate failed");
		goto fail;
	}

	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len = 0;

	if (1 != EVP_DigestFinal_ex(mdctx, md_value, &md_len)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "EVP_DigestFinal_ex failed");
		goto fail;
	}

	rv = ucv_string_new_length((const char*)md_value, md_len);

fail:
	EVP_MD_CTX_destroy(mdctx);
	return rv;
}

struct context {
	EVP_MD_CTX *mdctx;
	EVP_PKEY *pkey;
};

static uc_value_t *
pk_init(uc_vm_t *vm, size_t nargs)
{
	struct context *ctx = calloc(1, sizeof(struct context));

	ctx->mdctx = EVP_MD_CTX_create();
	return uc_resource_new(pk_type, ctx);
}

static void
pk_free(void *ptr)
{
	struct context *ctx = ptr;

	EVP_PKEY_free(ctx->pkey);
	EVP_MD_CTX_destroy(ctx->mdctx);
	free(ctx);
}

static uc_value_t *
pk_keygen(uc_vm_t *vm, size_t nargs)
{
	struct context *ctx = uc_fn_thisval(PK_TYPE);

	if (!ctx) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "invalid " PK_TYPE " object");
		return NULL;
	}

	EVP_PKEY_free(ctx->pkey);
	ctx->pkey = NULL;

	uc_value_t *type = uc_fn_arg(0);
	if (ucv_type(type) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "type is not a string");
		return NULL;
	}

	const char *type_str = ucv_string_get(type);

	if (!strcasecmp(type_str, "EC")) {
		if (nargs != 2) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Expected 2 arguments got %d", nargs);
			return NULL;
		}

		uc_value_t *curve_v = uc_fn_arg(1);
		if (ucv_type(curve_v) != UC_STRING) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "curve is not a string");
			return NULL;
		}

		const char *curve = ucv_string_get(curve_v);
		ctx->pkey = EVP_PKEY_Q_keygen(NULL, NULL, type_str, curve);
	} else if (!strcasecmp(type_str, "RSA")) {
		if (nargs != 2) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Expected 2 arguments got %d", nargs);
			return NULL;
		}

		uc_value_t *size_v = uc_fn_arg(1);
		if (ucv_type(size_v) != UC_INTEGER) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "size is not a string");
			return NULL;
		}

		size_t size = ucv_to_integer(size_v);
		ctx->pkey = EVP_PKEY_Q_keygen(NULL, NULL, type_str, size);
	} else {
		if (nargs != 1) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Expected 1 argument got %d", nargs);
			return NULL;
		}

		ctx->pkey = EVP_PKEY_Q_keygen(NULL, NULL, type_str);
	}

	if (!ctx->pkey) {
		raise_openssl_exception(vm, "Keygen failed");
		return NULL;
	}

	return TRUE;
}

static uc_value_t *
pk_get_public_key(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *res = NULL;
	struct context *ctx = uc_fn_thisval(PK_TYPE);

	if (!ctx) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "invalid " PK_TYPE " object");
		return NULL;
	}

	if (!ctx->pkey)
		return NULL;

	unsigned char *key = NULL;
	int size = i2d_PUBKEY(ctx->pkey, &key);

	if (size < 0) {
		raise_openssl_exception(vm, "failed to encode public key");
		goto fail;
	}

	res = ucv_string_new_length((const char*)key, size);

fail:
	free(key);
	return res;
}


static uc_value_t *
pk_set_raw_public_key(uc_vm_t *vm, size_t nargs)
{
	struct context *ctx = uc_fn_thisval(PK_TYPE);

	if (!ctx) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "invalid " PK_TYPE " object");
		return NULL;
	}

	uc_value_t *type = uc_fn_arg(0);
	if (ucv_type(type) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "type is not a string");
		return NULL;
	}

	const char *type_str = ucv_string_get(type);
	int type_id = 0;
	if (!strcasecmp(type_str, SN_ED25519))
		type_id = EVP_PKEY_ED25519;
	else if (!strcasecmp(type_str, SN_ED448))
		type_id = EVP_PKEY_ED448;
	else {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "type is not a valid raw key type (ED25519 or ED448)");
		return NULL;
	}

	uc_value_t *key = uc_fn_arg(1);
	if (ucv_type(key) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "key is not a string");
		return NULL;
	}

	EVP_PKEY_free(ctx->pkey);
	ctx->pkey = NULL;

	const unsigned char *key_str = (const unsigned char*)ucv_string_get(key);
	ctx->pkey = EVP_PKEY_new_raw_public_key(type_id, NULL, key_str, ucv_string_length(key));

	if (!ctx->pkey) {
		unsigned long err = ERR_get_error();
		char buf[120];

		ERR_error_string_n(err, buf, sizeof(buf));
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "not a valid raw key: %s", buf);
		return NULL;
	}

	return TRUE;
}

static uc_value_t *
pk_set_public_key(uc_vm_t *vm, size_t nargs)
{
	struct context *ctx = uc_fn_thisval(PK_TYPE);

	if (!ctx) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "invalid " PK_TYPE " object");
		return NULL;
	}

	uc_value_t *key = uc_fn_arg(0);

	EVP_PKEY_free(ctx->pkey);
	ctx->pkey = NULL;

	if (ucv_type(key) == UC_NULL) {
		return TRUE;
	}

	if (ucv_type(key) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "key is not a string");
		return NULL;
	}

	const unsigned char *key_str = (const unsigned char*)ucv_string_get(key);

	if (!d2i_PUBKEY(&ctx->pkey, &key_str, ucv_string_length(key))) {
		raise_openssl_exception(vm, "not a valid PEM/DER key");
		return NULL;
	}

	return TRUE;
}

static uc_value_t *
pk_sign(uc_vm_t *vm, size_t nargs)
{
	struct context *ctx = uc_fn_thisval(PK_TYPE);

	if (!ctx) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "invalid " PK_TYPE " object");
		return NULL;
	}

	uc_value_t *md_alg = uc_fn_arg(0);
	uc_value_t *msg = uc_fn_arg(1);

	if (md_alg != NULL && ucv_type(md_alg) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "md_alg is not a string");
		return NULL;
	}

	if (ucv_type(msg) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "msg is not a string");
		return NULL;
	}

	const EVP_MD *md = NULL;
	if (md_alg) {
		md = EVP_get_digestbyname(ucv_string_get(md_alg));
		if (!md) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "unknown MD algorithm");
			return NULL;
		}
	}

	if(1 != EVP_DigestSignInit(ctx->mdctx, NULL, md, NULL, ctx->pkey)) {
		raise_openssl_exception(vm, "EVP_DigestSignInit failed");
		return NULL;
	}

	size_t siglen = 0;

	if(1 != EVP_DigestSign(ctx->mdctx, NULL, &siglen,
			       (const unsigned char*)ucv_string_get(msg), ucv_string_length(msg))) {
		raise_openssl_exception(vm, "EVP_DigestSign failed");
		return NULL;
	}

	unsigned char *sig = alloca(siglen);

	if(1 != EVP_DigestSign(ctx->mdctx, sig, &siglen,
			       (const unsigned char*)ucv_string_get(msg), ucv_string_length(msg))) {
		raise_openssl_exception(vm, "EVP_DigestSign failed");
		return NULL;
	}

	uc_value_t *rv = ucv_string_new_length((const char*)sig, siglen);
	return rv;
}

static uc_value_t *
pk_verify(uc_vm_t *vm, size_t nargs)
{
	struct context *ctx = uc_fn_thisval(PK_TYPE);

	if (!ctx) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "invalid " PK_TYPE " object");
		return NULL;
	}

	uc_value_t *md_alg = uc_fn_arg(0);
	uc_value_t *msg = uc_fn_arg(1);
	uc_value_t *sig = uc_fn_arg(2);

	if (md_alg != NULL && ucv_type(md_alg) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "md_alg is not a string");
		return NULL;
	}

	if (ucv_type(msg) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "msg is not a string");
		return NULL;
	}

	if (ucv_type(sig) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "sig is not a string");
		return NULL;
	}

	const EVP_MD *md = NULL;
	if (md_alg) {
		md = EVP_get_digestbyname(ucv_string_get(md_alg));
		if (!md) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "unknown MD algorithm");
			return NULL;
		}
	}

	if(1 != EVP_DigestVerifyInit(ctx->mdctx, NULL, md, NULL, ctx->pkey)) {
		raise_openssl_exception(vm, "EVP_DigestVerifyInit failed");
		return NULL;
	}

	if(1 != EVP_DigestVerify(ctx->mdctx,
				 (const unsigned char*)ucv_string_get(sig), ucv_string_length(sig),
				 (const unsigned char*)ucv_string_get(msg), ucv_string_length(msg))) {
		raise_openssl_exception(vm, "EVP_DigestVerify failed");
		return NULL;
	} else {
		return TRUE;
	}
}

static const uc_function_list_t global_fns[] = {
	{ "md_digest",			md_digest },
	{ "pk",				pk_init },
};

static const uc_function_list_t pk_fns[] = {
	{ "keygen", 			pk_keygen },
	{ "get_public_key",		pk_get_public_key },
	{ "set_raw_public_key",		pk_set_raw_public_key },
	{ "set_public_key",		pk_set_public_key },
	{ "sign",			pk_sign },
	{ "verify",			pk_verify },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, global_fns);

	pk_type = uc_type_declare(vm, PK_TYPE, pk_fns, pk_free);
}

static void load()
{
	OpenSSL_add_all_digests();
}

static void unload()
{
	/* Cleanup OpenSSL_add_all_digests */
	EVP_cleanup();
}
