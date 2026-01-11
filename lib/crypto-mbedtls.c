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

#include <ucode/module.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>

#define PK_TYPE "crypto_mbedtls.pk"

#define TRUE ucv_boolean_new(true)
#define FALSE ucv_boolean_new(false)

/* MBEDTLS_PK_SIGNATURE_MAX_SIZE is not defined in version < 2.22.0 */
#if MBEDTLS_VERSION_NUMBER < 0x02160000
# ifndef MBEDTLS_PK_SIGNATURE_MAX_SIZE
/* Use definition from version 2.22.0 */
#  if MBEDTLS_ECDSA_MAX_LEN > MBEDTLS_MPI_MAX_SIZE
#   define MBEDTLS_PK_SIGNATURE_MAX_SIZE MBEDTLS_ECDSA_MAX_LEN
#  else
#   define MBEDTLS_PK_SIGNATURE_MAX_SIZE MBEDTLS_MPI_MAX_SIZE
#  endif
# endif /* MBEDTLS_PK_SIGNATURE_MAX_SIZE */
#endif /* MBEDTLS_PK_SIGNATURE_MAX_SIZE < 0x02160000 */

const char *personalization = "ucode-crypto-mbedtls";

struct context {
	mbedtls_pk_context pk;
	mbedtls_ctr_drbg_context ctr_drbg;
};

static uc_resource_type_t *pk_type;
static mbedtls_entropy_context entropy;

static void __attribute__((constructor)) load();
static void __attribute__((destructor)) unload();

static void raise_mbedtls_exception(uc_vm_t *vm, int errnum, const char *msg)
{
	char buf[120] = "";

	mbedtls_strerror(errnum, buf, sizeof(buf));
	uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "%s: %s", msg, buf);
}


static uc_value_t *
md_digest(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *alg = uc_fn_arg(0);
	uc_value_t *input = uc_fn_arg(1);

	if (ucv_type(alg) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "alg is not a string");
		return NULL;
	}

	if (ucv_type(input) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "input is not a string");
		return NULL;
	}

	const mbedtls_md_info_t *info = mbedtls_md_info_from_string(ucv_string_get(alg));

	if (!info) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "unknown MD algorithm");
		return NULL;
	}

	unsigned char size = mbedtls_md_get_size(info);
	char *output = alloca(size);

	if (mbedtls_md(info, (const unsigned char*)ucv_string_get(input), ucv_string_length(input), (unsigned char*)output)) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "bad input data");
		return NULL;
	}

	uc_value_t *rv = ucv_string_new_length(output, size);
	return rv;
}

static uc_value_t *
pk_init(uc_vm_t *vm, size_t nargs)
{
	struct context *ctx = calloc(1, sizeof(struct context));

	mbedtls_pk_init(&ctx->pk);
	mbedtls_ctr_drbg_init(&ctx->ctr_drbg);

	int ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &entropy,
					(const unsigned char *) personalization,
					strlen(personalization) );
	if( ret != 0 ) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Problem with random generator");
		return NULL;
	}

	return uc_resource_new(pk_type, ctx);
}

static void
pk_free(void *ptr)
{
	struct context *ctx = ptr;

	mbedtls_pk_free(&ctx->pk);
	mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
	free(ctx);
}

struct alias {
	const char *alias;
	const char *name;
};

static struct alias curve_aliases[] = {
	{ .alias = "P-192", .name = "secp192r1"},
	{ .alias = "P-224", .name = "secp224r1"},
	{ .alias = "P-256", .name = "secp256r1"},
	{ .alias = "P-384", .name = "secp384r1"},
	{ .alias = "P-521", .name = "secp521r1"},
	{ .alias = NULL, .name = NULL},
};

static const char *translate_curve(const char *type)
{
	if (!type)
		return NULL;

	for (int i=0; curve_aliases[i].alias; i++) {
		if (!strcmp(type, curve_aliases[i].alias))
			return curve_aliases[i].name;
	}

	return type;
};

static uc_value_t *
pk_keygen(uc_vm_t *vm, size_t nargs)
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

		const char *curve = translate_curve(ucv_string_get(curve_v));
		const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_info_from_name(curve);

		if (!curve_info) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Unsupported curve: %s", curve);
			return NULL;
		}

		const mbedtls_pk_info_t *info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
		if (mbedtls_pk_setup(&ctx->pk, info)) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "PK setup failed");
			return NULL;
		}
		int err = mbedtls_ecp_gen_key(curve_info->grp_id,
					      mbedtls_pk_ec(ctx->pk),
					      mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
		if (err != 0) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "EC gen key failed");
			return NULL;
		}
	} else if (!strcasecmp(type_str, "RSA")) {
		if (nargs != 2) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Expected 2 arguments got %d", nargs);
			return NULL;
		}

		uc_value_t *size_v = uc_fn_arg(1);
		if (ucv_type(size_v) != UC_INTEGER) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "size is not a number");
			return NULL;
		}

		size_t size = ucv_to_integer(size_v);
		const mbedtls_pk_info_t *info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
		if (mbedtls_pk_setup(&ctx->pk, info)) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "PK setup failed");
			return NULL;
		}

		int err = mbedtls_rsa_gen_key(mbedtls_pk_rsa(ctx->pk),
					      mbedtls_ctr_drbg_random, &ctx->ctr_drbg,
					      size, 65537);
		if (err != 0) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "RSA gen key failed");
			return NULL;
		}
	} else {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Unsupported key type %s", type_str);
		return NULL;
	}

	return TRUE;
}

static uc_value_t *
pk_get_public_key(uc_vm_t *vm, size_t nargs)
{
	struct context *ctx = uc_fn_thisval(PK_TYPE);

	if (!ctx) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "invalid " PK_TYPE " object");
		return NULL;
	}

	if (!mbedtls_pk_get_len(&ctx->pk)) {
		// No key
		return NULL;
	}

	unsigned char buf[16000];
	int res = mbedtls_pk_write_pubkey_der(&ctx->pk, buf, sizeof(buf));
	if (res <= 0) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "failed to get public key");
		return NULL;
	}

	uc_value_t *rv = ucv_string_new_length((const char*)(buf + sizeof(buf) - res), res);
	return rv;
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
	if (ucv_type(key) == UC_NULL) {
		mbedtls_pk_free(&ctx->pk);
		return NULL;
	}

	if (ucv_type(key) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "key is not a string");
		return NULL;
	}

	int err = mbedtls_pk_parse_public_key(&ctx->pk, (const unsigned char*)ucv_string_get(key), ucv_string_length(key));
	if (err)
		raise_mbedtls_exception(vm, err, "not a valid DER key");
	return NULL;
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
	uc_value_t *input = uc_fn_arg(1);

	if (ucv_type(md_alg) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "md_alg is not a string");
		return NULL;
	}

	if (ucv_type(input) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "input is not a string");
		return NULL;
	}

	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_string(ucv_string_get(md_alg));
	if (!md_info) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "unknown MD algorithm");
		return NULL;
	}

	unsigned char hash_len = mbedtls_md_get_size(md_info);
	unsigned char *hash = alloca(hash_len);

	if (mbedtls_md(md_info, (const unsigned char*)ucv_string_get(input), ucv_string_length(input), (unsigned char*)hash)) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "bad input data");
		return NULL;
	}

	const mbedtls_md_type_t md_type = mbedtls_md_get_type(md_info);
	unsigned char sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
	size_t sig_len = sizeof(sig);

	if (mbedtls_pk_sign(&ctx->pk, md_type, hash, hash_len, sig,
#if MBEDTLS_VERSION_MAJOR >= 3
			    sig_len,
#endif /* MBEDTLS_VERSION_MAJOR */
			    &sig_len, mbedtls_ctr_drbg_random, &ctx->ctr_drbg)) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "pk sign failed");
		return NULL;
	}

	uc_value_t *rv = ucv_string_new_length((const char*)sig, sig_len);
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
	uc_value_t *input = uc_fn_arg(1);
	uc_value_t *sig = uc_fn_arg(2);

	if (ucv_type(md_alg) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "md_alg is not a string");
		return NULL;
	}

	if (ucv_type(input) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "input is not a string");
		return NULL;
	}

	if (ucv_type(sig) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "sig is not a string");
		return NULL;
	}

	const mbedtls_md_info_t *md_info = mbedtls_md_info_from_string(ucv_string_get(md_alg));

	if (!md_info) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "unknown MD algorithm");
		return NULL;
	}

	unsigned char hash_size = mbedtls_md_get_size(md_info);
	unsigned char *hash = alloca(hash_size);

	if (mbedtls_md(md_info, (const unsigned char*)ucv_string_get(input), ucv_string_length(input), (unsigned char*)hash)) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "bad input data");
		return NULL;
	}

	const mbedtls_md_type_t md_type = mbedtls_md_get_type(md_info);

	int err = mbedtls_pk_verify(&ctx->pk, md_type,
				    hash, hash_size,
				    (const unsigned char*)ucv_string_get(sig), ucv_string_length(sig));
	if (err) {
		raise_mbedtls_exception(vm, err, "validation failed");
		return FALSE;
	}

	return TRUE;
}

static const uc_function_list_t global_fns[] = {
	{ "md_digest",			md_digest },
	{ "pk",				pk_init },
};

static const uc_function_list_t pk_fns[] = {
	{ "keygen", 			pk_keygen },
	{ "get_public_key",		pk_get_public_key },
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
	mbedtls_entropy_init(&entropy);
}

static void unload()
{
	mbedtls_entropy_free(&entropy);
}
