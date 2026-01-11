/*
 * Copyright (C) 2024 Mikael Magnusson <mikma@users.sourceforge.net>
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
 * # Crypto
 *
 * The `crypto` module provides message digest and message signing and
 * verification. There are two alternative implementations, `crypto_openssl`
 * and `crypto_mbedtls`. The `crypto_openssl` is preferred if available since
 * it supports EdDSA in addition to all algorithms supported
 * by `crypto_mbedtls`.
 *
 * @module crypto
 */

/**
 * Represents a public key context.
 *
 * @class module:crypto.pk
 * @hideconstructor
 */

/**
 * @function module:crypto#md_digest
 *
 * @param {string} alg
 * Message digest algorithm.
 *
 * @param {string} input
 * Input to the message digest algorithm.
 *
 * @returns {string}
 */

/**
 * @function module:crypto#pk
 *
 * @returns {crypto.pk}
 */

/**
 * @function module:crypto.pk#get_public_key
 *
 * @returns {?string} - Public key in DER format.
 */

/**
 * @function module:crypto.pk#keygen
 *
 * @param {('EC'|'RSA'|'ED25519')} type
 * Public key type.
 *
 * @param {('P-192'|'P-224'|'P-256'|'P-384'|'P-521'|'brainpoolP256r1'|'brainpoolP384r1'|'brainpoolP512r1'|number)} [param]
 * EC curve name (`string`), or RSA key length (`number`).
 *
 * @returns {string}
 */

/**
 * @function module:crypto.pk#set_public_key
 *
 * @param {?string} key
 * A public key in DER format.
 */

/**
 * Available only if the `crypto_openssl` module is installed.
 *
 * @function module:crypto.pk#set_raw_public_key
 *
 * @param {('ED25519'|'ED448')} type
 * @param {string} key
 * Public key in raw format.
 */

/**
 * @function module:crypto.pk#sign
 *
 * @param {?('SHA1'|'SHA224'|'SHA256'|'SHA384'|'SHA512'|string)} alg
 * The message digest algorithm.
 *
 * @param {string} input
 * The message to be signed.
 *
 * @returns {string}
 */

/**
 * @function module:crypto.pk#verify
 *
 * @param {?('SHA1'|'SHA224'|'SHA256'|'SHA384'|'SHA512'|string)} alg
 * The message digest algorithm.
 *
 * @param {string} input
 * The message to be verified.
 *
 * @param {string} sig
 * The signature to be verified.
 *
 * @returns {boolean}
 */

let crypto;

try {
	crypto = require('crypto_openssl');
} catch {
	try {
		crypto = require('crypto_mbedtls');
	} catch {
		die(`No module named 'crypto_openssl' or 'crypto_mbedtls' could be found`);
	}
}

export
function md_digest(...args) {
	return crypto.md_digest(...args);
};

export
function md_list(...args) {
	return crypto.md_list(...args);
};

export
function pk_list(...args) {
	return crypto.pk_list(...args);
};

export
function pk(...args) {
	return crypto.pk(...args);
};
