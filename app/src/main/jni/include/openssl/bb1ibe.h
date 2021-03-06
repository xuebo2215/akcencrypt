/* ====================================================================
 * Copyright (c) 2016 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */
/*
 * Boneh-Boyen Identity-Based Encryption (BB1-IBE)
 * see [RFC 5091](https://tools.ietf.org/html/rfc5091)
 * Identity-Based Cryptography Standard (IBCS) #1:
 * Supersingular Curve Implementations of the BF and BB1 Cryptosystems
 */

#ifndef HEADER_BB1IBE_H
#define HEADER_BB1IBE_H

#include "opensslconf.h"
#ifndef OPENSSL_NO_BB1IBE

#include <string.h>
#include "bn.h"
#include "ec.h"
#include "evp.h"
#include "asn1.h"
#include "fppoint.h"

#define BB1IBE_VERSION	2

#ifdef __cplusplus
extern "C" {
#endif


typedef struct BB1PublicParameters_st BB1PublicParameters;
typedef struct BB1MasterSecret_st BB1MasterSecret;
typedef struct BB1PrivateKeyBlock_st BB1PrivateKeyBlock;
typedef struct BB1CiphertextBlock_st BB1CiphertextBlock;


int BB1IBE_setup(const EC_GROUP *group, const EVP_MD *md,
	BB1PublicParameters **mpk, BB1MasterSecret **msk);
BB1PrivateKeyBlock *BB1IBE_extract_private_key(BB1PublicParameters *mpk,
	BB1MasterSecret *msk, const char *id, size_t idlen);
BB1CiphertextBlock *BB1IBE_do_encrypt(BB1PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	const char *id, size_t idlen);
int BB1IBE_do_decrypt(BB1PublicParameters *mpk,
	const BB1CiphertextBlock *in, unsigned char *out, size_t *outlen,
	BB1PrivateKeyBlock *sk);
int BB1IBE_encrypt(BB1PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	const char *id, size_t idlen);
int BB1IBE_decrypt(BB1PublicParameters *mpk,
	const unsigned char *in, size_t inlen,
	unsigned char *out, size_t *outlen,
	BB1PrivateKeyBlock *sk);

DECLARE_ASN1_FUNCTIONS(BB1MasterSecret)
DECLARE_ASN1_FUNCTIONS(BB1PublicParameters)
DECLARE_ASN1_FUNCTIONS(BB1PrivateKeyBlock)
DECLARE_ASN1_FUNCTIONS(BB1CiphertextBlock)

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_BB1IBE_strings(void);

/* Error codes for the BB1IBE functions. */

/* Function codes. */
# define BB1IBE_F_BB1CIPHERTEXTBLOCK_HASH_TO_RANGE        100
# define BB1IBE_F_BB1IBE_DECRYPT                          101
# define BB1IBE_F_BB1IBE_DOUBLE_HASH                      102
# define BB1IBE_F_BB1IBE_DO_DECRYPT                       103
# define BB1IBE_F_BB1IBE_DO_ENCRYPT                       104
# define BB1IBE_F_BB1IBE_ENCRYPT                          105
# define BB1IBE_F_BB1IBE_EXTRACT_PRIVATE_KEY              106
# define BB1IBE_F_BB1IBE_SETUP                            107

/* Reason codes. */
# define BB1IBE_R_BB1CIPHERTEXT_INVALID_MAC               100
# define BB1IBE_R_BB1IBE_HASH_FAILURE                     101
# define BB1IBE_R_BUFFER_TOO_SMALL                        102
# define BB1IBE_R_COMPUTE_OUTLEN_FAILURE                  103
# define BB1IBE_R_COMPUTE_TATE_FAILURE                    104
# define BB1IBE_R_D2I_FAILURE                             105
# define BB1IBE_R_DECRYPT_FAILURE                         106
# define BB1IBE_R_DOUBLE_HASH_FAILURE                     107
# define BB1IBE_R_ENCRYPT_FAILURE                         108
# define BB1IBE_R_I2D_FAILURE                             109
# define BB1IBE_R_INVALID_INPUT                           110
# define BB1IBE_R_INVALID_MD                              111
# define BB1IBE_R_INVALID_OUTPUT_BUFFER                   112
# define BB1IBE_R_INVALID_TYPE1CURVE                      113
# define BB1IBE_R_NOT_NAMED_CURVE                         114
# define BB1IBE_R_PARSE_PAIRING                           115

# ifdef  __cplusplus
}
# endif
#endif
#endif
