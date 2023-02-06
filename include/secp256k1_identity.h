/***********************************************************************
 * Copyright (c) 2022 Jayamine Alupotha                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

#ifndef RAHAS_SECP256K1_SECP256K1_IDENTITY_H
#define RAHAS_SECP256K1_SECP256K1_IDENTITY_H

# include "secp256k1.h"
# include "secp256k1_generator.h"
# include "secp256k1_commitment.h"

# ifdef __cplusplus
extern "C" {
# endif

#include <stdint.h>

#define OLD_PARTIAL_DATA    1
#define NEW_PARTIAL_DATA    0

#define HASH_SIZE   32
#define COM_SIZE    33

typedef struct {
    secp256k1_pedersen_commitment commit;
} secp256k1_identity;

typedef struct {
    unsigned char data[32];
} secp256k1_hash;

typedef struct {
    unsigned char data[64];
} secp256k1_identity_pf;

typedef struct {
    unsigned char *data;
    unsigned len;
} secp256k1_unlinked_identity_pf;


/**
 * Create an identity from the digest
 * @param ctx  - context object
 * @param id - output
 * @param blind
 * @param digest
 * @param value_gen
 * @param blind_gen
 * @return 1 - successful, 0 - unsuccessful (most probably because of invalid key, e.g., a blind is zero
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_identity_create(
        const secp256k1_context* ctx,
        secp256k1_identity *id,
        const unsigned char *blind,
        secp256k1_hash digest,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/**
 * Create a PoE for an identity
 * @param ctx  - context object
 * @param proof - out
 * @param id - identity
 * @param blind  - secret key
 * @param nonce
 * @param digest
 * @param value_gen
 * @param blind_gen
 * @return 1 - successful, 0 - unsuccessful (most probably because of invalid key, e.g., a blind is zero
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_identity_prove(
        const secp256k1_context* ctx,
        secp256k1_identity_pf *proof,
        secp256k1_identity *id,
        const unsigned char *blind,
        const unsigned char *nonce,
        const unsigned char *digest,
        const secp256k1_generator *blind_gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5)
SECP256K1_ARG_NONNULL(7);

/**
 * Verify PoE for an identity
 * @param ctx  - context object
 * @param proof
 * @param id - identity
 * @param digest
 * @param value_gen
 * @param blind_gen
 * @return 1- valid, 0 - invalid
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_identity_verify(
        const secp256k1_context* ctx,
        secp256k1_identity_pf *proof,
        secp256k1_identity *id,
        const unsigned char *digest,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5)
SECP256K1_ARG_NONNULL(6);

/**
 * Create a BDPoE for an identity
 * @param ctx  - context object
 * @param proof - out
 * @param index - corresponding identity index
 * @param blind - secret key
 * @param nonce
 * @param digest
 * @param challenge
 * @param ring_size
 * @param ids - all identities
 * @param value_gen
 * @param blind_gen
 * @return 1 - successful, 0 - unsuccessful (most probably because of invalid key, e.g., a blind is zero
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_unlinked_identity_prove(
        const secp256k1_context* ctx,
        secp256k1_unlinked_identity_pf *proof,
        int index,
        const unsigned char *blind,
        const unsigned char *nonce,
        const unsigned char *digest,
        const unsigned char *challenge,
        int ring_size,
        secp256k1_identity *ids,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6)
SECP256K1_ARG_NONNULL(9) SECP256K1_ARG_NONNULL(10) SECP256K1_ARG_NONNULL(11);

/**
 * Verify a DBPoE of an identity
 * @param ctx  - context object
 * @param proof - DBPoE
 * @param digest
 * @param challenge
 * @param others
 * @param ring_size
 * @param value_gen
 * @param blind_gen
 * @return 1 - valid, 0 - invalid
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_unlinked_identity_verify(
        const secp256k1_context* ctx,
        secp256k1_unlinked_identity_pf *proof,
        const unsigned char *digest,
        const unsigned char *challenge,
        secp256k1_identity *others,
        int ring_size,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5)
SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8);

/**
 * Create a BDPoE for an identity
 * @param ctx  - context object
 * @param proof - out
 * @param index - corresponding identity index
 * @param blind - secret key
 * @param nonce
 * @param digest
 * @param challenge
 * @param N - number of commitments
 * @param n - rounded up log(N) (can be more than log(N))
 * @param ids - all identities
 * @param value_gen
 * @param blind_gen
 * @return 1 - successful, 0 - unsuccessful (most probably because of invalid key, e.g., a blind is zero
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_unlinked_logarithmic_identity_prove(
        const secp256k1_context* ctx,
        secp256k1_unlinked_identity_pf *proof,
        int index,
        const unsigned char *blind,
        const unsigned char *digest,
        const unsigned char *challenge,
        int N,
        int n,
        secp256k1_identity *ids,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6)
SECP256K1_ARG_NONNULL(10) SECP256K1_ARG_NONNULL(11) SECP256K1_ARG_NONNULL(12);

/**
 * Verify a DBPoE of an identity
 * @param ctx  - context object
 * @param proof - DBPoE
 * @param digest
 * @param challenge
 * @param others
 * @param N - number of commitments
 * @param n - rounded up log(N) (can be more than log(N))
 * @param value_gen
 * @param blind_gen
 * @return 1 - valid, 0 - invalid
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_unlinked_logarithmic_identity_verify(
        const secp256k1_context* ctx,
        secp256k1_unlinked_identity_pf *proof,
        const unsigned char *digest,
        const unsigned char *challenge,
        secp256k1_identity *others,
        int N,
        int n,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5)
SECP256K1_ARG_NONNULL(8) SECP256K1_ARG_NONNULL(9);


/**
 *
 * @param ctx  - context object
 * @param gens - output
 * @param gen_seed - input seed
 * @return 1 - valid, 0 - invalid
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_get_multi_generators(
        const secp256k1_context* ctx,
        secp256k1_generator *gens,
        const unsigned char *gen_seed,
        int m
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/**
 * Generate a multi-generator Pedersen commitment
 * @param ctx - context object
 * @param com - commitment
 * @param blind - secret key
 * @param digests - m x 32 bytes when each digest is 32 bytes (digests can be all zero if there is nothing to commit)
 * @param blind_gen - generator for the key
 * @param gens - generators for the values
 * @param m - number of maximum generators
 * @return
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_get_multi_gen_commitment(
        secp256k1_pedersen_commitment *com,
        const unsigned char *blind,
        const unsigned char *digests,
        const secp256k1_generator *blind_gen,
        const secp256k1_generator *gens,
        int m
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);


/**
 * Create a  multi-generator BDPoE for an identity
 * @param ctx  - context object
 * @param proof - out
 * @param index_of_com - corresponding identity index
 * @param index_of_gen - corresponding generator index
 * @param blind - secret key
 * @param nonce
 * @param digests - all m digests included the digest that will be opened
 * @param challenge
 * @param N - number of commitments
 * @param n - rounded up log(N) (can be more than log(N))
 * @param ids - all identities
 * @param value_gen - m number of generators
 * @param blind_gen
 * @return 1 - successful, 0 - unsuccessful (most probably because of invalid key, e.g., a blind is zero
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_logarithmic_multi_gen_poe_prove(
        const secp256k1_context* ctx,
        secp256k1_unlinked_identity_pf *proof,
        int index_of_com,
        int index_of_gen,
        const unsigned char *blind,
        const unsigned char *digests,
        const unsigned char *challenge,
        int m,
        int N,
        int n,
        secp256k1_identity *ids,
        const secp256k1_generator *generators,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6)
SECP256K1_ARG_NONNULL(12) SECP256K1_ARG_NONNULL(13) SECP256K1_ARG_NONNULL(14);

/**
 * Verify a multi-generator DBPoE of an identity
 * @param ctx  - context object
 * @param proof - DBPoE
 * @param digest - the opened digest
 * @param challenge
 * @param others
 * @param N - number of commitments
 * @param n - rounded up log(N) (can be more than log(N))
 * @param value_gen - (m - 1) number of generators
 * @param blind_gen
 * @return 1 - valid, 0 - invalid
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_logarithmic_multi_gen_poe_verify(
        const secp256k1_context* ctx,
        secp256k1_unlinked_identity_pf *proof,
        const unsigned char *digest,
        const unsigned char *challenge,
        secp256k1_identity *others,
        int m,
        int N,
        int n,
        const secp256k1_generator *generators,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5)
SECP256K1_ARG_NONNULL(9) SECP256K1_ARG_NONNULL(10);

# ifdef __cplusplus
}
# endif

#endif /* RAHAS_SECP256K1_SECP256K1_IDENTITY_H */
