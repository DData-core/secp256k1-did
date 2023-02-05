

#ifndef RAHAS_SECP256K1_TESTS_IMPL_H
#define RAHAS_SECP256K1_TESTS_IMPL_H

#include "secp256k1_identity.h"
#include "openssl/rand.h"
#include "math.h"

void run_identity_tests(void) {
    secp256k1_pedersen_commitment com;
    secp256k1_identity id;
    secp256k1_identity *ids;
    secp256k1_identity id_parsed;
    secp256k1_identity_pf proof;
    secp256k1_unlinked_identity_pf proof1;
    unsigned char in[COM_SIZE];
    unsigned char out[COM_SIZE];
    unsigned char blind[32];
    unsigned char blinds[10][32];
    unsigned char nonce[32];
    secp256k1_hash digest;
    secp256k1_hash digest_up;
    int i, t;
    unsigned char msg[1];
    int index, index_of_com, index_of_gen, ring_size;
    double linear_time_prove = 0;
    double log_time_prove = 0;
    double linear_time_verify = 0;
    double log_time_verify = 0;
    time_t start;
    time_t end;
    int m = 5;
    secp256k1_generator generators[m];
    unsigned char digests[m * 32];

    int len;

    /* Identity creation */
    secp256k1_rand256(blind);
    secp256k1_rand256(nonce);
    secp256k1_rand256(digest.data);
    CHECK(secp256k1_identity_create(ctx, &id, blind, digest, &secp256k1_generator_const_h, &secp256k1_generator_const_g));

    /* Direct Proving */
    for (i = 0; i < 10; i++) {
        CHECK(secp256k1_identity_prove(ctx, &proof, &id, blind, nonce, digest.data,
                                       &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 1);
        CHECK(secp256k1_identity_verify(ctx, &proof, &id, digest.data,
                                        &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 1);
    }

    for (i = 0; i < 32; i++) {
        CHECK(secp256k1_identity_prove(ctx, &proof, &id, blind, nonce, digest.data,
                                       &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 1);
        digest.data[i] = ~digest.data[i];
        CHECK(secp256k1_identity_verify(ctx, &proof, &id, digest.data,
                                        &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 0);
        digest.data[i] = ~digest.data[i];
    }

    /* unlinked proving */
    ring_size = 10;

    ids = (secp256k1_identity *) malloc(ring_size * sizeof(secp256k1_identity));
    for (i = 0; i < ring_size; i++) {
        secp256k1_rand256(blinds[i]);
        digest.data[0] = i;
        CHECK(secp256k1_identity_create(ctx, &ids[i], blinds[i], digest, &secp256k1_generator_const_h,
                                        &secp256k1_generator_const_g));
        CHECK(secp256k1_identity_prove(ctx, &proof, &ids[i], blinds[i], nonce, digest.data,
                                       &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 1);
        CHECK(secp256k1_identity_verify(ctx, &proof, &ids[i], digest.data,
                                        &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 1);
    }
    for (index = 0; index < 10; index++) {
        digest.data[0] = index;
        start = clock();
        CHECK(secp256k1_unlinked_identity_prove(ctx, &proof1, index, blinds[index], nonce,
                                                digest.data, digest.data, ring_size, ids,
                                                &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 1);
        end = clock();
        linear_time_prove += ((double) (end - start)) / CLOCKS_PER_SEC;

        start = clock();
        CHECK(secp256k1_unlinked_identity_verify(ctx, &proof1, digest.data, digest.data, ids, ring_size,
                                                 &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 1);
        end = clock();
        linear_time_verify += ((double) (end - start)) / CLOCKS_PER_SEC;

        free(proof1.data);
    }

    for (index = 0; index < 10; index++) {
        digest.data[0] = index;
        start = clock();
        CHECK(secp256k1_unlinked_logarithmic_identity_prove(ctx, &proof1, index, blinds[index], nonce,
                                                            digest.data, digest.data, 10, 4, ids,
                                                            &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 1);
        end = clock();
        log_time_prove += ((double) (end - start)) / CLOCKS_PER_SEC;

        start = clock();
        CHECK(secp256k1_unlinked_logarithmic_identity_verify(ctx, &proof1, digest.data, digest.data, ids, 10, 4,
                                                             &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 1);
        end = clock();
        log_time_verify += ((double) (end - start)) / CLOCKS_PER_SEC;

        free(proof1.data);
    }
    printf("linear prove: %f\n", linear_time_prove);
    printf("linear verify: %f\n", linear_time_verify);
    printf("log prove: %f\n", log_time_prove);
    printf("log verify: %f\n", log_time_verify);

    index_of_com = 5;
    secp256k1_rand256(nonce);
    for (index_of_gen = 0; index_of_gen < m; index_of_gen++) {
        digest.data[0] = index_of_com;
        CHECK(secp256k1_unlinked_logarithmic_identity_prove(ctx, &proof1, index_of_com, blinds[index_of_com], nonce,
                                                            digest.data, digest.data, 10, 4, ids,
                                                            &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 1);

        CHECK(secp256k1_unlinked_logarithmic_identity_verify(ctx, &proof1, digest.data, digest.data, ids, 10, 4,
                                                             &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 1);

        free(proof1.data);
    }

    /* Multi Generator Proofs */
    m = 3;
    memset(digests, 0, m*32);
    for (t = 0; t < m; t++) {
        digests[t*32] = t + 1;
    }

    CHECK(secp256k1_get_multi_generators(ctx, generators, nonce, m));
    for (i = 0; i < ring_size; i++) {
        CHECK(secp256k1_get_multi_gen_commitment(ctx,
                                                 &ids[i].commit,
                                                 blinds[i],
                                                 digests,
                                                 &secp256k1_generator_const_g,
                                                 generators, m));
    }
    for (index_of_com = 0; index_of_com < ring_size; index_of_com++) {
        for (index_of_gen = 0; index_of_gen < m; index_of_gen++) {
            CHECK(secp256k1_logarithmic_multi_gen_poe_prove(ctx, &proof1, index_of_com, index_of_gen,
                                                            blinds[index_of_com], nonce,
                                                            digests, nonce, m, ring_size, 5, ids, generators,
                                                            &secp256k1_generator_const_h,
                                                            &secp256k1_generator_const_g) == 1);

            CHECK(secp256k1_logarithmic_multi_gen_poe_verify(ctx, &proof1,
                                                             digests + (index_of_gen * 32), nonce, ids, m, ring_size, 5,
                                                             generators, &secp256k1_generator_const_h,
                                                             &secp256k1_generator_const_g) == 1);

            free(proof1.data);
        }
    }

    free(ids);
}



#endif /* RAHAS_SECP256K1_TESTS_IMPL_H */
