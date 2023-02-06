

#ifndef RAHAS_SECP256K1_TESTS_IMPL_H
#define RAHAS_SECP256K1_TESTS_IMPL_H

#include "secp256k1_identity.h"
#include "openssl/rand.h"
#include "math.h"

void run_identity_tests(void) {
    secp256k1_identity id;
    secp256k1_identity *ids;
    secp256k1_identity_pf proof;
    secp256k1_unlinked_identity_pf proof1;
    unsigned char blind[32];
    unsigned char nonce[32];
    secp256k1_hash digest;
    int i, t;
    int index, index_of_com, index_of_gen, ring_size;
    double linear_time_prove = 0;
    double log_time_prove = 0;
    double linear_time_verify = 0;
    double log_time_verify = 0;
    time_t start;
    time_t end;
    int m = 5;

    secp256k1_generator *generators = malloc(m * sizeof(secp256k1_generator));
    unsigned char *digests = (unsigned char*) malloc(m * 32);
    unsigned char **blinds = (unsigned char**) malloc(10 * sizeof(unsigned char*));
    for (i = 0; i < 10; i++)
        blinds[i] = (unsigned char*) malloc(32);

    /* Identity creation */
    secp256k1_rand256(blind);
    secp256k1_rand256(nonce);
    secp256k1_rand256(digest.data);
    CHECK(secp256k1_identity_create(ctx, &id, blind, digest, &secp256k1_generator_const_h, &secp256k1_generator_const_g));

    /* Direct Proving */
    for (i = 0; i < 10; i++) {
        CHECK(secp256k1_identity_prove(ctx, &proof, &id, blind, nonce, digest.data,
                                       &secp256k1_generator_const_g) == 1);
        CHECK(secp256k1_identity_verify(ctx, &proof, &id, digest.data,
                                        &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 1);
    }

    for (i = 0; i < 32; i++) {
        CHECK(secp256k1_identity_prove(ctx, &proof, &id, blind, nonce, digest.data,
                                        &secp256k1_generator_const_g) == 1);
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
                                        &secp256k1_generator_const_g) == 1);
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
        CHECK(secp256k1_unlinked_logarithmic_identity_prove(ctx, &proof1, index, blinds[index],
                                                            digest.data, nonce, 10, 4, ids,
                                                            &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 1);
        end = clock();
        log_time_prove += ((double) (end - start)) / CLOCKS_PER_SEC;

        start = clock();
        CHECK(secp256k1_unlinked_logarithmic_identity_verify(ctx, &proof1, digest.data, nonce, ids, 10, 4,
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
        CHECK(secp256k1_unlinked_logarithmic_identity_prove(ctx, &proof1, index_of_com, blinds[index_of_com],
                                                            digest.data, nonce, 10, 4, ids,
                                                            &secp256k1_generator_const_h, &secp256k1_generator_const_g) == 1);

        CHECK(secp256k1_unlinked_logarithmic_identity_verify(ctx, &proof1, digest.data, nonce, ids, 10, 4,
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
        CHECK(secp256k1_get_multi_gen_commitment(&ids[i].commit,
                                                 blinds[i],
                                                 digests,
                                                 &secp256k1_generator_const_g,
                                                 generators, m));
    }
    for (index_of_com = 0; index_of_com < ring_size; index_of_com++) {
        for (index_of_gen = 0; index_of_gen < m; index_of_gen++) {
            CHECK(secp256k1_logarithmic_multi_gen_poe_prove(ctx, &proof1, index_of_com, index_of_gen,
                                                            blinds[index_of_com],
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
    free(generators);
    free(digests);
    for (i = 0; i < 10; i++)
        free(blinds[i]);
    free(blinds);

    double commit_time;
    double prove_time;
    double verify_time;

    int m_list[] = {2, 4, 8, 16, 32};
    int ring_list[] = {10, 20, 30, 40, 50};


    for (int l = 0; l < 5; l++) {
        m = m_list[l];
        ring_size = ring_list[l];
        ids = (secp256k1_identity *) malloc(ring_size * sizeof(secp256k1_identity));
        generators = (secp256k1_generator*) malloc(m * sizeof(secp256k1_generator));
        digests = (unsigned char*) malloc(m * 32);
        memset(digests, 0, m * 32);
        for (t = 0; t < m; t++) {
            digests[t * 32] = t + 1;
        }
        blinds = (unsigned char**) malloc(ring_size * sizeof(unsigned char*));
        for (i = 0; i < ring_size; i++) {
            blinds[i] = (unsigned char *) malloc(32);
            secp256k1_rand256(blinds[i]);
        }

        int n = 1;
        while ((1 << n) < m * ring_size)
            n++;

        index_of_com = ring_size/2;
        index_of_gen = m/2;

        printf("%d, %d, %d ", m, ring_size, n);
        CHECK(secp256k1_get_multi_generators(ctx, generators, nonce, m));

        commit_time = 0;
        for (i = 0; i < ring_size; i++) {
            start = clock();
            CHECK(secp256k1_get_multi_gen_commitment(&ids[i].commit,
                                                     blinds[i],
                                                     digests,
                                                     &secp256k1_generator_const_g,
                                                     generators, m));
            end = clock();
            commit_time += ((double) (end - start)) / CLOCKS_PER_SEC;
        }

        prove_time = 0;
        verify_time = 0;
        for (i = 0; i < 3; i++) {
            start = clock();
            CHECK(secp256k1_logarithmic_multi_gen_poe_prove(ctx, &proof1, index_of_com, index_of_gen,
                                                            blinds[index_of_com],
                                                            digests, nonce, m, ring_size, n, ids, generators,
                                                            &secp256k1_generator_const_h,
                                                            &secp256k1_generator_const_g) == 1);
            end = clock();
            prove_time += ((double) (end - start)) / CLOCKS_PER_SEC;

            start = clock();
            CHECK(secp256k1_logarithmic_multi_gen_poe_verify(ctx, &proof1,
                                                             digests + (index_of_gen * 32), nonce, ids, m, ring_size, n,
                                                             generators, &secp256k1_generator_const_h,
                                                             &secp256k1_generator_const_g) == 1);

            end = clock();
            verify_time += ((double) (end - start)) / CLOCKS_PER_SEC;
            free(proof1.data);
        }
        printf("%.2f, %.2f, %.2f\n", commit_time/ring_size, prove_time/3, verify_time/3);

        free(ids);
        free(generators);
        free(digests);
        for (i = 0; i < ring_size; i++)
            free(blinds[i]);
        free(blinds);
    }

}



#endif /* RAHAS_SECP256K1_TESTS_IMPL_H */
