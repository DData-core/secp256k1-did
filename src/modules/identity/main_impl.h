/***********************************************************************
 * Copyright (c) 2022 Jayamine Alupotha                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

#ifndef RAHAS_SECP256K1_MAIN_IMPL_H
#define RAHAS_SECP256K1_MAIN_IMPL_H

#include <openssl/rand.h>
#include "group.h"
#include "modules/commitment/main_impl.h"
#include "math.h"
#include "testrand_impl.h"


int secp256k1_identity_create(
        const secp256k1_context* ctx,
        secp256k1_identity *id,
        const unsigned char *blind,
        secp256k1_hash digest,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) {
    return secp256k1_pedersen_blind_commit(ctx, &id->commit, blind, digest.data, value_gen, blind_gen);
}

int secp256k1_identity_prove(
        const secp256k1_context* ctx,
        secp256k1_identity_pf *proof,
        secp256k1_identity *id,
        const unsigned char *blind,
        const unsigned char *nonce,
        const unsigned char *digest,
        const secp256k1_generator *blind_gen
) {
    secp256k1_scalar blind32;
    secp256k1_scalar nonce32;
    secp256k1_scalar digest32;
    secp256k1_scalar s;
    secp256k1_gej rj;
    secp256k1_ge geng;
    secp256k1_ge r;
    secp256k1_sha256 sha;
    int overflow;
    unsigned char buf[33];
    size_t buflen = sizeof(buf);

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(proof != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(digest != NULL);

    secp256k1_scalar_set_b32(&digest32, digest, NULL);
    secp256k1_scalar_set_b32(&nonce32, nonce, NULL);
    secp256k1_scalar_set_b32(&blind32, blind, NULL);

    secp256k1_scalar_set_b32(&blind32, blind, &overflow);
    /* Fail if the secret key is invalid. */
    if (overflow || secp256k1_scalar_is_zero(&blind32)) {
        memset(proof, 0, 3);
        return 0;
    }

    /* Nonce */
    if (!secp256k1_nonce_function_bipschnorr(buf, digest, blind, NULL, (void*)nonce, 0)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&nonce32, buf, NULL);
    if (secp256k1_scalar_is_zero(&nonce32)) {
        return 0;
    }

    /* r = nonce * g*/
    secp256k1_generator_load(&geng, blind_gen);
    secp256k1_ecmult_const(&rj, &geng, &nonce32, 256);
    secp256k1_ge_set_gej(&r, &rj);
    if (!secp256k1_fe_is_quad_var(&r.y)) {
        secp256k1_scalar_negate(&nonce32, &nonce32);
    }
    secp256k1_fe_normalize(&r.x);
    secp256k1_fe_get_b32(proof->data, &r.x);

    /* s = nonce - hash(r | digest | id) * blind */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, &proof->data[0], 32);
    secp256k1_pedersen_commitment_serialize(ctx, buf, &id->commit);
    secp256k1_sha256_write(&sha, buf, buflen);
    secp256k1_sha256_write(&sha, digest, 32);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(&s, buf, NULL);

    secp256k1_scalar_mul(&s, &s, &blind32);
    secp256k1_scalar_add(&s, &s, &nonce32);

    secp256k1_scalar_get_b32(&proof->data[32], &s);
    secp256k1_scalar_clear(&s);
    secp256k1_scalar_clear(&blind32);
    secp256k1_scalar_clear(&nonce32);
    secp256k1_scalar_clear(&digest32);

    return 1;
}

int secp256k1_identity_verify(
        const secp256k1_context* ctx,
        secp256k1_identity_pf *proof,
        secp256k1_identity *id,
        const unsigned char *digest,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) {
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_scalar nege;
    secp256k1_scalar digest32;
    secp256k1_ge geng;
    secp256k1_ge genh;
    secp256k1_gej lhsj;
    secp256k1_gej tmpj;
    secp256k1_ge lhs;
    secp256k1_fe rx;
    secp256k1_sha256 sha;
    unsigned char buf[33];
    size_t buflen = sizeof(buf);
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(proof != NULL);
    ARG_CHECK(digest != NULL);
    ARG_CHECK(id != NULL);

    secp256k1_scalar_set_b32(&digest32, digest, NULL);

    /* r = nonce * g*/
    if (!secp256k1_fe_set_b32(&rx, &proof->data[0])) {
        return 0;
    }

    /* s = nonce - hash(r | digest | id) * blind */
    secp256k1_scalar_set_b32(&s, &proof->data[32], &overflow);
    if (overflow) {
        return 0;
    }

    /* e = hash(r | digest | id) */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, &proof->data[0], 32);
    secp256k1_pedersen_commitment_serialize(ctx, buf, &id->commit);
    secp256k1_sha256_write(&sha, buf, buflen);
    secp256k1_sha256_write(&sha, digest, 32);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(&e, buf, NULL);

    /* rj = s*G + (digest*e)*H - e*id */
    secp256k1_generator_load(&geng, blind_gen);
    secp256k1_generator_load(&genh, value_gen);
    secp256k1_ecmult_const(&lhsj, &geng, &s, 256); /* s*G */

    secp256k1_pedersen_commitment_load(&lhs, &id->commit);
    secp256k1_scalar_negate(&nege, &e);
    secp256k1_ecmult_const(&tmpj, &lhs, &nege, 256); /* e*id */
    secp256k1_ge_set_gej(&lhs, &tmpj);
    secp256k1_gej_add_ge(&lhsj, &lhsj, &lhs);

    secp256k1_scalar_mul(&e, &e, &digest32);
    secp256k1_ecmult_const(&tmpj, &genh, &e, 256); /* (digest*e)*H */
    secp256k1_ge_set_gej(&lhs, &tmpj);
    secp256k1_gej_add_ge(&lhsj, &lhsj, &lhs);

    if (!secp256k1_gej_has_quad_y_var(&lhsj) /* fails if rj is infinity */
        || !secp256k1_gej_eq_x_var(&rx, &lhsj)) {
        return 0;
    }

    return 1;
}


int secp256k1_unlinked_identity_prove(
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
) {
    secp256k1_scalar blind32;
    secp256k1_scalar alpha;
    secp256k1_scalar digest32;
    secp256k1_scalar negdigest32;
    secp256k1_scalar s;
    secp256k1_scalar bj;
    secp256k1_gej rj;
    secp256k1_gej tmpj;
    secp256k1_ge geng;
    secp256k1_ge genh;
    secp256k1_ge r;
    secp256k1_sha256 sha;
    int overflow;
    unsigned char buf[32];
    int i, j;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(proof != NULL);
    ARG_CHECK(blind != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(digest != NULL);
    ARG_CHECK(challenge != NULL);

    secp256k1_scalar_set_b32(&digest32, digest, NULL);
    secp256k1_scalar_set_b32(&blind32, blind, NULL);

    secp256k1_scalar_set_b32(&blind32, blind, &overflow);
    /* Fail if the secret key is invalid. */
    if (overflow || secp256k1_scalar_is_zero(&blind32)) {
        memset(proof, 0, 3);
        return 0;
    }

    /* alpha */
    if (!secp256k1_nonce_function_bipschnorr(buf, digest, blind, NULL, (void*)nonce, 0)) {
        secp256k1_scalar_clear(&blind32);
        return 0;
    }
    secp256k1_scalar_set_b32(&alpha, buf, NULL);
    if (secp256k1_scalar_is_zero(&alpha)) {
        secp256k1_scalar_clear(&blind32);
        return 0;
    }

    secp256k1_generator_load(&geng, blind_gen);
    secp256k1_generator_load(&genh, value_gen);

    /* b[i] = Hash(alpha*G | challenge | digest) */
    secp256k1_ecmult_const(&rj, &geng, &alpha, 256);
    secp256k1_ge_set_gej(&r, &rj);
    if (!secp256k1_fe_is_quad_var(&r.y)) {
        secp256k1_scalar_negate(&alpha, &alpha);
    }
    secp256k1_fe_normalize(&r.x);
    secp256k1_fe_get_b32(buf, &r.x);

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, buf, 32);
    secp256k1_sha256_write(&sha, challenge, 32);
    secp256k1_sha256_write(&sha, digest, 32);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(&bj, buf, NULL);

    proof->data = (unsigned char*) malloc((32 + ring_size * 32) * sizeof(unsigned char));

    if (index == ring_size - 1) {
        secp256k1_scalar_get_b32(&proof->data[0], &bj);
    }

    for (i = 1; i < ring_size; i++) {
        j = (index + i) % ring_size;

        if (!secp256k1_nonce_function_bipschnorr(&proof->data[(j + 1) * 32], digest, blind, NULL, (void*)nonce, 0)) {
            free(proof->data);
            secp256k1_scalar_clear(&blind32);
            return 0;
        }
        secp256k1_scalar_set_b32(&s, &proof->data[(j + 1) * 32], NULL);
        if (secp256k1_scalar_is_zero(&s)) {
            free(proof->data);
            secp256k1_scalar_clear(&blind32);
            return 0;
        }

        /* b[i+1] = hash(sG + b[i](id[i] + -digest*H) | challenge | digest) */
        secp256k1_scalar_negate(&negdigest32, &digest32);
        secp256k1_ecmult_const(&rj, &genh, &negdigest32, 256);
        secp256k1_pedersen_commitment_load(&r, &ids[j].commit);
        secp256k1_gej_add_ge(&rj, &rj, &r);
        secp256k1_ge_set_gej(&r, &rj);
        secp256k1_ecmult_const(&rj, &r, &bj, 256);
        secp256k1_ecmult_const(&tmpj, &geng, &s, 256);
        secp256k1_ge_set_gej(&r, &tmpj);
        secp256k1_gej_add_ge(&rj, &rj, &r);

        secp256k1_ge_set_gej(&r, &rj);
        secp256k1_fe_normalize(&r.x);
        secp256k1_fe_get_b32(buf, &r.x);

        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, buf, 32);
        secp256k1_sha256_write(&sha, challenge, 32);
        secp256k1_sha256_write(&sha, digest, 32);
        secp256k1_sha256_finalize(&sha, buf);
        secp256k1_scalar_set_b32(&bj, buf, NULL);

        if (j == ring_size - 1) {
            secp256k1_scalar_get_b32(&proof->data[0], &bj);
        }
    }

    /* s[j] = alpha = b[j]*blind */
    secp256k1_scalar_mul(&s, &bj, &blind32);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_scalar_add(&s, &alpha, &s);
    secp256k1_scalar_get_b32(&proof->data[(index + 1)* 32], &s);
    secp256k1_scalar_clear(&s);
    secp256k1_scalar_clear(&blind32);
    secp256k1_scalar_clear(&alpha);

    return 1;
}


int secp256k1_unlinked_identity_verify(
        const secp256k1_context* ctx,
        secp256k1_unlinked_identity_pf *proof,
        const unsigned char *digest,
        const unsigned char *challenge,
        secp256k1_identity *ids,
        int ring_size,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) {
    secp256k1_scalar bj;
    secp256k1_scalar s;
    secp256k1_scalar digest32;
    secp256k1_scalar negdigest32;
    secp256k1_ge geng;
    secp256k1_ge genh;
    secp256k1_gej rj;
    secp256k1_gej tmpj;
    secp256k1_ge r;
    secp256k1_sha256 sha;
    unsigned char buf[33];
    int overflow;
    int j;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(proof != NULL);
    ARG_CHECK(digest != NULL);
    ARG_CHECK(challenge != NULL);
    ARG_CHECK(ring_size != 0);


    secp256k1_scalar_set_b32(&digest32, digest, NULL);

    secp256k1_generator_load(&geng, blind_gen);
    secp256k1_generator_load(&genh, value_gen);


    /* b[0] */
    secp256k1_scalar_set_b32(&bj, &proof->data[0], &overflow);
    if (overflow) {
        return 0;
    }

    for (j = 0; j < ring_size; j++) {
        secp256k1_scalar_set_b32(&s, &proof->data[(j + 1) * 32], NULL);

        /* b[i+1] = hash(sG + b[i](id[i] + -digest*H) | challenge | digest) */
        secp256k1_scalar_negate(&negdigest32, &digest32);
        secp256k1_ecmult_const(&rj, &genh, &negdigest32, 256);
        secp256k1_pedersen_commitment_load(&r, &ids[j].commit);
        secp256k1_gej_add_ge(&rj, &rj, &r);
        secp256k1_ge_set_gej(&r, &rj);
        secp256k1_ecmult_const(&rj, &r, &bj, 256);
        secp256k1_ecmult_const(&tmpj, &geng, &s, 256);
        secp256k1_ge_set_gej(&r, &tmpj);
        secp256k1_gej_add_ge(&rj, &rj, &r);

        secp256k1_ge_set_gej(&r, &rj);
        secp256k1_fe_normalize(&r.x);
        secp256k1_fe_get_b32(buf, &r.x);

        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, buf, 32);
        secp256k1_sha256_write(&sha, challenge, 32);
        secp256k1_sha256_write(&sha, digest, 32);
        secp256k1_sha256_finalize(&sha, buf);
        secp256k1_scalar_set_b32(&bj, buf, NULL);
    }

    secp256k1_scalar_set_b32(&s, &proof->data[0], NULL);
    return secp256k1_scalar_eq(&bj, &s);
}

int secp256k1_unlinked_logarithmic_zero_com_prove(
        const secp256k1_context* ctx,
        unsigned char *proof,
        int index,
        const unsigned char *blind,
        int ring_size,
        int n,
        const unsigned char *challenge,
        const secp256k1_pedersen_commitment *ids,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) {
    secp256k1_pedersen_commitment J[n] ;
    secp256k1_pedersen_commitment A[n];
    secp256k1_pedersen_commitment B[n];
    secp256k1_pedersen_commitment D[n];
    secp256k1_scalar f[n];
    secp256k1_scalar za[n];
    secp256k1_scalar zb[n];
    secp256k1_scalar zd;

    int N = (1 << n);

    secp256k1_scalar r[n];
    secp256k1_scalar a[n];
    secp256k1_scalar s[n];
    secp256k1_scalar v[n];
    secp256k1_scalar rho[n];
    uint8_t r32[n][32];
    uint8_t a32[n][32];
    uint8_t s32[n][32];
    uint8_t v32[n][32];
    uint8_t rho32[n][32];
    secp256k1_scalar d[n][2];
    secp256k1_scalar p[N][n + 1];
    secp256k1_scalar tmp1;
    secp256k1_scalar tmp2;
    secp256k1_scalar tmp3;
    secp256k1_ge geng;
    secp256k1_ge genh;
    secp256k1_gej Cj;
    secp256k1_gej Dj;
    secp256k1_ge tmpG;
    secp256k1_scalar x32;
    secp256k1_sha256 sha;
    unsigned char buf[32];
    int i, l, l1, overflow, i_l, j_l;
    int pointer = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(proof != NULL);
    ARG_CHECK(challenge != NULL);
    ARG_CHECK(ring_size != 0);
    ARG_CHECK(n != 0);
    ARG_CHECK(!(index > N || index < 0));

    secp256k1_generator_load(&geng, blind_gen);
    secp256k1_generator_load(&genh, value_gen);

    /* Set random challenges */
    for (l = 0; l < n; l++) {
        secp256k1_rand256(r32[l]);
        secp256k1_scalar_set_b32(&r[l], r32[l], &overflow);
        secp256k1_rand256(a32[l]);
        secp256k1_scalar_set_b32(&a[l], a32[l], &overflow);
        secp256k1_rand256(s32[l]);
        secp256k1_scalar_set_b32(&s[l], s32[l], &overflow);
        secp256k1_rand256(v32[l]);
        secp256k1_scalar_set_b32(&v[l], v32[l], &overflow);
        secp256k1_rand256(rho32[l]);
        secp256k1_scalar_set_b32(&rho[l], rho32[l], &overflow);
    }

    /* Find polynomial coefficients */
    /*
     * P(i) = prod F(index, i_j) = prod d(i_j, l_j)Z + (-1)^{d_{0, i_j}}a(index)
     */
    for (i = 0; i < N; i++) {
        /* Set p[i][l] = 0 */
        for (l = 0; l < n + 1; l++) {
            secp256k1_scalar_set_int(&p[i][l], 0);
        }
        for (l = 0; l < n; l++) {
            secp256k1_scalar_set_int(&d[l][0], 0);
            secp256k1_scalar_set_int(&d[l][1], 0);
        }

        /* Multiply by d(i_j, l_j)Z + (-1)^{d_{0, i_j}}a(index) */
        for (l = 0; l < n; l++) {
            i_l = (i & (1 << l)) >> l;
            j_l = (index & (1 << l)) >> l;

            secp256k1_scalar_set_b32(&d[l][0], a32[l], &overflow);
            if (i_l == 0) {
                secp256k1_scalar_negate(&d[l][0], &d[l][0]);
                secp256k1_scalar_set_int(&d[l][1], 1 - j_l);
            } else {
                secp256k1_scalar_set_int(&d[l][1], j_l);
            }
        }

        secp256k1_scalar_add(&p[i][0], &p[i][0], &d[0][0]);
        secp256k1_scalar_add(&p[i][1], &p[i][1], &d[0][1]);
        for (l = 1; l < n; l++) {
            secp256k1_scalar_set_int(&tmp1, 0);
            secp256k1_scalar_add(&tmp1, &tmp1, &p[i][0]);
            secp256k1_scalar_mul(&p[i][0], &p[i][0], &d[l][0]);
            for (l1 = 0; l1 < l; l1++) {
                /* tmp3 = d[l][1] * p[i][l] (X^(l + 1)) */
                secp256k1_scalar_mul(&tmp1, &tmp1, &d[l][1]);
                /* tmp4 = d[l][0] * p[i][l + 1] (X^(l + 1)) */
                secp256k1_scalar_mul(&tmp2, &p[i][l1 + 1], &d[l][0]);
                secp256k1_scalar_add(&tmp2, &tmp1, &tmp2);
                /* Copy &p[i][l1 + 1] */
                secp256k1_scalar_set_int(&tmp1, 0);
                secp256k1_scalar_add(&tmp1, &tmp1, &p[i][l1 + 1]);
                /* Update &p[i][l + 1]*/
                secp256k1_scalar_set_int(&p[i][l1 + 1], 0);
                secp256k1_scalar_add(&p[i][l1 + 1], &p[i][l1 + 1], &tmp2);
            }
            secp256k1_scalar_mul(&p[i][l + 1], &tmp1, &d[l][1]);
        }
    }

    /*
     * J_l  = com(j_l, r_l)
     * A_l  = com(a_l, s_l)
     * B_l  = com(a_l * j_l, t_l)
     * D_l = prod_{i=1}^{N} (𝐶𝑖ℎ−𝑑 )𝑝𝑖−1,𝑙 −1)× COM.cmt(0, 𝜌𝑙−1)
     */
    for (l = 0; l < n; l++) {
        j_l = (index & (1 << l)) >> l;
        if (!secp256k1_pedersen_commit(ctx, &J[l], r32[l], j_l,
                                       value_gen,
                                       blind_gen)
            || !secp256k1_pedersen_blind_commit(ctx, &A[l], s32[l], a32[l],
                                                value_gen,
                                                blind_gen)) {
            return 0;
        }

        if (j_l == 1) {
            if (!secp256k1_pedersen_blind_commit(ctx, &B[l], v32[l], a32[l],
                                                 value_gen,
                                                 blind_gen)) {
                return 0;
            }
        } else {
            if (!secp256k1_pedersen_commit(ctx, &B[l], v32[l], 0,
                                           value_gen,
                                           blind_gen)) {
                return 0;
            }
        }

        if (!secp256k1_pedersen_commit(ctx, &D[l], rho32[l], 0,
                                       value_gen,
                                       blind_gen)) {
            return 0;
        }

        secp256k1_pedersen_commitment_load(&tmpG, &D[l]);
        secp256k1_gej_set_ge(&Dj, &tmpG);
        for (i = 0; i < ring_size; i++) {
            if (secp256k1_scalar_is_zero(&p[i][l]) == 1) {
                continue;
            }
            secp256k1_pedersen_commitment_load(&tmpG, &ids[i]);
            secp256k1_ecmult_const(&Cj, &tmpG, &p[i][l], 256);
            secp256k1_ge_set_gej(&tmpG, &Cj);
            secp256k1_gej_add_ge(&Dj, &Dj, &tmpG);
        }
        secp256k1_ge_set_gej(&tmpG, &Dj);
        secp256k1_fe_normalize(&tmpG.x);
        secp256k1_pedersen_commitment_save(&D[l], &tmpG);

        secp256k1_pedersen_commitment_serialize(ctx, proof + pointer, &J[l]);
        pointer += 33;
        secp256k1_pedersen_commitment_serialize(ctx, proof + pointer, &A[l]);
        pointer += 33;
        secp256k1_pedersen_commitment_serialize(ctx, proof + pointer, &B[l]);
        pointer += 33;
        secp256k1_pedersen_commitment_serialize(ctx, proof + pointer, &D[l]);
        pointer += 33;

    }

    /* x */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, challenge, 32);
    secp256k1_sha256_write(&sha, proof, 33 * n * 4);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(&x32, buf, NULL);


    secp256k1_scalar_set_int(&tmp1, 1);
    secp256k1_scalar_set_int(&tmp2, 0);
    for (l = 0; l < n; l++) {
        j_l = (index & (1 << l)) >> l;
        secp256k1_scalar_set_b32(&f[l], a32[l], &overflow);
        if (j_l == 1) {
            secp256k1_scalar_add(&f[l], &f[l], &x32);
        }

        secp256k1_scalar_set_b32(&za[l], buf, &overflow);
        secp256k1_scalar_negate(&zb[l], &f[l]);
        secp256k1_scalar_add(&zb[l], &zb[l], &x32);

        secp256k1_scalar_mul(&za[l], &za[l], &r[l]);
        secp256k1_scalar_mul(&zb[l], &zb[l], &r[l]);

        secp256k1_scalar_add(&za[l], &za[l], &s[l]);
        secp256k1_scalar_add(&zb[l], &zb[l], &v[l]);

        secp256k1_scalar_mul(&tmp3, &rho[l], &tmp1);
        secp256k1_scalar_add(&tmp2, &tmp2, &tmp3);

        secp256k1_scalar_mul(&tmp1, &tmp1, &x32); /* should be after tmp2 */

        secp256k1_scalar_get_b32(proof + pointer, &f[l]);
        pointer += 32;
        secp256k1_scalar_get_b32(proof + pointer, &za[l]);
        pointer += 32;
        secp256k1_scalar_get_b32(proof + pointer, &zb[l]);
        pointer += 32;
    }
    secp256k1_scalar_set_b32(&zd, blind, &overflow); /* the known secret key */
    secp256k1_scalar_mul(&zd, &zd, &tmp1);
    secp256k1_scalar_negate(&tmp2, &tmp2);
    secp256k1_scalar_add(&zd, &zd, &tmp2);
    secp256k1_scalar_get_b32(proof + pointer, &zd);


    for (l = 0; l < n; l++) {
        secp256k1_rand256(a32[l]);
        memset(r32[l], 0, 32);
        memset(r32[l], 0, 32);
        memset(s32[l], 0, 32);
        memset(v32[l], 0, 32);
        memset(rho32[l], 0, 32);
        secp256k1_scalar_set_int(&a[l], 0);
        secp256k1_scalar_set_int(&r[l], 0);
        secp256k1_scalar_set_int(&s[l], 0);
        secp256k1_scalar_set_int(&v[l], 0);
        secp256k1_scalar_set_int(&rho[l], 0);
    }

    return 1;
}

int secp256k1_unlinked_logarithmic_zero_com_verify(
        const secp256k1_context* ctx,
        unsigned char *proof,
        int ring_size,
        int n,
        const unsigned char *challenge,
        const secp256k1_pedersen_commitment *ids,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) {
    secp256k1_pedersen_commitment J[n];
    secp256k1_pedersen_commitment A[n];
    secp256k1_pedersen_commitment B[n];
    secp256k1_pedersen_commitment D[n];
    secp256k1_scalar f[n];
    secp256k1_scalar za[n];
    secp256k1_scalar zb[n];
    secp256k1_scalar zd;

    int N = (1 << n);

    secp256k1_scalar tmpf[N];
    secp256k1_scalar tmp2;
    secp256k1_scalar tmp3;
    secp256k1_scalar tmp4;
    secp256k1_ge geng;
    secp256k1_ge genh;
    secp256k1_gej tmpj1;
    secp256k1_gej tmpj2;
    secp256k1_gej tmpj3;
    secp256k1_ge tmpG1;
    secp256k1_ge tmpG2;
    secp256k1_pedersen_commitment com;
    secp256k1_scalar x32;
    secp256k1_sha256 sha;
    unsigned char buf[32];
    unsigned char buf_blind[32];
    unsigned char RHS[32];
    unsigned char LHS[32];
    int i, l, overflow, i_l;
    int pointer = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(proof != NULL);
    ARG_CHECK(challenge != NULL);
    ARG_CHECK(N != 0);
    ARG_CHECK(n != 0);

    secp256k1_generator_load(&geng, blind_gen);
    secp256k1_generator_load(&genh, value_gen);

    /* x */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, challenge, 32);
    secp256k1_sha256_write(&sha, proof, 33 * n * 4);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(&x32, buf, NULL);

    for (l = 0; l < n; l++) {
        if (secp256k1_pedersen_commitment_parse(ctx, &J[l], proof + pointer) == 0)
            return 0;
        pointer += 33;
        if (secp256k1_pedersen_commitment_parse(ctx, &A[l], proof + pointer) == 0)
            return 0;
        pointer += 33;
        if (secp256k1_pedersen_commitment_parse(ctx, &B[l], proof + pointer) == 0)
            return 0;
        pointer += 33;
        if (secp256k1_pedersen_commitment_parse(ctx, &D[l], proof + pointer) == 0)
            return 0;
        pointer += 33;
    }

    for (l = 0; l < n; l++) {
        secp256k1_scalar_set_b32(&f[l], proof + pointer, &overflow);
        pointer += 32;
        secp256k1_scalar_set_b32(&za[l], proof + pointer, &overflow);
        pointer += 32;
        secp256k1_scalar_set_b32(&zb[l], proof + pointer, &overflow);
        pointer += 32;
    }
    secp256k1_scalar_set_b32(&zd, proof + pointer, &overflow);

    /* Verification */
    for (l = 0; l < n; l++) {
        secp256k1_pedersen_commitment_load(&tmpG1, &J[l]);
        secp256k1_ecmult_const(&tmpj1, &tmpG1, &x32, 256);
        secp256k1_pedersen_commitment_load(&tmpG2, &A[l]);
        secp256k1_gej_add_ge(&tmpj1, &tmpj1, &tmpG2);

        secp256k1_scalar_get_b32(buf, &f[l]);
        secp256k1_scalar_get_b32(buf_blind, &za[l]);
        if (!secp256k1_pedersen_blind_commit(ctx, &com, buf_blind, buf,
                                             value_gen,
                                             blind_gen)) {
            return 0;
        }
        secp256k1_ge_set_gej(&tmpG1, &tmpj1);
        secp256k1_fe_normalize(&tmpG1.x);
        secp256k1_fe_get_b32(LHS, &tmpG1.x);

        secp256k1_pedersen_commitment_load(&tmpG2, &com);
        secp256k1_fe_normalize(&tmpG2.x);
        secp256k1_fe_get_b32(RHS, &tmpG2.x);

        if (memcmp(LHS, RHS, 32) != 0)
            return 0;

        secp256k1_pedersen_commitment_load(&tmpG1, &J[l]);
        secp256k1_scalar_negate(&tmp3, &f[l]);
        secp256k1_scalar_add(&tmp3, &tmp3, &x32);
        secp256k1_ecmult_const(&tmpj1, &tmpG1, &tmp3, 256);
        secp256k1_pedersen_commitment_load(&tmpG2, &B[l]);
        secp256k1_gej_add_ge(&tmpj1, &tmpj1, &tmpG2);

        secp256k1_scalar_get_b32(buf_blind, &zb[l]);
        if (!secp256k1_pedersen_commit(ctx, &com, buf_blind, 0,
                                       value_gen,
                                       blind_gen)) {
            return 0;
        }
        secp256k1_ge_set_gej(&tmpG1, &tmpj1);
        secp256k1_fe_normalize(&tmpG1.x);
        secp256k1_fe_get_b32(LHS, &tmpG1.x);

        secp256k1_pedersen_commitment_load(&tmpG2, &com);
        secp256k1_fe_normalize(&tmpG2.x);
        secp256k1_fe_get_b32(RHS, &tmpG2.x);

        if (memcmp(LHS, RHS, 32) != 0)
            return 0;

    }


    /*
     * Correctness of the polynomial coefficients
     */
    for (i = 0; i < N; i++) {
        secp256k1_scalar_set_int(&tmpf[i], 1);
        for (l = 0; l < n; l++) {
            i_l = (i & (1 << l)) >> l;

            if (i_l == 1) {
                secp256k1_scalar_mul(&tmpf[i], &tmpf[i], &f[l]);
            } else {
                secp256k1_scalar_negate(&tmp4, &f[l]);
                secp256k1_scalar_add(&tmp4, &tmp4, &x32);
                secp256k1_scalar_mul(&tmpf[i], &tmpf[i], &tmp4);
            }
        }
    }

    /* ----------------------------------------------------------------------- */

    secp256k1_gej_set_infinity(&tmpj3);
    for (i = 0; i < ring_size; i++) {

        secp256k1_pedersen_commitment_load(&tmpG1, &ids[i]);
        secp256k1_ecmult_const(&tmpj2, &tmpG1, &tmpf[i], 256);
        secp256k1_ge_set_gej(&tmpG1, &tmpj2);
        secp256k1_gej_add_ge(&tmpj3, &tmpj3, &tmpG1);
    }

    secp256k1_scalar_set_int(&tmp2, 1);
    for (l = 0; l < n; l++) {
        secp256k1_scalar_negate(&tmp3, &tmp2);
        secp256k1_pedersen_commitment_load(&tmpG2, &D[l]);
        secp256k1_ecmult_const(&tmpj2, &tmpG2, &tmp3, 256);
        secp256k1_ge_set_gej(&tmpG2, &tmpj2);
        secp256k1_gej_add_ge(&tmpj3, &tmpj3, &tmpG2);

        secp256k1_scalar_mul(&tmp2, &tmp2, &x32);
    }

    secp256k1_scalar_get_b32(buf_blind, &zd);
    if (!secp256k1_pedersen_commit(ctx, &com, buf_blind, 0,
                                   value_gen,
                                   blind_gen)) {
        return 0;
    }
    secp256k1_ge_set_gej(&tmpG1, &tmpj3);
    secp256k1_fe_normalize(&tmpG1.x);
    secp256k1_fe_get_b32(RHS, &tmpG1.x);

    secp256k1_pedersen_commitment_load(&tmpG2, &com);
    secp256k1_fe_normalize(&tmpG2.x);
    secp256k1_fe_get_b32(LHS, &tmpG2.x);

    if (memcmp(LHS, RHS, 32) != 0)
        return 0;

    return 1;
}

int secp256k1_unlinked_logarithmic_identity_prove(
        const secp256k1_context* ctx,
        secp256k1_unlinked_identity_pf *proof,
        int index,
        const unsigned char *blind,
        const unsigned char *digest,
        const unsigned char *challenge,
        int ring_size,
        int n,
        secp256k1_identity *ids,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) {
    secp256k1_pedersen_commitment C[ring_size];

    int N = (1 << n);

    secp256k1_ge geng;
    secp256k1_ge genh;
    secp256k1_gej hnegj;
    secp256k1_gej Cj;
    secp256k1_ge tmpG;
    secp256k1_scalar negdigest32;
    int i, overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(proof != NULL);
    ARG_CHECK(digest != NULL);
    ARG_CHECK(challenge != NULL);
    ARG_CHECK(ring_size != 0);
    ARG_CHECK(n != 0);
    ARG_CHECK(!(index > N || index < 0));

    secp256k1_generator_load(&geng, blind_gen);
    secp256k1_generator_load(&genh, value_gen);

    secp256k1_scalar_set_b32(&negdigest32, digest, &overflow);
    secp256k1_scalar_negate(&negdigest32, &negdigest32);
    secp256k1_ecmult_const(&hnegj, &genh, &negdigest32, 256);

    proof->data = (uint8_t *) malloc((32 * (n * 3 + 1) + 33 * n * 4) * sizeof(uint8_t));

    for (i = 0; i < ring_size; i++) {
        secp256k1_pedersen_commitment_load(&tmpG, &ids[i].commit);
        secp256k1_gej_add_ge(&Cj, &hnegj, &tmpG);
        secp256k1_ge_set_gej(&tmpG, &Cj);
        secp256k1_pedersen_commitment_save(&C[i], &tmpG);
    }

    return secp256k1_unlinked_logarithmic_zero_com_prove(ctx, proof->data, index, blind,
                                                         ring_size, n, challenge, C, value_gen, blind_gen);
}

int secp256k1_unlinked_logarithmic_identity_verify(
        const secp256k1_context* ctx,
        secp256k1_unlinked_identity_pf *proof,
        const unsigned char *digest,
        const unsigned char *challenge,
        secp256k1_identity *ids,
        int ring_size,
        int n,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) {
    secp256k1_pedersen_commitment C[ring_size];

    int N = (1 << n);

    secp256k1_ge geng;
    secp256k1_ge genh;
    secp256k1_gej hnegj;
    secp256k1_gej Cj;
    secp256k1_ge tmpG;
    secp256k1_scalar negdigest32;
    int i, overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(proof != NULL);
    ARG_CHECK(digest != NULL);
    ARG_CHECK(challenge != NULL);
    ARG_CHECK(N != 0);
    ARG_CHECK(n != 0);

    secp256k1_generator_load(&geng, blind_gen);
    secp256k1_generator_load(&genh, value_gen);

    secp256k1_scalar_set_b32(&negdigest32, digest, &overflow);
    secp256k1_scalar_negate(&negdigest32, &negdigest32);
    secp256k1_ecmult_const(&hnegj, &genh, &negdigest32, 256);

    for (i = 0; i < ring_size; i++) {
        secp256k1_pedersen_commitment_load(&tmpG, &ids[i].commit);
        secp256k1_gej_add_ge(&Cj, &hnegj, &tmpG);
        secp256k1_ge_set_gej(&tmpG, &Cj);
        secp256k1_pedersen_commitment_save(&C[i], &tmpG);
    }

    return secp256k1_unlinked_logarithmic_zero_com_verify(ctx, proof->data, ring_size, n, challenge, C, value_gen, blind_gen);
}



int secp256k1_get_multi_generators(
        const secp256k1_context* ctx,
        secp256k1_generator *gens,
        const unsigned char *gen_seed,
        int m
) {
    secp256k1_sha256 sha;
    unsigned char buf[32];
    int i;

    memset(buf, 0, 32);
    for (i = 0; i < m; i++) {
        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, gen_seed, 32);
        secp256k1_sha256_write(&sha, buf, 32);
        secp256k1_sha256_finalize(&sha, buf);

        if(secp256k1_generator_generate(ctx, &gens[i], buf) == 0)
            i--;
    }
    return 1;
}


int secp256k1_get_multi_gen_commitment(
        secp256k1_pedersen_commitment *com,
        const unsigned char *blind,
        const unsigned char *digests,
        const secp256k1_generator *blind_gen,
        const secp256k1_generator *gens,
        int m
) {
    secp256k1_scalar tmp;
    secp256k1_ge tmpG;
    secp256k1_gej tmpGj;
    secp256k1_gej tmpGj1;
    int i, overflow;

    secp256k1_generator_load(&tmpG, blind_gen);
    secp256k1_scalar_set_b32(&tmp, blind, &overflow);
    if (overflow != 0)
        return 0;
    secp256k1_ecmult_const(&tmpGj, &tmpG, &tmp, 256);
    for (i = 0; i < m; i++) {
        secp256k1_generator_load(&tmpG, &gens[i]);
        secp256k1_scalar_set_b32(&tmp, digests + i * 32, &overflow);
        if (secp256k1_scalar_is_zero(&tmp))
            continue;
        secp256k1_ecmult_const(&tmpGj1, &tmpG, &tmp, 256);
        secp256k1_ge_set_gej(&tmpG, &tmpGj1);
        secp256k1_gej_add_ge(&tmpGj, &tmpGj, &tmpG);
    }
    secp256k1_ge_set_gej(&tmpG, &tmpGj);
    secp256k1_fe_normalize(&tmpG.x);
    secp256k1_pedersen_commitment_save(com, &tmpG);

    return 1;
}


int secp256k1_logarithmic_multi_gen_poe_prove (
        const secp256k1_context* ctx,
        secp256k1_unlinked_identity_pf *proof,
        int index_of_com,
        int index_of_gen,
        const unsigned char *blind,
        const unsigned char *digests,
        const unsigned char *challenge,
        int m,
        int ring_size,
        int n,
        secp256k1_identity *ids,
        const secp256k1_generator *generators,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) {
    secp256k1_ge Y[m];
    secp256k1_ge E[m];
    secp256k1_pedersen_commitment C[m*ring_size];
    secp256k1_pedersen_commitment com;
    secp256k1_scalar y[m];
    secp256k1_scalar e[m];

    int N = (1 << n);

    uint8_t y32[m][32];
    secp256k1_scalar tmp1;
    secp256k1_ge geng;
    secp256k1_ge genh[m];
    secp256k1_gej Cj;
    secp256k1_gej Dj;
    secp256k1_ge tmpG;
    secp256k1_scalar x032;
    secp256k1_scalar digest32[m];
    secp256k1_scalar negdigest32;
    secp256k1_sha256 sha;
    unsigned char buf[32];
    unsigned char challenge_x[32];
    int i, t, t1, overflow;
    int pointer = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(proof != NULL);
    ARG_CHECK(digests != NULL);
    ARG_CHECK(challenge != NULL);
    ARG_CHECK(ring_size != 0);
    ARG_CHECK(n != 0);
    ARG_CHECK(m >= 1);
    ARG_CHECK(!(index_of_com > N || index_of_com < 0));
    ARG_CHECK(!(index_of_gen > m || index_of_gen < 0));

    secp256k1_generator_load(&geng, blind_gen);

    for (t = 0; t < m; t++) {
        secp256k1_generator_load(&genh[t], &generators[t]);
        secp256k1_rand256(y32[t]);
        secp256k1_scalar_set_b32(&y[t], y32[t], &overflow);
        if (overflow) {
            return 0;
        }
        secp256k1_scalar_set_b32(&digest32[t], digests + (t * 32), &overflow);
        if (overflow) {
            secp256k1_scalar_set_int(&digest32[t], 0);
        }
    }

    proof->data = (uint8_t*) malloc(32 * (n * 3 + 1) + (33 * n * 4) + (m * (33 + 32)) * sizeof(uint8_t));

    /* $Y_t = \prod_{t'=1,t'\neq t}^{m-1}h_{t'}^{y_{t'}} \in \mathbb{G}$ */
    for (t = 0; t < m; t++) {
        secp256k1_gej_set_infinity(&Dj);
        for (t1 = 0; t1 < m; t1++) {
            if (t1 == t)
                continue;
            secp256k1_ecmult_const(&Cj, &genh[t1], &y[t1], 256);
            secp256k1_ge_set_gej(&tmpG, &Cj);
            secp256k1_gej_add_ge(&Dj, &Dj, &tmpG);
        }
        secp256k1_ge_set_gej(&Y[t], &Dj);
        secp256k1_fe_normalize(&Y[t].x);
        secp256k1_fe_get_b32(proof->data + pointer + 1, &Y[t].x);
        proof->data[pointer] = 9 ^ secp256k1_fe_is_quad_var(&Y[t].y);
        pointer += 33;
    }

    /* -------------------------------- */

    /* x_0 */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, digests + index_of_gen * 32, 32);
    secp256k1_sha256_write(&sha, challenge, 32);
    secp256k1_sha256_write(&sha, proof->data, 33 * m);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(&x032, buf, NULL);

    /* e_t = x_0d_t + y_t \in \mathbb{Z}_q */
    for (t = 0; t < m; t++) {
        secp256k1_scalar_mul(&e[t], &x032, &digest32[t]);
        secp256k1_scalar_add(&e[t], &e[t], &y[t]);

        secp256k1_scalar_get_b32(proof->data + pointer, &e[t]);
        pointer += 32;
    }

    /* $E_t = \prod_{t'=1,t'\neq t}^{m-1}h_{t'}^{-e_{t'}} \in \mathbb{G}$ */
    for (t = 0; t < m; t++) {
        secp256k1_scalar_negate(&e[t], &e[t]);
    }
    for (t = 0; t < m; t++) {
        secp256k1_gej_set_infinity(&Dj);
        for (t1 = 0; t1 < m; t1++) {
            if (t1 == t)
                continue;
            secp256k1_ecmult_const(&Cj, &genh[t1], &e[t1], 256);
            secp256k1_ge_set_gej(&tmpG, &Cj);
            secp256k1_gej_add_ge(&Dj, &Dj, &tmpG);
        }
        secp256k1_ge_set_gej(&E[t], &Dj);
        secp256k1_fe_normalize(&E[t].x);
    }

    /* C'_{m(i - 1) + t} = (C_{i})^{x_0}h_{t}^{(-x_0d_j)}Y_{t}\left(\prod_{t'=1;t'\neq t}^{m-1}h_{t'}^{-e_{t'}}\right) */
    secp256k1_scalar_negate(&negdigest32, &digest32[index_of_gen]);

    for (i = 0; i < ring_size; i++) {
        for (t = 0; t < m; t++) {
            secp256k1_pedersen_commitment_load(&tmpG, &ids[i].commit);
            secp256k1_ecmult_const(&Dj, &genh[t], &negdigest32, 256);
            secp256k1_gej_add_ge(&Cj, &Dj, &tmpG);
            secp256k1_ge_set_gej(&tmpG, &Cj);
            secp256k1_ecmult_const(&Cj, &tmpG, &x032, 256);
            if (m > 1) {
                secp256k1_gej_add_ge(&Cj, &Cj, &E[t]);
                secp256k1_gej_add_ge(&Cj, &Cj, &Y[t]);
            }
            secp256k1_ge_set_gej(&tmpG, &Cj);
            secp256k1_fe_normalize(&tmpG.x);
            secp256k1_pedersen_commitment_save(&C[i*m + t], &tmpG);
        }
    }

    secp256k1_scalar_set_b32(&tmp1, blind, &overflow);
    secp256k1_scalar_mul(&tmp1, &tmp1, &x032);
    secp256k1_scalar_get_b32(buf, &tmp1);
    if (!secp256k1_pedersen_commit(ctx, &com, buf, 0,
                                   value_gen,
                                   blind_gen)) {
        return 0;
    }

    if (memcmp(com.data, C[index_of_com * m + index_of_gen].data, 32) != 0)
        return 0;

    /* ---------------------------------------------------------- */
    secp256k1_scalar_get_b32(challenge_x, &x032);
    return secp256k1_unlinked_logarithmic_zero_com_prove(ctx, proof->data + pointer,
                                                         index_of_com * m + index_of_gen, buf,
                                                         ring_size * m, n, challenge_x, C, value_gen, blind_gen);

}


int secp256k1_logarithmic_multi_gen_poe_verify(
        const secp256k1_context* ctx,
        secp256k1_unlinked_identity_pf *proof,
        const unsigned char *digest,
        const unsigned char *challenge,
        secp256k1_identity *ids,
        int m,
        int ring_size,
        int n,
        const secp256k1_generator *generators,
        const secp256k1_generator *value_gen,
        const secp256k1_generator *blind_gen
) {
    secp256k1_ge Y[m];
    secp256k1_ge E[m];
    secp256k1_pedersen_commitment C[ring_size * m];
    secp256k1_scalar e[m];

    int N = (1 << n);

    secp256k1_ge geng;
    secp256k1_ge genh[m];
    secp256k1_gej Dj;
    secp256k1_gej Cj;
    secp256k1_ge tmpG1;
    secp256k1_scalar x032;
    secp256k1_scalar negdigest32;
    secp256k1_sha256 sha;
    unsigned char buf[32];
    unsigned char challenge_x[32];
    int i, t, t1, overflow;
    int pointer = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(proof != NULL);
    ARG_CHECK(digest != NULL);
    ARG_CHECK(challenge != NULL);
    ARG_CHECK(N != 0);
    ARG_CHECK(n != 0);

    secp256k1_generator_load(&geng, blind_gen);

    for (t = 0; t < m; t++) {
        secp256k1_generator_load(&genh[t], &generators[t]);
    }

    /* $Y_t = \prod_{t'=1,t'\neq t}^{m-1}h_{t'}^{y_{t'}} \in \mathbb{G}$ */
    for (t = 0; t < m; t++) {
        secp256k1_fe_set_b32(&Y[t].x, proof->data + pointer + 1);
        secp256k1_ge_set_xquad(&Y[t], &Y[t].x);
        if (proof->data[pointer] & 1) {
            secp256k1_ge_neg(&Y[t], &Y[t]);
        }
        pointer+= 33;
    }

    /* -------------------------------- */

    /* x_0 */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, digest, 32);
    secp256k1_sha256_write(&sha, challenge, 32);
    secp256k1_sha256_write(&sha, proof->data, 33 * m);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(&x032, buf, NULL);


    /* e_t = x_0d_t + y_t \in \mathbb{Z}_q */
    for (t = 0; t < m; t++) {
        secp256k1_scalar_set_b32(&e[t], proof->data + pointer, &overflow);
        if (secp256k1_scalar_is_zero(&e[t])) {
            return 0;
        }
        pointer += 32;
    }

    /* $E_t = \prod_{t'=1,t'\neq t}^{m-1}h_{t'}^{-e_{t'}} \in \mathbb{G}$ */
    for (t = 0; t < m; t++) {
        secp256k1_scalar_negate(&e[t], &e[t]);
    }
    for (t = 0; t < m; t++) {
        secp256k1_gej_set_infinity(&Dj);
        for (t1 = 0; t1 < m; t1++) {
            if (t1 == t)
                continue;
            secp256k1_ecmult_const(&Cj, &genh[t1], &e[t1], 256);
            secp256k1_ge_set_gej(&tmpG1, &Cj);
            secp256k1_gej_add_ge(&Dj, &Dj, &tmpG1);
        }
        secp256k1_ge_set_gej(&E[t], &Dj);
        secp256k1_fe_normalize(&E[t].x);
    }

    /* -------------------------------- */

    /* C'_{m(i - 1) + t} = (C_{i})^{x_0}h_{t}^{(-x_0d_j)}Y_{t}\left(\prod_{t'=1;t'\neq t}^{m-1}h_{t'}^{-e_{t'}}\right) */
    secp256k1_scalar_set_b32(&negdigest32, digest, &overflow);
    if (secp256k1_scalar_is_zero(&negdigest32))
        return 0;
    secp256k1_scalar_negate(&negdigest32, &negdigest32);

    for (i = 0; i < ring_size; i++) {
        for (t = 0; t < m; t++) {
            secp256k1_pedersen_commitment_load(&tmpG1, &ids[i].commit);
            secp256k1_ecmult_const(&Dj, &genh[t], &negdigest32, 256);
            secp256k1_gej_add_ge(&Cj, &Dj, &tmpG1);
            secp256k1_ge_set_gej(&tmpG1, &Cj);
            secp256k1_ecmult_const(&Cj, &tmpG1, &x032, 256);
            if (m > 1) {
                secp256k1_gej_add_ge(&Cj, &Cj, &E[t]);
                secp256k1_gej_add_ge(&Cj, &Cj, &Y[t]);
            }
            secp256k1_ge_set_gej(&tmpG1, &Cj);
            secp256k1_fe_normalize(&tmpG1.x);
            secp256k1_pedersen_commitment_save(&C[i*m + t], &tmpG1);
        }
    }

    secp256k1_scalar_get_b32(challenge_x, &x032);
    return secp256k1_unlinked_logarithmic_zero_com_verify(ctx, proof->data + pointer,
                                                          ring_size * m, n, challenge_x, C, value_gen, blind_gen);
}

#endif /* RAHAS_SECP256K1_MAIN_IMPL_H */
