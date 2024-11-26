// Software emulation of SHE
//
// Copyright (C) 2016-2022 Canis Automotive Labs Ltd.
//
// This software is licensed according to the APACHE LICENSE 2.0:
//
// https://www.apache.org/licenses/LICENSE-2.0.txt
//
// Created by ken on 02/11/16.

#include "swshe.h"

void FAST_CODE sm_mp(const sm_block_t *out_prev, const sm_block_t *x, sm_block_t *out_next)
{
    // The Miyaguchi-Preneel compression algorithm
    // The round keys are not cached because the key is dynamic, so compute the round keys
    sm_aes_enc_roundkey_t out_prev_roundkey;
    sm_expand_key_enc(out_prev, &out_prev_roundkey);

    // Encrypt X_i with the previous OUT (will be 0 for the first block)
    sm_block_t tmp_ciphertext;
    sm_aes_encrypt(&out_prev_roundkey, x, &tmp_ciphertext);
    // XOR together Xi, previous OUT and the output of the AES block
    out_next->words[0] = tmp_ciphertext.words[0] ^ x->words[0] ^ out_prev->words[0];
    out_next->words[1] = tmp_ciphertext.words[1] ^ x->words[1] ^ out_prev->words[1];
    out_next->words[2] = tmp_ciphertext.words[2] ^ x->words[2] ^ out_prev->words[2];
    out_next->words[3] = tmp_ciphertext.words[3] ^ x->words[3] ^ out_prev->words[3];
}

void FAST_CODE sm_kdf(const sm_block_t *k, sm_block_t *out, const sm_block_t *c)
{
    sm_block_t out_prev;
    out_prev.words[0] = 0;
    out_prev.words[1] = 0;
    out_prev.words[2] = 0;
    out_prev.words[3] = 0;

    // Round 1 is the IV (zero) and the key
    sm_mp(&out_prev, k, out);

    // Round 2 adds the constant
    out_prev.words[0] = out->words[0];
    out_prev.words[1] = out->words[1];
    out_prev.words[2] = out->words[2];
    out_prev.words[3] = out->words[3];
    sm_mp(&out_prev, c, out);
}
