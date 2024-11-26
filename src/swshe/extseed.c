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

// Takes either the state or the seed and produces a new one using M-P compression
static void FAST_CODE prng_extend(const sm_block_t *prng, const sm_block_t *entropy, const sm_block_t *c, sm_block_t *out)
{
    sm_block_t out_prev;
    out_prev.words[0] = 0;
    out_prev.words[1] = 0;
    out_prev.words[2] = 0;
    out_prev.words[3] = 0;

    // Round 1 is the IV (zero) and the state/seed
    sm_mp(&out_prev, prng, out);

    // Round 2 adds the entropy
    out_prev.words[0] = out->words[0];
    out_prev.words[1] = out->words[1];
    out_prev.words[2] = out->words[2];
    out_prev.words[3] = out->words[3];
    sm_mp(&out_prev, entropy, out);

    // Round 3 adds the constant
    out_prev.words[0] = out->words[0];
    out_prev.words[1] = out->words[1];
    out_prev.words[2] = out->words[2];
    out_prev.words[3] = out->words[3];
    sm_mp(&out_prev, c, out);
}

she_errorcode_t FAST_CODE sm_extend_seed(const sm_block_t *entropy)
{
    ////// Cannot use API unless the SHE has been initialized //////
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }

    // This operates like creating the next seed, but uses some entropy too
    // The PRNG_EXTENSION_C constant is:
    //
    // 0x80000000 00000000 00000000 00000100
    //
    // The entropy extension process is:
    //
    //    PRNG_STATE = AES-MP(PRNG_STATE | ENTROPY)
    //    PRNG_SEED = AES-MP(PRNG_SEED | ENTROPY)
    sm_block_t prng_extension_c;
    prng_extension_c.words[0] = BIG_ENDIAN_WORD(0x80000000U);
    prng_extension_c.words[1] = BIG_ENDIAN_WORD(0x00008000U);
    prng_extension_c.words[2] = BIG_ENDIAN_WORD(0x00000000U);
    prng_extension_c.words[3] = BIG_ENDIAN_WORD(0x00000100U);

    sm_block_t out;
    // Will take three rounds of M-P to compress the state and seed
    prng_extend(&sm_prng_state, entropy, &prng_extension_c, &out);
    sm_prng_state.words[0] = out.words[0];
    sm_prng_state.words[1] = out.words[1];
    sm_prng_state.words[2] = out.words[2];
    sm_prng_state.words[3] = out.words[3];

    prng_extend(&sm_sw_nvram_fs_ptr->prng_seed, entropy, &prng_extension_c, &out);
    sm_sw_nvram_fs_ptr->prng_seed.words[0] = out.words[0];
    sm_sw_nvram_fs_ptr->prng_seed.words[1] = out.words[1];
    sm_sw_nvram_fs_ptr->prng_seed.words[2] = out.words[2];
    sm_sw_nvram_fs_ptr->prng_seed.words[3] = out.words[3];

    // Flush the NVRAM back because the seed has changed and we don't want to lose this
    // on restart
    she_errorcode_t rc = sm_sw_callback_nvram_store_key_slots();
    return rc;
}
