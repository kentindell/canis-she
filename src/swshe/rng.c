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

// This is the current PRNG state, initialized by a seed and then updated each time
// a random number is requested
sm_block_t sm_prng_state;
sm_aes_enc_roundkey_t sm_prng_roundkey;

bool sm_prng_init;

// This is also an initialization of the HSM itself
she_errorcode_t FAST_CODE sm_init_rng(void)
{
    // First, update the keys from NVRAM, and marking the RAM key slot as empty
    she_errorcode_t rc;
    rc = sm_sw_callback_nvram_load_key_slots();
    if (rc != SHE_ERC_NO_ERROR) {
        return rc;
    }

    sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].flags = SWSM_FLAG_EMPTY_SLOT | SWSM_FLAG_PLAIN_KEY;
    // If key caching is enabled then also create the caches for the roundkey
    // Then create the cached k1 tweak
    sm_init_keys();

    // Then create the new seed. This is in several steps:
    //
    // 1. Obtain a seed key from the KDF using the PRNG_SEED_KEY_C constant
    // (the operating PRNG key is the same as the seed key because PRNG_SEED_KEY_C and PRNG_KEY_C
    //  are the same constants used in the KDF)
    sm_block_t prng_seed_key_c;
    prng_seed_key_c.words[0] = BIG_ENDIAN_WORD(0x01055348U);
    prng_seed_key_c.words[1] = BIG_ENDIAN_WORD(0x45008000U);
    prng_seed_key_c.words[2] = BIG_ENDIAN_WORD(0x00000000U);
    prng_seed_key_c.words[3] = BIG_ENDIAN_WORD(0x000000b0U);

    sm_block_t prng_key;

    sm_kdf(&sm_sw_nvram_fs_ptr->key_slots[SHE_SECRET_KEY].key, &prng_key, &prng_seed_key_c);

    // 2. Encrypt the previous seed with the derived key
    // The round keys have not been cached because this derived key is dynamic, so compute the round keys
    sm_expand_key_enc(&prng_key, &sm_prng_roundkey);
    // Encrypt the current seed key
    sm_block_t current_seed;
    current_seed = sm_sw_nvram_fs_ptr->prng_seed;
    sm_aes_encrypt(&sm_prng_roundkey, &current_seed, &sm_sw_nvram_fs_ptr->prng_seed);

    // 3. Flush back to NVRAM to ensure re-seeding is set for the next session
    rc = sm_sw_callback_nvram_store_key_slots();
    if (rc != SHE_ERC_NO_ERROR) {
        return rc;
    }
    // 4. Copy the new seed to the volatile PRNG state that is used to produce random numbers
    sm_prng_state.words[0] = sm_sw_nvram_fs_ptr->prng_seed.words[0];
    sm_prng_state.words[1] = sm_sw_nvram_fs_ptr->prng_seed.words[1];
    sm_prng_state.words[2] = sm_sw_nvram_fs_ptr->prng_seed.words[2];
    sm_prng_state.words[3] = sm_sw_nvram_fs_ptr->prng_seed.words[3];

    // Mark the RNG as being initialized
    sm_prng_init = true;

    return SHE_ERC_NO_ERROR;
}

she_errorcode_t FAST_CODE sm_rnd(sm_block_t *rn)
{
    // It's an error to try to get a random number without having first initialized the
    // random number generator
    if (!sm_prng_init) {
        return SHE_ERC_RNG_SEED;
    }

    // The RNG operates by encrypting the PRNG state with the PRNG key to get the next state
    sm_block_t next_prng_state;
    sm_aes_encrypt(&sm_prng_roundkey, &sm_prng_state, &next_prng_state);
    sm_prng_state.words[0] = next_prng_state.words[0];
    sm_prng_state.words[1] = next_prng_state.words[1];
    sm_prng_state.words[2] = next_prng_state.words[2];
    sm_prng_state.words[3] = next_prng_state.words[3];
    // Copy the current random number state as the result
    rn->words[0] = sm_prng_state.words[0];
    rn->words[1] = sm_prng_state.words[1];
    rn->words[2] = sm_prng_state.words[2];
    rn->words[3] = sm_prng_state.words[3];

    return SHE_ERC_NO_ERROR;
}

