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

// Calculate CMAC from raw keys, not using cached roundkey or tweak. This is not part of the API
// and is only for internal use during key loading (either from NVRAM or through the key loading
// API).
//
// Assumes a whole number of blocks (so will not calculate the K2 tweak, but does require the K1 tweak).
void FAST_CODE sm_dynamic_cmac(const sm_block_t *k, const uint32_t *words, uint32_t num_blocks, sm_block_t *mac)
{
    // Must calculate the roundkeys and also the K1 tweak
    sm_aes_enc_roundkey_t roundkey_k;

    // First expand the MAC key
    sm_expand_key_enc(k, &roundkey_k);
    // Calculate the K1 tweak
    sm_block_t k1;
    sm_cmac_k1(&roundkey_k, &k1);

    // Now calculate CMAC with these values
    sm_aes_cmac(&roundkey_k, words, num_blocks, mac, &k1);
}
