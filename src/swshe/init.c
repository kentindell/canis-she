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

sm_sw_cached_key_slot_t sm_cached_key_slots[SM_SW_NUM_KEYS];

void FAST_CODE sm_init_key(sm_key_id_t key_num)
{
    // If caching is enabled then hang on to the expanded key, else just use it to set the MAC K1 tweak
#ifdef SM_KEY_EXPANSION_CACHED
    sm_aes_enc_roundkey_t *enc_roundkey = &sm_cached_key_slots[key_num].enc_roundkey;
#else
    sm_aes_enc_roundkey_t expanded_roundkey;
    sm_aes_enc_roundkey_t *enc_roundkey = &expanded_roundkey;
#endif
    sm_expand_key_enc(&sm_sw_nvram_fs_ptr->key_slots[key_num].key, enc_roundkey);
    // Create the MAC K1 tweak
    sm_cmac_k1(enc_roundkey, &sm_cached_key_slots[key_num].k1);
}

// This sets up the key cache, including the K1 tweak.
void FAST_CODE sm_init_keys(void)
{
    for (uint8_t i = 0; i < SM_SW_NUM_KEYS; i++) {
        sm_init_key(i);
    }
}
