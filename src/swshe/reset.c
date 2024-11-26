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

// Backdoor call to set an encryption key
she_errorcode_t FAST_CODE sm_sw_nvram_backdoor_set_key(sm_key_id_t key_number, const sm_block_t *key, bool authentication_key)
{
    // Don't overwrite keys
    if ((key_number >= SM_SW_NUM_KEYS) || (key_number == 1U)) {
        return SHE_ERC_KEY_INVALID;
    }
    sm_sw_nvram_fs_ptr->key_slots[key_number].key.words[0] = key->words[0];
    sm_sw_nvram_fs_ptr->key_slots[key_number].key.words[1] = key->words[1];
    sm_sw_nvram_fs_ptr->key_slots[key_number].key.words[2] = key->words[2];
    sm_sw_nvram_fs_ptr->key_slots[key_number].key.words[3] = key->words[3];
    sm_sw_nvram_fs_ptr->key_slots[key_number].counter = 0;
    sm_sw_nvram_fs_ptr->key_slots[key_number].flags = authentication_key ? SHE_FLAG_KEY_USAGE : 0;
    if (key_number == SHE_RAM_KEY) {
        sm_sw_nvram_fs_ptr->key_slots[key_number].flags |= SWSM_FLAG_PLAIN_KEY;
    }
    // Set up the key in the table (including cache of roundkey expansion if necessaary)
    sm_init_key(key_number);
    return sm_sw_callback_nvram_store_key_slots();
}

// Set the whole set of keys to a factory default
she_errorcode_t FAST_CODE sm_sw_nvram_factory_reset(const sm_block_t *secret_key)
{
    for (uint32_t i = 0; i < SM_SW_NUM_KEYS; i++) {
        sm_sw_nvram_fs_ptr->key_slots[i].key.words[0] = 0;
        sm_sw_nvram_fs_ptr->key_slots[i].key.words[1] = 0;
        sm_sw_nvram_fs_ptr->key_slots[i].key.words[2] = 0;
        sm_sw_nvram_fs_ptr->key_slots[i].key.words[3] = 0;
        sm_sw_nvram_fs_ptr->key_slots[i].counter = 0;
        sm_sw_nvram_fs_ptr->key_slots[i].flags = SWSM_FLAG_EMPTY_SLOT;
    }
    // RAM key is a plain key
    sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].flags |= SWSM_FLAG_PLAIN_KEY;
    // Secret key
    sm_sw_nvram_fs_ptr->key_slots[SHE_SECRET_KEY].key.words[0] = secret_key->words[0];
    sm_sw_nvram_fs_ptr->key_slots[SHE_SECRET_KEY].key.words[1] = secret_key->words[1];
    sm_sw_nvram_fs_ptr->key_slots[SHE_SECRET_KEY].key.words[2] = secret_key->words[2];
    sm_sw_nvram_fs_ptr->key_slots[SHE_SECRET_KEY].key.words[3] = secret_key->words[3];

    // Write this back to NVRAM
    return sm_sw_callback_nvram_store_key_slots();
}
