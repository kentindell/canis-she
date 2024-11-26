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

she_errorcode_t FAST_CODE sm_get_id(const sm_block_t *challenge, sm_block_t *id, uint8_t *sreg, sm_block_t *mac)
{
    ////// Cannot use API unless the SHE has been initialized //////
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }

    // Get the current device ID into a block (MSB-aligned in a block)
    sm_block_t device_uid;
    she_errorcode_t rc;
    rc = sm_sw_callback_nvram_get_uid(device_uid.bytes);
    if (rc != SHE_ERC_NO_ERROR) {
        return rc;
    }
    // TODO the status register also includes boot, debugger and busy operations
    device_uid.bytes[15] = sm_prng_init ? 1U << 5 : 0;

    // Compute the MAC, using the ECU master key, of the challenge, ID and SREG
    // or return a MAC of 0 if the ECU master key is empty
    if (sm_sw_nvram_fs_ptr->key_slots[SHE_MASTER_ECU_KEY].flags & SWSM_FLAG_EMPTY_SLOT) {
        mac->words[0] = 0;
        mac->words[1] = 0;
        mac->words[2] = 0;
        mac->words[3] = 0;
    }
    else {
#ifdef SM_KEY_EXPANSION_CACHED
        sm_aes_enc_roundkey_t *enc_roundkey = &sm_cached_key_slots[SHE_MASTER_ECU_KEY].enc_roundkey;
#else
        sm_aes_enc_roundkey_t expanded_roundkey;
        sm_aes_enc_roundkey_t *enc_roundkey = &expanded_roundkey;
        sm_expand_key_enc(&sm_sw_nvram_fs_ptr->key_slots[SHE_MASTER_ECU_KEY].key, enc_roundkey);
#endif
        const sm_block_t *k1 = &sm_cached_key_slots[SHE_MASTER_ECU_KEY].k1;    // Cached K1 tweak (calculated on load from NVRAM, setting)

        uint32_t message[8];

        message[0] = challenge->words[0];
        message[1] = challenge->words[1];
        message[2] = challenge->words[2];
        message[3] = challenge->words[3];
        message[4] = device_uid.words[0];
        message[5] = device_uid.words[1];
        message[6] = device_uid.words[2];
        message[7] = device_uid.words[3];

        // CMAC is done with the master ECU key over CHALLENGE|ID|SREG, or two blocks
        sm_aes_cmac(enc_roundkey, message, 2U, mac, k1);
    }
    // Set the status register
    *sreg = device_uid.bytes[15];

    // Set the UID
    id->words[0] = device_uid.words[0];
    id->words[1] = device_uid.words[1];
    id->words[2] = device_uid.words[2];
    id->words[3] = device_uid.words[3];

    return SHE_ERC_NO_ERROR;
}
