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

// Bitmap to indicate the authorizing keys given a memory slot
CONST uint16_t sm_key_auth_table[16] = {
    0,                                                              // 0    SM_SECRET_KEY
    (1U << SHE_MASTER_ECU_KEY),                                     // 1    SM_MASTER_ECU_KEY
    (1U << SHE_MASTER_ECU_KEY) | (1U << SHE_BOOT_MAC_KEY),          // 2    SM_BOOT_MAC_KEY
    (1U << SHE_MASTER_ECU_KEY) | (1U << SHE_BOOT_MAC_KEY),          // 3    SM_BOOT_MAC
    (1U << SHE_MASTER_ECU_KEY) | (1U << SHE_KEY_1),                 // 4    SM_KEY_1
    (1U << SHE_MASTER_ECU_KEY) | (1U << SHE_KEY_2),                 // 5    SM_KEY_2
    (1U << SHE_MASTER_ECU_KEY) | (1U << SHE_KEY_3),                 // 6    SM_KEY_3
    (1U << SHE_MASTER_ECU_KEY) | (1U << SHE_KEY_4),                 // 7    SM_KEY_4
    (1U << SHE_MASTER_ECU_KEY) | (1U << SHE_KEY_5),                 // 8    SM_KEY_5
    (1U << SHE_MASTER_ECU_KEY) | (1U << SHE_KEY_6),                 // 9    SM_KEY_6
    (1U << SHE_MASTER_ECU_KEY) | (1U << SHE_KEY_7),                 // 10   SM_KEY_7
    (1U << SHE_MASTER_ECU_KEY) | (1U << SHE_KEY_8),                 // 11   SM_KEY_8
    (1U << SHE_MASTER_ECU_KEY) | (1U << SHE_KEY_9),                 // 12   SM_KEY_9
    (1U << SHE_MASTER_ECU_KEY) | (1U << SHE_KEY_10),                // 13   SM_KEY_10
    (1U << SHE_MASTER_ECU_KEY) | (1U << SHE_KEY_1) |                // 14   SM_RAM_KEY
                                 (1U << SHE_KEY_2) |
                                 (1U << SHE_KEY_3) |
                                 (1U << SHE_KEY_4) |
                                 (1U << SHE_KEY_5) |
                                 (1U << SHE_KEY_6) |
                                 (1U << SHE_KEY_7) |
                                 (1U << SHE_KEY_8) |
                                 (1U << SHE_KEY_9) |
                                 (1U << SHE_KEY_10) |
                                 (1U << SHE_SECRET_KEY),
    0                                                               // Undefined
};

// The MAC mask is precomputed as an array (in RAM) to ensure that the MAC runs in constant time regardless of the
// number of bits compared (use of the C shift operation could become a loop if the CPU didn't have a barrel shifter)
static CONST uint32_t mac_mask_128[] = {
    0xffffffffU,
    0xffffffffU,
    0xffffffffU,
    0xffffffffU,
};

she_errorcode_t FAST_CODE sm_load_key(const sm_block_t *m1, const sm_block_t *m2_0, const sm_block_t *m2_1, const sm_block_t *m3, sm_block_t *m4_0, sm_block_t *m4_1, sm_block_t *m5)
{
    ////// Cannot use API unless the SHE has been initialized //////
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }

    // Get the current device ID into a block (MSB-aligned in a block)
    sm_block_t device_uid = {{0, 0,0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    she_errorcode_t rc;
    rc = sm_sw_callback_nvram_get_uid(device_uid.bytes);
    if (rc != SHE_ERC_NO_ERROR) {
        return rc;
    }

    /////////////////////////////////////////// PART 1: KEY LOADING MESSAGE //////////////////////////////////////////
    // M1 contains UID, AuthID and memory slot [plaintext]
    // M2 contains the new counter, flags, padding (block 0) and the new key value (block 1), CBC encrypted with K1 (IV=0) [encrypted]
    // M3 contains CMAC (using K2) over M1 and M2 (i.e. three blocks) [plaintext, encrypt-then-MAC scheme]
    // device_uid contains the device UID (MSB-aligned 120 bits)

    // Step 1: Extract UID, AuthID and memory slot from M1
    // - UID is 120 bits
    // - Memory slot is 4 bits
    // - AuthID is 4 bits
    uint8_t memory_slot = (m1->bytes[15] >> 4) & 0xfU;
    uint8_t auth_id = m1->bytes[15] & 0xfU;
    sm_block_t m1_uid; // 120 bits, MSB aligned

    // UID is top 128 bits of M1
    m1_uid.words[0] = m1->words[0];
    m1_uid.words[1] = m1->words[1];
    m1_uid.words[2] = m1->words[2];
    m1_uid.words[3] = m1->words[3];
    m1_uid.bytes[15] = 0;

    // Step 2: Check the requested memory slot is not write protected
    if (sm_sw_nvram_fs_ptr->key_slots[memory_slot].flags & SHE_FLAG_WRITE_PROTECTION) {
        return SHE_ERC_KEY_WRITE_PROTECTED;
    }

    // Step 3: Check AuthID is OK to authorize memory_slot
    // The key has to be one that can be authorized
    if ((sm_key_auth_table[memory_slot] & (1U << auth_id)) == 0) {
        // Key not authorized
        return SHE_ERC_KEY_INVALID;
    }
    // The key must not be empty (unless it is authorizing itself)
    if (sm_sw_nvram_fs_ptr->key_slots[memory_slot].flags & SWSM_FLAG_EMPTY_SLOT) {
        if (auth_id != memory_slot) {
            return SHE_ERC_KEY_EMPTY;
        }
    }

    // Step 3: Check CMAC(M1 | M2) = M3 using KDF(AuthID, KEY_UPDATE_MAC_C)
    sm_block_t k2;
    sm_block_t key_update_enc_c;

    key_update_enc_c.words[0] = BIG_ENDIAN_WORD(0x01015348U);
    key_update_enc_c.words[1] = BIG_ENDIAN_WORD(0x45008000U);
    key_update_enc_c.words[2] = BIG_ENDIAN_WORD(0x00000000U);
    key_update_enc_c.words[3] = BIG_ENDIAN_WORD(0x000000b0U);

    sm_block_t key_update_mac_c;
    key_update_mac_c.words[0] = BIG_ENDIAN_WORD(0x01025348U);
    key_update_mac_c.words[1] = BIG_ENDIAN_WORD(0x45008000U);
    key_update_mac_c.words[2] = BIG_ENDIAN_WORD(0x00000000U);
    key_update_mac_c.words[3] = BIG_ENDIAN_WORD(0x000000b0U);

    // M1 is one 128-bit block; M2 is two 128-bit blocks
    uint32_t m1_m2_words[12];
    m1_m2_words[0]  = m1->words[0];
    m1_m2_words[1]  = m1->words[1];
    m1_m2_words[2]  = m1->words[2];
    m1_m2_words[3]  = m1->words[3];
    m1_m2_words[4]  = m2_0->words[0];
    m1_m2_words[5]  = m2_0->words[1];
    m1_m2_words[6]  = m2_0->words[2];
    m1_m2_words[7]  = m2_0->words[3];
    m1_m2_words[8]  = m2_1->words[0];
    m1_m2_words[9]  = m2_1->words[1];
    m1_m2_words[10] = m2_1->words[2];
    m1_m2_words[11] = m2_1->words[3];

    // K2 = KDF(AuthID, KEY_UPDATE_MAC_C
    sm_kdf(&sm_sw_nvram_fs_ptr->key_slots[auth_id].key, &k2, &key_update_mac_c);

    // Compute the MAC for M1|M2 using derived key K2
    sm_block_t m3_computed;
    sm_dynamic_cmac(&k2, m1_m2_words, 3U, &m3_computed);

    // Compare M3 with the computed M3 to verify M1 | M2
    // (Full 128 bits of the MAC is compared)
    if (sm_compare_mac(m3, &m3_computed, mac_mask_128)) {
        // A mismatch, so do not accept the load
        return SHE_ERC_KEY_UPDATE_ERROR;
    }

    // Do UID match using wildcard rules (constant time comparison)
    uint32_t wildcard_mask = ((sm_sw_nvram_fs_ptr->key_slots[memory_slot].flags >> SHE_FLAG_WILDCARD_offset) & 0x1U) - 1U;
    // The wildcard mask is set to 0 if wildcard UID is allowed, which forces the device UID to 0
    // and allowing a UID of 0 in M1 to match
    uint32_t uid_bits_different_wildcard; // 0 if M1 UID = 0 and wildcard set
    uid_bits_different_wildcard = m1_uid.words[0] - (device_uid.words[0] & wildcard_mask);
    uid_bits_different_wildcard |= m1_uid.words[1] - (device_uid.words[1] & wildcard_mask);
    uid_bits_different_wildcard |= m1_uid.words[2] - (device_uid.words[2] & wildcard_mask);
    uid_bits_different_wildcard |= m1_uid.words[3] - (device_uid.words[3] & wildcard_mask);

    uint32_t uid_bits_different; // Compare to UID; 0 if the device ID and the M1 UID match
    uid_bits_different = m1_uid.words[0] - device_uid.words[0];
    uid_bits_different |= m1_uid.words[1] - device_uid.words[1];
    uid_bits_different |= m1_uid.words[2] - device_uid.words[2];
    uid_bits_different |= m1_uid.words[3] - device_uid.words[3];

    // If wildcard is disabled then uid_bits_different == uid_bits_different_wildcard
    // If wildcard is allowed then uid_bits_different_wildcard == 0 if M1 UID == 0
    // uid_bits_different == 0 if M1 UID = device ID
    if ((uid_bits_different_wildcard & uid_bits_different) != 0) {
        return SHE_ERC_KEY_UPDATE_ERROR;
    }

    // Step 5: Decrypt M2 with KDF(AuthID, KEY_UPDATE_ENC_C) [M2 is two blocks, CBC mode is used, IV=0]

    // Get K1 = KDF(AuthID, KEY_UPDATE_ENC_C)
    sm_block_t k1;
    sm_kdf(&sm_sw_nvram_fs_ptr->key_slots[auth_id].key, &k1, &key_update_enc_c);

    sm_aes_enc_roundkey_t k1_enc_roundkey;
    sm_aes_dec_roundkey_t k1_dec_roundkey;
    sm_expand_key_enc(&k1, &k1_enc_roundkey);
    sm_expand_key_dec(&k1_enc_roundkey, &k1_dec_roundkey);

    sm_block_t m2_0_plaintext;
    sm_block_t m2_1_plaintext;

    // Decrypt first M2 block
    // The IV here is 0 so the CBC XOR is null
    sm_aes_decrypt(&k1_dec_roundkey, m2_0, &m2_0_plaintext);

    // Decrypt second M2 block
    sm_aes_decrypt(&k1_dec_roundkey, m2_1, &m2_1_plaintext);
    // XOR in previous ciphertext block, as per CBC rules
    m2_1_plaintext.words[0] ^= m2_0->words[0];
    m2_1_plaintext.words[1] ^= m2_0->words[1];
    m2_1_plaintext.words[2] ^= m2_0->words[2];
    m2_1_plaintext.words[3] ^= m2_0->words[3];

    // Step 6: Extract Counter, Key, F from decrypted M2
    // Counter is 28 bits, F is 6 bits
    uint32_t counter = BIG_ENDIAN_WORD(m2_0_plaintext.words[0]) >> 4; // 28-bits, MSB-aligned
    uint8_t flags = (uint8_t)((m2_0_plaintext.bytes[3] & 0x0fU) << 2); // Four bits of flags in the first word, next 2 in the next word
    flags |= (m2_0_plaintext.bytes[4] >> 6) & 0x3U;

    // Step 7: Check counter > existing counter, store new key, counter, else fail
    if (counter > sm_sw_nvram_fs_ptr->key_slots[memory_slot].counter) {
        sm_sw_nvram_fs_ptr->key_slots[memory_slot].counter = counter;
        sm_sw_nvram_fs_ptr->key_slots[memory_slot].key = m2_1_plaintext;
        sm_sw_nvram_fs_ptr->key_slots[memory_slot].flags = flags;

        // Update the cached roundkey and K1 tweak using the key for CMAC calculation
        sm_aes_enc_roundkey_t *roundkey;
#ifdef SM_KEY_EXPANSION_CACHED
        roundkey = &sm_cached_key_slots[memory_slot].enc_roundkey;
#else
        sm_aes_enc_roundkey_t enc_roundkey;
        roundkey = &enc_roundkey;
#endif
        // Either temporary calculation or result pushed into the cache
        sm_expand_key_enc(&m2_1_plaintext, roundkey);

        // Set the new key's K1 tweak value for the CMAC algorithm so that this can be used in a future CMAC call
        sm_cmac_k1(roundkey, &sm_cached_key_slots[memory_slot].k1);

        // The RAM key always has a counter and flags of 0 so that it can always be set
        // NB: the "plain key" flag has not been set because it is not set through the plain key command
        // This might not be the roundkey but it's easier to just overwrite those values anyway
        sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].counter = 0;
        sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].flags = 0;

        // Flush the file system back to NVRAM
        rc = sm_sw_callback_nvram_store_key_slots();
        if (rc != SHE_ERC_NO_ERROR) {
            return rc;
        }
    }
    else {
        return SHE_ERC_KEY_UPDATE_ERROR;
    }

    ////////////////////////////////////////// PART 2: VERIFICATION MESSAGE //////////////////////////////////////////

    // M1 contains UID, AuthID and memory slot
    // M4 contains the encrypted counter (plus UID)
    // M5 contains the MAC of M4

    const sm_block_t *key_id = &sm_sw_nvram_fs_ptr->key_slots[memory_slot].key;
    uint32_t id_counter = sm_sw_nvram_fs_ptr->key_slots[memory_slot].counter;

    // K3 = KDF(KeyID, KEY_UPDATE_ENC_C)
    sm_block_t k3;
    sm_kdf(key_id, &k3, &key_update_enc_c);

    sm_block_t plaintext;
    plaintext.words[0] = BIG_ENDIAN_WORD((id_counter << 4) | (1U << 3));
    plaintext.words[1] = 0;
    plaintext.words[2] = 0;
    plaintext.words[3] = 0;

    sm_aes_enc_roundkey_t k3_enc_roundkey;
    sm_expand_key_enc(&k3, &k3_enc_roundkey);
    sm_aes_encrypt(&k3_enc_roundkey, &plaintext, m4_1);

    // M4 = UID | ID | AuthID (ID and AuthID are 4 bits, UID is 120 bits)
    m4_0->words[0] = device_uid.words[0];
    m4_0->words[1] = device_uid.words[1];
    m4_0->words[2] = device_uid.words[2];
    m4_0->words[3] = device_uid.words[3];
    m4_0->bytes[15] = ((uint8_t)(memory_slot << 4)) | auth_id;

    uint32_t m4_words[8U];
    m4_words[0] = m4_0->words[0];
    m4_words[1] = m4_0->words[1];
    m4_words[2] = m4_0->words[2];
    m4_words[3] = m4_0->words[3];
    m4_words[4] = m4_1->words[0];
    m4_words[5] = m4_1->words[1];
    m4_words[6] = m4_1->words[2];
    m4_words[7] = m4_1->words[3];

    // K4 = KDF(KeyID, KEY_UPDATE_MAC_C)
    sm_block_t k4;
    sm_kdf(key_id, &k4, &key_update_mac_c);

    // Compute M5, the CMAC of the two-block M4 using the derived key K4
    sm_dynamic_cmac(&k4, m4_words, 2U, m5);

    return SHE_ERC_NO_ERROR;
}

she_errorcode_t FAST_CODE sm_load_plain_key(const sm_block_t *plain_key)
{
    ////// Cannot use API unless the SHE has been initialized //////
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }

    sm_aes_enc_roundkey_t *roundkey;

    sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].key.words[0] = plain_key->words[0];
    sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].key.words[1] = plain_key->words[1];
    sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].key.words[2] = plain_key->words[2];
    sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].key.words[3] = plain_key->words[3];
    sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].flags = SWSM_FLAG_PLAIN_KEY;
#ifdef SM_KEY_EXPANSION_CACHED
    roundkey = &sm_cached_key_slots[SHE_RAM_KEY].enc_roundkey;
#else
    sm_aes_enc_roundkey_t enc_roundkey;
    roundkey = &enc_roundkey;
#endif
    // Expand into the cache (if a cache is present) or just a temporary place
    sm_expand_key_enc(&sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].key, roundkey);

    // Also set the new key's K1 tweak value for the CMAC algorithm so that this can be used in a future CMAC call
    sm_cmac_k1(roundkey, &sm_cached_key_slots[SHE_RAM_KEY].k1);

    // Don't flush the file system back: this key is never saved
    return SHE_ERC_NO_ERROR;
}
