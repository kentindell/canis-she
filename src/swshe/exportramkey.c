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

she_errorcode_t FAST_CODE sm_export_ram_key(sm_block_t *m1, sm_block_t *m2_0, sm_block_t *m2_1, sm_block_t *m3, sm_block_t *m4_0, sm_block_t *m4_1, sm_block_t *m5)
{
    //    K1 = KDF(KEYSECRET_KEY, KEY_UPDATE_ENC_C)
    //    K2 = KDF(KEYSECRET_KEY, KEY_UPDATE_MAC_C)
    //    CID = 0 (28 bits)
    //    FID = 0 (5 bits)
    //    M1 = UID|IDRAM_KEY|IDSECRET_KEY
    //    M2 = ENCCBC,K1,IV=0(CID|FID|"0...0"95|KEYRAM_KEY) = ENCCBC,K1,IV=0("0...0"128|KEYRAM_KEY)
    //    M3 = CMACK2(M1|M2)
    //    K3 = KDF(KEYRAM_KEY, KEY_UPDATE_ENC_C) K4 = KDF(KEYRAM_KEY, KEY_UPDATE_MAC_C)
    //    M4 = UID|IDRAM_KEY|IDSECRET_KEY|ENCECB,K3(CID) M5 = CMACK4(M4)

    ////// Cannot use API unless the SHE has been initialized //////
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }

    ////// KEY_UPDATE_ENC_C //////
    sm_block_t key_update_enc_c;
    key_update_enc_c.words[0] = BIG_ENDIAN_WORD(0x01015348U);
    key_update_enc_c.words[1] = BIG_ENDIAN_WORD(0x45008000U);
    key_update_enc_c.words[2] = BIG_ENDIAN_WORD(0x00000000U);
    key_update_enc_c.words[3] = BIG_ENDIAN_WORD(0x000000b0U);

    ////// KEY_UPDATE_MAC_C //////
    sm_block_t key_update_mac_c;
    key_update_mac_c.words[0] = BIG_ENDIAN_WORD(0x01025348U);
    key_update_mac_c.words[1] = BIG_ENDIAN_WORD(0x45008000U);
    key_update_mac_c.words[2] = BIG_ENDIAN_WORD(0x00000000U);
    key_update_mac_c.words[3] = BIG_ENDIAN_WORD(0x000000b0U);

    ////// M1 //////
    sm_sw_callback_nvram_get_uid(m1->bytes);
    m1->bytes[15] = (SHE_RAM_KEY << 4) | SHE_SECRET_KEY;

    ////// M2 //////
    sm_block_t k1;
    sm_kdf(&sm_sw_nvram_fs_ptr->key_slots[SHE_SECRET_KEY].key, &k1, &key_update_enc_c);

    sm_block_t tmp;
    tmp.words[0] = 0;
    tmp.words[1] = 0;
    tmp.words[2] = 0;
    tmp.words[3] = 0;

    // First block is IV (all zero) XOR with messsage block 0 (all zero)
    sm_aes_enc_roundkey_t k1_roundkey;
    sm_expand_key_enc(&k1, &k1_roundkey);
    sm_aes_encrypt(&k1_roundkey, &tmp, m2_0);
    // CBC mode XORs ciphertext and plaintext
    tmp.words[0] ^= sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].key.words[0];
    tmp.words[1] ^= sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].key.words[1];
    tmp.words[2] ^= sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].key.words[2];
    tmp.words[3] ^= sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].key.words[3];
    // This is encrypted to create the second block of M2
    sm_aes_encrypt(&k1_roundkey, &tmp, m2_1);

    ////// M3 //////
    // M3 is CMAC with K2 of M1 | M2
    // The message is three blocks long
    sm_block_t k2;
    sm_kdf(&sm_sw_nvram_fs_ptr->key_slots[SHE_SECRET_KEY].key, &k2, &key_update_mac_c);

    uint32_t message_m1_m2[12];
    message_m1_m2[0] = m1->words[0];
    message_m1_m2[1] = m1->words[1];
    message_m1_m2[2] = m1->words[2];
    message_m1_m2[3] = m1->words[3];
    message_m1_m2[4] = m2_0->words[0];
    message_m1_m2[5] = m2_0->words[1];
    message_m1_m2[6] = m2_0->words[2];
    message_m1_m2[7] = m2_0->words[3];
    message_m1_m2[8] = m2_1->words[0];
    message_m1_m2[9] = m2_1->words[1];
    message_m1_m2[10] = m2_1->words[2];
    message_m1_m2[11] = m2_1->words[3];
    sm_dynamic_cmac(&k2, message_m1_m2, 3U, m3);

    ////// M4 //////
    sm_block_t k3;
    sm_kdf(&sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].key, &k3, &key_update_enc_c);

    sm_block_t cid;
    cid.words[0] = 0;
    cid.words[1] = 0;
    cid.words[2] = 0;
    cid.words[3] = 0;

    she_errorcode_t rc = sm_sw_callback_nvram_get_uid(m4_0->bytes);
    if (rc != SHE_ERC_NO_ERROR) {
        return rc;
    }
    m4_0->bytes[15] |= (SHE_RAM_KEY << 4) | SHE_SECRET_KEY;

    sm_aes_enc_roundkey_t k3_roundkey;
    sm_expand_key_enc(&k3, &k3_roundkey);
    sm_aes_encrypt(&k3_roundkey, &cid, m4_1);

    ////// M5 //////
    sm_block_t k4;
    sm_kdf(&sm_sw_nvram_fs_ptr->key_slots[SHE_RAM_KEY].key, &k4, &key_update_mac_c);

    uint32_t message_m4[8];
    message_m4[0] = m4_0->words[0];
    message_m4[1] = m4_0->words[1];
    message_m4[2] = m4_0->words[2];
    message_m4[3] = m4_0->words[3];
    message_m4[4] = m4_1->words[0];
    message_m4[5] = m4_1->words[1];
    message_m4[6] = m4_1->words[2];
    message_m4[7] = m4_1->words[3];
    sm_dynamic_cmac(&k4, message_m4, 2U, m5);

    return SHE_ERC_NO_ERROR;
}
