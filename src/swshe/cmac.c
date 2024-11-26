// Secure Hardware Extensions (SHE) Hardware Security Module (HSM) API
//
// Copyright (C) 2016-2022 Canis Automotive Labs Ltd.
//
// This software is licensed according to the APACHE LICENSE 2.0:
//
// https://www.apache.org/licenses/LICENSE-2.0.txt

#include "swshe.h"

// Treat AES block as a 128-bit big-endian integer and shift it left by 1.
// This is called as part of K1 derivation in the CMAC algorithm but only when AES key expansion is done.
CONST uint8_t sm_k1_xor_const[2] = {0x0, 0x87U};

// This is called with roundkeys, so that if the system has cached the roundkey for
// a given key then the fast cached value can be used. The result can be stored with
// a defined key, or used immediately and discarded.
void FAST_CODE sm_cmac_k1(const sm_aes_enc_roundkey_t *k, sm_block_t *k1)
{
    sm_block_t zero;

    // Calculate K1 according to CMAC specification
    //
    // Step 1.  L := AES-128(K, const_Zero);
    // Step 2.  if MSB(L) is equal to 0
    //          then    K1 := L << 1;
    //          else    K1 := (L << 1) XOR const_Rb;
    // [ Step 3.  if MSB(K1) is equal to 0              ]
    // [          then    K2 := K1 << 1;                ]
    // [          else    K2 := (K1 << 1) XOR const_Rb; ]
    // [ Step 4.  return K1, K2;                        ]
    //
    // NB: We do not need K2 (and hence can skip steps 3 and 4) because padding is done at the SHE level

    zero.words[0] = 0;
    zero.words[1] = 0;
    zero.words[2] = 0;
    zero.words[3] = 0;

    sm_aes_encrypt(k, &zero, k1);

    // If the MSB of L is 1 then top 8 bits get 0x87 XORed in
    // This should run in constant time
    uint8_t xor_val = sm_k1_xor_const[k1->bytes[0] >> 7];

    // L << 1
    lsl_128(k1->words);
    // XOR in the appropriate constant
    k1->bytes[15] ^= xor_val;
}

// Computes the CMAC for a number of blocks, using an AES encryption roundkey and pre-computed K1.
// This is called with cached values for normal operation where loaded keys are used, and from
// dynamically calculated roundkeys for K and K1 values when keys from the KDF are used.
void FAST_CODE sm_aes_cmac(const sm_aes_enc_roundkey_t *rk, const uint32_t *words, uint32_t num_blocks, sm_block_t *mac, const sm_block_t *k1)
{
    // The IV is zero
    mac->words[0] = 0;
    mac->words[1] = 0;
    mac->words[2] = 0;
    mac->words[3] = 0;

    for (;;) {
        if (num_blocks == 1U) {
            // Last block
            mac->words[0] ^= words[0] ^ k1->words[0];
            mac->words[1] ^= words[1] ^ k1->words[1];
            mac->words[2] ^= words[2] ^ k1->words[2];
            mac->words[3] ^= words[3] ^ k1->words[3];
            sm_aes_encrypt(rk, mac, mac);
            break;
        } else {
            mac->words[0] ^= words[0];
            mac->words[1] ^= words[1];
            mac->words[2] ^= words[2];
            mac->words[3] ^= words[3];
            sm_aes_encrypt(rk, mac, mac);
            num_blocks -= 1U;
            words += 4U;
        }
    }
}

she_errorcode_t FAST_CODE sm_generate_mac(sm_key_id_t key_id, const uint32_t *message, uint32_t message_length, sm_block_t *mac)
{
    ////// Cannot use API unless the SHE has been initialized //////
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }
    if (sm_sw_nvram_fs_ptr->key_slots[key_id].flags & SWSM_FLAG_EMPTY_SLOT) {
        return SHE_ERC_KEY_EMPTY;
    }
    if (sm_sw_nvram_fs_ptr->key_slots[key_id].flags & SHE_FLAG_KEY_USAGE) {
        if (sm_sw_nvram_fs_ptr->key_slots[key_id].flags & SHE_FLAG_VERIFY_ONLY) {
            return SHE_ERC_KEY_INVALID;
        }
    }
    else {
        return SHE_ERC_KEY_INVALID;
    }
    if (message_length & 0x7fU) {
        // TODO allow arbitrary bit lengths and do the necessary padding
        return SHE_ERC_GENERAL_ERROR;
    }
#ifdef SM_KEY_EXPANSION_CACHED
    sm_aes_enc_roundkey_t *enc_roundkey = &sm_cached_key_slots[key_id].enc_roundkey;
#else
    sm_aes_enc_roundkey_t expanded_roundkey;
    sm_aes_enc_roundkey_t *enc_roundkey = &expanded_roundkey;
    sm_expand_key_enc(&sm_sw_nvram_fs_ptr->key_slots[key_id].key, enc_roundkey);
#endif
    const sm_block_t *k1 = &sm_cached_key_slots[key_id].k1;    // Cached K1 tweak (calculated on load from NVRAM, setting)

    sm_aes_cmac(enc_roundkey, message, message_length >> 7, mac, k1);

    return SHE_ERC_NO_ERROR;
}

// Returns 0 if the two MACs agree; constant time comparison to prevent timing side-channels
uint32_t FAST_CODE sm_compare_mac(const sm_block_t *m, const sm_block_t *m_star, const uint32_t *mac_mask)
{
    uint32_t bits_different;

    bits_different = (m->words[0] & mac_mask[0]) ^ (m_star->words[0] & mac_mask[0]);
    bits_different |= (m->words[1] & mac_mask[1]) ^ (m_star->words[1] & mac_mask[1]);
    bits_different |= (m->words[2] & mac_mask[2]) ^ (m_star->words[2] & mac_mask[2]);
    bits_different |= (m->words[3] & mac_mask[3]) ^ (m_star->words[3] & mac_mask[3]);

    return bits_different;
}

she_errorcode_t FAST_CODE sm_verify_mac(sm_key_id_t key_id, const uint32_t *message, uint32_t message_length, const sm_block_t *mac, uint8_t mac_length, bool *verification_status)
{
    ////// Cannot use API unless the SHE has been initialized //////
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }
    if (sm_sw_nvram_fs_ptr->key_slots[key_id].flags & SWSM_FLAG_EMPTY_SLOT) {
        return SHE_ERC_KEY_EMPTY;
    }
    if (sm_sw_nvram_fs_ptr->key_slots[key_id].flags & SHE_FLAG_KEY_USAGE) {
        // Key OK to be used to verify
    }
    else {
        return SHE_ERC_KEY_INVALID;
    }
    if (message_length & 0x7fU) {
        // TODO allow arbitrary bit lengths and do the necessary padding
        return SHE_ERC_GENERAL_ERROR;
    }

    sm_block_t calculated_mac;
#ifdef SM_KEY_EXPANSION_CACHED
    sm_aes_enc_roundkey_t *roundkey = &sm_cached_key_slots[key_id].enc_roundkey;
#else
    sm_block_t *key = &sm_sw_nvram_fs_ptr->key_slots[key_id].key;
    sm_aes_enc_roundkey_t enc_roundkey;
    sm_aes_enc_roundkey_t *roundkey = &enc_roundkey;
    sm_expand_key_enc(key, roundkey);
#endif

    sm_aes_cmac(roundkey, message, message_length >> 7, &calculated_mac, &sm_cached_key_slots[key_id].k1);

    // Need to compare the most-significant n bits of the MAC; function requires a 4-word mask to be precomputed
    uint32_t mac_mask[4];
    asrm_128(mac_mask, mac_length);

    *verification_status = sm_compare_mac(mac, &calculated_mac, mac_mask) != 0;

    return SHE_ERC_NO_ERROR;
}
