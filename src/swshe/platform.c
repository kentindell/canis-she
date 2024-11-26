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

//// Checks that the platform is compiled OK
she_errorcode_t FAST_CODE sm_platform_check(void)
{
    sm_block_t test;

    test.words[0] = 0x00010203U;
    test.words[1] = 0x04050607U;
    test.words[2] = 0x08090a0bU;
    test.words[3] = 0x0c0d0e0fU;

#ifdef SM_CPU_BIG_ENDIAN
    if (test.bytes[0]  != 0x00U ||
        test.bytes[1]  != 0x01U ||
        test.bytes[2]  != 0x02U ||
        test.bytes[3]  != 0x03U ||
        test.bytes[4]  != 0x04U ||
        test.bytes[5]  != 0x05U ||
        test.bytes[6]  != 0x06U ||
        test.bytes[7]  != 0x07U ||
        test.bytes[8]  != 0x08U ||
        test.bytes[9]  != 0x09U ||
        test.bytes[10] != 0x0aU ||
        test.bytes[11] != 0x0bU ||
        test.bytes[12] != 0x0cU ||
        test.bytes[13] != 0x0dU ||
        test.bytes[14] != 0x0eU ||
        test.bytes[15] != 0x0fU) {
        return SHE_ERC_GENERAL_ERROR;
    }
#else
    if (test.bytes[0]  != 0x03U ||
        test.bytes[1]  != 0x02U ||
        test.bytes[2]  != 0x01U ||
        test.bytes[3]  != 0x00U ||
        test.bytes[4]  != 0x07U ||
        test.bytes[5]  != 0x06U ||
        test.bytes[6]  != 0x05U ||
        test.bytes[7]  != 0x04U ||
        test.bytes[8]  != 0x0bU ||
        test.bytes[9]  != 0x0aU ||
        test.bytes[10] != 0x09U ||
        test.bytes[11] != 0x08U ||
        test.bytes[12] != 0x0fU ||
        test.bytes[13] != 0x0eU ||
        test.bytes[14] != 0x0dU ||
        test.bytes[15] != 0x0cU) {
        return SHE_ERC_GENERAL_ERROR;
    }
#endif

    // Execute one test vector to see if the platform has initialized all the tables etc.
    // Set this key to 000102030405060708090a0b0c0d0e0f
    sm_block_t key = {.bytes = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}};

    sm_block_t plaintext = {.bytes = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}};

    sm_block_t expected_ciphertext = {.bytes = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 
                                                0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a}};

    sm_sw_nvram_backdoor_set_key(SHE_KEY_2, &key, false);

    sm_block_t ciphertext;
    sm_init_rng();
    she_errorcode_t rc = sm_enc_ecb(SHE_KEY_2, &plaintext, &ciphertext);
    if (rc) {
        return SHE_ERC_GENERAL_ERROR;
    }

    for (uint32_t i = 0; i < 16U; i++) {
        if (expected_ciphertext.bytes[i] != ciphertext.bytes[i]) {
            return SHE_ERC_GENERAL_ERROR;
        }
    }

    return SHE_ERC_NO_ERROR;
}
 