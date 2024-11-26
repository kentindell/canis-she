// Test vectors for security module
//
// Copyright (C) 2016-2022 Canis Automotive Labs Ltd.
//
// This software is licensed according to the APACHE LICENSE 2.0:
//
// https://www.apache.org/licenses/LICENSE-2.0.txt

#include <stdint.h>
#include <stdlib.h>

// HSM API
#include "../she.h"
#include "../nvram.h"
#include "test.h"

typedef union {uint8_t bytes[16]; uint32_t word;} bytes16_t;
typedef union {uint8_t bytes[32]; uint32_t word;} bytes32_t;

// Tests
//
// Test the remaining vectors in the AUTOSAR SHE specification
// including load key functions

void sm_init_key(sm_key_id_t key_num);

static void set_master_ecu_key(const sm_block_t *key)
{
    sm_sw_nvram_fs_ptr->key_slots[1].key.words[0] = key->words[0];
    sm_sw_nvram_fs_ptr->key_slots[1].key.words[1] = key->words[1];
    sm_sw_nvram_fs_ptr->key_slots[1].key.words[2] = key->words[2];
    sm_sw_nvram_fs_ptr->key_slots[1].key.words[3] = key->words[3];
    sm_sw_nvram_fs_ptr->key_slots[1].counter = 0;
    // FIXME what are the permissions for the ECU master key?
    // sm_sw_nvram_fs_ptr->key_slots[1].flags = authentication_key ? SHE_FLAG_KEY_USAGE : 0;

    // Set up the key in the table (including cache of roundkey expansion if necessaary)
    sm_init_key(1);
}

// Test CMAC vectors
void test3(void)
{
    printf("Testing CMAC checks\n");
    printf("===================\n");

    she_errorcode_t rc;

    sm_block_t cmac_key = {.bytes = {0x2b, 0x7e, 0x15, 0x16,
                                     0x28, 0xae, 0xd2, 0xa6,
                                     0xab, 0xf7, 0x15, 0x88,
                                     0x09, 0xcf, 0x4f, 0x3c}};

    sm_sw_nvram_backdoor_set_key(SHE_KEY_3, &cmac_key, true);

    bytes16_t message1 = {.bytes = {0x6b, 0xc1, 0xbe, 0xe2,                        
                                    0x2e, 0x40, 0x9f, 0x96,
                                    0xe9, 0x3d, 0x7e, 0x11,
                                    0x73, 0x93, 0x17, 0x2a}};

    sm_block_t mac;
    sm_init_rng();

    printf("Generating MAC (1)\n");
    rc = sm_generate_mac(SHE_KEY_3, &message1.word, 128U, &mac);
    if (rc) {
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
    }

    sm_block_t expected_mac = {.bytes = {0x07, 0x0a, 0x16, 0xb4,
                                         0x6b, 0x4d, 0x41, 0x44,
                                         0xf7, 0x9b, 0xdd, 0x9d,
                                         0xd0, 0x4a, 0x28, 0x7c}};

    printf("Expected MAC: ");
    printf_block(&expected_mac);
    printf("Actual MAC:   ");
    printf_block(&mac);

    if (!block_equals(&expected_mac, &mac)) {
        printf("TEST FAILED\n");
        exit(1);
    }

    // MAC is ce0cbf17 38f4df64 28b1d93b f12081c9
    // for a 2 block message of:
    //
    // 6bc1bee2 2e409f96 e93d7e11 7393172a
    // ae2d8a57 1e03ac9c 9eb76fac 45af8e51

    bytes32_t message2 = {.bytes = {0x6b, 0xc1, 0xbe, 0xe2,
                                    0x2e, 0x40, 0x9f, 0x96,
                                    0xe9, 0x3d, 0x7e, 0x11,
                                    0x73, 0x93, 0x17, 0x2a,
                                    0xae, 0x2d, 0x8a, 0x57,
                                    0x1e, 0x03, 0xac, 0x9c,
                                    0x9e, 0xb7, 0x6f, 0xac,
                                    0x45, 0xaf, 0x8e, 0x51}};
                                                                                                                                                                                                                                                       
    printf("Generating MAC (2)\n");

    rc = sm_generate_mac(SHE_KEY_3, &message2.word, 256U, &mac);
    if (rc) {
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
    }
    expected_mac = (sm_block_t) {.bytes = {0xce, 0x0c, 0xbf, 0x17,                                        
                                           0x38, 0xf4, 0xdf, 0x64,
                                           0x28, 0xb1, 0xd9, 0x3b,
                                           0xf1, 0x20, 0x81, 0xc9}};

    printf("Expected MAC: ");
    printf_block(&expected_mac);
    printf("Actual MAC:   ");
    printf_block(&mac);
    if (!block_equals(&expected_mac, &mac)) {
        printf("TEST FAILED\n");
        exit(1);
    }

    printf("Generating MAC (3)\n");
    // Check that CMAC with the 0x87 tweak works
    expected_mac = (sm_block_t) {.bytes = {0xed, 0x3c, 0x4c, 0x25, 0xd3, 0x13, 0xb0, 0x24,
                                           0xf7, 0xed, 0x12, 0x70, 0xe7, 0xfe, 0x40, 0xe4}};

    sm_block_t key_0x87 = {.bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04}};

    message2 = (bytes32_t) {.bytes = {0x01, 0x02, 0x03, 0x04,
                                      0x05, 0x06, 0x07, 0x08,
                                      0x09, 0x0a, 0x0b, 0x0c,
                                      0x0d, 0x0e, 0x0f, 0x10,
                                      0x11, 0x12, 0x13, 0x14,
                                      0x15, 0x16, 0x17, 0x18,
                                      0x19, 0x1a, 0x1b, 0x1c,
                                      0x1d, 0x1e, 0x1f, 0x20}};

    sm_sw_nvram_backdoor_set_key(SHE_KEY_3, &key_0x87, true);
    rc = sm_generate_mac(SHE_KEY_3, &message2.word, 256U, &mac);
    if (rc) {
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
    }

    printf_she_errorcode_t(rc);
    printf("Expected MAC: ");
    printf_block(&expected_mac);
    printf("Actual MAC:   ");
    printf_block(&mac);

    if (!block_equals(&expected_mac, &mac)) {
        printf("TEST FAILED\n");
        exit(1);
    }
}


// Test memory update protocol
void test4(void)
{
    printf("Testing memory update protocol\n");
    printf("==============================\n");

    she_errorcode_t rc;

    sm_block_t key_new = {.bytes = {0x0f, 0x0e, 0x0d, 0x0c,
                                    0x0b, 0x0a, 0x09, 0x08,
                                    0x07, 0x06, 0x05, 0x04,
                                    0x03, 0x02, 0x01, 0x00}};

    sm_block_t auth_key = {.bytes = {0x00, 0x01, 0x02, 0x03,
                                     0x04, 0x05, 0x06, 0x07,
                                     0x08, 0x09, 0x0a, 0x0b,
                                     0x0c, 0x0d, 0x0e, 0x0f}};


    // uint8_t id = 0x04U;         // New key goes into slot 4
    // uint8_t f_id = 0x00U;       // New flags (none set)
    // uint32_t counter_id = 0x1;  // New counter for key 4

    // Set the master ECU key
    set_master_ecu_key(&auth_key);

    printf_block(&sm_sw_nvram_fs_ptr->key_slots[1].key);


    // 120 bit UID of HSM
    test_uid[0] = 0x00;
    test_uid[1] = 0x00;
    test_uid[2] = 0x00;
    test_uid[3] = 0x00;
    test_uid[4] = 0x00;
    test_uid[5] = 0x00;
    test_uid[6] = 0x00;
    test_uid[7] = 0x00;
    test_uid[8] = 0x00;
    test_uid[9] = 0x00;
    test_uid[10] = 0x00;
    test_uid[11] = 0x00;
    test_uid[12] = 0x00;
    test_uid[13] = 0x00;
    test_uid[14] = 0x01U;

    sm_block_t m1 = {.bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x41}};
    sm_block_t m2_0 = {.bytes = {0x2b, 0x11, 0x1e, 0x2d, 0x93, 0xf4, 0x86, 0x56, 0x6b, 0xcb, 0xba, 0x1d, 0x7f, 0x7a, 0x97, 0x97}};
    sm_block_t m2_1 = {.bytes = {0xc9, 0x46, 0x43, 0xb0, 0x50, 0xfc, 0x5d, 0x4d, 0x7d, 0xe1, 0x4c, 0xff, 0x68, 0x22, 0x03, 0xc3}};

    sm_block_t m3 = {.bytes = {0xb9, 0xd7, 0x45, 0xe5, 0xac, 0xe7, 0xd4, 0x18, 0x60, 0xbc, 0x63, 0xc2, 0xb9, 0xf5, 0xbb, 0x46}};

    sm_block_t m4_0;
    sm_block_t m4_1;
    
    sm_block_t m5;

    sm_block_t expected_m4_0 = {.bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x41}};
    sm_block_t expected_m4_1 = {.bytes = {0xb4, 0x72, 0xe8, 0xd8, 0x72, 0x7d, 0x70, 0xd5, 0x72, 0x95, 0xe7, 0x48, 0x49, 0xa2, 0x79, 0x17}};
    sm_block_t expected_m5 = {.bytes = {0x82, 0x0d, 0x8d, 0x95, 0xdc, 0x11, 0xb4, 0x66, 0x88, 0x78, 0x16, 0x0c, 0xb2, 0xa4, 0xe2, 0x3e}};

    // Initialize HSM
    sm_init_rng();
    
    // Load the key into the system
    rc = sm_load_key(&m1, &m2_0, &m2_1, &m3, &m4_0, &m4_1, &m5);
    if (rc) {
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
    }

    // Check key loaded into slot 4 is the expected key
    printf("Key 4:\n");
    printf_block(&sm_sw_nvram_fs_ptr->key_slots[4].key);
    printf("Counter 4: %d\n", sm_sw_nvram_fs_ptr->key_slots[4].counter);
    printf("Flags: %d\n", sm_sw_nvram_fs_ptr->key_slots[4].flags);

    // Check M4 and M5 against expected values
    printf("M4:\n");
    printf_block(&m4_0);
    printf_block(&m4_1);
    printf("M5:\n");
    printf_block(&m5);

    if (!block_equals(&expected_m4_0, &m4_0)) {
        printf("m4_0 mismatch\n");
        printf("TEST FAILED\n");
        exit(1);
    }
    if (!block_equals(&expected_m4_1, &m4_1)) {
        printf("m4_1 mismatch\n");
        printf("TEST FAILED\n");
        exit(1);
    }
    if (!block_equals(&expected_m5, &m5)) {
        printf("m5 mismatch\n");
        printf("TEST FAILED\n");
        exit(1);
    }
}


int main(void)
{
    printf("Running tests..\n");
    test3();
    test4();

    printf("============\n");
    printf("TESTS PASSED\n");
}
