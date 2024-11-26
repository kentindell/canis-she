// Test vectors for security module
//
// Copyright (C) 2016-2022 Canis Automotive Labs Ltd.
//
// This software is licensed according to the APACHE LICENSE 2.0:
//
// https://www.apache.org/licenses/LICENSE-2.0.txt
//
// Compile this with:
//
// cc vectors.c ../swshe/libswshe.a -o vectors
//
// (libswshe.a is the library containing the software emulated SHE HSM)

#ifndef EMBEDDED
#include <stdio.h>
#endif

#include <stdint.h>
#include <stdlib.h>

// This vector test will check that the HSM library for a software HSM (with or without hardware
// acceleration) implements the test vectors properly.

// HSM API
#include "../she.h"
#include "../nvram.h"

#ifndef EMBEDDED
void printf_block(sm_block_t *block)
{
    uint8_t *b = (uint8_t *)(block->words);

    for (uint32_t i = 0; i < 16; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

void printf_she_errorcode_t(she_errorcode_t code)
{
    switch (code) {
        case SHE_ERC_NO_ERROR:
            printf("SHE_ERC_NO_ERROR\n");
            break;
        case SHE_ERC_SEQUENCE_ERROR:
            printf("SHE_ERC_SEQUENCE_ERROR\n");
            break;
        case SHE_ERC_KEY_NOT_AVAILABLE:
            printf("SHE_ERC_KEY_NOT_AVAILABLE\n");
            break;
        case SHE_ERC_KEY_INVALID:
            printf("SHE_ERC_KEY_INVALID\n");
            break;
        case SHE_ERC_KEY_EMPTY:
            printf("SHE_ERC_KEY_EMPTY\n");
            break;
        case SHE_ERC_MEMORY_FAILURE:
            printf("SHE_ERC_MEMORY_FAILURE\n");
            break;
        case SHE_ERC_BUSY:
            printf("SHE_ERC_BUSY\n");
            break;
        case SHE_ERC_GENERAL_ERROR:
            printf("SHE_ERC_GENERAL_ERROR\n");
            break;
        case SHE_ERC_KEY_WRITE_PROTECTED:
            printf("SHE_ERC_KEY_WRITE_PROTECTED\n");
            break;
        case SHE_ERC_KEY_UPDATE_ERROR:
            printf("SHE_ERC_KEY_UPDATE_ERROR\n");
            break;
        case SHE_ERC_RNG_SEED:
            printf("SHE_ERC_RNG_SEED\n");
            break;
        default:
            printf("UNKNOWN ERROR CODE\n");
            break;
    }
}
#endif // EMBEDDED

bool block_equals(sm_block_t *a, sm_block_t *b)
{
    if (a->words[0] == b->words[0] &&
        a->words[1] == b->words[1] &&
        a->words[2] == b->words[2] &&
        a->words[3] == b->words[3]) {
        return true;
    }
    else {
        return false;
    }
}

#ifdef EMBEDDED
volatile uint32_t sm_breakpoint = 0; // Declared so that the compiler won't optimize away
#endif

// Test platform is OK
void test1(void)
{
    she_errorcode_t rc;
    rc = sm_platform_check();
    if (rc) {
 #ifdef EMBEDDED
        // In an embedded system, put a breakpoint here in this infinite loop to see a fail
        for(;;)
            sm_breakpoint++;
 #else       
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }
}

// Test AES encrypt and decrypt against standard test vectors
void test2(void)
{
    she_errorcode_t rc;

    // Set this key to 000102030405060708090a0b0c0d0e0f
    sm_block_t key = {.bytes = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}};

    // Set this plaintext to 00112233445566778899aabbccddeeff
    sm_block_t plaintext = {.bytes = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                                      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}};

    // Expected ciphertext is 69c4e0d86a7b0430d8cdb78070b4c55a
    sm_block_t expected_ciphertext = {.bytes = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 
                                                0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a}};

#ifndef EMBEDDED
    printf("Testing AES encrypt and decrypt\n");
    printf("===============================\n");
    printf("Key:                 ");
    printf_block(&key);
    printf("Plaintext:           ");
    printf_block(&plaintext);
    printf("Expected ciphertext: ");
    printf_block(&expected_ciphertext);
#endif

    sm_sw_nvram_backdoor_set_key(SHE_KEY_2, &key, false);

    sm_block_t ciphertext;
    sm_init_rng();
    rc = sm_enc_ecb(SHE_KEY_2, &plaintext, &ciphertext);
    if (rc) {
#ifdef EMBEDDED 
        for(;;)
            sm_breakpoint++;
#else    
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }

#ifndef EMBEDDED
    printf("Actual ciphertext:   ");
    printf_block(&ciphertext);
#endif

    // Decrypt back to new plaintext
    sm_block_t plaintext2;

    rc = sm_dec_ecb(SHE_KEY_2, &ciphertext, &plaintext2);
    if (rc) {
#ifdef EMBEDDED 
        for(;;)
        ;  
#else    
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }

#ifndef EMBEDDED
    printf("Plaintext:           ");
    printf_block(&plaintext2);
#endif

    if (!block_equals(&plaintext, &plaintext2)) {
#ifdef EMBEDDED 
        for(;;)
            sm_breakpoint++; 
#else    
        printf("TEST FAILED: plaintext round trip failed\n");
        exit(1);
#endif
    }
}

typedef union {uint8_t bytes[16]; uint32_t word;} bytes16_t;
typedef union {uint8_t bytes[32]; uint32_t word;} bytes32_t;

// Test CMAC vectors
void test3(void)
{
#ifndef EMBEDDED
    printf("Testing CMAC checks\n");
    printf("===================\n");
#endif

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

#ifndef EMBEDDED
    printf("Generating MAC (1)\n");
#endif
    rc = sm_generate_mac(SHE_KEY_3, &message1.word, 128U, &mac);
    if (rc) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }

    sm_block_t expected_mac = {.bytes = {0x07, 0x0a, 0x16, 0xb4,
                                         0x6b, 0x4d, 0x41, 0x44,
                                         0xf7, 0x9b, 0xdd, 0x9d,
                                         0xd0, 0x4a, 0x28, 0x7c}};

#ifndef EMBEDDED
    printf("Expected MAC: ");
    printf_block(&expected_mac);
    printf("Actual MAC:   ");
    printf_block(&mac);
#endif

    if (!block_equals(&expected_mac, &mac)) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED\n");
        exit(1);
#endif
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
                                                                                                                                                                                                                                                       
#ifndef EMBEDDED
    printf("Generating MAC (2)\n");
#endif

    rc = sm_generate_mac(SHE_KEY_3, &message2.word, 256U, &mac);
    if (rc) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }
    expected_mac = (sm_block_t) {.bytes = {0xce, 0x0c, 0xbf, 0x17,                                        
                                           0x38, 0xf4, 0xdf, 0x64,
                                           0x28, 0xb1, 0xd9, 0x3b,
                                           0xf1, 0x20, 0x81, 0xc9}};

#ifndef EMBEDDED
    printf("Expected MAC: ");
    printf_block(&expected_mac);
    printf("Actual MAC:   ");
    printf_block(&mac);
#endif
    if (!block_equals(&expected_mac, &mac)) {
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED\n");
        exit(1);
#endif
    }

#ifndef EMBEDDED
    printf("Generating MAC (3)\n");
#endif
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
#ifdef EMBEDDED
        for(;;)
            sm_breakpoint++;
#else
        printf("TEST FAILED: unexpected return code ");
        printf_she_errorcode_t(rc);
        exit(1);
#endif
    }

#ifndef EMBEDDED
    printf_she_errorcode_t(rc);
    printf("Expected MAC: ");
    printf_block(&expected_mac);
    printf("Actual MAC:   ");
    printf_block(&mac);
#endif

    if (!block_equals(&expected_mac, &mac)) {
#ifdef EMBEDDED
        for(;;)
            ;
#else
        printf("TEST FAILED\n");
        exit(1);
#endif
    }
}

#ifdef EMBEDDED
void sm_vector_test(void)
{
    test1();
    test2();
    test3();
}

#else

int main(void)
{
    printf("Running tests..\n");

    test1();
    test2();
    test3();

    printf("============\n");
    printf("TESTS PASSED\n");
}

#endif // EMBEDDED
