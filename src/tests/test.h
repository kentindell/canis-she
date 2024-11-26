// Test vectors for security module
//
// Copyright (C) 2016-2022 Canis Automotive Labs Ltd.
//
// This software is licensed according to the APACHE LICENSE 2.0:
//
// https://www.apache.org/licenses/LICENSE-2.0.txt

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// HSM API
#include "../she.h"
#include "../nvram.h"

// Filled in with the test vector
extern uint8_t test_uid[];

static void inline printf_block(sm_block_t *block)
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

static inline bool block_equals(sm_block_t *a, sm_block_t *b)
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
