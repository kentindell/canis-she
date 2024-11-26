// Test emulation of the NVRAM callbacks
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

// UID that can be re-written by the tests
uint8_t test_uid[15];

// This would typically be in EEPROM or flash in a real system
static sm_sw_nvram_fs_t sm_sw_nvram_fs;       

sm_sw_nvram_fs_t *sm_sw_nvram_fs_ptr = &sm_sw_nvram_fs;

she_errorcode_t sm_sw_callback_nvram_load_key_slots(void)
{
    // The NVRAM is pre-initialized by the test harness
    return SHE_ERC_NO_ERROR;
}

she_errorcode_t sm_sw_callback_nvram_store_key_slots(void)
{
    // We don't flush to NVRAM in testing
    return SHE_ERC_NO_ERROR;
}

she_errorcode_t sm_sw_callback_nvram_get_uid(uint8_t *uid)
{
    // Return the test vector UID
    uid[0]  = test_uid[0];
    uid[1]  = test_uid[1];
    uid[2]  = test_uid[2];
    uid[3]  = test_uid[3];
    uid[4]  = test_uid[4];
    uid[5]  = test_uid[5];
    uid[6]  = test_uid[6];
    uid[7]  = test_uid[7];
    uid[8]  = test_uid[8];
    uid[9]  = test_uid[9];
    uid[10] = test_uid[10];
    uid[11] = test_uid[11];
    uid[12] = test_uid[12];
    uid[13] = test_uid[13];
    uid[14] = test_uid[14];

    return SHE_ERC_NO_ERROR;
}