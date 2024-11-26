// Secure Hardware Extensions (SHE) Hardware Security Module (HSM) API
//
// API for NVRAM callbacks to application environment
//
// Copyright (C) 2016-2022 Canis Automotive Labs Ltd.
//
// This software is licensed according to the APACHE LICENSE 2.0:
//
// https://www.apache.org/licenses/LICENSE-2.0.txt

#ifndef NVRAM_H
#define NVRAM_H

#include "she.h"

#define SM_SW_NUM_KEYS                              (16U)

// This is what goes into NVRAM
typedef struct {
    sm_block_t key;                                 // We store just the 128-bit AES keys in NVRAM
    uint32_t counter;                               // 28 bits, saturating add
    uint8_t flags;                                  // 5:0 contains SHE flags, bit 7 == empty slot flag
} sm_sw_nvram_key_slot_t;

typedef struct {
    sm_block_t prng_seed;                           // The seed for the CSPRNG is stored between sessions
    sm_sw_nvram_key_slot_t key_slots[SM_SW_NUM_KEYS];
    uint32_t write_count;                           // Exclusive use by NVRAM driver
    uint32_t crc;                                   // Exclusive use by NVRAM driver
} sm_sw_nvram_fs_t;

// This points to an external structure that will be included into the atomic "file system" of the
// target device
extern sm_sw_nvram_fs_t *sm_sw_nvram_fs_ptr;

// Callbacks to load and store the key slots (typically there will be a flush operation after
// each key load transaction)
she_errorcode_t sm_sw_callback_nvram_load_key_slots(void);
she_errorcode_t sm_sw_callback_nvram_store_key_slots(void);

// HSM asks for the unique 120 bit UID for this device (15 bytes)
she_errorcode_t sm_sw_callback_nvram_get_uid(uint8_t *uid);

// Call to set the NVRAM cache to a factory default, which can then be written to NVRAM
// Sets the SECRET_KEY, which "has to be inserted during chip fabrication by the semiconductor
// manufacturer and should not be stored outside of SHE"
//
// This is the master key for the chip. Typically, the provisioning system of the platform will
// make this call when first settting up a system.
she_errorcode_t sm_sw_nvram_factory_reset(const sm_block_t *secret_key);

// Backdoor call to set an encryption key
// This API is deprecated and will be replaced by the SHE mechanism for loading a key
she_errorcode_t sm_sw_nvram_backdoor_set_key(sm_key_id_t key_number, const sm_block_t *key, bool authentication_key);

#endif // NVRAM_H
