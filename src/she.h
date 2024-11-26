// Secure Hardware Extensions (SHE) Hardware Security Module (HSM) API
//
// Copyright (C) 2016-2022 Canis Automotive Labs Ltd.
//
// This defines a set of standard functions for accessing a security module above those required by
// CryptoCAN
//
// This software is licensed according to the APACHE LICENSE 2.0:
//
// https://www.apache.org/licenses/LICENSE-2.0.txt

#ifndef SM_SHE_H
#define SM_SHE_H

#include "hsm.h"

she_errorcode_t sm_dec_ecb(sm_key_id_t key_id,
                           const sm_block_t *ciphertext,
                           sm_block_t *plaintext);

// In order to load a key, an authorizing key must be known:
//
// For the master key, the master key must be known
// For a user key, either the master key or the user key must be known
//
// The key distribution system has to create two keys, K1 and K2 from the authorizing key (using a compression function)
// then generate M1, M2 and M3:
//
// - M1 is the UID, the key slot to be updated, and the authorizing key slot
// - M2 is a CBC-encrypted block of a new counter for the key, the new key value, and a new set of key permissions (using key=K1, IV=0)
// - M3 is a CMAC of the M! | M2 using key=K2
//
// K1 and K2 are generated from a key distribution function KDF:
//
// KDF(K, C) = AES-MP(K | C), where K = key, C is a constant as follows:
//
// where C is defined as follows for the functions:
//
// KEY_UPDATE_ENC_C             0x01015348 45008000 00000000 000000B0 (for K1, K3)
// KEY_UPDATE_MAC_C             0x01025348 45008000 00000000 000000B0 (for K2, K4)
// DEBUG_KEY_C                  0x01035348 45008000 00000000 000000B0
// PRNG_KEY_C                   0x01045348 45008000 00000000 000000B0
// PRNG_SEED_KEY_C              0x01055348 45008000 00000000 000000B0
// PRNG_EXTENSION_C             0x80000000 00000000 00000000 00000100
//
// Key permissions are four bits:
// - Write protection (key cannot be changed)
// - Boot protection (key is disabled on boot failure)
// - Debugger protection (key is disabled if debugger connected)
// - Key usage (set if MAC, clear if AES encrypt/decrypt)
// - Wildcard (whether a wildcard UID of 0 can be used to set the key)
//
// Operation fails if:
// - MAC doesn't verify
// - Authorizing key slot is empty (unless the authorizing key and the key are the same slot)
// - Key slot is write-protected
// - New counter isn't > the old counter value (the counter is a saturating 28 bit counter)
//
// The verification message indicates to the remote key loader that the key update has taken place. This generates
// M4 and M5:
//
// K3 = KDF(K_ID, KEY_UPDATE_ENC_C)
// M4* = AES encrypt (K3, C_ID)
// M4 = UID | ID | AuthID | M4*
// K4 = KDF(K_ID, KEY_UPDATE_MAC_C)
// M5 = CMAC(K4, M4)
//
// Maps on to the SHE command CMD_LOAD_KEY.
she_errorcode_t sm_load_key(const sm_block_t *m1,
                            const sm_block_t *m2_0, 
                            const sm_block_t *m2_1, 
                            const sm_block_t *m3, 
                            sm_block_t *m4_0, 
                            sm_block_t *m4_1, 
                            sm_block_t *m5);

// This only applies to the RAM key. Maps on to the SHE command CMD_LOAD_PLAIN_KEY.
she_errorcode_t sm_load_plain_key(const sm_block_t *key);

// This converts the key into an encrypted form using the secret ROM key so that the central system can
// receive it. This can be used to form an end-to-end encryption system using the secret keys.
// Maps on to the SHE command CMD_EXPORT_RAM_KEY.
she_errorcode_t sm_export_ram_key(sm_block_t *m1,
                                  sm_block_t *m2_0,
                                  sm_block_t *m2_1,
                                  sm_block_t *m3,
                                  sm_block_t *m4_0,
                                  sm_block_t *m4_1,
                                  sm_block_t *m5);

// Merges the seed with a new source of entropy. Maps on to the SHE command CMD_EXTEND_SEED.
she_errorcode_t sm_extend_seed(const sm_block_t *entropy);

// Returns the unique ID of the device (this is used to look up keys and counters etc. in a central database).
// Maps on to the SHE command CMD_GET_ID.
//
// ID is returned in the first 15 bytes of the block `id`.
// SREG is returned directly (is also in byte 15 if the block)
//
// MAC is 0 if the master ECU key slot is empty. MAC is otherwise computed as:
//
// CMAC_KEY_MASTER_ECU_KEY(CHALLENGE|ID|SREG)
//
// where SREG is the status register of the SHE.
she_errorcode_t sm_get_id(const sm_block_t *challenge,
                          sm_block_t *id,
                          uint8_t *sreg,
                          sm_block_t *mac);

// NB: The secure boot functions are not included in this security module because this is very
// hardware-dependent and need to be accessed at a low level. Missing boot calls:
//
// sm_secure_boot()
// sm_boot_failure()
// sm_boot_ok()
//
// There are also calls to enable a debugger to connect to the device for secure debugging only
// by authorized developers.
//
// sm_debug()

// The API is synchronous: it does not return until the call has succeeded or failed. In the future
// an aynch extended API can be used to issue commands and poll for the response.
//
// sm_get_status()
// sm_cancel()

#endif // SM_SHE_H
