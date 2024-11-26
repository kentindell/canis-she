// Hardware Security module API
//
// Copyright (C) 2016-2022 Canis Automotive Labs Ltd.
//
// This defines a set of standard functions for accessing a security module
//
// This software is licensed according to the APACHE LICENSE 2.0:
//
// https://www.apache.org/licenses/LICENSE-2.0.txt
//
/// \brief Security Module API
/// \author Ken Tindell
/// \date 02/11/16

#ifndef SM_HSM_H
#define SM_HSM_H

#include <stdint.h>
#include <stdbool.h>

#define SHE_SECRET_KEY                          (0U)
#define SHE_MASTER_ECU_KEY                      (1U)
#define SHE_BOOT_MAC_KEY                        (2U)
#define SHE_BOOT_MAC                            (3U)
#define SHE_KEY_1                               (4U)
#define SHE_KEY_2                               (5U)
#define SHE_KEY_3                               (6U)
#define SHE_KEY_4                               (7U)
#define SHE_KEY_5                               (8U)
#define SHE_KEY_6                               (9U)
#define SHE_KEY_7                               (10U)
#define SHE_KEY_8                               (11U)
#define SHE_KEY_9                               (12U)
#define SHE_KEY_10                              (13U)
#define SHE_RESERVED                            (14U)
#define SHE_RAM_KEY                             (15U)

// Status flags
#define SHE_BUSY                                (1U << 0)
#define SHE_SECURE_BOOT                         (1U << 1)
#define SHE_BOOT_INIT                           (1U << 2)
#define SHE_BOOT_FINISHED                       (1U << 3)
#define SHE_BOOT_OK                             (1U << 4)
#define SHE_RND_INIT                            (1U << 5)
#define SHE_EXT_DEBUGGER                        (1U << 6)
#define SHE_INT_DEBUGGER                        (1U << 7)

// Key flags
#define SHE_FLAG_WRITE_PROTECTION_offset        (5U)
#define SHE_FLAG_BOOT_PROTECTION_offset         (4U)
#define SHE_FLAG_DEBUGGER_PROTECTION_offset     (3U)
#define SHE_FLAG_KEY_USAGE_offset               (2U)
#define SHE_FLAG_WILDCARD_offset                (1U)
#define SHE_FLAG_VERIFY_ONLY_offset             (0U)

#define SHE_FLAG_WRITE_PROTECTION               (1U << SHE_FLAG_WRITE_PROTECTION_offset)
#define SHE_FLAG_BOOT_PROTECTION                (1U << SHE_FLAG_BOOT_PROTECTION_offset)
#define SHE_FLAG_DEBUGGER_PROTECTION            (1U << SHE_FLAG_DEBUGGER_PROTECTION_offset)
#define SHE_FLAG_KEY_USAGE                      (1U << SHE_FLAG_KEY_USAGE_offset)
#define SHE_FLAG_WILDCARD                       (1U << SHE_FLAG_WILDCARD_offset)
#define SHE_FLAG_VERIFY_ONLY                    (1U << SHE_FLAG_VERIFY_ONLY_offset)

typedef enum {
    SHE_ERC_NO_ERROR = 0,
    SHE_ERC_SEQUENCE_ERROR,
    SHE_ERC_KEY_NOT_AVAILABLE,
    SHE_ERC_KEY_INVALID,
    SHE_ERC_KEY_EMPTY,
    SHE_ERC_MEMORY_FAILURE,
    SHE_ERC_BUSY,
    SHE_ERC_GENERAL_ERROR,
    SHE_ERC_KEY_WRITE_PROTECTED,
    SHE_ERC_KEY_UPDATE_ERROR,
    SHE_ERC_RNG_SEED
} she_errorcode_t;

typedef union {
    uint8_t bytes[16];
    uint32_t words[4];
} sm_block_t;

typedef uint8_t sm_key_id_t;    // 0-15

// Checks that the platform is compiled correctly on the target device
she_errorcode_t sm_platform_check(void);

// Key permissions: there is a permissions matrix for keys that permits them to be used for
// certain operations, so a key may be programmed to only verify a MAC or to only generate a MAC,
// and keys can be set not to be used for both a MAC and encryption.

// Encrypts a block using a specific key. Maps on to the SHE command CMD_ENC_ECB.
// This is only valid for the user keys and the RAM key.
she_errorcode_t sm_enc_ecb(sm_key_id_t key_id,
                           const sm_block_t *plaintext,
                           sm_block_t *ciphertext);

// This uses the FIPS CMAC. The API checks for key permissions: a key is either used for AES encryption/decryption
// or it is used for CMAC generation (the RAM key is general purpose so that the module can be used as
// a crypto accelerator).
//
// This maps on to the SHE CMD_GENERATE_MAC command (but ensures that the addendum words are included in
// the MAC - the API is structured this way to allow certain 32-bit values to included in a MAC without copying
// to contiguous memory)
//
// This is only valid for keys with the correct usage permissions set
// The message length is in bits
// There may be implementation restrictions of the message length value
she_errorcode_t sm_generate_mac(sm_key_id_t key_id,
                                const uint32_t *message,
                                uint32_t message_length,
                                sm_block_t *mac);

// Maps on to the SHE command CMD_VERIFY_MAC.
// This is only valid for the user keys and the RAM key.
// There may be implementation restrictions of the MAC length value
she_errorcode_t sm_verify_mac(sm_key_id_t key_id,
                              const uint32_t *message,
                              uint32_t message_length,
                              const sm_block_t *mac,
                              uint8_t mac_length,
                              bool *verification_status);

// Maps on to the SHE 2.0 command CMD_INIT_GCM.
// This initializes the AES-GCM function with the IV
she_errorcode_t sm_enc_aes_gcm_init(sm_key_id_t key_id,
                                    const sm_block_t *iv);

// Maps on to the SHE 2.0 command CMD_GCM_AAD.
// This adds additional authenticated data
she_errorcode_t sm_enc_aes_gcm_aad(sm_key_id_t key_id,
                                   const sm_block_t *aad);


// Maps on to the SHE 2.0 command CMD_GCM_ENC_DATA.
// This encrypts plaintext
she_errorcode_t sm_enc_aes_gcm_enc_data(sm_key_id_t key_id,
                                        const sm_block_t *plaintext,
                                        sm_block_t *ciphertext);

// Maps on to the SHE 2.0 command CMD_GCM_DEC_DATA.
// This decrypts ciphertext
she_errorcode_t sm_enc_aes_gcm_dec_data(sm_key_id_t key_id,
                                        const sm_block_t *ciphertext,
                                        sm_block_t *plaintext);

// Maps on to the SHE 2.0 command CMD_GCM_TAG.
// This produces the AEAD tag
she_errorcode_t sm_enc_aes_gcm_tag(sm_key_id_t key_id,
                                   const sm_block_t *tag);

// This rolls the seed around to the next one in the sequence (the seed is a 128-bit block)
// and ensures it is stored atomically in non-volatile storage; the call does not succeed until the store
// is successful, and this should act as a gate on all other functionality of the security module (re-using
// random numbers is a severe vulnerability). Maps on to the SHE command CMD_INIT_RNG.
she_errorcode_t sm_init_rng(void);

// Returns a random number (this is an operation using the secret key and the CSPRNG state produced
// from the seed). Maps on to the SHE command CMD_RND.
she_errorcode_t sm_rnd(sm_block_t *rn);

#endif //SM_HSM_H
