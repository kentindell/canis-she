// AES encryption support
//
// This software is licensed according to the APACHE LICENSE 2.0:
//
// https://www.apache.org/licenses/LICENSE-2.0.txt
//
#include "swshe.h"

// We put these constants in RAM so accesses are achieved in constant time on an MCU
CONST uint32_t sm_round_constants[10] = {
    //lint --e{843}  suppress "could be declared as const"
    AES_CONST(0x00000001U),
    AES_CONST(0x00000002U),
    AES_CONST(0x00000004U),
    AES_CONST(0x00000008U),
    AES_CONST(0x00000010U),
    AES_CONST(0x00000020U),
    AES_CONST(0x00000040U),
    AES_CONST(0x00000080U),
    AES_CONST(0x0000001bU),
    AES_CONST(0x00000036U),
};

// Put this in RAM to get constant time access to it
// #if !defined(__LINT__)
// CONST uint32_t sm_forward_lookup[256] __attribute__ (( nocommon )) = {
// #else
//lint -e{843}  suppress "could be declared as const"
// Cannot use static CONST because the compiler puts into ROM regardless of
CONST uint32_t sm_forward_lookup[256] = {
// #endif
    AES_CONST(0xa56363c6U), AES_CONST(0x847c7cf8U), AES_CONST(0x997777eeU), AES_CONST(0x8d7b7bf6U),
    AES_CONST(0x0df2f2ffU), AES_CONST(0xbd6b6bd6U), AES_CONST(0xb16f6fdeU), AES_CONST(0x54c5c591U),
    AES_CONST(0x50303060U), AES_CONST(0x03010102U), AES_CONST(0xa96767ceU), AES_CONST(0x7d2b2b56U),
    AES_CONST(0x19fefee7U), AES_CONST(0x62d7d7b5U), AES_CONST(0xe6abab4dU), AES_CONST(0x9a7676ecU),
    AES_CONST(0x45caca8fU), AES_CONST(0x9d82821fU), AES_CONST(0x40c9c989U), AES_CONST(0x877d7dfaU),
    AES_CONST(0x15fafaefU), AES_CONST(0xeb5959b2U), AES_CONST(0xc947478eU), AES_CONST(0x0bf0f0fbU),
    AES_CONST(0xecadad41U), AES_CONST(0x67d4d4b3U), AES_CONST(0xfda2a25fU), AES_CONST(0xeaafaf45U),
    AES_CONST(0xbf9c9c23U), AES_CONST(0xf7a4a453U), AES_CONST(0x967272e4U), AES_CONST(0x5bc0c09bU),
    AES_CONST(0xc2b7b775U), AES_CONST(0x1cfdfde1U), AES_CONST(0xae93933dU), AES_CONST(0x6a26264cU),
    AES_CONST(0x5a36366cU), AES_CONST(0x413f3f7eU), AES_CONST(0x02f7f7f5U), AES_CONST(0x4fcccc83U),
    AES_CONST(0x5c343468U), AES_CONST(0xf4a5a551U), AES_CONST(0x34e5e5d1U), AES_CONST(0x08f1f1f9U),
    AES_CONST(0x937171e2U), AES_CONST(0x73d8d8abU), AES_CONST(0x53313162U), AES_CONST(0x3f15152aU),
    AES_CONST(0x0c040408U), AES_CONST(0x52c7c795U), AES_CONST(0x65232346U), AES_CONST(0x5ec3c39dU),
    AES_CONST(0x28181830U), AES_CONST(0xa1969637U), AES_CONST(0x0f05050aU), AES_CONST(0xb59a9a2fU),
    AES_CONST(0x0907070eU), AES_CONST(0x36121224U), AES_CONST(0x9b80801bU), AES_CONST(0x3de2e2dfU),
    AES_CONST(0x26ebebcdU), AES_CONST(0x6927274eU), AES_CONST(0xcdb2b27fU), AES_CONST(0x9f7575eaU),
    AES_CONST(0x1b090912U), AES_CONST(0x9e83831dU), AES_CONST(0x742c2c58U), AES_CONST(0x2e1a1a34U),
    AES_CONST(0x2d1b1b36U), AES_CONST(0xb26e6edcU), AES_CONST(0xee5a5ab4U), AES_CONST(0xfba0a05bU),
    AES_CONST(0xf65252a4U), AES_CONST(0x4d3b3b76U), AES_CONST(0x61d6d6b7U), AES_CONST(0xceb3b37dU),
    AES_CONST(0x7b292952U), AES_CONST(0x3ee3e3ddU), AES_CONST(0x712f2f5eU), AES_CONST(0x97848413U),
    AES_CONST(0xf55353a6U), AES_CONST(0x68d1d1b9U), AES_CONST(0x00000000U), AES_CONST(0x2cededc1U),
    AES_CONST(0x60202040U), AES_CONST(0x1ffcfce3U), AES_CONST(0xc8b1b179U), AES_CONST(0xed5b5bb6U),
    AES_CONST(0xbe6a6ad4U), AES_CONST(0x46cbcb8dU), AES_CONST(0xd9bebe67U), AES_CONST(0x4b393972U),
    AES_CONST(0xde4a4a94U), AES_CONST(0xd44c4c98U), AES_CONST(0xe85858b0U), AES_CONST(0x4acfcf85U),
    AES_CONST(0x6bd0d0bbU), AES_CONST(0x2aefefc5U), AES_CONST(0xe5aaaa4fU), AES_CONST(0x16fbfbedU),
    AES_CONST(0xc5434386U), AES_CONST(0xd74d4d9aU), AES_CONST(0x55333366U), AES_CONST(0x94858511U),
    AES_CONST(0xcf45458aU), AES_CONST(0x10f9f9e9U), AES_CONST(0x06020204U), AES_CONST(0x817f7ffeU),
    AES_CONST(0xf05050a0U), AES_CONST(0x443c3c78U), AES_CONST(0xba9f9f25U), AES_CONST(0xe3a8a84bU),
    AES_CONST(0xf35151a2U), AES_CONST(0xfea3a35dU), AES_CONST(0xc0404080U), AES_CONST(0x8a8f8f05U),
    AES_CONST(0xad92923fU), AES_CONST(0xbc9d9d21U), AES_CONST(0x48383870U), AES_CONST(0x04f5f5f1U),
    AES_CONST(0xdfbcbc63U), AES_CONST(0xc1b6b677U), AES_CONST(0x75dadaafU), AES_CONST(0x63212142U),
    AES_CONST(0x30101020U), AES_CONST(0x1affffe5U), AES_CONST(0x0ef3f3fdU), AES_CONST(0x6dd2d2bfU),
    AES_CONST(0x4ccdcd81U), AES_CONST(0x140c0c18U), AES_CONST(0x35131326U), AES_CONST(0x2fececc3U),
    AES_CONST(0xe15f5fbeU), AES_CONST(0xa2979735U), AES_CONST(0xcc444488U), AES_CONST(0x3917172eU),
    AES_CONST(0x57c4c493U), AES_CONST(0xf2a7a755U), AES_CONST(0x827e7efcU), AES_CONST(0x473d3d7aU),
    AES_CONST(0xac6464c8U), AES_CONST(0xe75d5dbaU), AES_CONST(0x2b191932U), AES_CONST(0x957373e6U),
    AES_CONST(0xa06060c0U), AES_CONST(0x98818119U), AES_CONST(0xd14f4f9eU), AES_CONST(0x7fdcdca3U),
    AES_CONST(0x66222244U), AES_CONST(0x7e2a2a54U), AES_CONST(0xab90903bU), AES_CONST(0x8388880bU),
    AES_CONST(0xca46468cU), AES_CONST(0x29eeeec7U), AES_CONST(0xd3b8b86bU), AES_CONST(0x3c141428U),
    AES_CONST(0x79dedea7U), AES_CONST(0xe25e5ebcU), AES_CONST(0x1d0b0b16U), AES_CONST(0x76dbdbadU),
    AES_CONST(0x3be0e0dbU), AES_CONST(0x56323264U), AES_CONST(0x4e3a3a74U), AES_CONST(0x1e0a0a14U),
    AES_CONST(0xdb494992U), AES_CONST(0x0a06060cU), AES_CONST(0x6c242448U), AES_CONST(0xe45c5cb8U),
    AES_CONST(0x5dc2c29fU), AES_CONST(0x6ed3d3bdU), AES_CONST(0xefacac43U), AES_CONST(0xa66262c4U),
    AES_CONST(0xa8919139U), AES_CONST(0xa4959531U), AES_CONST(0x37e4e4d3U), AES_CONST(0x8b7979f2U),
    AES_CONST(0x32e7e7d5U), AES_CONST(0x43c8c88bU), AES_CONST(0x5937376eU), AES_CONST(0xb76d6ddaU),
    AES_CONST(0x8c8d8d01U), AES_CONST(0x64d5d5b1U), AES_CONST(0xd24e4e9cU), AES_CONST(0xe0a9a949U),
    AES_CONST(0xb46c6cd8U), AES_CONST(0xfa5656acU), AES_CONST(0x07f4f4f3U), AES_CONST(0x25eaeacfU),
    AES_CONST(0xaf6565caU), AES_CONST(0x8e7a7af4U), AES_CONST(0xe9aeae47U), AES_CONST(0x18080810U),
    AES_CONST(0xd5baba6fU), AES_CONST(0x887878f0U), AES_CONST(0x6f25254aU), AES_CONST(0x722e2e5cU),
    AES_CONST(0x241c1c38U), AES_CONST(0xf1a6a657U), AES_CONST(0xc7b4b473U), AES_CONST(0x51c6c697U),
    AES_CONST(0x23e8e8cbU), AES_CONST(0x7cdddda1U), AES_CONST(0x9c7474e8U), AES_CONST(0x211f1f3eU),
    AES_CONST(0xdd4b4b96U), AES_CONST(0xdcbdbd61U), AES_CONST(0x868b8b0dU), AES_CONST(0x858a8a0fU),
    AES_CONST(0x907070e0U), AES_CONST(0x423e3e7cU), AES_CONST(0xc4b5b571U), AES_CONST(0xaa6666ccU),
    AES_CONST(0xd8484890U), AES_CONST(0x05030306U), AES_CONST(0x01f6f6f7U), AES_CONST(0x120e0e1cU),
    AES_CONST(0xa36161c2U), AES_CONST(0x5f35356aU), AES_CONST(0xf95757aeU), AES_CONST(0xd0b9b969U),
    AES_CONST(0x91868617U), AES_CONST(0x58c1c199U), AES_CONST(0x271d1d3aU), AES_CONST(0xb99e9e27U),
    AES_CONST(0x38e1e1d9U), AES_CONST(0x13f8f8ebU), AES_CONST(0xb398982bU), AES_CONST(0x33111122U),
    AES_CONST(0xbb6969d2U), AES_CONST(0x70d9d9a9U), AES_CONST(0x898e8e07U), AES_CONST(0xa7949433U),
    AES_CONST(0xb69b9b2dU), AES_CONST(0x221e1e3cU), AES_CONST(0x92878715U), AES_CONST(0x20e9e9c9U),
    AES_CONST(0x49cece87U), AES_CONST(0xff5555aaU), AES_CONST(0x78282850U), AES_CONST(0x7adfdfa5U),
    AES_CONST(0x8f8c8c03U), AES_CONST(0xf8a1a159U), AES_CONST(0x80898909U), AES_CONST(0x170d0d1aU),
    AES_CONST(0xdabfbf65U), AES_CONST(0x31e6e6d7U), AES_CONST(0xc6424284U), AES_CONST(0xb86868d0U),
    AES_CONST(0xc3414182U), AES_CONST(0xb0999929U), AES_CONST(0x772d2d5aU), AES_CONST(0x110f0f1eU),
    AES_CONST(0xcbb0b07bU), AES_CONST(0xfc5454a8U), AES_CONST(0xd6bbbb6dU), AES_CONST(0x3a16162cU),
};

uint8_t FAST_CODE sm_sbox(uint8_t n)
{
    return (sm_forward_lookup[n] >> 8) & 0xffU;
}

#define SBOX32(n)       (ror8_byte(sm_forward_lookup[(uint8_t)(n)]))

// Called to expand the AES key into the round key. This can be done once at boot to save CPU time, 
// or done on the fly to put the expanded key on to the stack etc.
//
// Note that with a pure hardware AES accelerator key expansion is done in hardware and there will be no use for this
// code.
void FAST_CODE sm_expand_key_enc(const sm_block_t *key, sm_aes_enc_roundkey_t *roundkey)
{
    uint32_t *rk = roundkey->roundkey_words;

    // Copy the AES key words into the round key array.
    rk[0] = key->words[0];
    rk[1] = key->words[1];
    rk[2] = key->words[2];
    rk[3] = key->words[3];

    for (uint32_t i = 0; i < 10U; i++) {
#ifdef SM_CPU_BIG_ENDIAN
        rk[4] = rk[0] ^ sm_round_constants[i] ^ (SBOX32(WORD_7_0(rk[3])) << 8) ^ (SBOX32(WORD_15_8(rk[3])) << 16) ^ (SBOX32(WORD_23_16(rk[3])) << 24) ^ (SBOX32(WORD_31_24(rk[3])));
#else
        rk[4] = rk[0] ^ sm_round_constants[i] ^ (SBOX32(WORD_15_8(rk[3]))) ^ (SBOX32(WORD_23_16(rk[3])) << 8) ^ (SBOX32(WORD_31_24(rk[3])) << 16) ^ (SBOX32(WORD_7_0(rk[3])) << 24);
#endif
        rk[5] = rk[1] ^ rk[4];
        rk[6] = rk[2] ^ rk[5];
        rk[7] = rk[3] ^ rk[6];
        
        rk += 4U;
    }
}

//lint -e{835}  suppress "A zero has been given as argument to operator +"
//static void __attribute__( ( long_call, section(".ramfunc") ) ) forward_round(uint32_t x[], const uint8_t y[], const uint32_t rk[]) {
static void FAST_CODE forward_round(uint32_t x[], const uint8_t y[], const uint32_t rk[]) {
#ifdef SM_CPU_BIG_ENDIAN
    x[0] = rk[0] ^ sm_forward_lookup[y[0  + B_7_0]] ^ ror8(sm_forward_lookup[y[4  + B_15_8]]) ^ ror16(sm_forward_lookup[y[8  + B_23_16]]) ^ ror24(sm_forward_lookup[y[12 + B_31_24]]);
    x[1] = rk[1] ^ sm_forward_lookup[y[4  + B_7_0]] ^ ror8(sm_forward_lookup[y[8  + B_15_8]]) ^ ror16(sm_forward_lookup[y[12 + B_23_16]]) ^ ror24(sm_forward_lookup[y[0  + B_31_24]]);
    x[2] = rk[2] ^ sm_forward_lookup[y[8  + B_7_0]] ^ ror8(sm_forward_lookup[y[12 + B_15_8]]) ^ ror16(sm_forward_lookup[y[0  + B_23_16]]) ^ ror24(sm_forward_lookup[y[4  + B_31_24]]);
    x[3] = rk[3] ^ sm_forward_lookup[y[12 + B_7_0]] ^ ror8(sm_forward_lookup[y[0  + B_15_8]]) ^ ror16(sm_forward_lookup[y[4  + B_23_16]]) ^ ror24(sm_forward_lookup[y[8  + B_31_24]]);
#else
    x[0] = rk[0] ^ sm_forward_lookup[y[0  + B_7_0]] ^ ror24(sm_forward_lookup[y[4  + B_15_8]]) ^ ror16(sm_forward_lookup[y[8  + B_23_16]]) ^ ror8(sm_forward_lookup[y[12 + B_31_24]]);
    x[1] = rk[1] ^ sm_forward_lookup[y[4  + B_7_0]] ^ ror24(sm_forward_lookup[y[8  + B_15_8]]) ^ ror16(sm_forward_lookup[y[12 + B_23_16]]) ^ ror8(sm_forward_lookup[y[0  + B_31_24]]);
    x[2] = rk[2] ^ sm_forward_lookup[y[8  + B_7_0]] ^ ror24(sm_forward_lookup[y[12 + B_15_8]]) ^ ror16(sm_forward_lookup[y[0  + B_23_16]]) ^ ror8(sm_forward_lookup[y[4  + B_31_24]]);
    x[3] = rk[3] ^ sm_forward_lookup[y[12 + B_7_0]] ^ ror24(sm_forward_lookup[y[0  + B_15_8]]) ^ ror16(sm_forward_lookup[y[4  + B_23_16]]) ^ ror8(sm_forward_lookup[y[8  + B_31_24]]);
#endif
}

//lint -e{835}  suppress "A zero has been given as argument to operator +"
static void forward_round_last(uint32_t x[], const uint8_t y[], const uint32_t rk[]) {
#ifdef SM_CPU_BIG_ENDIAN
    x[0] = rk[0] ^ (SBOX32(y[0  + B_7_0]) << 24) ^ (SBOX32(y[4  + B_15_8]) << 16) ^ (SBOX32(y[8  + B_23_16]) <<  8) ^ (SBOX32(y[12 + B_31_24]) << 0);
    x[1] = rk[1] ^ (SBOX32(y[4  + B_7_0]) << 24) ^ (SBOX32(y[8  + B_15_8]) << 16) ^ (SBOX32(y[12 + B_23_16]) <<  8) ^ (SBOX32(y[0  + B_31_24]) << 0);
    x[2] = rk[2] ^ (SBOX32(y[8  + B_7_0]) << 24) ^ (SBOX32(y[12 + B_15_8]) << 16) ^ (SBOX32(y[0  + B_23_16]) <<  8) ^ (SBOX32(y[4  + B_31_24]) << 0);
    x[3] = rk[3] ^ (SBOX32(y[12 + B_7_0]) << 24) ^ (SBOX32(y[0  + B_15_8]) << 16) ^ (SBOX32(y[4  + B_23_16]) <<  8) ^ (SBOX32(y[8  + B_31_24]) << 0);
#else
    x[0] = rk[0] ^ (SBOX32(y[0  + B_7_0]) <<  0) ^ (SBOX32(y[4  + B_15_8]) <<  8) ^ (SBOX32(y[8  + B_23_16]) << 16) ^ (SBOX32(y[12 + B_31_24]) << 24);
    x[1] = rk[1] ^ (SBOX32(y[4  + B_7_0]) <<  0) ^ (SBOX32(y[8  + B_15_8]) <<  8) ^ (SBOX32(y[12 + B_23_16]) << 16) ^ (SBOX32(y[0  + B_31_24]) << 24);
    x[2] = rk[2] ^ (SBOX32(y[8  + B_7_0]) <<  0) ^ (SBOX32(y[12 + B_15_8]) <<  8) ^ (SBOX32(y[0  + B_23_16]) << 16) ^ (SBOX32(y[4  + B_31_24]) << 24);
    x[3] = rk[3] ^ (SBOX32(y[12 + B_7_0]) <<  0) ^ (SBOX32(y[0  + B_15_8]) <<  8) ^ (SBOX32(y[4  + B_23_16]) << 16) ^ (SBOX32(y[8  + B_31_24]) << 24);
#endif
}

//lint -restore

// Plaintext is in big-endian format
//
// For performance the following puts the function into RAM:
//
// __attribute__( ( long_call, section(".data") ) ) void encrypt(const aes_roundkey_t *roundkey, const struct aes_block *plaintext, struct aes_block *ciphertext)
void FAST_CODE sm_aes_encrypt(const sm_aes_enc_roundkey_t *roundkey, const sm_block_t *plaintext, sm_block_t *ciphertext)
{       
    uint32_t x[4];
    uint32_t y[4];

    const uint32_t *rk = roundkey->roundkey_words;

    // First round
    x[0] = plaintext->words[0] ^ rk[0];
    x[1] = plaintext->words[1] ^ rk[1];
    x[2] = plaintext->words[2] ^ rk[2];
    x[3] = plaintext->words[3] ^ rk[3];
    rk += 4U;

    // Next 9 rounds
    forward_round(y, (uint8_t *) x, rk);
    rk += 4U;
    forward_round(x, (uint8_t *) y, rk);
    rk += 4U;
    forward_round(y, (uint8_t *) x, rk);
    rk += 4U;
    forward_round(x, (uint8_t *) y, rk);
    rk += 4U;
    forward_round(y, (uint8_t *) x, rk);
    rk += 4U;
    forward_round(x, (uint8_t *) y, rk);
    rk += 4U;
    forward_round(y, (uint8_t *) x, rk);
    rk += 4U;
    forward_round(x, (uint8_t *) y, rk);
    rk += 4U;
    forward_round(y, (uint8_t *) x, rk);
    rk += 4U;
    // rk now roundkey + 40

    // Final (11th) round doesn't do the column mixing so we use a special version
    // of the forward function.
    forward_round_last(x, (uint8_t *) y, rk);

    // Return result
    ciphertext->words[0] = x[0];
    ciphertext->words[1] = x[1];
    ciphertext->words[2] = x[2];
    ciphertext->words[3] = x[3];
}

she_errorcode_t FAST_CODE sm_enc_ecb(sm_key_id_t key_id, const sm_block_t *plaintext, sm_block_t *ciphertext)
{
    ////// Cannot use API unless the SHE has been initialized //////
    if (!sm_prng_init) {
        return SHE_ERC_GENERAL_ERROR;
    }
    if (sm_sw_nvram_fs_ptr->key_slots[key_id].flags & SWSM_FLAG_EMPTY_SLOT) {
        return SHE_ERC_KEY_EMPTY;
    }
    if ((key_id < SHE_KEY_1 || key_id > SHE_KEY_10 || (sm_sw_nvram_fs_ptr->key_slots[key_id].flags & SHE_FLAG_KEY_USAGE)) && key_id != SHE_RAM_KEY) {
        return SHE_ERC_KEY_INVALID;
    }
#ifdef SM_KEY_EXPANSION_CACHED
    const sm_aes_enc_roundkey_t *roundkey = &sm_cached_key_slots[key_id].enc_roundkey;
#else
    sm_aes_enc_roundkey_t expanded_roundkey;
    sm_aes_enc_roundkey_t *roundkey = &expanded_roundkey;
    sm_expand_key_enc(&sm_sw_nvram_fs_ptr->key_slots[key_id].key, roundkey);
#endif
    sm_aes_encrypt(roundkey, plaintext, ciphertext);

    return SHE_ERC_NO_ERROR;
}
