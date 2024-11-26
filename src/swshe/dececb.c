// This software is licensed according to the APACHE LICENSE 2.0:
//
// https://www.apache.org/licenses/LICENSE-2.0.txt
//
// AES decryption

#include "swshe.h"

// Put this in RAM to get constant time access to it
#if !defined(__LINT__)
CONST uint32_t sm_reverse_lookup[256] __attribute__ (( nocommon )) = {
#else
        //lint -e{843}  suppress "could be declared as const"
uint32_t sm_reverse_lookup[256] = {
#endif
        AES_CONST(0x50a7f451U), AES_CONST(0x5365417eU), AES_CONST(0xc3a4171aU), AES_CONST(0x965e273aU),
        AES_CONST(0xcb6bab3bU), AES_CONST(0xf1459d1fU), AES_CONST(0xab58faacU), AES_CONST(0x9303e34bU),
        AES_CONST(0x55fa3020U), AES_CONST(0xf66d76adU), AES_CONST(0x9176cc88U), AES_CONST(0x254c02f5U),
        AES_CONST(0xfcd7e54fU), AES_CONST(0xd7cb2ac5U), AES_CONST(0x80443526U), AES_CONST(0x8fa362b5U),
        AES_CONST(0x495ab1deU), AES_CONST(0x671bba25U), AES_CONST(0x980eea45U), AES_CONST(0xe1c0fe5dU),
        AES_CONST(0x02752fc3U), AES_CONST(0x12f04c81U), AES_CONST(0xa397468dU), AES_CONST(0xc6f9d36bU),
        AES_CONST(0xe75f8f03U), AES_CONST(0x959c9215U), AES_CONST(0xeb7a6dbfU), AES_CONST(0xda595295U),
        AES_CONST(0x2d83bed4U), AES_CONST(0xd3217458U), AES_CONST(0x2969e049U), AES_CONST(0x44c8c98eU),
        AES_CONST(0x6a89c275U), AES_CONST(0x78798ef4U), AES_CONST(0x6b3e5899U), AES_CONST(0xdd71b927U),
        AES_CONST(0xb64fe1beU), AES_CONST(0x17ad88f0U), AES_CONST(0x66ac20c9U), AES_CONST(0xb43ace7dU),
        AES_CONST(0x184adf63U), AES_CONST(0x82311ae5U), AES_CONST(0x60335197U), AES_CONST(0x457f5362U),
        AES_CONST(0xe07764b1U), AES_CONST(0x84ae6bbbU), AES_CONST(0x1ca081feU), AES_CONST(0x942b08f9U),
        AES_CONST(0x58684870U), AES_CONST(0x19fd458fU), AES_CONST(0x876cde94U), AES_CONST(0xb7f87b52U),
        AES_CONST(0x23d373abU), AES_CONST(0xe2024b72U), AES_CONST(0x578f1fe3U), AES_CONST(0x2aab5566U),
        AES_CONST(0x0728ebb2U), AES_CONST(0x03c2b52fU), AES_CONST(0x9a7bc586U), AES_CONST(0xa50837d3U),
        AES_CONST(0xf2872830U), AES_CONST(0xb2a5bf23U), AES_CONST(0xba6a0302U), AES_CONST(0x5c8216edU),
        AES_CONST(0x2b1ccf8aU), AES_CONST(0x92b479a7U), AES_CONST(0xf0f207f3U), AES_CONST(0xa1e2694eU),
        AES_CONST(0xcdf4da65U), AES_CONST(0xd5be0506U), AES_CONST(0x1f6234d1U), AES_CONST(0x8afea6c4U),
        AES_CONST(0x9d532e34U), AES_CONST(0xa055f3a2U), AES_CONST(0x32e18a05U), AES_CONST(0x75ebf6a4U),
        AES_CONST(0x39ec830bU), AES_CONST(0xaaef6040U), AES_CONST(0x069f715eU), AES_CONST(0x51106ebdU),
        AES_CONST(0xf98a213eU), AES_CONST(0x3d06dd96U), AES_CONST(0xae053eddU), AES_CONST(0x46bde64dU),
        AES_CONST(0xb58d5491U), AES_CONST(0x055dc471U), AES_CONST(0x6fd40604U), AES_CONST(0xff155060U),
        AES_CONST(0x24fb9819U), AES_CONST(0x97e9bdd6U), AES_CONST(0xcc434089U), AES_CONST(0x779ed967U),
        AES_CONST(0xbd42e8b0U), AES_CONST(0x888b8907U), AES_CONST(0x385b19e7U), AES_CONST(0xdbeec879U),
        AES_CONST(0x470a7ca1U), AES_CONST(0xe90f427cU), AES_CONST(0xc91e84f8U), AES_CONST(0x00000000U),
        AES_CONST(0x83868009U), AES_CONST(0x48ed2b32U), AES_CONST(0xac70111eU), AES_CONST(0x4e725a6cU),
        AES_CONST(0xfbff0efdU), AES_CONST(0x5638850fU), AES_CONST(0x1ed5ae3dU), AES_CONST(0x27392d36U),
        AES_CONST(0x64d90f0aU), AES_CONST(0x21a65c68U), AES_CONST(0xd1545b9bU), AES_CONST(0x3a2e3624U),
        AES_CONST(0xb1670a0cU), AES_CONST(0x0fe75793U), AES_CONST(0xd296eeb4U), AES_CONST(0x9e919b1bU),
        AES_CONST(0x4fc5c080U), AES_CONST(0xa220dc61U), AES_CONST(0x694b775aU), AES_CONST(0x161a121cU),
        AES_CONST(0x0aba93e2U), AES_CONST(0xe52aa0c0U), AES_CONST(0x43e0223cU), AES_CONST(0x1d171b12U),
        AES_CONST(0x0b0d090eU), AES_CONST(0xadc78bf2U), AES_CONST(0xb9a8b62dU), AES_CONST(0xc8a91e14U),
        AES_CONST(0x8519f157U), AES_CONST(0x4c0775afU), AES_CONST(0xbbdd99eeU), AES_CONST(0xfd607fa3U),
        AES_CONST(0x9f2601f7U), AES_CONST(0xbcf5725cU), AES_CONST(0xc53b6644U), AES_CONST(0x347efb5bU),
        AES_CONST(0x7629438bU), AES_CONST(0xdcc623cbU), AES_CONST(0x68fcedb6U), AES_CONST(0x63f1e4b8U),
        AES_CONST(0xcadc31d7U), AES_CONST(0x10856342U), AES_CONST(0x40229713U), AES_CONST(0x2011c684U),
        AES_CONST(0x7d244a85U), AES_CONST(0xf83dbbd2U), AES_CONST(0x1132f9aeU), AES_CONST(0x6da129c7U),
        AES_CONST(0x4b2f9e1dU), AES_CONST(0xf330b2dcU), AES_CONST(0xec52860dU), AES_CONST(0xd0e3c177U),
        AES_CONST(0x6c16b32bU), AES_CONST(0x99b970a9U), AES_CONST(0xfa489411U), AES_CONST(0x2264e947U),
        AES_CONST(0xc48cfca8U), AES_CONST(0x1a3ff0a0U), AES_CONST(0xd82c7d56U), AES_CONST(0xef903322U),
        AES_CONST(0xc74e4987U), AES_CONST(0xc1d138d9U), AES_CONST(0xfea2ca8cU), AES_CONST(0x360bd498U),
        AES_CONST(0xcf81f5a6U), AES_CONST(0x28de7aa5U), AES_CONST(0x268eb7daU), AES_CONST(0xa4bfad3fU),
        AES_CONST(0xe49d3a2cU), AES_CONST(0x0d927850U), AES_CONST(0x9bcc5f6aU), AES_CONST(0x62467e54U),
        AES_CONST(0xc2138df6U), AES_CONST(0xe8b8d890U), AES_CONST(0x5ef7392eU), AES_CONST(0xf5afc382U),
        AES_CONST(0xbe805d9fU), AES_CONST(0x7c93d069U), AES_CONST(0xa92dd56fU), AES_CONST(0xb31225cfU),
        AES_CONST(0x3b99acc8U), AES_CONST(0xa77d1810U), AES_CONST(0x6e639ce8U), AES_CONST(0x7bbb3bdbU),
        AES_CONST(0x097826cdU), AES_CONST(0xf418596eU), AES_CONST(0x01b79aecU), AES_CONST(0xa89a4f83U),
        AES_CONST(0x656e95e6U), AES_CONST(0x7ee6ffaaU), AES_CONST(0x08cfbc21U), AES_CONST(0xe6e815efU),
        AES_CONST(0xd99be7baU), AES_CONST(0xce366f4aU), AES_CONST(0xd4099feaU), AES_CONST(0xd67cb029U),
        AES_CONST(0xafb2a431U), AES_CONST(0x31233f2aU), AES_CONST(0x3094a5c6U), AES_CONST(0xc066a235U),
        AES_CONST(0x37bc4e74U), AES_CONST(0xa6ca82fcU), AES_CONST(0xb0d090e0U), AES_CONST(0x15d8a733U),
        AES_CONST(0x4a9804f1U), AES_CONST(0xf7daec41U), AES_CONST(0x0e50cd7fU), AES_CONST(0x2ff69117U),
        AES_CONST(0x8dd64d76U), AES_CONST(0x4db0ef43U), AES_CONST(0x544daaccU), AES_CONST(0xdf0496e4U),
        AES_CONST(0xe3b5d19eU), AES_CONST(0x1b886a4cU), AES_CONST(0xb81f2cc1U), AES_CONST(0x7f516546U),
        AES_CONST(0x04ea5e9dU), AES_CONST(0x5d358c01U), AES_CONST(0x737487faU), AES_CONST(0x2e410bfbU),
        AES_CONST(0x5a1d67b3U), AES_CONST(0x52d2db92U), AES_CONST(0x335610e9U), AES_CONST(0x1347d66dU),
        AES_CONST(0x8c61d79aU), AES_CONST(0x7a0ca137U), AES_CONST(0x8e14f859U), AES_CONST(0x893c13ebU),
        AES_CONST(0xee27a9ceU), AES_CONST(0x35c961b7U), AES_CONST(0xede51ce1U), AES_CONST(0x3cb1477aU),
        AES_CONST(0x59dfd29cU), AES_CONST(0x3f73f255U), AES_CONST(0x79ce1418U), AES_CONST(0xbf37c773U),
        AES_CONST(0xeacdf753U), AES_CONST(0x5baafd5fU), AES_CONST(0x146f3ddfU), AES_CONST(0x86db4478U),
        AES_CONST(0x81f3afcaU), AES_CONST(0x3ec468b9U), AES_CONST(0x2c342438U), AES_CONST(0x5f40a3c2U),
        AES_CONST(0x72c31d16U), AES_CONST(0x0c25e2bcU), AES_CONST(0x8b493c28U), AES_CONST(0x41950dffU),
        AES_CONST(0x7101a839U), AES_CONST(0xdeb30c08U), AES_CONST(0x9ce4b4d8U), AES_CONST(0x90c15664U),
        AES_CONST(0x6184cb7bU), AES_CONST(0x70b632d5U), AES_CONST(0x745c6c48U), AES_CONST(0x4257b8d0U)
};

// This shouldn't be declared const because if in flash memory it will be subject to cache
// delays and consequent timing side-channel attacks.
CONST uint8_t sm_inv_sbox[256] __attribute__ (( nocommon )) = {
    0x52U, 0x09U, 0x6aU, 0xd5U, 0x30U, 0x36U, 0xa5U, 0x38U, 0xbfU, 0x40U, 0xa3U, 0x9eU, 0x81U, 0xf3U, 0xd7U, 0xfbU,
    0x7cU, 0xe3U, 0x39U, 0x82U, 0x9bU, 0x2fU, 0xffU, 0x87U, 0x34U, 0x8eU, 0x43U, 0x44U, 0xc4U, 0xdeU, 0xe9U, 0xcbU,
    0x54U, 0x7bU, 0x94U, 0x32U, 0xa6U, 0xc2U, 0x23U, 0x3dU, 0xeeU, 0x4cU, 0x95U, 0x0bU, 0x42U, 0xfaU, 0xc3U, 0x4eU,
    0x08U, 0x2eU, 0xa1U, 0x66U, 0x28U, 0xd9U, 0x24U, 0xb2U, 0x76U, 0x5bU, 0xa2U, 0x49U, 0x6dU, 0x8bU, 0xd1U, 0x25U,
    0x72U, 0xf8U, 0xf6U, 0x64U, 0x86U, 0x68U, 0x98U, 0x16U, 0xd4U, 0xa4U, 0x5cU, 0xccU, 0x5dU, 0x65U, 0xb6U, 0x92U,
    0x6cU, 0x70U, 0x48U, 0x50U, 0xfdU, 0xedU, 0xb9U, 0xdaU, 0x5eU, 0x15U, 0x46U, 0x57U, 0xa7U, 0x8dU, 0x9dU, 0x84U,
    0x90U, 0xd8U, 0xabU, 0x00U, 0x8cU, 0xbcU, 0xd3U, 0x0aU, 0xf7U, 0xe4U, 0x58U, 0x05U, 0xb8U, 0xb3U, 0x45U, 0x06U,
    0xd0U, 0x2cU, 0x1eU, 0x8fU, 0xcaU, 0x3fU, 0x0fU, 0x02U, 0xc1U, 0xafU, 0xbdU, 0x03U, 0x01U, 0x13U, 0x8aU, 0x6bU,
    0x3aU, 0x91U, 0x11U, 0x41U, 0x4fU, 0x67U, 0xdcU, 0xeaU, 0x97U, 0xf2U, 0xcfU, 0xceU, 0xf0U, 0xb4U, 0xe6U, 0x73U,
    0x96U, 0xacU, 0x74U, 0x22U, 0xe7U, 0xadU, 0x35U, 0x85U, 0xe2U, 0xf9U, 0x37U, 0xe8U, 0x1cU, 0x75U, 0xdfU, 0x6eU,
    0x47U, 0xf1U, 0x1aU, 0x71U, 0x1dU, 0x29U, 0xc5U, 0x89U, 0x6fU, 0xb7U, 0x62U, 0x0eU, 0xaaU, 0x18U, 0xbeU, 0x1bU,
    0xfcU, 0x56U, 0x3eU, 0x4bU, 0xc6U, 0xd2U, 0x79U, 0x20U, 0x9aU, 0xdbU, 0xc0U, 0xfeU, 0x78U, 0xcdU, 0x5aU, 0xf4U,
    0x1fU, 0xddU, 0xa8U, 0x33U, 0x88U, 0x07U, 0xc7U, 0x31U, 0xb1U, 0x12U, 0x10U, 0x59U, 0x27U, 0x80U, 0xecU, 0x5fU,
    0x60U, 0x51U, 0x7fU, 0xa9U, 0x19U, 0xb5U, 0x4aU, 0x0dU, 0x2dU, 0xe5U, 0x7aU, 0x9fU, 0x93U, 0xc9U, 0x9cU, 0xefU,
    0xa0U, 0xe0U, 0x3bU, 0x4dU, 0xaeU, 0x2aU, 0xf5U, 0xb0U, 0xc8U, 0xebU, 0xbbU, 0x3cU, 0x83U, 0x53U, 0x99U, 0x61U,
    0x17U, 0x2bU, 0x04U, 0x7eU, 0xbaU, 0x77U, 0xd6U, 0x26U, 0xe1U, 0x69U, 0x14U, 0x63U, 0x55U, 0x21U, 0x0cU, 0x7dU
};

#define INV_SBOX32(n)   ((uint32_t)sm_inv_sbox[(n)])

//lint -e{835}  suppress "A zero has been given as argument to operator +"
//static void __attribute__( ( long_call, section(".ramfunc") ) ) reverse_round(uint32_t x[], const uint8_t y[], const uint32_t rk[]) {
static void FAST_CODE reverse_round(uint32_t x[], const uint8_t y[], const uint32_t rk[]) {
#ifdef SM_CPU_BIG_ENDIAN
    x[0] = rk[0] ^ sm_reverse_lookup[y[ 0 + B_7_0]] ^  ror8(sm_reverse_lookup[y[12 + B_15_8]]) ^ ror16(sm_reverse_lookup[y[ 8 + B_23_16]]) ^ ror24(sm_reverse_lookup[y[ 4 + B_31_24]]);
    x[1] = rk[1] ^ sm_reverse_lookup[y[ 4 + B_7_0]] ^  ror8(sm_reverse_lookup[y[ 0 + B_15_8]]) ^ ror16(sm_reverse_lookup[y[12 + B_23_16]]) ^ ror24(sm_reverse_lookup[y[ 8 + B_31_24]]);
    x[2] = rk[2] ^ sm_reverse_lookup[y[ 8 + B_7_0]] ^  ror8(sm_reverse_lookup[y[ 4 + B_15_8]]) ^ ror16(sm_reverse_lookup[y[ 0 + B_23_16]]) ^ ror24(sm_reverse_lookup[y[12 + B_31_24]]);
    x[3] = rk[3] ^ sm_reverse_lookup[y[12 + B_7_0]] ^  ror8(sm_reverse_lookup[y[ 8 + B_15_8]]) ^ ror16(sm_reverse_lookup[y[ 4 + B_23_16]]) ^ ror24(sm_reverse_lookup[y[ 0 + B_31_24]]);
#else
    x[0] = rk[0] ^ sm_reverse_lookup[y[0  + B_7_0]] ^ ror24(sm_reverse_lookup[y[12 + B_15_8]]) ^ ror16(sm_reverse_lookup[y[8  + B_23_16]]) ^  ror8(sm_reverse_lookup[y[4  + B_31_24]]);
    x[1] = rk[1] ^ sm_reverse_lookup[y[4  + B_7_0]] ^ ror24(sm_reverse_lookup[y[0  + B_15_8]]) ^ ror16(sm_reverse_lookup[y[12 + B_23_16]]) ^  ror8(sm_reverse_lookup[y[8  + B_31_24]]);
    x[2] = rk[2] ^ sm_reverse_lookup[y[8  + B_7_0]] ^ ror24(sm_reverse_lookup[y[4  + B_15_8]]) ^ ror16(sm_reverse_lookup[y[0  + B_23_16]]) ^  ror8(sm_reverse_lookup[y[12 + B_31_24]]);
    x[3] = rk[3] ^ sm_reverse_lookup[y[12 + B_7_0]] ^ ror24(sm_reverse_lookup[y[8  + B_15_8]]) ^ ror16(sm_reverse_lookup[y[4  + B_23_16]]) ^  ror8(sm_reverse_lookup[y[0  + B_31_24]]);
#endif
}

//lint -e{835}  suppress "A zero has been given as argument to operator +"
static void FAST_CODE reverse_round_last(uint32_t x[], const uint8_t y[], const uint32_t rk[]) {
#ifdef SM_CPU_BIG_ENDIAN
    x[0] = rk[0] ^ (INV_SBOX32(y[0  + B_7_0]) << 24) ^ (INV_SBOX32(y[12 + B_15_8]) << 16) ^ (INV_SBOX32(y[8  + B_23_16]) <<  8) ^ (INV_SBOX32(y[4  + B_31_24]) << 0);
    x[1] = rk[1] ^ (INV_SBOX32(y[4  + B_7_0]) << 24) ^ (INV_SBOX32(y[0  + B_15_8]) << 16) ^ (INV_SBOX32(y[12 + B_23_16]) <<  8) ^ (INV_SBOX32(y[8  + B_31_24]) << 0);
    x[2] = rk[2] ^ (INV_SBOX32(y[8  + B_7_0]) << 24) ^ (INV_SBOX32(y[4  + B_15_8]) << 16) ^ (INV_SBOX32(y[0  + B_23_16]) <<  8) ^ (INV_SBOX32(y[12 + B_31_24]) << 0);
    x[3] = rk[3] ^ (INV_SBOX32(y[12 + B_7_0]) << 24) ^ (INV_SBOX32(y[8  + B_15_8]) << 16) ^ (INV_SBOX32(y[4  + B_23_16]) <<  8) ^ (INV_SBOX32(y[0  + B_31_24]) << 0);
#else
    x[0] = rk[0] ^ (INV_SBOX32(y[0  + B_7_0]) <<  0) ^ (INV_SBOX32(y[12 + B_15_8]) <<  8) ^ (INV_SBOX32(y[8  + B_23_16]) << 16) ^ (INV_SBOX32(y[4  + B_31_24]) << 24);
    x[1] = rk[1] ^ (INV_SBOX32(y[4  + B_7_0]) <<  0) ^ (INV_SBOX32(y[0  + B_15_8]) <<  8) ^ (INV_SBOX32(y[12 + B_23_16]) << 16) ^ (INV_SBOX32(y[8  + B_31_24]) << 24);
    x[2] = rk[2] ^ (INV_SBOX32(y[8  + B_7_0]) <<  0) ^ (INV_SBOX32(y[4  + B_15_8]) <<  8) ^ (INV_SBOX32(y[0  + B_23_16]) << 16) ^ (INV_SBOX32(y[12 + B_31_24]) << 24);
    x[3] = rk[3] ^ (INV_SBOX32(y[12 + B_7_0]) <<  0) ^ (INV_SBOX32(y[8  + B_15_8]) <<  8) ^ (INV_SBOX32(y[4  + B_23_16]) << 16) ^ (INV_SBOX32(y[0  + B_31_24]) << 24);
#endif
}

void FAST_CODE sm_aes_decrypt(const sm_aes_dec_roundkey_t *roundkey, const sm_block_t *ciphertext, sm_block_t *plaintext)
{
    uint32_t x[4];
    uint32_t y[4];

    const uint32_t *rk = roundkey->roundkey_words;

    // First round
    x[0] = ciphertext->words[0] ^ rk[0];
    x[1] = ciphertext->words[1] ^ rk[1];
    x[2] = ciphertext->words[2] ^ rk[2];
    x[3] = ciphertext->words[3] ^ rk[3];
    rk += 4U;

    // Next 9 rounds
    reverse_round(y, (uint8_t *) x, rk);

    rk += 4U;
    reverse_round(x, (uint8_t *) y, rk);
    rk += 4U;
    reverse_round(y, (uint8_t *) x, rk);
    rk += 4U;
    reverse_round(x, (uint8_t *) y, rk);
    rk += 4U;
    reverse_round(y, (uint8_t *) x, rk);
    rk += 4U;
    reverse_round(x, (uint8_t *) y, rk);
    rk += 4U;
    reverse_round(y, (uint8_t *) x, rk);
    rk += 4U;
    reverse_round(x, (uint8_t *) y, rk);
    rk += 4U;
    reverse_round(y, (uint8_t *) x, rk);
    rk += 4U;
    // rk now roundkey + 40

    // Final (11th) round doesn't do the column mixing so we use a special version
    // of the reverse function.
    reverse_round_last(x, (uint8_t *) y, rk);

    // Return result
    plaintext->words[0] = x[0];
    plaintext->words[1] = x[1];
    plaintext->words[2] = x[2];
    plaintext->words[3] = x[3];
}

// This modifies an existing forward encryption key schedule for use in decryption
void FAST_CODE sm_expand_key_dec(const sm_aes_enc_roundkey_t *fwd_roundkey, sm_aes_dec_roundkey_t *rev_roundkey)
{
    uint32_t *rev_rk = &rev_roundkey->roundkey_words[0];
    const uint32_t *fwd_rk = &fwd_roundkey->roundkey_words[40];

    // Create 11 128-bit roundkeys
    // Copy the last four words into the new round key
    *(rev_rk++) = *(fwd_rk++);  // 40
    *(rev_rk++) = *(fwd_rk++);  // 41
    *(rev_rk++) = *(fwd_rk++);  // 42
    *(rev_rk++) = *fwd_rk;      // 43

    // Next block word
    fwd_rk -= 7U;               // 36

    // Work our way backwards down the round keys in blocks
    for(uint32_t i = 9U; i > 0; i--) {
#ifdef SM_CPU_BIG_ENDIAN
        *(rev_rk++) =   ror24(sm_reverse_lookup[sm_sbox(WORD_7_0(*fwd_rk))]) 
                      ^ ror16(sm_reverse_lookup[sm_sbox(WORD_15_8(*fwd_rk))]) 
                      ^  ror8(sm_reverse_lookup[sm_sbox(WORD_23_16(*fwd_rk))]) 
                      ^      (sm_reverse_lookup[sm_sbox(WORD_31_24(*fwd_rk))]);
        fwd_rk++;               // 37
        *(rev_rk++) =   ror24(sm_reverse_lookup[sm_sbox(WORD_7_0(*fwd_rk))]) 
                      ^ ror16(sm_reverse_lookup[sm_sbox(WORD_15_8(*fwd_rk))]) 
                      ^  ror8(sm_reverse_lookup[sm_sbox(WORD_23_16(*fwd_rk))]) 
                      ^      (sm_reverse_lookup[sm_sbox(WORD_31_24(*fwd_rk))]);
        fwd_rk++;               // 38
        *(rev_rk++) =   ror24(sm_reverse_lookup[sm_sbox(WORD_7_0(*fwd_rk))]) 
                      ^ ror16(sm_reverse_lookup[sm_sbox(WORD_15_8(*fwd_rk))]) 
                      ^  ror8(sm_reverse_lookup[sm_sbox(WORD_23_16(*fwd_rk))]) 
                      ^      (sm_reverse_lookup[sm_sbox(WORD_31_24(*fwd_rk))]);
        fwd_rk++;               // 39
        *(rev_rk++) =   ror24(sm_reverse_lookup[sm_sbox(WORD_7_0(*fwd_rk))]) 
                      ^ ror16(sm_reverse_lookup[sm_sbox(WORD_15_8(*fwd_rk))]) 
                      ^  ror8(sm_reverse_lookup[sm_sbox(WORD_23_16(*fwd_rk))]) 
                      ^      (sm_reverse_lookup[sm_sbox(WORD_31_24(*fwd_rk))]);
        fwd_rk -= 7U;           // 32
#else
        *(rev_rk++) =        (sm_reverse_lookup[sm_sbox(WORD_7_0(*fwd_rk))]) 
                      ^ ror24(sm_reverse_lookup[sm_sbox(WORD_15_8(*fwd_rk))]) 
                      ^ ror16(sm_reverse_lookup[sm_sbox(WORD_23_16(*fwd_rk))]) 
                      ^  ror8(sm_reverse_lookup[sm_sbox(WORD_31_24(*fwd_rk))]);
        fwd_rk++;     // 37
        *(rev_rk++) =        (sm_reverse_lookup[sm_sbox(WORD_7_0(*fwd_rk))]) 
                      ^ ror24(sm_reverse_lookup[sm_sbox(WORD_15_8(*fwd_rk))]) 
                      ^ ror16(sm_reverse_lookup[sm_sbox(WORD_23_16(*fwd_rk))]) 
                      ^  ror8(sm_reverse_lookup[sm_sbox(WORD_31_24(*fwd_rk))]);
        fwd_rk++;     // 38
        *(rev_rk++) =        (sm_reverse_lookup[sm_sbox(WORD_7_0(*fwd_rk))]) 
                      ^ ror24(sm_reverse_lookup[sm_sbox(WORD_15_8(*fwd_rk))]) 
                      ^ ror16(sm_reverse_lookup[sm_sbox(WORD_23_16(*fwd_rk))]) 
                      ^  ror8(sm_reverse_lookup[sm_sbox(WORD_31_24(*fwd_rk))]);
        fwd_rk++;     // 39
        *(rev_rk++) =        (sm_reverse_lookup[sm_sbox(WORD_7_0(*fwd_rk))]) 
                      ^ ror24(sm_reverse_lookup[sm_sbox(WORD_15_8(*fwd_rk))]) 
                      ^ ror16(sm_reverse_lookup[sm_sbox(WORD_23_16(*fwd_rk))]) 
                      ^  ror8(sm_reverse_lookup[sm_sbox(WORD_31_24(*fwd_rk))]);
        fwd_rk -= 7U; // 32
#endif
    }
    *(rev_rk++) = *(fwd_rk++);  // 0
    *(rev_rk++) = *(fwd_rk++);  // 1
    *(rev_rk++) = *(fwd_rk++);  // 2
    *rev_rk = *fwd_rk;          // 3

    // Here rx should be pointing to word 44 and sk to word 3
}

she_errorcode_t FAST_CODE sm_dec_ecb(sm_key_id_t key_id, const sm_block_t *ciphertext, sm_block_t *plaintext)
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
    sm_aes_dec_roundkey_t dec_roundkey;
    sm_expand_key_dec(&sm_cached_key_slots[key_id].enc_roundkey, &dec_roundkey);
#else
    sm_aes_enc_roundkey_t enc_roundkey;
    sm_aes_dec_roundkey_t dec_roundkey;
    sm_expand_key_enc(&sm_sw_nvram_fs_ptr->key_slots[key_id].key, &enc_roundkey);
    sm_expand_key_dec(&enc_roundkey, &dec_roundkey);
#endif
    sm_aes_decrypt(&dec_roundkey, ciphertext, plaintext);

    return SHE_ERC_NO_ERROR;
}
