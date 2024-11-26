// Software emulation of a hardware security module (HSM)
//
// Copyright (C) 2016-2022 Canis Automotive Labs Ltd.
//
// This defines a set of standard functions for accessing a security module
//
// This software is licensed according to the APACHE LICENSE 2.0:
//
// https://www.apache.org/licenses/LICENSE-2.0.txt

#ifndef SM_SWSHE_H
#define SM_SWSHE_H

#include "../she.h"
#include "../nvram.h"

// HSM must be built with little or big endian selected
#if (!defined(SM_CPU_LITTLE_ENDIAN) && !defined(SM_CPU_BIG_ENDIAN)) || defined(SM_CPU_LITTLE_ENDIAN) && defined(SM_CPU_BIG_ENDIAN)
#error "Exactly one of SM_CPU_LITTLE_ENDIAN or SM_CPU_BIG_ENDIAN must be defined"
#endif 

// Constants should go into flash or RAM depending on RAM vs. speed tradeoff
#if (!defined(SM_ROM_TABLES) && !defined(SM_RAM_TABLES)) || defined(SM_ROM_TABLES) && defined(SM_RAM_TABLES)
#error "Exactly one of SM_ROM_TABLES or SM_RAM_TABLES must be defined"
#endif 

// Round keys can be cached in the key tables or computed when keys are loaded
#if (!defined(SM_KEY_EXPANSION_CACHED) && !defined(SM_NO_KEY_EXPANSION_CACHE)) || defined(SM_KEY_EXPANSION_CACHED) && defined(SM_NO_KEY_EXPANSION_CACHE)
#error "Exactly one of SM_KEY_EXPANSION_CACHED or SM_NO_KEY_EXPANSION_CACHE must be defined"
#endif 

#if defined(SM_ROM_TABLES) || defined(FLASH_TABLES)
#define CONST       const
#else
#define CONST       /* */
#endif

#ifdef SM_CODE_IN_RAM
#define FAST_CODE __attribute__( (noinline, long_call, section(SM_RAM_SECTION) ) ) 
#else
#define FAST_CODE /* */ 
#endif

#define SWSM_FLAG_EMPTY_SLOT                        (1U << 7)
#define SWSM_FLAG_PLAIN_KEY                         (1U << 6)

#ifdef SM_CPU_BIG_ENDIAN
#define AES_CONST(c)   ((((c) >> 24) & 0x000000ff) | (((c) >> 8) & 0x0000ff00) | (((c) << 8) & 0x00ff0000) | (((c) << 24) & 0xff000000))
#else
#define AES_CONST(c)   (c)
#endif

#define WORD_7_0(w)     ((uint8_t)((w)))
#define WORD_15_8(w)    ((uint8_t)(((w) >> 8)))
#define WORD_23_16(w)   ((uint8_t)(((w)) >> 16))
#define WORD_31_24(w)   ((uint8_t)(((w)) >> 24))

#define B_7_0           (0U)
#define B_15_8          (1U)
#define B_23_16         (2U)
#define B_31_24         (3U)

typedef struct {
    uint32_t roundkey_words[44];
} sm_aes_enc_roundkey_t;

typedef struct {
    uint32_t roundkey_words[44];
} sm_aes_dec_roundkey_t;

// Not stored in NVRAM but set on load/initialize from the NVRAM
typedef struct {
#ifdef SM_KEY_EXPANSION_CACHED
    sm_aes_enc_roundkey_t enc_roundkey;
#endif
    sm_block_t k1;                          // This is for keys that can be used as MACs
} sm_sw_cached_key_slot_t;

void sm_expand_key_enc(const sm_block_t *key, sm_aes_enc_roundkey_t *roundkey);
void FAST_CODE sm_expand_key_dec(const sm_aes_enc_roundkey_t *fwd_roundkey, sm_aes_dec_roundkey_t *rev_roundkey);
void FAST_CODE sm_dynamic_cmac(const sm_block_t *k, const uint32_t *words, uint32_t num_blocks, sm_block_t *mac);
void FAST_CODE sm_kdf(const sm_block_t *k, sm_block_t *out, const sm_block_t *c);
void FAST_CODE sm_mp(const sm_block_t *out_prev, const sm_block_t *x, sm_block_t *out_next);
void FAST_CODE sm_aes_encrypt(const sm_aes_enc_roundkey_t *roundkey, const sm_block_t *plaintext, sm_block_t *ciphertext);
void FAST_CODE sm_aes_decrypt(const sm_aes_dec_roundkey_t *roundkey, const sm_block_t *ciphertext, sm_block_t *plaintext);
void FAST_CODE sm_init_key(sm_key_id_t key_num);
void FAST_CODE sm_init_keys(void);
void FAST_CODE sm_cmac_k1(const sm_aes_enc_roundkey_t *k, sm_block_t *k1);
uint32_t FAST_CODE sm_compare_mac(const sm_block_t *m, const sm_block_t *m_star, const uint32_t *mac_mask);
void FAST_CODE sm_aes_cmac(const sm_aes_enc_roundkey_t *rk, const uint32_t *words, uint32_t num_blocks, sm_block_t *mac, const sm_block_t *k1);
uint8_t FAST_CODE sm_sbox(uint8_t n);

extern sm_sw_cached_key_slot_t sm_cached_key_slots[SM_SW_NUM_KEYS];
extern bool sm_prng_init;
extern sm_block_t sm_prng_state;
extern sm_aes_enc_roundkey_t sm_prng_roundkey;

// These are private to the library compilation and are not exposed to the link namespace

// Conditionally swaps to big-endian storage
// Defined as a macro because the compiler might not inline, and if it
// doesn't inline and puts it into flash with a cache then this won't give a constant execution time
#if defined(_MSC_VER)
#define BYTE_SWAP(x)     _byteswap_ulong((x))
#elif (__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8)
#define BYTE_SWAP(x)     __builtin_bswap32((x))
#elif defined(__has_builtin) && __has_builtin(__builtin_bswap64)  /* For clang */
#define BYTE_SWAP(x)     __builtin_bswap32((x))
#else
static inline uint32_t BYTE_SWAP(uint32_t w)
{
    uint32_t tmp;
    uint8_t *buf = (uint8_t *)&tmp;
    buf[0] = w >> 24;
    buf[1] = w >> 16U;
    buf[2] = w >> 8U;
    buf[3] = w & 0xffU;

    return tmp;
}
#endif

#define BLOCK_SWAP(b)   ((b)[0] = BYTE_SWAP((b)[0]), (b)[1] = BYTE_SWAP((b)[1]), (b)[2] = BYTE_SWAP((b)[2]), (b)[3] = BYTE_SWAP((b)[3]))

static inline uint32_t ror1(uint32_t x)
{
    return x >> 31;
}

// Compilers do a good job at converting these to ROR instructions
static inline uint32_t ror8(uint32_t x)
{
    return (x >> 8) | (x << 24);
}

static inline uint32_t ror16(uint32_t x)
{
    return (x >> 16) | (x << 16);
}

static inline uint32_t ror24(uint32_t x)
{
    return (x << 8) | (x >> 24);
}

static inline uint32_t ror8_byte(uint32_t x)
{
    return (uint8_t)(x >> 8);
}


#ifndef SM_CPU_BIG_ENDIAN
#define BIG_ENDIAN_WORD(w)          BYTE_SWAP((w))
#else
#define BIG_ENDIAN_WORD(w)          (w)
#endif

// Make a mask based on the number of bits from the most significant bit
// Requires constant time shift operation (i.e. barrel shifter) to avoid
// variable time, and is also implementation dependent (due to shifting
// negative numbers).
#ifdef ASRM64
// Implementation targeted at 64-bit CPU cores. May not compile down to
// branch-free implementation: need to check assembler.
static inline void asrm_128(uint32_t *x, uint32_t n)
{
    uint64_t m0;
    uint64_t m1;
    int64_t nn;

    nn = (n - 1U) & 0x7fU;
    m0 = (int64_t)0x8000000000000000 >> nn;
    nn -= 64U;
    m0 |= ~((int64_t)nn >> 63);
    m1 = ((int64_t)0x8000000000000000 >> nn) & ~((int64_t)nn >> 63);

    x[0] = m0 >> 32;
    x[1] = m0;
    x[2] = m1 >> 32;
    x[3] = m1;

#ifndef SM_CPU_BIG_ENDIAN
    BLOCK_SWAP(x);
#endif
}
#else
// Implementation targeted at 32-bit CPU cores.
static inline void asrm_128(uint32_t *x, uint32_t n)
{
    n -= 1U;
    n &= 0x7fU;
    x[0] = (int32_t)0x80000000 >> n;
    n -= 32U;
    x[0] |= ~((int32_t)n >> 31);
    x[1] = (int32_t)0x80000000 >> n & ~((int32_t)n >> 31);
    n -= 32U;
    x[1] |= ~((int32_t)n >> 31);
    x[2] = (int32_t)0x80000000 >> n & ~((int32_t)n >> 31);
    n -= 32U;
    x[2] |= ~((int32_t)n >> 31);
    x[3] = (int32_t)0x80000000 >> n & ~((int32_t)n >> 31);

#ifndef SM_CPU_BIG_ENDIAN
    BLOCK_SWAP(x);
#endif
}
#endif // ASRM64

// x points to four 32-bit unsigned words, the lowest address is the most-significant word
static inline void lsl_128(uint32_t *x)
{
#ifndef SM_CPU_BIG_ENDIAN
    // Need to do a logical shift left on 128 bits but in big endian memory order
    BLOCK_SWAP(x);
#endif

    uint32_t x_1 = (x[1] >> 31);
    uint32_t x_2 = (x[2] >> 31);
    uint32_t x_3 = (x[3] >> 31);

    x[0] <<= 1;
    x[1] <<= 1;
    x[2] <<= 1;
    x[3] <<= 1;

    x[0] |= x_1;
    x[1] |= x_2;
    x[2] |= x_3;

    // This is the equivalent of the above, but clang compiler is sometimes better at compiling
    // the above. On PowerPC architectures it makes no difference, though.
    //
    //    x[0] = (x[0] << 1) | (x[1] >> 31);
    //    x[1] = (x[1] << 1) | (x[2] >> 31);
    //    x[2] = (x[2] << 1) | (x[3] >> 31);
    //    x[3] = (x[3] << 1);

#ifndef SM_CPU_BIG_ENDIAN
    // Swap back to little endian
    BLOCK_SWAP(x);
#endif
}

#ifdef DEBUG_PRINTING
static void inline printf_buf(const uint8_t *buf)
{
    for (uint32_t i = 0; i < 16; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}
#endif

#endif // SM_SWSHE_H