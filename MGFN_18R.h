#pragma once

// encryption.h — core definitions & prototypes

#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

    /* -------------------------------------------------------------------------- */
    /*  Public constants                                                          */
    /* -------------------------------------------------------------------------- */

#define _CRT_RAND_S            /* enable rand_s on MSVC */
#define SBOX_SIZE      16
#define BLOCK_SIZE     1048576
#define KEY            16
#define MAX_KEYS       16
#define BUFFER_PAIRS   4096

/* S‑box */
    extern uint8_t S[SBOX_SIZE];

    /* Pre‑computed T‑tables (AES‑like) */
    extern const uint32_t te1[256];
    extern const uint32_t te2[256];
    extern const uint32_t te3[256];
    extern const uint32_t te4[256];

    /* -------------------------------------------------------------------------- */
    /*  Data structures                                                           */
    /* -------------------------------------------------------------------------- */

    typedef struct {
        uint64_t round_keys[14]; /* 14 raw round keys */
        uint64_t rk[26];         /* expanded schedule used by encryption */
    } KeySchedule;

    /* 64‑bit plaintext/ciphertext pair (differential analysis etc.) */
    typedef struct {
        uint64_t plaintext;
        uint64_t ciphertext;
    } Pair;

    /* -------------------------------------------------------------------------- */
    /*  API – key schedule                                                        */
    /* -------------------------------------------------------------------------- */

    void split_master_key(
        uint8_t* master_key,
        uint64_t* high,
        uint64_t* low
    );

    void rotate_right_61_bits(
        uint64_t* high,
        uint64_t* low
    );

    void rotate_right_67_bits(
        uint64_t* high,
        uint64_t* low
    );

    uint8_t substitute_with_sbox(
        uint8_t nibble
    );

    void key_schedule(
        uint8_t* mk,
        KeySchedule* ks
    );

    /* -------------------------------------------------------------------------- */
    /*  API – encryption core                                                     */
    /* -------------------------------------------------------------------------- */

    uint64_t Table_lookup(
        uint64_t input
    );

    uint64_t encrypt_single_round(
        uint64_t P,
        uint64_t key
    );

    void encrypt(
        uint64_t plaintext,
        KeySchedule* key_schedule,
        uint64_t* ciphertext
    );

    /* -------------------------------------------------------------------------- */
    /*  Utilities                                                                 */
    /* -------------------------------------------------------------------------- */

    void save_to_file(
        FILE* file,
        uint64_t plaintext,
        uint64_t ciphertext
    );

    void generate_random_data(
        uint64_t* data
    );

    uint32_t array_to_int(
        uint8_t* bit_list
    );

    uint32_t convert_key_array_to_uint32(
        uint8_t right_keys[9]
    );

    /* -------------------------------------------------------------------------- */
    /*  API – decryption helpers                                                  */
    /* -------------------------------------------------------------------------- */

    uint32_t decrypt_half_one_round(
        uint64_t ciphertext1,
        uint8_t rk24_xor_k14[9]
    );

    uint32_t decrypt_half_one_round1(
        uint64_t ciphertext1,
        uint32_t rk24_xor_k14
    );

    uint32_t decrypt_half_two_round(
        uint64_t ciphertext1,
        uint8_t rk24_xor_k14[9],
        uint8_t rk23_xor_k14[9]
    );

    uint32_t decrypt_half_three_round(
        uint64_t ciphertext1,
        uint8_t rk24_xor_k14[9],
        uint8_t rk23_xor_k14[9],
        uint8_t rk22_xor_k14[9]
    );

    /* -------------------------------------------------------------------------- */
#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* ENCRYPTION_H */
