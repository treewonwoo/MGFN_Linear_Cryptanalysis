#pragma once
/* -------------------------------------------------------------------------- */
/*  MGFN_18R.h — public interface for 18‑round master‑key recovery            */
/* -------------------------------------------------------------------------- */

#ifndef MGFN_18R_H
#define MGFN_18R_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "MGFN_18R.h"   /* Pair structure and encryption utilities */

    /* -------------------------------------------------------------------------- */
    /*  User‑facing API                                                           */
    /* -------------------------------------------------------------------------- */

    /**
     * Recovers the 128‑bit master key from **two** plaintext–ciphertext pairs and
     * the 32‑bit sub‑keys of rounds 16, 17, and 18.
     *
     * @param pairs          Two (P,C) pairs collected from the target cipher.
     * @param rk16_xor_K10_R          32‑bit key for rk16 ^ K10_R .
     * @param rk17_xor_K10_L          32‑bit key for rk17 ^ K10_L.
     * @param rk18_xor_K10_R          32‑bit key for rk18 ^ K10_R.
     * @param master_key_out Output buffer (16 bytes) that receives the recovered
     *                       128‑bit master key on success.
     *
     * @return 1 on success, 0 if no master key satisfies the supplied data.
     */
    int find_master_key(
        const Pair   pairs[2],
        uint32_t     rk16_xor_K10_R,
        uint32_t     rk17_xor_K10_L,
        uint32_t     rk18_xor_K10_R,
        uint8_t      master_key_out[16]
    );

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* MGFN_18R_H */
