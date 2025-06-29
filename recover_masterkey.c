/*-----------------------------------------------------------------------------
 * MGFN_18R.c — master‑key recovery (18‑round reduced) implementation
 * ---------------------------------------------------------------------------
 * API:
 *     int find_master_key(
 *         const Pair pairs[2],             // two plaintext/ciphertext pairs
 *         uint32_t     rk16,
 *         uint32_t     rk17,
 *         uint32_t     rk18,
 *         uint8_t      master_key[16]);    // ← filled on success (big‑endian)
 *
 * The function performs the multithreaded search formerly placed in `main()`.
 * It enumerates 2^35 candidates using OpenMP and stops as soon as a key is
 * found that:
 *   • yields the supplied keys  (bit constraints baked into the
 *     combinatorial search), and
 *   • correctly encrypts *both* given plaintexts to the supplied ciphertexts.
 *----------------------------------------------------------------------------*/

#include "MGFN_18R.h"
#include "recover_masterkey.h"
#include <omp.h>
#include <string.h>

 /*-------------------------------------------------------------*/
 /*  Local helpers                                              */
 /*-------------------------------------------------------------*/
static inline uint8_t sub4(uint8_t x)
{
    static const uint8_t S[16] = {
        0x7,0xE,0xF,0x0,0xD,0xB,0x8,0x1,
        0x9,0x3,0x4,0xC,0x2,0x5,0xA,0x6
    };
    return S[x & 0xF];
}
static inline uint8_t inv4(uint8_t x)
{
    static const uint8_t IS[16] = {
        0x3,0x7,0xC,0x9,0xA,0xD,0xF,0x0,
        0x6,0x8,0xE,0x5,0xB,0x4,0x1,0x2
    };
    return IS[x & 0xF];
}

static inline void rotl61(uint64_t* hi, uint64_t* lo)
{
    uint64_t h = *hi, l = *lo;
    *hi = (h << 61) | (l >> 3);
    *lo = (l << 61) | (h >> 3);
}
static inline void rotl67(uint64_t* hi, uint64_t* lo)
{
    uint64_t h = *hi, l = *lo;
    *hi = (l << 3) | (h >> 61);
    *lo = (h << 3) | (l >> 61);
}

/*  Undo final permutation in the key schedule, recovering master‑key bits  */
static void unpermute_key(
    uint64_t  mkh,
    uint64_t  mkl,
    uint64_t* out_h,
    uint64_t* out_l)
{
    rotl61(&mkh, &mkl);
    for (int r = 10; r > 0; --r) {
        /* undo round constant */
        uint8_t rc = r, up = (rc >> 2) & 3, dn = rc & 3;
        mkh = (mkh & ~3ULL) | ((mkh & 3ULL) ^ up);
        mkl = (mkl & ~(3ULL << 62)) | ((((mkl >> 62) & 3ULL) ^ dn) << 62);

        /* undo S‑box on top byte */
        uint8_t sb = (mkh >> 56) & 0xFF;
        uint8_t n0 = (sb >> 4) & 0xF, n1 = sb & 0xF;
        uint8_t o0 = inv4(n0), o1 = inv4(n1);
        mkh &= 0x00FFFFFFFFFFFFFFULL;
        mkh |= (uint64_t)o0 << 60 | (uint64_t)o1 << 56;

        rotl67(&mkh, &mkl);
    }
    *out_h = mkh;
    *out_l = mkl;
}

/*-------------------------------------------------------------*/
/*  Search context (TLS‑friendly globals)                      */
/*-------------------------------------------------------------*/
static Pair      g_pairs[2];
static uint32_t  g_RK16, g_RK17, g_RK18;
static volatile int g_found = 0;
static uint8_t   g_found_key[16];

/*-------------------------------------------------------------*/
/*  Candidate verification                                     */
/*-------------------------------------------------------------*/
static int verify_master_key(uint64_t hi, uint64_t lo)
{
    /* build 128‑bit key in big‑endian order */
    uint8_t mk[16];
    for (int i = 0; i < 8; ++i) mk[i] = (uint8_t)(hi >> (56 - 8 * i));
    for (int i = 0; i < 8; ++i) mk[8 + i] = (uint8_t)(lo >> (56 - 8 * i));

    KeySchedule ks;
    key_schedule(mk, &ks);

    uint64_t ct;
    encrypt(g_pairs[0].plaintext, &ks, &ct);
    if (ct != g_pairs[0].ciphertext) return 0;

    encrypt(g_pairs[1].plaintext, &ks, &ct);
    if (ct != g_pairs[1].ciphertext) return 0;

    memcpy(g_found_key, mk, 16);
    return 1;
}

/*-------------------------------------------------------------*/
/*  Core enumeration (one of 64 outer templates)               */
/*-------------------------------------------------------------*/
static void search_one(
    uint8_t  in_bits,
    uint32_t RK16,
    uint32_t RK17,
    uint32_t RK18)
{
    /*=========== fixed bit expansion =========================*/
    uint8_t MK64 = (in_bits >> 5) & 1, MK63 = (in_bits >> 4) & 1,
        MK62 = (in_bits >> 3) & 1, MK61 = (in_bits >> 2) & 1,
        MK60 = (in_bits >> 1) & 1, MK59 = in_bits & 1;

    uint8_t a = inv4(((MK62 << 3) | (MK61 << 2) | (MK60 << 1) | MK59)) ^ 0x8 ^ ((RK16 >> 1) & 0xF);
    uint8_t b = inv4((((a & 3) << 2) | (MK64 << 1) | MK63)) ^ 0x4 ^ ((RK16 >> 5) & 0xF);

    uint8_t MK68 = (a >> 3) & 1, MK67 = (a >> 2) & 1, MK66 = (a >> 1) & 1, MK65 = a & 1;
    uint8_t MK72 = (b >> 3) & 1, MK71 = (b >> 2) & 1, MK70 = (b >> 1) & 1, MK69 = b & 1;

#define XOR1(x,off) ((x) ^ ((RK18>>(off))&1))
#define XOR2(x,off) ((x) ^ ((RK16>>(off))&1))
    uint8_t MK125 = XOR1(MK64, 0), MK126 = XOR1(MK65, 1), MK127 = XOR1(MK66, 2);
    uint8_t MK0 = XOR1(MK67, 3), MK1 = XOR1(MK68, 4), MK2 = XOR1(MK69, 5) ^ 1;
    uint8_t MK3 = XOR1(MK70, 6), MK4 = XOR1(MK71, 7) ^ 1, MK5 = XOR1(MK72, 8);

    uint8_t MK58 = XOR2(MK64, 0);
    uint8_t MK73 = XOR2(MK67, 9), MK74 = XOR2(MK68, 10), MK75 = XOR2(MK69, 11),
        MK76 = XOR2(MK70, 12), MK77 = XOR2(MK71, 13), MK78 = XOR2(MK72, 14);

    uint8_t MK6 = XOR1(MK73, 9), MK7 = XOR1(MK74, 10), MK8 = XOR1(MK75, 11),
        MK9 = XOR1(MK76, 12), MK10 = XOR1(MK77, 13), MK11 = XOR1(MK78, 14);

    uint8_t MK79 = XOR2(MK73, 15), MK80 = XOR2(MK74, 16), MK81 = XOR2(MK75, 17),
        MK82 = XOR2(MK76, 18), MK83 = XOR2(MK77, 19), MK84 = XOR2(MK78, 20);

    uint8_t MK12 = XOR1(MK79, 15), MK13 = XOR1(MK80, 16), MK14 = XOR1(MK81, 17),
        MK15 = XOR1(MK82, 18), MK16_ = XOR1(MK83, 19), MK17 = XOR1(MK84, 20);

    uint8_t MK85 = XOR2(MK79, 21), MK86 = XOR2(MK80, 22), MK87 = XOR2(MK81, 23),
        MK88 = XOR2(MK82, 24), MK89 = XOR2(MK83, 25), MK90 = XOR2(MK84, 26);

    uint8_t MK18 = XOR1(MK85, 21), MK19 = XOR1(MK86, 22), MK20 = XOR1(MK87, 23),
        MK21 = XOR1(MK88, 24), MK22 = XOR1(MK89, 25), MK23 = XOR1(MK90, 26);

    uint8_t MK91 = XOR2(MK85, 27), MK92 = XOR2(MK86, 28), MK93 = XOR2(MK87, 29),
        MK94 = XOR2(MK88, 30), MK95 = XOR2(MK89, 31);

    uint8_t MK24 = XOR1(MK91, 27), MK25 = XOR1(MK92, 28), MK26 = XOR1(MK93, 29),
        MK27 = XOR1(MK94, 30), MK28 = XOR1(MK95, 31);
#undef XOR1
#undef XOR2

    /*=========== template hi / lo ============================*/
    uint64_t tmpl_hi = 0, tmpl_lo = 0;
#define SET_H(pos,val)  (tmpl_hi |= (uint64_t)(val) << (pos))
#define SET_L(pos,val)  (tmpl_lo |= (uint64_t)(val) << (pos))
    /* fixed hi bits */
    SET_H(0, MK64); SET_H(1, MK65); SET_H(2, MK66); SET_H(3, MK67);
    SET_H(4, MK68); SET_H(5, MK69); SET_H(6, MK70); SET_H(7, MK71);
    SET_H(8, MK72); SET_H(9, MK73); SET_H(10, MK74); SET_H(11, MK75);
    SET_H(12, MK76); SET_H(13, MK77); SET_H(14, MK78); SET_H(15, MK79);
    SET_H(16, MK80); SET_H(17, MK81); SET_H(18, MK82); SET_H(19, MK83);
    SET_H(20, MK84); SET_H(21, MK85); SET_H(22, MK86); SET_H(23, MK87);
    SET_H(24, MK88); SET_H(25, MK89); SET_H(26, MK90); SET_H(27, MK91);
    SET_H(28, MK92); SET_H(29, MK93); SET_H(30, MK94); SET_H(31, MK95);
    SET_H(61, MK125); SET_H(62, MK126); SET_H(63, MK127);

    /* fixed lo bits */
    SET_L(0, MK0); SET_L(1, MK1); SET_L(2, MK2); SET_L(3, MK3);
    SET_L(4, MK4); SET_L(5, MK5); SET_L(6, MK6); SET_L(7, MK7);
    SET_L(8, MK8); SET_L(9, MK9); SET_L(10, MK10); SET_L(11, MK11);
    SET_L(12, MK12); SET_L(13, MK13); SET_L(14, MK14); SET_L(15, MK15);
    SET_L(16, MK16_); SET_L(17, MK17); SET_L(18, MK18); SET_L(19, MK19);
    SET_L(20, MK20); SET_L(21, MK21); SET_L(22, MK22); SET_L(23, MK23);
    SET_L(24, MK24); SET_L(25, MK25); SET_L(26, MK26); SET_L(27, MK27);
    SET_L(28, MK28); SET_L(58, MK58); SET_L(59, MK59); SET_L(60, MK60);
    SET_L(61, MK61); SET_L(62, MK62); SET_L(63, MK63);
#undef SET_H
#undef SET_L

    /*=========== inner 2^29 loop =============================*/
#pragma omp parallel
    {
        uint64_t local_cnt = 0;
        int32_t i = 0;
#pragma omp for schedule(static)
        for (i = 0; i < (1U << 29); ++i) {
            if (g_found) continue;

            uint64_t hi = tmpl_hi | ((uint64_t)(i ^ (RK17 & 0x1FFFFFFF)) << 32);
            uint64_t lo = tmpl_lo | ((uint64_t)i << 29);

            uint64_t rh, rl;
            unpermute_key(hi, lo, &rh, &rl);

            if (verify_master_key(rh, rl)) {
#pragma omp critical
                {
                    g_found = 1;
                }
            }

            if (++local_cnt == (1ULL << 20)) {
                local_cnt = 0; /* simple dividend to throttle */
            }
        }
    }
}

/*-------------------------------------------------------------*/
/*  Public API                                                 */
/*-------------------------------------------------------------*/
int find_master_key(
    const Pair   pairs[2],
    uint32_t     rk16,
    uint32_t     rk17,
    uint32_t     rk18,
    uint8_t      master_key_out[16])
{
    /* initialise globals */
    memcpy(g_pairs, pairs, sizeof(Pair) * 2);
    g_RK16 = rk16; g_RK17 = rk17; g_RK18 = rk18;
    g_found = 0;

    /* 64 outer templates */
    for (uint8_t in = 0; in < 64 && !g_found; ++in)
        search_one(in, rk16, rk17, rk18);

    if (!g_found) return 0;
    memcpy(master_key_out, g_found_key, 16);
    return 1;
}