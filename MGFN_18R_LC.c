#define _CRT_SECURE_NO_WARNINGS
/*#define DEBUG_KEY_SCHEDULE*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <omp.h>

#include "MGFN_18R.h"          /* Encryption & key‑schedule API */
#include "recover_masterkey.h" /* Master‑key recovery (RK16 xor K10_R,RK17 xor K10_L,RK18 xor K10_R + 2 pairs ⇒ 128‑bit) */

/* -------------------------------------------------------------------------- */
/*  Macros & constants                                                        */
/* -------------------------------------------------------------------------- */
#define TARGET_PAIRS  ((uint64_t)1ULL << 33)   /* 2^33 (P,C) pairs                    */
#define BUFFER_PAIRS  4096                     /* I/O buffer                          */
#define TOTAL_KEYS    1                        /* Number of random keys for demo      */
#define MAX_THREADS   32                       /* OpenMP threads                      */
#define MAX_KEYS      16                       /* Nibble (4‑bit) candidates           */

/* Map stage number to key index position */
static inline int stage_to_pos(int stage)
{
    static const int tbl[8] = { 8, 1, 5, 7, 4, 6, 2, 3 };
    return (stage >= 0 && stage < 8) ? tbl[stage] : -1;
}

/* Required number of (P,C) pairs per Round·Stage as exponent (2^exp) */
static const int stage_exp[3][8] = {
    {29, 31, 31, 29, 33, 33, 33, 33}, /* round 0 */
    {29, 31, 31, 29, 31, 31, 31, 31}, /* round 1 */
    {27, 29, 29, 27, 29, 29, 29, 29}  /* round 2 */
};

/* -------------------------------------------------------------------------- */
/*  Select the key index with the largest deviation in statistics             */
/* -------------------------------------------------------------------------- */
static int find_max_deviation_index(const uint64_t* bucket, uint64_t used)
{
    uint64_t half = used >> 1, max_diff = 0;
    int best = -1;

    puts("Idx\tValue\t\tDiff");
    puts("---\t-------------\t-------------");

    for (int i = 0; i < MAX_KEYS; ++i) {
        uint64_t diff = (bucket[i] > half) ? bucket[i] - half : half - bucket[i];
        printf("%3d\t%llu\t%llu\n", i,
            (unsigned long long)bucket[i],
            (unsigned long long)diff);
        if (diff > max_diff) {
            max_diff = diff;
            best = i;
        }
    }
    printf("\nMax deviation at index %d (diff = %llu)\n\n",
        best, (unsigned long long)max_diff);
    return best;
}

/* -------------------------------------------------------------------------- */
/*  (P,C) generation + progress display                                       */
/* -------------------------------------------------------------------------- */
static void generate_dataset(const KeySchedule* ks,
    const char* path,
    uint64_t pairs)
{
    FILE* fp = fopen(path, "wb");
    if (!fp) {
        perror("open dataset");
        return;
    }

    uint64_t global_cnt = 0;
    double t0 = omp_get_wtime();

#pragma omp parallel num_threads(MAX_THREADS)
    {
        uint64_t buf[BUFFER_PAIRS][2];
        size_t cnt = 0;
        int64_t idx = 0;
#pragma omp for schedule(static)
        for (idx = 0; idx < pairs; ++idx) {
            uint64_t pt, ct;
            generate_random_data(&pt);
            encrypt(pt, (KeySchedule*)ks, &ct);

            buf[cnt][0] = pt;
            buf[cnt][1] = ct;
            ++cnt;

            if (cnt == BUFFER_PAIRS) {
#pragma omp critical
                fwrite(buf, sizeof(buf[0]), BUFFER_PAIRS, fp);
                cnt = 0;
            }

#pragma omp atomic
            ++global_cnt;

            if (omp_get_thread_num() == 0 && (global_cnt & 0xFFFF) == 0) {
                double prog = (double)global_cnt / pairs;
                double pct = ((int)(prog * 1000)) / 10.0;
                double eta = prog ? (omp_get_wtime() - t0) * (1.0 / prog - 1.0) : 0.0;

                printf("\r[DATA] %.1f%% | %llu/%llu | ETA %.2fs ",
                    pct, (unsigned long long)global_cnt, (unsigned long long)pairs, eta);
                fflush(stdout);
            }
        }

        /* Flush remaining data */
#pragma omp critical
        if (cnt)
            fwrite(buf, sizeof(buf[0]), cnt, fp);
    }
    puts("");
    fclose(fp);
}

/* -------------------------------------------------------------------------- */
/*  Linear Cryptanalysis                                                      */
/* -------------------------------------------------------------------------- */
static void linear_attack_recover_keys(const char* dataset_path,
    uint8_t rk_nib[3][9],
    FILE* logfp)
{
    extern uint8_t S[16];

    uint8_t right_keys[3][9] = { {0} };

    FILE* fp = fopen(dataset_path, "rb");
    if (!fp) {
        perror("open dataset");
        return;
    }

    Pair* buffer = malloc(sizeof(Pair) * 2 * BUFFER_PAIRS);
    if (!buffer) {
        puts("malloc fail");
        fclose(fp);
        return;
    }

    puts("[*] Start Linear Cryptanalysis");

    for (int round = 0; round < 3; ++round) {
        for (int stage = 0; stage < 8; ++stage) {
            rewind(fp);
            uint64_t bucket[MAX_KEYS] = { 0 };
            uint64_t need = 1ULL << stage_exp[round][stage];
            uint64_t used = 0;
            double t0 = omp_get_wtime();

            while (used < need) {
                size_t want = BUFFER_PAIRS;
                if (used + want > need)
                    want = (size_t)(need - used);
                size_t n = fread(buffer, sizeof(Pair), want, fp);
                if (!n)
                    break;

#pragma omp parallel for schedule(static)
                for (int key_idx = 0; key_idx < MAX_KEYS; ++key_idx) {
                    uint64_t local_sum = 0;
                    uint32_t key = (uint32_t)key_idx;

                    for (size_t i = 0; i < n; ++i) {
                        uint64_t P = buffer[i].plaintext;
                        uint64_t C = buffer[i].ciphertext;
                        uint32_t d1 = 0, d2 = 0;
                        uint64_t t = 0;

                        /* Round‑specific linear approximations */
                        if (round == 0) {
                            uint8_t rotated_C = ((((C >> 15) & 0xE)) ^ ((C >> 31) & 1)) & 0xF;

                            /* Stage‑by‑stage boolean expressions */
                            if (stage == 0) {
                                t = (P >> 48) & 1;
                                t ^= (C >> 48) & 1;
                                t ^= (C >> 16) & 1;
                                t ^= S[(rotated_C ^ key) & 0xF] & 1;
                            }
                            else if (stage == 1) {
                                t = (P >> 48) & 1;
                                t ^= (C >> 16) & 1;
                                t ^= (C >> 50) & 1;
                                t ^= (S[(((C >> 8) & 0xF) ^ key) & 0xF] >> 2) & 1;
                            }
                            else if (stage == 2) {
                                t = (P >> 48) & 1;
                                t ^= (C >> 16) & 1;
                                t ^= (C >> 50) & 1;
                                t ^= (C >> 63) & 1;
                                t ^= (S[(((C >> 8) & 0xF) ^ right_keys[round][1]) & 0xF] >> 2) & 1;
                                t ^= S[(((C >> 19) & 0xF) ^ key) & 0xF] & 1;
                            }
                            else if (stage == 3) {
                                t = (P >> 48) & 1;
                                t ^= (C >> 16) & 1;
                                t ^= (C >> 49) & 1;
                                t ^= (C >> 63) & 1;
                                t ^= S[(((C >> 19) & 0xF) ^ right_keys[round][5]) & 0xF] & 1;
                                t ^= S[(((C >> 27) & 0xF) ^ key) & 0xF] & 1;
                            }
                            else if (stage == 4) {
                                t = (P >> 16) & 1;
                                t ^= ((C >> 18) & 1) ^ ((C >> 40) & 1) ^ ((C >> 43) & 1) ^ ((C >> 48) & 1);
                                t ^= S[(rotated_C ^ right_keys[round][8]) & 0xF] & 1;
                                t ^= (S[(((C >> 8) & 0xF) ^ right_keys[round][1]) & 0xF] >> 1) & 1;
                                t ^= (S[(((C >> 4) & 0xF) ^ key) & 0xF] >> 1) & 1;
                            }
                            else if (stage == 5) {
                                t = (P >> 16) & 1;
                                t ^= ((C >> 18) & 1) ^ ((C >> 41) & 1) ^ ((C >> 43) & 1) ^ ((C >> 48) & 1);
                                t ^= S[(rotated_C ^ right_keys[round][8]) & 0xF] & 1;
                                t ^= (S[(((C >> 8) & 0xF) ^ right_keys[round][1]) & 0xF] >> 1) & 1;
                                t ^= S[(((C >> 23) & 0xF) ^ key) & 0xF] & 1;
                            }
                            else if (stage == 6) {
                                t = (P >> 16) & 1;
                                t ^= ((C >> 17) & 1) ^ ((C >> 31) & 1) ^ ((C >> 48) & 1) ^ ((C >> 51) & 1) ^
                                    ((C >> 53) & 1) ^ ((C >> 59) & 1) ^ ((C >> 61) & 1);
                                t ^= S[(rotated_C ^ right_keys[round][8]) & 0xF] & 1;
                                t ^= (S[(rotated_C ^ right_keys[round][8]) & 0xF] >> 3) & 1;
                                t ^= (S[(((C >> 19) & 0xF) ^ right_keys[round][5]) & 0xF] >> 3) & 1;
                                t ^= (S[(((C >> 4) & 0xF) ^ right_keys[round][4]) & 0xF] >> 2) & 1;
                                t ^= (S[(((C >> 12) & 0xF) ^ key) & 0xF] >> 1) & 1;
                            }
                            else if (stage == 7) {
                                t = (P >> 16) & 1;
                                t ^= ((C >> 17) & 1) ^ ((C >> 31) & 1) ^ ((C >> 48) & 1) ^ ((C >> 51) & 1) ^
                                    ((C >> 53) & 1) ^ ((C >> 60) & 1);
                                t ^= S[(rotated_C ^ right_keys[round][8]) & 0xF] & 1;
                                t ^= (S[(((C >> 19) & 0xF) ^ right_keys[round][5]) & 0xF] >> 3) & 1;
                                t ^= (S[(((C >> 12) & 0xF) ^ right_keys[round][2]) & 0xF] >> 1) & 1;
                                t ^= (S[((C & 0xF) ^ key) & 0xF] >> 3) & 1;
                            }
                        }
                        else if (round == 1) {
                            d1 = decrypt_half_one_round(C, right_keys[0]);

                            if (stage == 0) {
                                t = (d1 >> 16) & 1;
                                t ^= (P >> 16) & 1;
                                t ^= (C >> 16) & 1;
                                t ^= substitute_with_sbox((((d1 >> 15) & 0xE) ^ ((d1 >> 31) & 1)) ^ key) & 1;
                            }
                            else if (stage == 1) {
                                t = (P >> 16) & 1;
                                t ^= (C >> 18) & 1;
                                t ^= (d1 >> 16) & 1;
                                t ^= (substitute_with_sbox(((d1 >> 8) & 0xF) ^ key) >> 2) & 1;
                            }
                            else if (stage == 2) {
                                t = (P >> 16) & 1;
                                t ^= (C >> 18) & 1;
                                t ^= (C >> 31) & 1;
                                t ^= (d1 >> 16) & 1;
                                t ^= (substitute_with_sbox(((d1 >> 8) & 0xF) ^ right_keys[round][1]) >> 2) & 1;
                                t ^= substitute_with_sbox(((d1 >> 19) & 0xF) ^ key) & 1;
                            }
                            else if (stage == 3) {
                                t = (P >> 16) & 1;
                                t ^= (C >> 17) & 1;
                                t ^= (C >> 31) & 1;
                                t ^= (d1 >> 16) & 1;
                                t ^= substitute_with_sbox(((d1 >> 19) & 0xF) ^ right_keys[round][5]) & 1;
                                t ^= substitute_with_sbox(((d1 >> 27) & 0xF) ^ key) & 1;
                            }
                            else if (stage == 4) {
                                t = (P >> 48) & 1;
                                t ^= (P >> 16) & 1;
                                t ^= (C >> 8) & 1;
                                t ^= (C >> 11) & 1;
                                t ^= (C >> 16) & 1;
                                t ^= (d1 >> 18) & 1;
                                t ^= substitute_with_sbox((((d1 >> 15) & 0xE) ^ ((d1 >> 31) & 1)) ^ right_keys[round][8]) & 1;
                                t ^= (substitute_with_sbox(((d1 >> 8) & 0xF) ^ right_keys[round][1]) >> 1) & 1;
                                t ^= (substitute_with_sbox(((d1 >> 4) & 0xF) ^ key) >> 1) & 1;
                            }
                            else if (stage == 5) {
                                t = (P >> 48) & 1;
                                t ^= (P >> 16) & 1;
                                t ^= (C >> 9) & 1;
                                t ^= (C >> 11) & 1;
                                t ^= (C >> 16) & 1;
                                t ^= (d1 >> 18) & 1;
                                t ^= substitute_with_sbox((((d1 >> 15) & 0xE) ^ ((d1 >> 31) & 1)) ^ right_keys[round][8]) & 1;
                                t ^= (substitute_with_sbox(((d1 >> 8) & 0xF) ^ right_keys[round][1]) >> 1) & 1;
                                t ^= substitute_with_sbox(((d1 >> 23) & 0xF) ^ key) & 1;
                            }
                            else if (stage == 6) {
                                t = (P >> 48) & 1;
                                t ^= (P >> 16) & 1;
                                t ^= (C >> 16) & 1;
                                t ^= (C >> 19) & 1;
                                t ^= (C >> 21) & 1;
                                t ^= (C >> 27) & 1;
                                t ^= (C >> 29) & 1;
                                t ^= (d1 >> 17) & 1;
                                t ^= (d1 >> 31) & 1;
                                t ^= substitute_with_sbox((((d1 >> 15) & 0xE) ^ ((d1 >> 31) & 1)) ^ right_keys[round][8]) & 1;
                                t ^= (substitute_with_sbox((((d1 >> 15) & 0xE) ^ ((d1 >> 31) & 1)) ^ right_keys[round][8]) >> 3) & 1;
                                t ^= (substitute_with_sbox(((d1 >> 19) & 0xF) ^ right_keys[round][5]) >> 3) & 1;
                                t ^= (substitute_with_sbox(((d1 >> 4) & 0xF) ^ right_keys[round][4]) >> 2) & 1;
                                t ^= (substitute_with_sbox(((d1 >> 12) & 0xF) ^ key) >> 1) & 1;
                            }
                            else if (stage == 7) {
                                t = (P >> 48) & 1;
                                t ^= (P >> 16) & 1;
                                t ^= (C >> 16) & 1;
                                t ^= (C >> 19) & 1;
                                t ^= (C >> 21) & 1;
                                t ^= (C >> 28) & 1;
                                t ^= (d1 >> 17) & 1;
                                t ^= (d1 >> 31) & 1;
                                t ^= substitute_with_sbox((((d1 >> 15) & 0xE) ^ ((d1 >> 31) & 1)) ^ right_keys[round][8]) & 1;
                                t ^= (substitute_with_sbox(((d1 >> 19) & 0xF) ^ right_keys[round][5]) >> 3) & 1;
                                t ^= (substitute_with_sbox(((d1 >> 12) & 0xF) ^ right_keys[round][2]) >> 1) & 1;
                                t ^= (substitute_with_sbox((d1 & 0xF) ^ key) >> 3) & 1;
                            }
                        }
                        else /* round == 2 */ {
                            d1 = decrypt_half_one_round(C, right_keys[0]);
                            d2 = decrypt_half_two_round(C, right_keys[0], right_keys[1]);

                            if (stage == 0) {
                                t = (P >> 48) & 1;
                                t ^= (P >> 16) & 1;
                                t ^= (d1 >> 16) & 1;
                                t ^= (d2 >> 16) & 1;
                                t ^= substitute_with_sbox((((d2 >> 15) & 0xE) ^ ((d2 >> 31) & 1)) ^ key) & 1;
                            }
                            else if (stage == 1) {
                                t = (P >> 48) & 1;
                                t ^= (P >> 16) & 1;
                                t ^= (d1 >> 18) & 1;
                                t ^= (d2 >> 16) & 1;
                                t ^= (substitute_with_sbox(((d2 >> 8) & 0xF) ^ key) >> 2) & 1;
                            }
                            else if (stage == 2) {
                                t = (P >> 48) & 1;
                                t ^= (P >> 16) & 1;
                                t ^= (d1 >> 18) & 1;
                                t ^= (d1 >> 31) & 1;
                                t ^= (d2 >> 16) & 1;
                                t ^= (substitute_with_sbox(((d2 >> 8) & 0xF) ^ right_keys[round][1]) >> 2) & 1;
                                t ^= substitute_with_sbox(((d2 >> 19) & 0xF) ^ key) & 1;
                            }
                            else if (stage == 3) {
                                t = (P >> 48) & 1;
                                t ^= (P >> 16) & 1;
                                t ^= (d1 >> 17) & 1;
                                t ^= (d1 >> 31) & 1;
                                t ^= (d2 >> 16) & 1;
                                t ^= substitute_with_sbox(((d2 >> 19) & 0xF) ^ right_keys[round][5]) & 1;
                                t ^= substitute_with_sbox(((d2 >> 27) & 0xF) ^ key) & 1;
                            }
                            else if (stage == 4) {
                                t = (P >> 48) & 1;
                                t ^= (d1 >> 8) & 1;
                                t ^= (d1 >> 11) & 1;
                                t ^= (d1 >> 16) & 1;
                                t ^= (d2 >> 18) & 1;
                                t ^= substitute_with_sbox((((d2 >> 15) & 0xE) ^ ((d2 >> 31) & 1)) ^ right_keys[round][8]) & 1;
                                t ^= (substitute_with_sbox(((d2 >> 8) & 0xF) ^ right_keys[round][1]) >> 1) & 1;
                                t ^= (substitute_with_sbox(((d2 >> 4) & 0xF) ^ key) >> 1) & 1;
                            }
                            else if (stage == 5) {
                                t = (P >> 48) & 1;
                                t ^= (d1 >> 9) & 1;
                                t ^= (d1 >> 11) & 1;
                                t ^= (d1 >> 16) & 1;
                                t ^= (d2 >> 18) & 1;
                                t ^= substitute_with_sbox((((d2 >> 15) & 0xE) ^ ((d2 >> 31) & 1)) ^ right_keys[round][8]) & 1;
                                t ^= (substitute_with_sbox(((d2 >> 8) & 0xF) ^ right_keys[round][1]) >> 1) & 1;
                                t ^= substitute_with_sbox(((d2 >> 23) & 0xF) ^ key) & 1;
                            }
                            else if (stage == 6) {
                                t = (P >> 48) & 1;
                                t ^= (d1 >> 16) & 1;
                                t ^= (d1 >> 19) & 1;
                                t ^= (d1 >> 21) & 1;
                                t ^= (d1 >> 27) & 1;
                                t ^= (d1 >> 29) & 1;
                                t ^= (d2 >> 17) & 1;
                                t ^= (d2 >> 31) & 1;
                                t ^= substitute_with_sbox((((d2 >> 15) & 0xE) ^ ((d2 >> 31) & 1)) ^ right_keys[round][8]) & 1;
                                t ^= (substitute_with_sbox((((d2 >> 15) & 0xE) ^ ((d2 >> 31) & 1)) ^ right_keys[round][8]) >> 3) & 1;
                                t ^= (substitute_with_sbox(((d2 >> 19) & 0xF) ^ right_keys[round][5]) >> 3) & 1;
                                t ^= (substitute_with_sbox(((d2 >> 4) & 0xF) ^ right_keys[round][4]) >> 2) & 1;
                                t ^= (substitute_with_sbox(((d2 >> 12) & 0xF) ^ key) >> 1) & 1;
                            }
                            else if (stage == 7) {
                                t = (P >> 48) & 1;
                                t ^= (d1 >> 16) & 1;
                                t ^= (d1 >> 19) & 1;
                                t ^= (d1 >> 21) & 1;
                                t ^= (d1 >> 28) & 1;
                                t ^= (d2 >> 17) & 1;
                                t ^= (d2 >> 31) & 1;
                                t ^= substitute_with_sbox((((d2 >> 15) & 0xE) ^ ((d2 >> 31) & 1)) ^ right_keys[round][8]) & 1;
                                t ^= (substitute_with_sbox(((d2 >> 19) & 0xF) ^ right_keys[round][5]) >> 3) & 1;
                                t ^= (substitute_with_sbox(((d2 >> 12) & 0xF) ^ right_keys[round][2]) >> 1) & 1;
                                t ^= (substitute_with_sbox((d2 & 0xF) ^ key) >> 3) & 1;
                            }
                        }

                        /* Accumulate parity */
                        local_sum += t;
                    }
#pragma omp atomic
                    bucket[key_idx] += local_sum;
                }
                used += n;

                double prog = (double)used / need;
                double pct = ((int)(prog * 1000)) / 10.0;
                double eta = prog ? (omp_get_wtime() - t0) * (1.0 / prog - 1.0) : 0.0;
                printf("\r[Round %d, Stage %d] %.1f%% | %llu/%llu | ETA %.1fs ",
                    round, stage, pct, (unsigned long long)used, (unsigned long long)need, eta);
                fflush(stdout);
            }
            puts("");

            /* Pick the nibble with the largest bias */
            int best = find_max_deviation_index(bucket, used);
            int pos = stage_to_pos(stage);
            right_keys[round][pos] = (uint8_t)best;
            rk_nib[round][pos] = (uint8_t)best;
            printf("[Round %d, Stage %d] key[%d] = %d\n", round, stage, pos, best);
        }
    }

    free(buffer);
    fclose(fp);

    /* Optional log output */
    if (logfp) {
        for (int r = 0; r < 3; ++r) {
            fprintf(logfp, "R%d:", 24 - r);
            for (int n = 0; n < 9; ++n)
                fprintf(logfp, " %X", rk_nib[r][n]);
            fputc('\n', logfp);
        }
        fflush(logfp);
    }
}

/* -------------------------------------------------------------------------- */
/*  Main                                                                      */
/* -------------------------------------------------------------------------- */
int main(void)
{
    omp_set_num_threads(MAX_THREADS);

    const char* DATA_BIN = "E:/wonwoo/pt_ct_tmp.bin"; /* Output file for plaintext‑ciphertext pairs */
    const char* LOG_FILE = "E:/wonwoo/keys.txt";     /* Log for recovered subkeys & master key */
    FILE* logfp = fopen(LOG_FILE, "a");
    if (!logfp) {
        perror("log file");
        return 1;
    }

    /* Demo master key */
    uint8_t mkey[16] = {
        0xB7, 0x45, 0xC5, 0xC6, 0x10, 0x61, 0x98, 0xF3,
        0xCA, 0x4C, 0xD4, 0x5E, 0x2B, 0x9F, 0x91, 0x0F };

    /* (0) Key schedule */
    KeySchedule ks;
    key_schedule(mkey, &ks);

    /* (1) Generate 2^33 known (P,C) pairs */
    generate_dataset(&ks, DATA_BIN, TARGET_PAIRS);

    /* (2) Linear attack to recover the last three round keys as 9‑nibble arrays */
    uint8_t rk_nib[3][9] = { {0} };
    linear_attack_recover_keys(DATA_BIN, rk_nib, logfp);

    /* (3) Convert nibbles → 32‑bit words */
    uint32_t rk32[3];
    for (int r = 0; r < 3; ++r) {
        rk32[r] = convert_key_array_to_uint32(rk_nib[r]); /* Helper from recover_masterkey.h */
        printf("\n R%d: %08X\n", 18 - r, rk32[r]);
    }

    /* (4) Master‑key recovery using two (P,C) pairs and RK16 xor K10_R,RK17 xor K10_L,RK18 xor K10_R */
    Pair two[2];
    FILE* fp = fopen(DATA_BIN, "rb");
    fread(two, sizeof(Pair), 2, fp);
    fclose(fp);

    uint8_t rec[16];
    if (!find_master_key(two, rk32[2], rk32[1], rk32[0], rec))
        fprintf(logfp, "[Key] master‑key recovery FAILED\n\n");

    fprintf(logfp, "Recovered : ");
    for (int i = 0; i < 16; ++i)
        fprintf(logfp, "%02X", rec[i]);
    fprintf(logfp, "\n\n");
    fflush(logfp);

    printf("Recovered : ");
    for (int i = 0; i < 16; ++i)
        printf("%02X", rec[i]);
    printf("\n");

    puts(memcmp(mkey, rec, 16) == 0 ? "[OK] master_key matched" : "[!] MISMATCH");

    fclose(logfp);
    return 0;
}
