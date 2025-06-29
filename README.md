# MGFN-18R Linear Cryptanalysis and Master-Key Recovery

This repository provides a full C implementation for linear cryptanalysis and 128-bit master-key recovery on a reduced 18-round version of a block cipher called MGFN-18R.

The code performs:
- Key schedule and encryption of MGFN-18R
- Dataset generation for known (plaintext, ciphertext) pairs
- 3-round linear cryptanalysis
- Recovery of the final 3 round keys: rk16 ^ K10_R, rk17 ^ K10_L, rk18 ^ K10_R
- Exhaustive search over 2^35 master-key candidates to find the correct 128-bit key

---

## 🔧 Features

- 3-round nibble-by-nibble round-key recovery (R16–R18 xor K10_*)
- 2^35 candidate search using only 2 known (P, C) pairs
- Full 128-bit key reconstruction from partially recovered round keys
- Highly parallelized with OpenMP
- Scalable dataset size: adjustable up to 2^33 (P, C) pairs

---

## 📁 Project Structure

This project is structured for Visual Studio:

MGFN_18R_LC_CODE/
├── Source File/
│   └── MGFN_18R_LC.c             # Main logic: linear cryptanalysis and master-key recovery
├── Header File/
│   ├── MGFN_18R.c                # Cipher round function and key schedule
│   ├── MGFN_18R.h                # Definitions: KeySchedule, Pair, S-box
│   ├── recover_masterkey.c       # Final key recovery logic using R16~R18
│   └── recover_masterkey.h       # API: find_master_key()

All `.c` files are compiled as part of the project.  
No need to build them separately.

---

## ⚙️ Build (Visual Studio)

Requirements:
- Visual Studio 2019 or later
- OpenMP enabled (via /openmp)
- C11 or later language standard

How to configure:

1. Open or create a project named MGFN_18R_LC_CODE
2. Add the 4 `.c` and 2 `.h` files to the project
3. Enable OpenMP:
   Project → Properties → C/C++ → Language → OpenMP Support → Yes
4. Set language standard:
   Project → Properties → C/C++ → Language → C Language Standard → ISO C11
5. Build and run (Ctrl + F5)

---

## 🚀 Usage

Run the executable to start full recovery flow:

    MGFN_18R_LC.exe

This will:
1. Generate N plaintext-ciphertext pairs using a random 128-bit master key
2. Perform 3-round linear cryptanalysis
3. Recover 32-bit round keys:
   - rk16 ⊕ K10_R
   - rk17 ⊕ K10_L
   - rk18 ⊕ K10_R
4. Search among 2^35 possible master keys using 2 known (P, C) pairs
5. Output recovered key and verification result

Note:  
Dataset size and file paths are defined in `MGFN_18R_LC.c`.  
You can adjust:
- `#define TARGET_PAIRS ((uint64_t)1ULL << N)` for dataset size
- `const char* DATA_BIN = "..."` and `LOG_FILE = "..."` for file output location

---

## 📂 Output

- Ciphertext dataset (binary):
  ./pt_ct_tmp.bin

- Recovered round keys and final master key log:
  ./keys.txt

These files are configurable from within the source code.

---

## 📄 Key API

```c
int find_master_key(
    const Pair      pairs[2],
    uint32_t        rk16_xor_K10_R,  // 32-bit key: rk16 ^ K10_R
    uint32_t        rk17_xor_K10_L,  // 32-bit key: rk17 ^ K10_L
    uint32_t        rk18_xor_K10_R,  // 32-bit key: rk18 ^ K10_R
    uint8_t         master_key_out[16]
);

MIT License

Copyright (c) 2025 Wonwoo Song

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the “Software”), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
