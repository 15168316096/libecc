# libecc CKB-VM Contract Audit Report

**Project**: libecc (Elliptic Curve Cryptography Library for CKB)  
**Repository**: https://github.com/15168316096/libecc  
**Date**: 2026-03-02  
**Scope**: Full code audit of the libecc library adapted for CKB-VM (RISC-V) environment  

---

## 1. Executive Summary

This report presents the security audit of the **libecc** library — an elliptic curve cryptography (ECC) library adapted to run on CKB-VM (a RISC-V based virtual machine for Nervos CKB smart contracts). The library implements ECDSA signature/verification following ISO 14888-3, with support for SECP256R1 curve and SHA-256 hash function in its default CKB configuration.

### Overall Risk Assessment: **MEDIUM**

| Category | Finding Count | Severity |
|----------|:------------:|----------|
| Critical | 1 | 🔴 Critical |
| High     | 2 | 🟠 High |
| Medium   | 3 | 🟡 Medium |
| Low      | 2 | 🟢 Low |
| Informational | 3 | ℹ️ Info |

---

## 2. Architecture Overview

### 2.1 Library Layer Structure

```
┌──────────────────────────────────────────┐
│           libsign.a (Signatures)          │
│  ECDSA, ECKCDSA, ECGDSA, ECRDSA, etc.   │
├──────────────────────────────────────────┤
│            libec.a (EC Curves)            │
│  Point operations, scalar multiplication  │
├──────────────────────────────────────────┤
│         libarith.a (Arithmetic)           │
│  NN (natural numbers), Fp (prime fields)  │
├──────────────────────────────────────────┤
│          External Dependencies            │
│  rand.c, print.c, time.c (CKB stubs)     │
└──────────────────────────────────────────┘
```

### 2.2 CKB-Specific Adaptations

The library is adapted for CKB-VM through:
- **Custom RISC-V 64-bit assembly** (`ll_u256_mont-riscv64.S`) for Montgomery multiplication
- **CKB stdlib stubs** (`deps/ckb-c-stdlib`) for `nostdlib` environment
- **No-op random source** (`get_random` returns 0 without filling buffer)
- **No-op printf** (silenced output for CKB-VM)
- **Deterministic time counter** (incrementing integer instead of real clock)
- **`ckb_exit()` for assertion failures** via `MUST_HAVE` macro

### 2.3 CKB-VM Execution Context

The library is compiled for CKB-VM with these flags:
```
-fno-builtin -nostdinc -nostdlib -nostartfiles
-DWITH_CKB -DCKB_DECLARATION_ONLY
-DUSER_NN_BIT_LEN=256 -DWORDSIZE=64
```

Build target: `CC=riscv64-unknown-linux-gnu-gcc make ckb_execs`

---

## 3. CKB Contract API Analysis

### 3.1 Contract Type

This library operates as a **CellDep dependency** — it does not directly implement a Lock or Type script. Instead, it provides cryptographic primitives (ECDSA signature verification) that CKB contracts can link against to verify signatures.

### 3.2 Cell Structure Definition

When used as a CellDep in a CKB transaction:

```typescript
type LibeccCellDep {
    code_hash: Hash(libecc_binary),  // Hash of compiled RISC-V binary
    hash_type: "data",               // Direct code reference
    args: Bytes                      // Unused (library, not script)
}
```

### 3.3 Syscall Usage Analysis

The library itself does **not** directly invoke CKB syscalls. However, it integrates with `ckb-c-stdlib` via:

| Component | CKB Integration | Usage |
|-----------|----------------|-------|
| `print.c` | `#include "ckb_syscalls.h"` | No-op `ext_printf` (debug output silenced) |
| `rand.c` | Direct stub | `get_random()` returns 0 (no-op) |
| `time.c` | Direct stub | `get_ms_time()` returns incrementing counter |
| `utils.h` | `ckb_exit()` | Assertion failure handler |

### 3.4 Data Flow

```
CKB Contract (caller)
    │
    ├── Provides: public key, message hash, signature (r, s)
    │
    ▼
libecc ECDSA Verify
    │
    ├── Parses signature → (r, s) values
    ├── Computes H(m) via SHA-256
    ├── Performs EC scalar multiplication (W' = uG + vY)
    ├── Compares r' with r
    │
    ▼
Returns: 0 (valid) or -1 (invalid)
```

---

## 4. Test Case Analysis

Based on the CKB contract test analysis framework:

### 4.1 Library Self-Tests

| Test Type | Command | Description |
|-----------|---------|-------------|
| Known Vectors | `ec_self_tests vectors` | Tests against known ECDSA test vectors |
| Random Sig/Verify | `ec_self_tests rand` | Random key generation + sign + verify |
| Montgomery Mul | `nn_mul_redc1` | Montgomery multiplication correctness |

### 4.2 CKB-VM Integration Tests

| Inputs | Outputs | Scenario | Description |
|--------|---------|----------|-------------|
| Known test vectors | Verification result | `ckb-debugger --bin ec_self_tests vectors` | Validate ECDSA sig/verify correctness on CKB-VM |
| Random keypairs | Sign + Verify cycle | `ec_self_tests rand` | End-to-end signature lifecycle on CKB-VM |
| Montgomery inputs | Reduced product | `nn_mul_redc1` | RISC-V assembly Montgomery multiplication |

### 4.3 Missing Test Coverage

| Scenario | Description | Priority |
|----------|-------------|----------|
| Edge case: zero signature | Verify rejection of (r=0, s=0) | High |
| Edge case: max value signature | Verify with r, s near curve order q | High |
| Invalid curve points | Public key on wrong curve | Medium |
| Cycle budget test | Verify operation within ~1,000M cycle limit | Medium |
| Multi-caller scenario | Multiple CKB scripts using library concurrently | Low |

---

## 5. Security Findings

### 5.1 🔴 CRITICAL: No-Op Random Source in CKB Environment

**File**: `src/external_deps/rand.c:18-27`

```c
#if defined(WITH_CKB)
int get_random(unsigned char *buf, u16 len) {
  return 0;  // Buffer is NOT filled with random data
}
```

**Impact**: The `get_random()` function in the CKB environment returns success (0) **without writing any random data to the buffer**. The buffer contents remain uninitialized (or zero-initialized depending on the caller).

**Risk**: 
- **Signature generation is UNSAFE** on CKB-VM — the random ephemeral key `k` in ECDSA signing would be predictable/zero, leading to **private key recovery** from a single signature.
- Blinding masks (`scalar_b`, `b`) used for side-channel protection are ineffective (always zero/uninitialized).
- `nn_get_random_mod()` which calls `get_random()` would produce biased/predictable values.

**Mitigation**: This is by design — the library is documented to be used **only for signature verification** on CKB-VM, not for signing. The comment in the code acknowledges this limitation. However:
1. There is no compile-time guard preventing `_ecdsa_sign_finalize()` from being called.
2. The `ecdsa_init_pub_key()` function calls `nn_get_random_mod()` for blinding during public key initialization, which silently produces predictable blinding factors.

**Recommendation**: 
- Add `#error` or runtime check to prevent ECDSA sign functions from being callable in CKB builds.
- Alternatively, mark sign functions with `__attribute__((error("...")))` for compile-time prevention.

---

### 5.2 🟠 HIGH: Deterministic Random in Non-CKB `fimport` (Unix Build)

**File**: `src/external_deps/rand.c:68-78`

```c
// Original /dev/urandom reading code is COMMENTED OUT
// Replaced with deterministic pattern:
for (u16 i = 0; i < buflen; i++){
    buf[i] = i + (int)(*path);
}
return 0;
```

**Impact**: The Unix/non-CKB build path has its `/dev/urandom` reading code **commented out** and replaced with a completely deterministic pattern (`buf[i] = i + '/dev/urandom'[0]`). This means:
- All "random" values are predictable: `buf[0] = 0x2F, buf[1] = 0x30, buf[2] = 0x31, ...`
- **Any ECDSA signature generated in the non-CKB Unix build** uses a predictable ephemeral key `k`, enabling **private key extraction**.

**Recommendation**: 
- Restore the original `/dev/urandom` reading code for Unix builds.
- This appears to be a debugging/testing change that was committed accidentally. The commented-out code should be restored immediately.

---

### 5.3 🟠 HIGH: Commented-Out Debug Code in ECDSA Verification

**File**: `src/sig/ecdsa.c:577-594`

```c
// nn_set_word_value(&u, 2);
// nn_set_word_value(&v, 2);
/* 7. Compute W' = uG + vY */
// prj_pt_mul_monty(&uG, &u, G);
// prj_pt_mul_monty(&vY, &v, Y);
// prj_pt_add_monty(&W_prime, &uG, &vY);
// ...
// prj_pt_copy(&W_prime, Y);
// prj_pt_copy(&W_prime, G);
prj_pt_ec_mult_wnaf(&W_prime, &u, G, &v, Y);
// prj_pt_copy(&uG, G);
// prj_pt_copy(&vY, Y);
// prj_pt_copy(&W_prime, Y);
// prj_pt_uninit(&W_prime);
// prj_pt_ec_mult_wnaf(&W_prime, &u, G, &v, Y);
```

**Impact**: Extensive commented-out debug code remains in the critical ECDSA verification path. While the active code (`prj_pt_ec_mult_wnaf`) appears correct, this indicates:
- The verification path was actively modified/debugged, increasing risk of residual errors.
- Some commented lines (e.g., `nn_set_word_value(&u, 2)`) would completely break verification if accidentally uncommented.
- The replacement of standard `prj_pt_mul_monty + prj_pt_add_monty` with `prj_pt_ec_mult_wnaf` (windowed NAF) changes the algorithm — this should be verified against known test vectors.

**Recommendation**: 
- Remove all commented-out debug code from the verification path.
- Ensure the `prj_pt_ec_mult_wnaf` replacement has been validated against the full ECDSA test vector suite.

---

### 5.4 🟡 MEDIUM: ECDSA Verify Uses Projective X Directly (Skips Affine Conversion)

**File**: `src/sig/ecdsa.c:608-613`

```c
// Original (commented out):
// prj_pt_to_aff(&W_prime_aff, &W_prime);
// nn_mod(&r_prime, &(W_prime_aff.x.fp_val), q);

// Current (projective coordinate):
nn_mod(&r_prime, &(W_prime.X.fp_val), q);
prj_pt_uninit(&W_prime);
```

**Impact**: The standard ECDSA verification (Step 9) requires computing `r' = W'_x mod q` where `W'_x` is the **affine** x-coordinate. The current code uses `W_prime.X.fp_val` which is the **projective** X coordinate. In projective coordinates, the affine x-coordinate is `X/Z^2` (or `X/Z` for Jacobian).

If `prj_pt_ec_mult_wnaf` normalizes the output point to `Z=1`, this is correct. However, if Z ≠ 1, then `X ≠ x_affine` and verification will produce incorrect results.

**Recommendation**: 
- Verify that `prj_pt_ec_mult_wnaf` always returns points with `Z=1` (normalized).
- If not guaranteed, restore the `prj_pt_to_aff` conversion or add an explicit normalization step.
- Add an assertion: `MUST_HAVE(nn_isone(&W_prime.Z.fp_val))` before using `W_prime.X`.

---

### 5.5 🟡 MEDIUM: Blinding Ineffective in CKB Environment

**File**: `src/sig/ecdsa.c:31-61` (public key init), `src/curves/prj_pt_monty.c` (scalar multiplication)

**Impact**: The library implements multiple blinding countermeasures:
1. **Scalar blinding** in `ecdsa_init_pub_key()`: `nn_get_random_mod(&scalar_b, ...)` 
2. **Projective coordinate blinding** in Montgomery ladder
3. **Signature blinding** (when `USE_SIG_BLINDING` is defined)

All of these depend on `get_random()`, which is a **no-op in CKB**. This means:
- All blinding masks are **zero or uninitialized memory** on CKB-VM.
- The scalar blinding `b*q + m` becomes `0*q + m = m` (no blinding).
- Projective coordinate randomization does not occur.

**Mitigation Note**: Side-channel attacks (DPA, SPA, timing) are generally not applicable in the CKB-VM environment since:
- CKB-VM is a software emulator — there are no physical side channels.
- Execution is deterministic and isolated per transaction.

However, if CKB-VM ever exposes cycle-count or execution-time information to other scripts or observers, the lack of blinding could become relevant.

**Recommendation**: Document that blinding is intentionally disabled for CKB-VM and explain the threat model.

---

### 5.6 🟡 MEDIUM: Missing Input Validation on Assembly Montgomery Multiplication

**File**: `src/nn/nn_mul_redc1.c:99-112`

```c
#ifdef WITH_LL_U256_MONT
static void my_nn_mul_redc1(nn_t out, nn_src_t in1, nn_src_t in2, nn_src_t p,
                            word_t mpinv) {
  nn_set_wlen(out, p->wlen);
  ll_u256_mont_mul(out->val, in1->val, in2->val, p->val, mpinv);
}
```

**Impact**: The assembly-optimized Montgomery multiplication wrapper (`my_nn_mul_redc1`) directly passes raw array pointers to the RISC-V assembly function without:
- Checking that `in1`, `in2`, and `p` have exactly 4 words (256 bits).
- Checking that `out` has sufficient capacity.
- Checking that the assembly output is within bounds.

If called with inputs of unexpected sizes, the assembly code would read/write beyond buffer boundaries.

**Recommendation**: Add `MUST_HAVE(p->wlen == 4)` assertion before calling `ll_u256_mont_mul`.

---

### 5.7 🟢 LOW: No Cycle Budget Verification

**File**: `.github/workflows/ckb.yml:42`

```yaml
ckb-debugger --max-cycles 999999999999 --bin ec_self_tests vectors
```

**Impact**: The CI test uses an extremely high cycle limit (999,999,999,999) which far exceeds the CKB network limit (~1,000,000,000 cycles). This means the tests don't validate whether the library operates within the actual CKB cycle budget.

**Recommendation**: 
- Add a separate CI test with realistic cycle limits (e.g., 500M or 1B cycles) for individual verification operations.
- Document the expected cycle cost per ECDSA verification.

---

### 5.8 🟢 LOW: Potential Integer Overflow in `fimport` Stub

**File**: `src/external_deps/rand.c:73-74`

```c
for (u16 i = 0; i < buflen; i++){
    buf[i] = i + (int)(*path);
}
```

**Impact**: `(int)(*path)` casts a `char` to `int`, then adds `i` (a `u16`). The result is implicitly truncated to `unsigned char` for `buf[i]`. While this is a deterministic stub (not a security function), the wrapping behavior is undocumented.

**Recommendation**: This code should be removed entirely (see Finding 5.2).

---

### 5.9 ℹ️ INFO: Performance Test Disabled for CKB

**File**: `src/tests/ec_self_tests.c`

Performance tests are explicitly disabled for CKB builds ("PERFORMANCE tests are too slow to run on ckb"). This is appropriate given CKB-VM's interpreted execution model but means there's no benchmark data for CKB-VM cycle consumption.

---

### 5.10 ℹ️ INFO: Only SECP256R1 + SHA256 + ECDSA Enabled by Default

**File**: `src/lib_ecc_config.h`

The default configuration enables only:
- Curve: `SECP256R1` (P-256)
- Hash: `SHA256`
- Signature: `ECDSA`

All other curves, hash algorithms, and signature schemes are commented out. This minimizes code size and attack surface for CKB deployment.

---

### 5.11 ℹ️ INFO: `ext_printf` is No-Op in CKB

**File**: `src/external_deps/print.c:18-24`

The `ext_printf` function does nothing in CKB mode. This is appropriate for the CKB-VM environment where stdout is not available, but it means debug output (`VERBOSE_INNER_VALUES`) is silently discarded. Note that `VERBOSE_INNER_VALUES` is set in the CKB build flags, which compiles debug print calls that are then discarded — minor code size overhead.

---

## 6. Error Scenarios and Return Codes

| Code | Function | Cause | Behavior |
|------|----------|-------|----------|
| 0 | `_ecdsa_verify_finalize` | Valid signature | Verification succeeds |
| -1 | `_ecdsa_verify_init` | r or s is 0 or ≥ q | Reject immediately |
| -1 | `_ecdsa_verify_init` | Signature length mismatch | Reject immediately |
| -1 | `_ecdsa_verify_finalize` | W' is point at infinity | Reject — invalid signature |
| -1 | `_ecdsa_verify_finalize` | r' ≠ r | Reject — signature doesn't match |
| -2 | `MUST_HAVE` (via `ckb_exit`) | Assertion failure | Script aborts via `ckb_exit(-2)` |
| -1 | `_ecdsa_sign_finalize` | Random generation failure | Sign operation fails |

---

## 7. Recommendations Summary

### Immediate Actions (Before Production Deployment)

| # | Priority | Recommendation |
|---|----------|----------------|
| 1 | 🔴 Critical | Restore `/dev/urandom` reading in Unix `rand.c` or guard against signing in CKB mode |
| 2 | 🟠 High | Remove commented-out debug code from `ecdsa.c` verification path |
| 3 | 🟠 High | Verify `prj_pt_ec_mult_wnaf` returns normalized points (Z=1) or restore affine conversion |
| 4 | 🟡 Medium | Add compile-time guards preventing sign functions from being called in CKB builds |

### Recommended Improvements

| # | Priority | Recommendation |
|---|----------|----------------|
| 5 | 🟡 Medium | Add bounds checks in assembly Montgomery multiplication wrapper |
| 6 | 🟡 Medium | Document that blinding is disabled in CKB mode and explain the security model |
| 7 | 🟢 Low | Add realistic cycle-budget tests in CI |
| 8 | 🟢 Low | Remove `VERBOSE_INNER_VALUES` from CKB build flags to reduce binary size |

### Test Coverage Improvements

| Test Case | Input | Expected Output | Status |
|-----------|-------|-----------------|--------|
| Known ECDSA vectors on CKB-VM | Standard test vectors | Verification passes | ✅ Covered |
| Random sign/verify cycle | Random keypairs | Round-trip succeeds | ✅ Covered (non-CKB only) |
| Zero signature rejection | `(r=0, s=0)` | Reject with -1 | ⚠️ Not explicitly tested |
| Max-value signature | `(r=q-1, s=q-1)` | Reject or verify correctly | ⚠️ Not explicitly tested |
| Cycle budget validation | ECDSA verify | Within 1B cycles | ❌ Not tested |
| Assembly vs C comparison | Same inputs | Same output | ✅ Covered (`nn_mul_redc1` test) |

---

## 8. Conclusion

The libecc library is a well-structured and carefully implemented ECC library with good side-channel protections in its original form. The CKB-VM adaptation is functionally correct for **signature verification only**, which is the intended use case.

The most critical finding is the **no-op random source** (Finding 5.1), which makes the library **unsafe for any operation requiring randomness** (signing, key generation). This is acknowledged in code comments but lacks compile-time enforcement. The **commented-out original `/dev/urandom` code** in the Unix build (Finding 5.2) is also concerning and should be addressed.

The switch from standard two-step EC point multiplication (`prj_pt_mul_monty` + `prj_pt_add_monty`) to the optimized `prj_pt_ec_mult_wnaf` function in ECDSA verification (Finding 5.3/5.4) improves performance but requires careful validation that the output is properly normalized.

**For CKB production use (verification only)**: The library is **conditionally suitable** pending resolution of findings 5.3 and 5.4, and cleanup of finding 5.2.

**For general-purpose use (signing + verification)**: The library is **NOT suitable** in its current state due to findings 5.1 and 5.2.

---

*Report generated based on CKB VM Contract Test Analysis methodology.*
