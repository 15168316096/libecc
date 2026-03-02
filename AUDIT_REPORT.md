# 安全审计报告: libecc

> 基于 [AI-Driven Security Audit Skill](https://github.com/15168316096/ckb-test-skills/blob/main/.claude/skills/security-audit/SKILL.md) 方法论生成

---

## 1. 执行摘要

| 项目 | 详情 |
|------|------|
| **项目名称** | libecc — 椭圆曲线密码学库 (CKB-VM RISC-V 适配版) |
| **仓库地址** | https://github.com/15168316096/libecc |
| **审计日期** | 2026-03-02 |
| **审计范围** | 全量源码审计 (src/ 目录, 57 个 .c 文件, 81 个 .h 文件, 1 个 .S 汇编文件) |
| **编程语言** | C99 + RISC-V 64-bit Assembly |
| **构建工具** | GNU Make, riscv64-unknown-linux-gnu-gcc |
| **项目类型** | 密码学库 (ECC/ECDSA, 适配 CKB-VM 智能合约环境) |
| **依赖数量** | 1 (ckb-c-stdlib, git submodule) |
| **现有测试数** | 3 个测试程序 (ec_self_tests, ec_utils, nn_mul_redc1) |
| **总审计项** | 22 |
| **审计方法** | 正向逻辑审查 + 逆向攻击思维 + 上下文关联审查 |

### 项目概况

libecc 是一个基于 ISO 14888-3 标准的椭圆曲线密码学库，原始设计为纯 C99 无外部依赖的可移植库。本仓库为其 CKB-VM (Nervos CKB 区块链的 RISC-V 虚拟机) 适配版本，主要用于在链上智能合约中执行 ECDSA 签名验证。

默认配置仅启用:
- **曲线**: SECP256R1 (P-256)
- **哈希**: SHA-256
- **签名方案**: ECDSA

### 架构层次

```
┌──────────────────────────────────────────┐
│           libsign.a (签名层)              │
│  ECDSA 签名/验证, 密钥管理                │
├──────────────────────────────────────────┤
│            libec.a (椭圆曲线层)           │
│  点运算, 标量乘法 (Montgomery/wNAF)       │
├──────────────────────────────────────────┤
│         libarith.a (算术层)               │
│  大数运算 (NN), 素域运算 (Fp)             │
├──────────────────────────────────────────┤
│          外部依赖适配层                    │
│  rand.c (随机源), print.c, time.c        │
│  CKB: 空操作桩 | Unix: /dev/urandom      │
└──────────────────────────────────────────┘
```

### 信任边界

```
不可信区域                        可信区域
┌─────────────┐                ┌─────────────────┐
│ CKB 交易数据 │───────────────▶│ libecc 验证逻辑   │
│  - 公钥      │  函数调用       │  - 签名解析       │
│  - 签名(r,s) │  (参数传入)     │  - 哈希计算       │
│  - 消息哈希   │                │  - EC 点乘        │
└─────────────┘                │  - 结果比较       │
                               └─────────────────┘
                                       │
                                       ▼
                               返回 0 (有效) 或 -1 (无效)
```

---

## 2. 风险评级

| 级别 | 数量 | 说明 |
|:----:|:----:|------|
| ■ Critical | 2 | 随机源安全性严重缺陷 |
| ■ High | 3 | 汇编边界检查缺失、调试代码残留、签名防护缺失 |
| ■ Medium | 3 | 恒定时间问题、MUST_HAVE 空宏、盲化无效 |
| ■ Low | 2 | CI 周期预算、nn_cmp 时间泄露 |

**总体风险评级: 中等 (MEDIUM)**
> 对于 CKB 链上仅验证签名的场景，核心验证逻辑正确。主要风险集中在随机源和开发卫生方面。

---

## 3. 关键发现（按严重级别降序）

### AUDIT-CRYPTO-001: CKB 环境随机源为空操作 — 签名生成不安全
- **状态**: ❌ 发现漏洞
- **严重级别**: 🔴 Critical
- **影响范围**: CKB-VM 构建的所有依赖随机性的操作

#### 分析过程

逐行审查 `src/external_deps/rand.c` 的 CKB 分支:

```c
// src/external_deps/rand.c:18-27
#if defined(WITH_CKB)
int get_random(unsigned char *buf, u16 len) {
  // Note that even while doing purely deterministic operations like
  // signature verification, libecc still expects random source which
  // returns no error.
  return 0;  // ← 返回成功但未写入任何随机数据
}
```

追踪调用链:
1. `_ecdsa_sign_finalize()` → `ctx->rand(&k, q)` → 最终调用 `get_random()`
2. `ecdsa_init_pub_key()` → `nn_get_random_mod(&scalar_b, ...)` → `get_random()`
3. `nn_get_random_mod()` → `get_random((u8 *)tmp_rand.val, (u16)(2 * q_len))`

在 CKB 环境中，`get_random()` 返回 0 (成功) 但缓冲区 `buf` 未被填充。这意味着:
- `tmp_rand.val` 保持为零初始化状态
- `nn_get_random_mod` 计算 `out = 0 mod (q-1) = 0`，然后 `out += 1 = 1`
- 所有 "随机" 值均为 **固定值 1**

#### 发现
- **ECDSA 签名中 k = 1**: 攻击者可通过 `s = k^-1 * (xr + e) mod q` 中 k=1 直接恢复私钥 x — **Critical**
- 标量盲化因子 `scalar_b = 1`: 盲化失效 — **Medium** (CKB-VM 无物理侧信道)
- `ecdsa_init_pub_key` 的盲化无效但不影响计算正确性 — **Low**

#### 关键代码引用
```c
// src/nn/nn_rand.c:86-132  — nn_get_random_mod 依赖 get_random
// src/sig/ecdsa.c:242      — 签名使用随机 k
// src/sig/ecdsa.c:42       — 公钥初始化使用随机盲化
```

#### 修复建议
1. **优先方案**: 在 CKB 构建中使用编译时防护禁止签名函数:
```c
#ifdef WITH_CKB
#define _ecdsa_sign_init(...) \
    _Static_assert(0, "ECDSA signing is not safe in CKB environment")
#endif
```
2. **替代方案**: 运行时检查，在签名函数入口返回错误

---

### AUDIT-CRYPTO-002: Unix 构建中 /dev/urandom 读取被注释替换为确定性填充
- **状态**: ❌ 发现漏洞
- **严重级别**: 🔴 Critical
- **影响范围**: 非 CKB 的 Unix/macOS 构建

#### 分析过程

```c
// src/external_deps/rand.c:46-78
static int fimport(unsigned char *buf, u16 buflen, const char *path)
{
    // ========= 原始安全代码已被注释 =========
    // u16 rem = buflen, copied = 0;
    // ssize_t ret;
    // int fd;
    // fd = open(path, O_RDONLY);
    // ...read from /dev/urandom...
    // close(fd);
    // return (copied == buflen) ? 0 : -1;

    // ========= 替换为确定性模式 =========
    for (u16 i = 0; i < buflen; i++){
        buf[i] = i + (int)(*path);  // path = "/dev/urandom", *path = '/' = 0x2F
    }
    return 0;
}
```

**逆向攻击思维**: 攻击者知道 `buf[i] = i + 0x2F`，可完全预测任何 "随机" 值:
- `buf[0] = 0x2F, buf[1] = 0x30, buf[2] = 0x31, ...`
- ECDSA 签名的 k 值完全可预测 → **私钥可恢复**

#### 发现
- Unix 构建中所有签名均使用可预测的 k — **Critical**
- 疑似调试/测试修改被意外提交

#### 修复建议
恢复原始 `/dev/urandom` 读取代码:
```c
static int fimport(unsigned char *buf, u16 buflen, const char *path)
{
    u16 rem = buflen, copied = 0;
    ssize_t ret;
    int fd;
    fd = open(path, O_RDONLY);
    if (fd == -1) { return -1; }
    while (rem) {
        ret = (int)read(fd, buf + copied, rem);
        if (ret <= 0) { break; }
        rem -= (u16)ret;
        copied += (u16)ret;
    }
    close(fd);
    return (copied == buflen) ? 0 : -1;
}
```

---

### AUDIT-LOGIC-002: ECDSA 验证路径中残留大量注释调试代码
- **状态**: ❌ 发现漏洞
- **严重级别**: 🟠 High
- **影响范围**: ECDSA 签名验证核心路径

#### 分析过程

```c
// src/sig/ecdsa.c:577-594 — _ecdsa_verify_finalize 关键路径
    // nn_set_word_value(&u, 2);          ← 危险! 会将 u 固定为 2
    // nn_set_word_value(&v, 2);          ← 危险! 会将 v 固定为 2
    /* 7. Compute W' = uG + vY */
    // prj_pt_mul_monty(&uG, &u, G);     ← 原始两步法
    // prj_pt_mul_monty(&vY, &v, Y);
    // prj_pt_add_monty(&W_prime, &uG, &vY);
    // prj_pt_copy(&W_prime, Y);          ← 危险! 直接将结果设为 Y
    // prj_pt_copy(&W_prime, G);          ← 危险! 直接将结果设为 G
    prj_pt_ec_mult_wnaf(&W_prime, &u, G, &v, Y);  // ← 当前使用的正确代码
    // prj_pt_copy(&uG, G);
    // prj_pt_copy(&vY, Y);
    // prj_pt_copy(&W_prime, Y);
    // prj_pt_uninit(&W_prime);
    // prj_pt_ec_mult_wnaf(&W_prime, &u, G, &v, Y);
```

#### 发现
- 当前活跃代码 (`prj_pt_ec_mult_wnaf`) 经验证正确 — ✅
- 注释中包含 3 处若取消注释会立即破坏验证的代码 — **High 风险** (代码维护隐患)
- 表明验证路径经历了大量调试迭代

#### 修复建议
删除所有注释调试代码，仅保留:
```c
    /* 7. Compute W' = uG + vY */
    prj_pt_ec_mult_wnaf(&W_prime, &u, G, &v, Y);
```

---

### AUDIT-MEMORY-002: RISC-V 汇编 Montgomery 乘法包装缺少边界检查
- **状态**: ❌ 发现漏洞
- **严重级别**: 🟠 High
- **影响范围**: 启用 `WITH_LL_U256_MONT` 时的 Montgomery 乘法

#### 分析过程

```c
// src/nn/nn_mul_redc1.c:108-112
static void my_nn_mul_redc1(nn_t out, nn_src_t in1, nn_src_t in2, nn_src_t p,
                            word_t mpinv) {
  nn_set_wlen(out, p->wlen);
  ll_u256_mont_mul(out->val, in1->val, in2->val, p->val, mpinv);
  // ← 无检查: in1/in2/p 是否恰好为 4 个 word (256-bit)
}
```

`ll_u256_mont_mul` 是 RISC-V 汇编函数，硬编码处理 4×64-bit = 256-bit 操作数。若传入 wlen ≠ 4 的参数:
- **wlen < 4**: 汇编代码读取未初始化内存 (nn.val 数组中超出 wlen 的部分应为 0，但依赖隐式假设)
- **wlen > 4**: 汇编代码只处理前 4 个 word，高位数据被忽略，产生错误结果

#### 发现
- 在 SECP256R1 (256-bit) 场景下，p->wlen 恒等于 4，因此**当前场景安全** — ⚠️ 条件性通过
- 若库配置切换到非 256-bit 曲线且启用汇编优化，将产生静默计算错误 — **High**

#### 修复建议
```c
static void my_nn_mul_redc1(nn_t out, nn_src_t in1, nn_src_t in2, nn_src_t p,
                            word_t mpinv) {
  MUST_HAVE(p->wlen == 4);  // 确保 256-bit 操作数
  nn_set_wlen(out, p->wlen);
  ll_u256_mont_mul(out->val, in1->val, in2->val, p->val, mpinv);
}
```

---

### AUDIT-LOGIC-003: CKB 构建中签名函数无编译时防护
- **状态**: ❌ 发现漏洞
- **严重级别**: 🟠 High
- **影响范围**: CKB-VM 环境中的签名安全

#### 分析过程

CKB 环境下 `get_random()` 为空操作 (AUDIT-CRYPTO-001)，但签名函数 `_ecdsa_sign_init / _ecdsa_sign_update / _ecdsa_sign_finalize` 在 CKB 构建中仍然可调用且会"成功"执行 — 只是产出的签名完全不安全。

**上下文关联审查**: 调用者若不知道 CKB 环境的限制，可能误用签名功能。

#### 修复建议
在签名函数顶部添加 CKB 防护:
```c
int _ecdsa_sign_init(struct ec_sign_context *ctx)
{
#ifdef WITH_CKB
    // CKB 环境无安全随机源，禁止签名操作
    return -1;
#endif
    // ... 原有代码 ...
}
```

---

### AUDIT-MEMORY-004: MUST_HAVE 宏在特定构建配置下为空操作
- **状态**: ❌ 发现问题
- **严重级别**: 🟡 Medium
- **影响范围**: 无 WITH_STDLIB、无 WITH_CKB、非 DEBUG 的构建

#### 分析过程

```c
// src/utils/utils.h:71-83
#ifdef WITH_CKB
    #define MUST_HAVE(x) do { if (!(x)) { printf(...); ckb_exit(-2); } } while (0)
#else
    #ifdef WITH_STDLIB
        #define MUST_HAVE(x) do { if (!(x)) { printf(...); exit(-2); } } while (0)
    #else
        #define MUST_HAVE(x)  // ← 空宏! 所有安全断言被静默忽略
    #endif
#endif
```

当构建不定义 `WITH_STDLIB` 和 `WITH_CKB` 且不是 `DEBUG` 模式时，**所有 MUST_HAVE 检查被编译为空操作**。这意味着:
- `nn_check_initialized(A)` 中的 magic 值检查被跳过
- 缓冲区长度检查被跳过
- 空指针检查被跳过

#### 发现
- CKB 构建和标准 Unix 构建不受影响 (均定义了相应宏)
- 裸机嵌入式构建 (无 stdlib) 受影响

#### 修复建议
将空宏替换为无限循环 (原始 libecc 设计意图):
```c
#else
#define MUST_HAVE(x) do { if (!(x)) { while(1); } } while(0)
#endif
```

---

### AUDIT-CRYPTO-003: 签名验证中 nn_cmp 非恒定时间
- **状态**: ⚠️ 建议改进
- **严重级别**: 🟡 Medium
- **影响范围**: ECDSA 验证的时间侧信道

#### 分析过程

```c
// src/sig/ecdsa.c:617
ret = (nn_cmp(&r_prime, r) != 0) ? -1 : 0;
```

`nn_cmp` 实现为逐 word 比较，遇到不等即返回，执行时间依赖输入:

```c
// src/nn/nn.c — nn_cmp 实现
for (i = cmp_len; i > 0; i--) {
    if (A->val[i-1] > B->val[i-1]) { return 1; }
    if (A->val[i-1] < B->val[i-1]) { return -1; }
}
return 0;  // 仅在完全相等时走到此处
```

#### 发现
- nn_cmp 为非恒定时间比较 — ⚠️
- 在 CKB-VM 软件仿真环境中，时间侧信道不可直接利用 — 风险低
- 在原生执行环境 (Unix 构建) 中，理论上可通过时间差区分有效/无效签名

#### 修复建议
使用恒定时间比较:
```c
ret = are_equal(&r_prime, r, sizeof(nn)) ? 0 : -1;  // 或自定义 nn_ct_cmp
```

---

### AUDIT-CRYPTO-006: CKB 环境下侧信道盲化失效
- **状态**: ⚠️ 建议改进
- **严重级别**: 🟡 Medium

#### 分析过程

库实现了三层侧信道防护:
1. **标量盲化**: `ecdsa_init_pub_key()` 中 `nn_get_random_mod(&scalar_b, ...)` → CKB 下 scalar_b = 1
2. **坐标盲化**: Montgomery ladder 中随机化投影坐标 → CKB 下无随机化
3. **签名盲化**: `USE_SIG_BLINDING` 宏控制 → CKB 构建未启用

#### 发现
- CKB-VM 是确定性软件仿真器，无物理侧信道 (功耗、电磁、缓存时间) — ✅ 风险低
- 若 CKB-VM 暴露 cycle 计数信息给外部观察者，可能存在时间信道 — 需动态验证

#### 修复建议
在文档中明确记录:
> CKB-VM 环境下，侧信道盲化被有意禁用。CKB-VM 的确定性执行模型不暴露物理侧信道。如果 CKB-VM 版本升级引入 cycle 计数的外部可观察性，需重新评估此设计决策。

---

### AUDIT-LOGIC-001: ECDSA 验证使用投影 X 坐标 (已确认安全)
- **状态**: ✅ 通过
- **严重级别**: 🟡 Medium (初始评估) → 🟢 Low (确认后)

#### 分析过程

```c
// src/sig/ecdsa.c:612
nn_mod(&r_prime, &(W_prime.X.fp_val), q);
// 原始代码 (已注释):
// prj_pt_to_aff(&W_prime_aff, &W_prime);
// nn_mod(&r_prime, &(W_prime_aff.x.fp_val), q);
```

**关键问题**: `W_prime.X.fp_val` 是投影坐标 X，仿射坐标 x = X/Z。当 Z ≠ 1 时 X ≠ x。

**深度审查 `prj_pt_ec_mult_wnaf` 末尾代码**:
```c
// src/curves/prj_pt_monty.c (prj_pt_ec_mult_wnaf 函数末尾)
// 1. 计算 Z 的逆元
fp_inv(&zinv, &out->Z);
// 2. X = X * Z^-1 (从 Montgomery 域转换)
fp_mul(&out->X, &out->X, &zinv);
// 3. Y = Y * Z^-1
fp_mul(&out->Y, &out->Y, &zinv);
// 4. Z = 1 (归一化)
fp_one(&out->Z);              // ← 关键: 输出已归一化
```

#### 发现
- `prj_pt_ec_mult_wnaf` **确实将输出归一化为 Z=1** — ✅
- 因此投影 X 坐标 = 仿射 x 坐标，当前代码**正确**
- 建议添加防御性断言: `MUST_HAVE(fp_isone(&W_prime.Z))`

---

### 其他发现 (Low / Informational)

| ID | 标题 | 级别 | 状态 |
|----|------|------|------|
| AUDIT-CRYPTO-004 | 敏感密钥材料使用后清零 | 🟢 Low | ✅ 通过 — PTR_NULLIFY/VAR_ZEROIFY 使用正确 |
| AUDIT-CRYPTO-005 | 椭圆曲线点有效性验证 | 🟢 Low | ✅ 通过 — prj_pt_import_from_buf 验证点在曲线上 |
| AUDIT-CRYPTO-007 | 哈希截断处理 (ECDSA Step 2) | 🟢 Low | ✅ 通过 — 符合 ISO 14888-3 |
| AUDIT-INPUT-001 | ECDSA 签名输入范围检查 | 🟢 Low | ✅ 通过 — r=0, s=0, r≥q, s≥q 均被正确拒绝 |
| AUDIT-INPUT-002 | 公钥导入缓冲区验证 | 🟢 Low | ✅ 通过 |
| AUDIT-INPUT-003 | nn_init_from_buf 安全性 | 🟢 Low | ✅ 通过 |
| AUDIT-MEMORY-001 | siglen 整数截断 | 🟢 Low | ✅ 通过 — SECP256R1 siglen=64 在 u8 范围内 |
| AUDIT-MEMORY-003 | 栈上数组对齐 | 🟢 Low | ✅ 通过 |
| AUDIT-SPEC-001 | ISO 14888-3 一致性 | 🟢 Low | ✅ 通过 — 步骤顺序调整有合理说明 |
| AUDIT-ALIGN-001 | nn 结构体内存对齐 | 🟢 Low | ✅ 通过 |
| AUDIT-ALIGN-002 | RISC-V 汇编对齐安全 | 🟢 Low | ✅ 通过 |

---

## 4. 审计覆盖矩阵

| 模块/函数 | DIM-CRYPTO | DIM-INPUT | DIM-MEMORY | DIM-LOGIC | DIM-SPEC | DIM-ALIGN |
|-----------|:----------:|:---------:|:----------:|:---------:|:--------:|:---------:|
| `ecdsa.c` — _ecdsa_sign_finalize | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| `ecdsa.c` — _ecdsa_verify_init | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| `ecdsa.c` — _ecdsa_verify_finalize | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| `ecdsa.c` — ecdsa_init_pub_key | ✅ | ✅ | — | ✅ | — | — |
| `ec_key.c` — 密钥导入/导出 | — | ✅ | ✅ | — | — | — |
| `nn_rand.c` — nn_get_random_mod | ✅ | — | ✅ | — | — | — |
| `nn_mul_redc1.c` — nn_mul_redc1 | — | — | ✅ | ✅ | — | ✅ |
| `nn_mul_redc1.c` — my_nn_mul_redc1 | — | — | ✅ | — | — | ✅ |
| `prj_pt_monty.c` — prj_pt_ec_mult_wnaf | ✅ | — | — | ✅ | — | ✅ |
| `prj_pt_monty.c` — prj_pt_mul_monty_blind | ✅ | — | — | ✅ | — | — |
| `rand.c` — get_random (CKB) | ✅ | — | — | — | — | — |
| `rand.c` — fimport (Unix) | ✅ | — | — | — | — | — |
| `utils.h` — MUST_HAVE | — | — | ✅ | — | — | — |
| `ll_u256_mont-riscv64.S` | — | — | ✅ | — | — | ✅ |

图例: ✅ 已审计 | — 不适用

---

## 5. 依赖安全状态

| 依赖 | 版本 | 类型 | 已知 CVE | 状态 |
|------|------|------|---------|------|
| ckb-c-stdlib | git submodule | C 标准库桩 (CKB-VM) | 需验证 | ⚠️ 建议核查 |

**说明**: libecc 核心库无外部依赖 (纯 C99, 自包含)。唯一的外部依赖是 `ckb-c-stdlib`，作为 git submodule 引入，用于提供 CKB-VM 环境下的 libc 替代和 syscall 定义。

**建议**: 
- 验证 `deps/ckb-c-stdlib` 指向的 commit 是否为最新稳定版
- 定期更新子模块以获取安全修复

---

## 6. 改进建议（非漏洞类）

### 6.1 代码质量
| # | 建议 | 优先级 |
|---|------|--------|
| 1 | 清除 `ecdsa.c` 验证路径中所有注释调试代码 | 高 |
| 2 | 移除 CKB 构建标志中的 `VERBOSE_INNER_VALUES` 以减小二进制体积 | 低 |
| 3 | 为 `prj_pt_ec_mult_wnaf` 的 Z=1 归一化添加防御性断言 | 中 |

### 6.2 测试覆盖
| # | 建议 | 优先级 |
|---|------|--------|
| 4 | 添加边界值签名测试: (r=0, s=0), (r=q-1, s=q-1) | 高 |
| 5 | 在 CI 中使用真实 CKB cycle 预算 (≤1B cycles) 进行验证操作测试 | 中 |
| 6 | 添加汇编 vs C 实现的交叉验证测试用例 | 中 |

### 6.3 文档
| # | 建议 | 优先级 |
|---|------|--------|
| 7 | 文档化 CKB 环境仅支持签名验证的限制 | 高 |
| 8 | 文档化侧信道盲化在 CKB-VM 中被有意禁用的安全模型 | 中 |
| 9 | 记录每次 ECDSA 验证的预期 cycle 消耗 | 低 |

---

## 7. 附录: 完整 TODO 文档终态

完整的审计 TODO 文档见: [SECURITY_AUDIT_TODO.md](SECURITY_AUDIT_TODO.md)

### 终态统计
- 总审计项: 22
- ✅ 通过: 12
- ⚠️ 建议改进: 3
- ❌ 发现问题: 7
- 待修复项: 7

### 错误场景与返回码

| 返回码 | 函数 | 触发条件 | 行为 |
|--------|------|---------|------|
| 0 | `_ecdsa_verify_finalize` | 签名有效 | 验证成功 |
| -1 | `_ecdsa_verify_init` | r=0, s=0, r≥q, s≥q | 立即拒绝 |
| -1 | `_ecdsa_verify_init` | 签名长度不匹配 | 立即拒绝 |
| -1 | `_ecdsa_verify_finalize` | W' 为无穷远点 | 拒绝无效签名 |
| -1 | `_ecdsa_verify_finalize` | r' ≠ r | 签名不匹配 |
| -2 | `MUST_HAVE` → `ckb_exit` | 断言失败 | CKB 脚本中止 |
| -1 | `_ecdsa_sign_finalize` | 随机数生成失败 | 签名操作失败 |

---

### 审计结论

**对于 CKB 链上仅验证签名的使用场景**: 库的核心验证逻辑 (`_ecdsa_verify_init` → `_ecdsa_verify_update` → `_ecdsa_verify_finalize`) **经审计确认正确**。`prj_pt_ec_mult_wnaf` 函数正确归一化输出点 (Z=1)，ECDSA 验证步骤与 ISO 14888-3 一致。

**主要风险点**:
1. 随机源安全性 (AUDIT-CRYPTO-001/002) 使签名操作不安全，但验证不受影响
2. 注释调试代码 (AUDIT-LOGIC-002) 增加代码维护风险
3. 汇编包装边界检查缺失 (AUDIT-MEMORY-002) 在当前 SECP256R1 配置下安全，但不健壮

**建议**: 解决 7 项待修复问题后可投入生产使用（仅限验证场景）。

---

*报告基于 [AI-Driven Security Audit Skill](https://github.com/15168316096/ckb-test-skills/blob/main/.claude/skills/security-audit/SKILL.md) 方法论生成。*
*审计维度: DIM-CRYPTO, DIM-INPUT, DIM-MEMORY, DIM-LOGIC, DIM-SPEC, DIM-CKB-ALIGN, DIM-DEPS*
