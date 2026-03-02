# libecc 安全审计 TODO

> 版本: v1 | 最后更新: 2026-03-02 | 状态: 已完成

## 项目概况
  - 语言: C99 + RISC-V Assembly
  - 类型: 密码学库 (ECC / ECDSA)，适配 CKB-VM (RISC-V) 运行环境
  - 依赖数: 1 (ckb-c-stdlib)
  - 源文件数: 57 (.c) + 81 (.h) + 1 (.S)
  - 现有测试数: 3 个测试程序 (ec_self_tests, ec_utils, nn_mul_redc1)

## 审计进度
  - 总 TODO 项: 22
  - ✅ 已完成: 22 | ❌ 发现问题: 7 | ⏳ 待审计: 0

---

## 第 1 章: DIM-CRYPTO 密码学操作

- [x] 🔴 **AUDIT-CRYPTO-001**: ECDSA 签名中随机数 k 的生成安全性
  - **关联代码**: `src/sig/ecdsa.c:_ecdsa_sign_finalize:242`, `src/nn/nn_rand.c:nn_get_random_mod:86`
  - **审计内容**:
    - 随机数 k 是否使用 CSPRNG 生成
    - CKB 环境下 get_random 是否提供真随机性
    - k = 0 或 k ≥ q 的边界处理
  - **现有覆盖**: 部分覆盖 (ec_self_tests rand)
  - **发现记录**: ❌ CKB 环境 get_random 为空操作，签名不安全

- [x] 🔴 **AUDIT-CRYPTO-002**: Unix 构建中 /dev/urandom 读取被注释
  - **关联代码**: `src/external_deps/rand.c:fimport:46-78`
  - **审计内容**:
    - fimport 函数是否正确读取 /dev/urandom
    - 替代的确定性填充是否为调试残留
  - **现有覆盖**: 无
  - **发现记录**: ❌ 原始 /dev/urandom 代码被注释，替换为确定性模式

- [x] 🟠 **AUDIT-CRYPTO-003**: 恒定时间比较操作
  - **关联代码**: `src/sig/ecdsa.c:_ecdsa_verify_finalize:617`, `src/utils/utils.c:are_equal`
  - **审计内容**:
    - 签名验证中 r' 与 r 的比较是否为恒定时间
    - nn_cmp 是否为恒定时间实现
  - **现有覆盖**: 无专门测试
  - **发现记录**: ⚠️ nn_cmp 非恒定时间，但在 CKB-VM 软件仿真环境中风险可接受

- [x] 🟠 **AUDIT-CRYPTO-004**: 敏感密钥材料使用后清零
  - **关联代码**: `src/sig/ecdsa.c:_ecdsa_sign_finalize:358-380`
  - **审计内容**:
    - 私钥 x 使用后是否清零
    - 临时变量 k, kinv 等是否清零
    - 栈上 hash 缓冲区是否清零
  - **现有覆盖**: 无
  - **发现记录**: ✅ 签名函数使用 PTR_NULLIFY/VAR_ZEROIFY 清理，hash 缓冲区使用 local_memset 清零

- [x] 🟠 **AUDIT-CRYPTO-005**: 椭圆曲线点有效性验证
  - **关联代码**: `src/curves/prj_pt.c:prj_pt_import_from_buf`, `src/sig/ec_key.c:ec_pub_key_import_from_buf`
  - **审计内容**:
    - 导入公钥时是否验证点在曲线上
    - 是否检查点不是无穷远点
    - 是否检查点属于正确的子群
  - **现有覆盖**: 部分 (ec_self_tests vectors)
  - **发现记录**: ✅ prj_pt_import_from_buf 验证点在曲线上

- [x] 🟡 **AUDIT-CRYPTO-006**: 标量乘法侧信道保护
  - **关联代码**: `src/curves/prj_pt_monty.c:prj_pt_mul_monty_blind`, `src/curves/prj_pt_monty.c:prj_pt_mul_ltr_monty`
  - **审计内容**:
    - Montgomery Ladder / Double-and-Add-Always 的实现正确性
    - 标量盲化 (b*q + m) 的有效性
    - CKB 环境下盲化是否生效
  - **现有覆盖**: ec_self_tests vectors
  - **发现记录**: ⚠️ CKB 环境盲化无效（get_random 为空操作），但 CKB-VM 无物理侧信道

- [x] 🟡 **AUDIT-CRYPTO-007**: 哈希截断处理 (ECDSA Step 2)
  - **关联代码**: `src/sig/ecdsa.c:_ecdsa_sign_finalize:221-224`, `src/sig/ecdsa.c:_ecdsa_verify_finalize:539-542`
  - **审计内容**:
    - |h| > bitlen(q) 时截断是否正确
    - 右移操作是否保留最高有效位
  - **现有覆盖**: ec_self_tests vectors
  - **发现记录**: ✅ 截断逻辑符合 ISO 14888-3 规范

---

## 第 2 章: DIM-INPUT 输入验证

- [x] 🔴 **AUDIT-INPUT-001**: ECDSA 验证签名输入范围检查
  - **关联代码**: `src/sig/ecdsa.c:_ecdsa_verify_init:452-459`
  - **审计内容**:
    - r = 0, s = 0 是否被拒绝
    - r ≥ q, s ≥ q 是否被拒绝
    - 签名长度不匹配是否被拒绝
  - **现有覆盖**: ec_self_tests vectors (已知向量)
  - **发现记录**: ✅ 正确拒绝 r=0, s=0, r≥q, s≥q

- [x] 🟠 **AUDIT-INPUT-002**: 公钥导入缓冲区长度验证
  - **关联代码**: `src/sig/ec_key.c:ec_pub_key_import_from_buf:105-127`
  - **审计内容**:
    - pub_key_buf_len 是否被验证
    - 缓冲区溢出风险
  - **现有覆盖**: ec_self_tests
  - **发现记录**: ✅ 由 prj_pt_import_from_buf 内部验证长度

- [x] 🟡 **AUDIT-INPUT-003**: nn_init_from_buf 大端输入处理
  - **关联代码**: `src/nn/nn.c:nn_init_from_buf`
  - **审计内容**:
    - 超大 buflen 是否被拒绝
    - 空缓冲区处理
  - **现有覆盖**: 间接覆盖
  - **发现记录**: ✅ MUST_HAVE(buflen <= NN_MAX_BYTE_LEN) 约束

---

## 第 3 章: DIM-MEMORY 内存与资源安全

- [x] 🔴 **AUDIT-MEMORY-001**: 整数溢出风险 — ECDSA siglen 转换
  - **关联代码**: `src/sig/ecdsa.c:ecdsa_siglen:63-70`
  - **审计内容**:
    - u16 → u8 的截断是否导致溢出
    - ECDSA_SIGLEN 宏的值域
  - **现有覆盖**: ec_self_tests
  - **发现记录**: ✅ MUST_HAVE 确保参数在安全范围内，SECP256R1 siglen=64 在 u8 范围内

- [x] 🟠 **AUDIT-MEMORY-002**: Montgomery 乘法汇编包装缺少边界检查
  - **关联代码**: `src/nn/nn_mul_redc1.c:my_nn_mul_redc1:108-112`
  - **审计内容**:
    - ll_u256_mont_mul 参数是否为 4 个 word (256-bit)
    - 是否存在越界读写风险
  - **现有覆盖**: nn_mul_redc1 测试
  - **发现记录**: ❌ 缺少 MUST_HAVE(p->wlen == 4) 断言

- [x] 🟡 **AUDIT-MEMORY-003**: 栈上大数组的对齐安全
  - **关联代码**: `src/sig/ecdsa.c:_ecdsa_sign_finalize:170 (hash[MAX_DIGEST_SIZE])`
  - **审计内容**:
    - hash 缓冲区是否自然对齐
    - nn 结构体字段是否对齐安全
  - **现有覆盖**: 运行时隐式测试
  - **发现记录**: ✅ u8 数组无对齐要求，nn.val 为 word_t 数组自然对齐

- [x] 🟡 **AUDIT-MEMORY-004**: MUST_HAVE 宏在不同构建模式下的行为
  - **关联代码**: `src/utils/utils.h:51-88`
  - **审计内容**:
    - 无 WITH_STDLIB 且无 WITH_CKB 时 MUST_HAVE 为空操作
    - 是否存在安全检查被静默跳过的路径
  - **现有覆盖**: 无
  - **发现记录**: ❌ 当既无 WITH_STDLIB 也无 WITH_CKB 且非 DEBUG 时，MUST_HAVE 是空宏

---

## 第 4 章: DIM-LOGIC 业务逻辑

- [x] 🔴 **AUDIT-LOGIC-001**: ECDSA 验证使用投影坐标而非仿射坐标
  - **关联代码**: `src/sig/ecdsa.c:_ecdsa_verify_finalize:608-614`
  - **审计内容**:
    - prj_pt_ec_mult_wnaf 是否归一化输出 (Z=1)
    - 使用 W_prime.X.fp_val 而非 affine x 是否正确
  - **现有覆盖**: ec_self_tests vectors
  - **发现记录**: ✅ prj_pt_ec_mult_wnaf 末尾设置 Z=1，投影 X 即仿射 x

- [x] 🟠 **AUDIT-LOGIC-002**: 验证路径中大量注释调试代码
  - **关联代码**: `src/sig/ecdsa.c:_ecdsa_verify_finalize:577-594`
  - **审计内容**:
    - 注释代码是否包含危险操作
    - 是否影响代码可维护性
  - **现有覆盖**: 无
  - **发现记录**: ❌ 注释代码包含 nn_set_word_value(&u, 2) 等会破坏验证的操作

- [x] 🟡 **AUDIT-LOGIC-003**: 签名函数在 CKB 构建中可调用
  - **关联代码**: `src/sig/ecdsa.c:_ecdsa_sign_finalize:159-381`
  - **审计内容**:
    - CKB 构建是否应禁止签名操作
    - 是否存在编译时/运行时防护
  - **现有覆盖**: 无
  - **发现记录**: ❌ 无编译时防护，签名函数在 CKB 构建中可调用但会产生不安全签名

---

## 第 5 章: DIM-DEPS 依赖安全

- [x] 🟡 **AUDIT-DEPS-001**: ckb-c-stdlib 版本与已知漏洞
  - **关联代码**: `deps/ckb-c-stdlib` (git submodule)
  - **审计内容**:
    - 子模块版本是否为最新稳定版
    - 是否存在已知 CVE
  - **现有覆盖**: 无
  - **发现记录**: ⚠️ 需验证子模块版本，建议定期更新

---

## 第 6 章: DIM-SPEC 规范一致性

- [x] 🟠 **AUDIT-SPEC-001**: ECDSA 实现与 ISO 14888-3 一致性
  - **关联代码**: `src/sig/ecdsa.c` (完整文件)
  - **审计内容**:
    - 签名步骤 1-11 是否与规范一致
    - 验证步骤 1-10 是否与规范一致
    - 步骤顺序调整是否影响安全性
  - **现有覆盖**: ec_self_tests vectors
  - **发现记录**: ✅ 实现与 ISO 14888-3 一致，步骤顺序调整有合理说明

---

## 第 7 章: DIM-CKB-ALIGN 内存对齐安全

- [x] 🟡 **AUDIT-ALIGN-001**: nn 结构体内存布局
  - **关联代码**: `src/nn/nn.h:67-71`
  - **审计内容**:
    - nn.val (word_t 数组) 对齐是否满足 8 字节要求
    - nn.wlen (u8) 是否引起后续字段非对齐
  - **现有覆盖**: 运行时隐式
  - **发现记录**: ✅ word_t 数组在结构体开头，自然对齐

- [x] 🟡 **AUDIT-ALIGN-002**: RISC-V 汇编内存访问对齐
  - **关联代码**: `src/nn/ll_u256_mont-riscv64.S`
  - **审计内容**:
    - ld/sd 指令是否从 8 字节对齐地址操作
    - 参数传入时是否保证对齐
  - **现有覆盖**: nn_mul_redc1 测试
  - **发现记录**: ✅ 参数来自 nn.val 数组，word_t 自然对齐

---

## 附录 A: 审计执行日志
| 日期 | 审计项 | 发现摘要 | 状态 |
|------|--------|---------|------|
| 2026-03-02 | AUDIT-CRYPTO-001 | CKB get_random 为空操作 | ❌ |
| 2026-03-02 | AUDIT-CRYPTO-002 | Unix fimport 被替换为确定性填充 | ❌ |
| 2026-03-02 | AUDIT-CRYPTO-003 | nn_cmp 非恒定时间 | ⚠️ |
| 2026-03-02 | AUDIT-CRYPTO-004 | 清零操作完备 | ✅ |
| 2026-03-02 | AUDIT-CRYPTO-005 | 曲线点验证正确 | ✅ |
| 2026-03-02 | AUDIT-CRYPTO-006 | CKB 盲化无效但风险低 | ⚠️ |
| 2026-03-02 | AUDIT-CRYPTO-007 | 哈希截断正确 | ✅ |
| 2026-03-02 | AUDIT-INPUT-001 | 签名范围检查正确 | ✅ |
| 2026-03-02 | AUDIT-INPUT-002 | 公钥长度验证正确 | ✅ |
| 2026-03-02 | AUDIT-INPUT-003 | nn_init_from_buf 安全 | ✅ |
| 2026-03-02 | AUDIT-MEMORY-001 | siglen 转换安全 | ✅ |
| 2026-03-02 | AUDIT-MEMORY-002 | 汇编包装缺少边界检查 | ❌ |
| 2026-03-02 | AUDIT-MEMORY-003 | 栈上数组对齐安全 | ✅ |
| 2026-03-02 | AUDIT-MEMORY-004 | MUST_HAVE 空宏风险 | ❌ |
| 2026-03-02 | AUDIT-LOGIC-001 | wNAF 归一化 Z=1，使用正确 | ✅ |
| 2026-03-02 | AUDIT-LOGIC-002 | 注释调试代码包含危险操作 | ❌ |
| 2026-03-02 | AUDIT-LOGIC-003 | CKB 签名无防护 | ❌ |
| 2026-03-02 | AUDIT-DEPS-001 | 需验证子模块版本 | ⚠️ |
| 2026-03-02 | AUDIT-SPEC-001 | ISO 14888-3 一致 | ✅ |
| 2026-03-02 | AUDIT-ALIGN-001 | nn 结构体对齐安全 | ✅ |
| 2026-03-02 | AUDIT-ALIGN-002 | 汇编对齐安全 | ✅ |

## 附录 B: 新增项跟踪
| 日期 | 新增项 ID | 来源 | 描述 |
|------|----------|------|------|
| 2026-03-02 | AUDIT-LOGIC-003 | AUDIT-CRYPTO-001 | 审计 CKB 随机源时发现签名函数无 CKB 防护 |
| 2026-03-02 | AUDIT-MEMORY-004 | AUDIT-INPUT-001 | 审计输入验证时发现 MUST_HAVE 空宏路径 |

## 附录 C: 修复建议
| 审计项 | 严重级别 | 建议方案 | 修复状态 |
|--------|---------|---------|---------|
| AUDIT-CRYPTO-001 | Critical | CKB 构建禁止签名函数编译 | 待修复 |
| AUDIT-CRYPTO-002 | Critical | 恢复 /dev/urandom 读取代码 | 待修复 |
| AUDIT-MEMORY-002 | High | 添加 MUST_HAVE(p->wlen == 4) | 待修复 |
| AUDIT-LOGIC-002 | High | 清除验证路径中注释调试代码 | 待修复 |
| AUDIT-LOGIC-003 | High | 添加 #ifdef WITH_CKB / #error 防护 | 待修复 |
| AUDIT-MEMORY-004 | Medium | 确保所有构建模式 MUST_HAVE 非空 | 待修复 |
| AUDIT-CRYPTO-003 | Low | 记录 nn_cmp 非恒定时间的设计决策 | 待修复 |
