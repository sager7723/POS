# Strict Patent Path

本项目所有文件的最终目的都是：完全、完整地实现专利中的“面向权益证明共识算法的质押隐藏确定性抽签方法”，不会使用替代实现。

## 1. 唯一生产目标

最终生产路径必须实现专利 Step0-Step23：

- Pedersen 质押承诺；
- KMS/TFHE/TRLWE 门限全同态加密；
- 密钥同态 PRF；
- 秘密分享；
- Cut & Choose 零知识证明；
- 同态质押求和；
- 同态 PRF 合成与缩放；
- 同态比较、定位、选择；
- 只解密总质押和中签票根后半部分；
- 中签者揭示票根原像；
- 其他参与者公开验证中签正确性。

## 2. 严格运行环境

最终专利路径必须使用：

    POS_STRICT_PATENT_MODE=1
    POS_FHE_BACKEND=kms-threshold

最终路径不得使用：

- mock backend
- plaintext backend
- OpenFHE replacement path
- encoded_value fallback
- metadata.noise fallback
- expected_result
- expected_index
- expected_*_for_test
- POS_KMS_EVAL_*_EXPECTED_*

## 3. 保留的生产主线文件

核心密码学模块：

    pos/crypto/*

核心协议模块：

    pos/protocol/preparation.py
    pos/protocol/candidacy.py
    pos/protocol/election.py
    pos/protocol/patent_phase4.py
    pos/protocol/patent_step18.py
    pos/protocol/patent_step20.py
    pos/protocol/patent_timer.py

## 4. 后续实现顺序

Stage A 之后，严格按以下顺序补齐：

1. Stage B: KMS DKG transcript
2. Stage C: remove expected_result / expected_index oracle from KMS evaluator
3. Stage D: pure ciphertext Step12 / Step16 / Step17 / Step18
4. Stage E: opaque KMS ciphertext compatible Cut & Choose proofs
5. Stage F: candidacy witness binding without encoded_value / metadata.noise
6. Stage G: strict Step19-Step23 reveal chain
7. Stage H: final Step0-Step23 patent election entrypoint
8. Stage I: final performance benchmark

## 5. 最终验收条件

最终性能测试前必须满足：

1. POS_STRICT_PATENT_MODE=1
2. POS_FHE_BACKEND=kms-threshold
3. 不使用 mock/plaintext/OpenFHE replacement
4. 不使用 expected_result / expected_index
5. 不读取 encoded_value / metadata.noise
6. 不逐个解密参与者质押
7. 不逐个解密所有候选票根
8. 只解密 total stake
9. 只解密 winning ticket suffix
10. winner 通过 ticket preimage 揭示
11. Step23 公开验证通过

## 6. Stage C-1 KMS evaluator oracle guard

Stage C-1 增加严格保护：

- 在 `POS_STRICT_PATENT_MODE=1` 且 `POS_FHE_BACKEND=kms-threshold` 时；
- 任意 KMS/TFHE evaluator 调用前都会检查 `POS_KMS_TFHE_EVAL_BIN --help`；
- 如果 evaluator CLI 暴露 `expected-result` 或 `expected-index`，则直接拒绝执行；
- 这可以防止 expected-oracle evaluator 被误当作最终专利 TFHE/RLWE 实现。

注意：Stage C-1 只是保护层，不代表 TFHE/RLWE evaluator 已经完成真实同态计算。真实计算将在 Stage C-2 中实现。
