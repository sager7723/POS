B. 术语对照表

| 术语              | 含义                      | 工程中的建议表示                           |
| --------------- | ----------------------- | ---------------------------------- |
| PoS             | 权益证明共识算法                | `ProofOfStake` / 文档术语              |
| 参与者 `Pi`        | 抽签选举中的节点                | `Participant`                      |
| 质押值 `STK_i`     | 参与者的真实质押数量              | `stake_value`                      |
| 质押承诺 `CM_i`     | 对质押值做的 Pedersen 承诺      | `stake_commitment`                 |
| Pedersen承诺      | 用随机数隐藏明文的承诺机制           | `commit()` / `verify_commitment()` |
| 随机数 `R_i`       | 生成质押承诺时用的随机盲化值          | `commit_randomness`                |
| ThFHE           | 门限全同态加密方案               | `ThresholdFHE`                     |
| 完整公钥 `PK`       | 所有参与者分布式生成的公钥           | `public_key`                       |
| 部分私钥 `PSK_i`    | 单个参与者本地产生的部分私钥          | `partial_secret_key`               |
| 解密分片            | 门限解密时各方输出的局部解密结果        | `decrypt_share`                    |
| 分片公钥            | 解密分片对应的公钥信息             | `share_public_key`                 |
| SecretSharing   | 线性门限秘密分享算法              | `share_secret()`                   |
| SecretRecover   | 秘密恢复函数                  | `recover_secret()`                 |
| 指数上恢复           | 在群指数形式上的恢复              | `recover_secret_in_exponent()`     |
| 随机种子            | 用于后续派生随机揭示索引等           | `random_seed`                      |
| 密钥同态PRF         | 生成可分布式组合伪随机值的函数         | `key_homomorphic_prf`              |
| 伪随机数分片 `PPRF_i` | 每个参与者本地生成的伪随机片段         | `prf_share`                        |
| 伪随机数分片密文        | 对伪随机数分片的 FHE 加密结果       | `encrypted_prf_share`              |
| 零知识证明分片         | 用于 cut-and-choose 的证明切片 | `proof_share`                      |
| cut-and-choose  | 随机揭示部分证明分片的验证策略         | `cut_and_choose`                   |
| 票根              | 中签者私有的随机凭证原像            | `ticket_preimage`                  |
| 票根哈希值           | 对票根做哈希后的值               | `ticket_hash`                      |
| 前半票根哈希          | 哈希值前半段，明文公开             | `ticket_hash_prefix`               |
| 后半票根哈希          | 哈希值后半段，密文参与选举           | `ticket_hash_suffix`               |
| 参选消息            | 参与者广播的完整报名消息            | `CandidateMessage`                 |
| 质押和密文           | 所有有效质押密文的同态求和结果         | `encrypted_total_stake`            |
| 缩放比例            | 将伪随机值映射到总质押区间的比例        | `scale_ratio`                      |
| 质押累加密文          | 按参与者序号累加的质押密文前缀和        | `cumulative_stake_ciphertexts`     |
| 同态比较电路          | 比较随机值与累加质押区间的电路         | `compare_circuit`                  |
| 中签票根密文          | 选举结果对应的加密票根信息           | `winning_ticket_ciphertext`        |
| 中签者             | 被唯一确定选中的领导者节点           | `winner`                           |
