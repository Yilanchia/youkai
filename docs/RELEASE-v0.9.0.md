# youkai v0.9.0

**一个没有直接打击能力的脑 —— 自托管的授权渗透控制台。**

youkai 把 Fairy(web)与 Verdex(binary)的精华原生吸收进一个 Go 二进制:常驻 HTTP 控制台 +
PostgreSQL 账本 + 内嵌 SPA。它自己对目标发请求,所以那套"只读默认、逐请求审计、利用停在人前、
自动深度利用编译期不存在"的纪律,不是外包给另一个进程,而是它**自己的骨头**。

## 三条不可谈判的性质

1. **授权优先,证据可复核。** 没有 scope 护照,一个请求都不会发;每一次发包都留一条审计行,
   每条发现都必须带齐四样证据(请求锚点 / 最小影响 / 停止点 / 反证说明),缺了就在报告里
   标 `incomplete`,不伪装成完整。
2. **自治只读、档 2 人批、档 3 不在仓库。** 自治循环只跑 tier 1;登录、主动探针、播种、注册
   全部停在审批台,一步一批,单个批准用完即焚;利用级代码不存在于本仓库,也没有能打开的开关。
3. **报告是账本投影。** 同一账本重复出报告字节一致;快照 append-only 且带 sha256;披露包只收
   verified,无授权依据不出。

## 能力面

- **Web 只读**:probe / scan / crawl / fingerprint / headers / CORS / 暴露面 / 跳转链 / 反射上下文。
- **授权与越权**:账号层(多身份、归属、BOLA 配对)、权限矩阵、双账号对比、CDP 浏览器
  (登录态在 Fetch 闸内逐请求、按 host 注入)。
- **检测覆盖(v0.9)**:OpenAPI/Swagger 接入(文档化端点 → 可测面)、GraphQL introspection、
  JWT 结构审计(只读,不爆破不伪造)、OAuth/OIDC 配置审计(不换 token)。
- **证据与披露(v0.5)**:四样证据、不可变快照、SARIF 2.1.0、只含 verified 的披露包、覆盖声明。
- **配置面(v0.4)**:LLM API 可在 UI 配置并热生效(key 只存环境变量引用或加密密文),
  护照全字段可编辑且改动进审计;墙与放行权不在配置面里。
- **过程记忆(v0.7)**:trace 跨轮检索,同目标已做的只读检查不再重复派生。
- **二进制(v0.2)**:静态分析、反汇编、反编译、符号/字符串/加壳识别;只读、离线、不执行样本。

## 验证

- `go test ./...` —— 全绿(全新 PostgreSQL 上可复现)。
- 两个必过的 CI 作业:`ci`(build / vet / gofmt / 全量测试,Go 1.22 + stable)与
  `invariants`(唯一出口 / 报告纯投影 / 档 3 墙 / 浏览器无第二出口 / 数据库护栏,五个命名作业)。
- `scripts/acceptance-v02.ps1` —— 端到端:建作业 → 自治只读 → 停档 2 → 人批一步 → 出证据/披露,
  含真机 Chrome 渲染与页内越界拦断。
- `bench`(本机靶场,不外推):recall 8/8、precision 1.000、19 次请求、**越界请求 0**。

## 红线

只对**授权目标**动手:CTF、自建靶场、你拥有或被明确授权的系统。没有护照,youkai 一个请求都不会发;
利用只在人逐步过闸时发生;自动深度利用不在本仓库。漏洞上报请走私密渠道(见 SECURITY.md)。

## 许可

MIT。移植自 Fairy / Verdex(均 MIT,保留其版权);只借 ARTEX / norma 的**思想**,不含其代码。
详见 [NOTICE](https://github.com/Yilanchia/youkai/blob/main/NOTICE) 与
[LICENSE](https://github.com/Yilanchia/youkai/blob/main/LICENSE)。

---

逐版实现报告见 [docs/](https://github.com/Yilanchia/youkai/tree/main/docs);
真机走查结果见 [E2E-RESULT-v0.5](https://github.com/Yilanchia/youkai/blob/main/docs/E2E-RESULT-v0.5.md)。
