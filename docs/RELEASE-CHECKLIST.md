# 发布就绪清单(youkai → 公开 GitHub 仓库)

> 用途:把 youkai 推成公开仓库并发 v0.9.0 的照做清单。执行者:DeepSeek(或维护者),在**有网**的本机环境。
> 背景:v0.1→v0.9 已逐版实现并审查通过;历史提交已扫过,只含测试夹具与本机开发默认口令(`youkai_dev_pw`),无真实目标/凭据/密钥。

## 已完成(Claude 侧)

- [x] 历史提交敏感信息扫描:干净(假夹具 + 本机 dev 口令,无真实泄露)。
- [x] `.youkai/hands.example.json` 路径中性化。
- [x] CONTRIBUTING / bench/README 注明 `youkai_dev_pw` 仅本机开发用。
- [x] `.gitignore` 挡住 `.pgsql/`、`.youkai/`(会话密钥/账本/artifacts)、`*.exe`。

## 发布前本机收尾(有网环境)

- [ ] `go mod tidy` —— 修 `gopkg.in/yaml.v3` 的 `// indirect` 标记(它其实是 direct;本次因离线未能跑成)。
- [ ] `go build ./... && go vet ./... && gofmt -l .`(gofmt 须无输出)。
- [ ] `go test ./... -count=1` 全绿(需本机 PostgreSQL + `YOUKAI_TEST_DSN`)。
- [ ] `scripts/acceptance-v02.ps1` 全过(自管 PG/靶场/服务)。
- [ ] `go run ./bench` 越界请求=0、recall/precision 如实记录。

## 建仓库并推送(public)

- [ ] 建 **public** GitHub 仓库(建议名 `youkai`)。
- [ ] 确认工作树干净、`.gitignore` 生效后 `git push`(全历史)。
- [ ] 进 Actions 页,确认两个 workflow **实际跑绿**:
      - `ci.yml`(build/vet/gofmt/test,带 postgres:16 容器)
      - `invariants.yml`(五个命名安全门禁)
      - ⚠️ GitHub runner 环境与本机不同(PG 容器、可能缺 Chrome):首推后大概率要微调 workflow 才绿。browser 相关测试在无 Chrome 时应 skip 而非 fail —— 若 fail,确认 skip 逻辑。
- [ ] README 顶部 CI badge 的占位 `owner/repo` 换成真实仓库路径。

## 打 tag 与 release

- [ ] `git tag v0.9.0 && git push --tags`。
- [ ] GitHub Release note:用各 `docs/IMPL-STATUS-v0.x.md` 的"一句话"汇总能力;点明三条:
      ① 授权优先 + 逐请求审计 + 证据可复核;② 自治只读、档 2 人批、档 3 不在本仓库;
      ③ 能力面(web + binary + 账号/BOLA + CDP 浏览器 + 配置 + 证据/披露 + API schema/JWT/OAuth)。
- [ ] Release note 附红线声明(SECURITY.md 口径):只对授权目标、无 scope 不发包、不含自动深度利用。

## 2026-11-14 实际执行记录

- `go mod tidy` 完成:`gopkg.in/yaml.v3` 变为 direct;tidy 会把 `go` 顶到 1.25
  (经 yaml.v3 的测试依赖 `rogpeppe/go-internal`),已把该依赖钉在 v1.12.0 以保持 `go 1.22`。
- 首次推送被 GitHub **Push Protection** 拦下:`internal/binary` 的测试夹具里有合成 AWS key。
  已换成 AWS 官方文档示例值(`AKIAIOSFODNN7EXAMPLE` / `…EXAMPLEKEY`),并用 `filter-branch`
  把旧值从**全部历史**中清掉(仓库此前从未推送,重写安全)。
- 首次 CI 红:`web/index.html` 被 `.gitignore` 的 `*.html` 吃掉,**SPA 入口没进仓库** → `go build` 失败。
  已加 `!/web/*.html` 并补提交。
- 第二次 CI 红(clean DB):`internal/api` 测试夹具在 `Migrate` 之前 `DELETE FROM settings`。
  本地一直有已迁移的库所以没暴露。已改为先 migrate。
- 第三次 CI 红(仅 Go 1.22):测试夹具用明文 HTTP 下发 `Secure` cookie,jar 是否接受随 Go 版本变化。
  该用例只关心"克隆之间 cookie 隔离",已去掉 Secure 标志,与版本无关。
- 最终:`ci`(1.22 + stable)与 `invariants`(五个命名作业)**全绿**;`v0.9.0` 已打 tag 并推送。

- **已发布**:<https://github.com/Yilanchia/youkai/releases/tag/v0.9.0>(tag 指向最后一个全绿的提交)。
- 两个徽章实测为 `passing`;仓库描述与 topics 已填。
- `go-licenses report ./...`:全部为 MIT / BSD-3-Clause,**依赖图里没有任何 copyleft**,
  清单已写进 `NOTICE`。

## 发布后

- [ ] README 徽章显示绿;`go-licenses report ./...` 核对传递依赖许可(NOTICE 已声明)。
- [ ] 真实目标按 COMPETITIVE 90 天计划第三阶段推进:先自有资产,再明确允许自动化扫描的 bug bounty。

## 卡住就回报

CI 第一次推上去后最容易卡在 Actions 环境差异(PG、Chrome、gofmt、依赖拉取)。红了把 Actions 日志发回,按日志微调 workflow,不改运行时代码、不放松安全门禁。
