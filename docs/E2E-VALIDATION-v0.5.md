# E2E 实战验证剧本 v0.5(主线闭环:建作业 → 自治只读 → 停档 2 → 人批一步 → 出证据/披露)

> 用途:在真实靶场把 v0.1→v0.5 的主线跑一遍,验证"自主走只读链、停在人前、一步步批利用、留下可复核证据"真能闭环。
> 执行者:维护者(在本机 PowerShell 跑)或 DeepSeek。**不加新功能** —— 这是验证,不是开发。
> 为什么不由 Claude 代跑:启 PostgreSQL 常驻服务 + 浏览器交互需要在本机 PowerShell 环境;git-bash 里管 Windows 常驻进程不可靠。

## 它验证什么(对照愿景)

- 无 scope 不动作;自治段**只跑档 1**、绝不自动 approve/利用;
- 遇档 2(param/login/accounts/利用)**停在人前**,门口摆齐"确切请求 + 最小影响 + 停止点 + 证据";
- 人用 high-auth + 一次批准放行**一个**动作,执行后批准即消费;
- candidate 需操作员判定才升 verified;报告四样证据齐、快照不可改、披露只收 verified;
- 全程越界请求 0、凭据/正文零泄漏。

## A. 自动化验收(先跑这个,判总绿)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\acceptance-v02.ps1
```

**判据**:末行 `ALL ACCEPTANCE ASSERTIONS PASSED`(退出码 0)。任何 `FAIL ...` 行即视为回归,记到下面"结果回填"。
它已覆盖:postgres/build/access-control/scope/autonomous-run/evidence/tier-2-door/accounts/BOLA/browser/
runtime-config/evidence-report/database-guards/report 共 14 段断言。这一关过了,说明**代码级主线没退化**。

> 若 PostgreSQL 起不来:脚本会打印 `.pgsql/server.log` 末尾。常见是 stale `postmaster.pid`(进程已死)——
> 删 `.pgsql/data/postmaster.pid` 再跑(只在确认端口无监听、owner PID 不存在时)。

## B. 人工 UI 走查(脚本断言覆盖不到的"人在环手感")

自动化证明了 API/数据库层对,这一节用眼睛确认**操作员体验**对。先手动起服务:

```powershell
.\start-youkai.cmd
```
浏览器会在 youkaid 就绪后自动打开 `http://127.0.0.1:8799/#token=...`。标题应为 **youkai**(不是别的应用的缓存页);若空白,Ctrl+F5 一次。

靶场另开一个 PowerShell 窗口起:
```powershell
python scripts\lab-target.py 18080
```

逐步走查(每步记"通过/异常"):

| # | 操作 | 应看到(通过标准) |
|---|---|---|
| B1 | 建作业:include `127.0.0.1:18080`、basis 填 ≥8 字(如 `self-hosted lab`)、留默认只读方法 | 作业建成;不填 basis / 填 `*` 被拒 |
| B2 | 不配 scope 直接想跑 | 被拒,提示需要护照 |
| B3 | 启动自治只读运行(seed `http://127.0.0.1:18080/search?q=acceptance`) | 任务台看到 probe/scan 跑;`/.git/config` 命中、`/search` 反射入证据;**运行停在 `needs_approval`** |
| B4 | 审批台 | 看到**一个**待批 `param`(档 2),展开有:确切请求 / 最小影响 / 停止点 / 证据;**没有"全部放行"按钮** |
| B5 | 不配 high-auth 直接批 | 被拒(428/提示缺 high-auth) |
| B6 | 配好 high-auth 后批准这一个 → 执行 | 只执行这一步、回灌证据、**再停在下一步**;同一批准不能再用 |
| B7 | 账号面板:provision alice/bob(档 2,双条件) | 视图显示两身份 session_ready;**界面不出现任何 cookie/密码** |
| B8 | BOLA:声明归属后看引擎派生 | 自动派 `compare`(档 1);越权对象产出 `bola` 候选(candidate,非 verified) |
| B9 | 证据面板:对一条 candidate 点"确认判定" | 需 operator + note + confirm 才升 verified;缺一被拒 |
| B10 | 出快照报告 | 生成快照(带 sha8 + 时间);每条 finding 四段证据齐;incomplete 的显式标注 |
| B11 | 导 SARIF | verified→error、candidate→warning |
| B12 | 出披露包 | **只含 verified**;candidate 不出现;无 verified 时给明确空态;正文无凭据/响应正文 |
| B13 | 配置面板的"隔离墙"段 | 只读展示(provider 不可用、档位表、high-auth 状态);**没有任何可点开关** |
| B14 | LLM 配置:填 base_url+model+key(或 key_from_env)→ 保存 → 测试连接 | 保存后 key 不回显;测试回 ok/延迟或错误,不回模型正文 |

## C. 结果回填模板(执行后填这里,或新开 IMPL-STATUS 回填)

```
日期:
环境:Go ___ / PostgreSQL ___ / Chrome|Edge ___
A 自动化:[ ] ALL PASSED  /  失败断言:________________
B 人工走查:
  B1 建作业/护照校验 ...... [ ]
  B2 无 scope 拒绝 ......... [ ]
  B3 自治只读停在档 2 ...... [ ]
  B4 审批台一次一个/无全放 . [ ]
  B5 无 high-auth 拒绝 ..... [ ]
  B6 批准一步即消费 ........ [ ]
  B7 账号 provision 无凭据 . [ ]
  B8 BOLA candidate ....... [ ]
  B9 verified 需判定 ....... [ ]
  B10 快照四样齐 ........... [ ]
  B11 SARIF 分级 ........... [ ]
  B12 披露只含 verified .... [ ]
  B13 墙段无开关 ........... [ ]
  B14 LLM 配置 key 不回显 .. [ ]
发现的问题(逐条:现象 / 期望 / 严重度 / 是否阻断):
结论:主线闭环 [ 成立 / 有缺口 ]
```

## D. 判定与下一步

- **A 全绿 + B 全通过** → 主线闭环成立,进路线图下一项(登录态浏览器)。
- **任一 FAIL/异常** → 记进 C,按严重度决定先修再走;回归类(原本绿的变红)优先。

把 C 填好的结果发回,我据此决定修 bug 还是推进下一个 DEVPLAN。
