# IMPL-STATUS v0.23 — 会打会修:方案文本 + 修复建议

> 日期:2026-11-16 · 承接 DEVPLAN-v0.23 · `go test ./...` 全绿 · 真机点过一遍
> **没有新增任何打击能力**:这一版只是把"这条洞怎么用、怎么修"写成文本。

## 一句话

以前报告说的是"这里有个洞";现在它还会说**"这个洞这么验证、这么修,PoC 骨架在这"** ——
方案是文本,扳机永远在人手里。

## 模块一 · web 利用方案(`web_exploit_plan`)

`internal/web/exploit_plan.go`,一条**档 2** 能力,只写文件、**没有任何 guard 调用**(这个文件里
连 discipline 都没 import)。

每份方案四段:

```
① 利用思路       这条为什么能利用、攻击者能拿到什么
② PoC 骨架       具体请求/载荷,占位符(<SESSION-A>/<TARGET>/<OTHER-ID>)
③ 验证成功的样子  看什么响应才算真的成立
④ 修复           通用最佳实践
```

覆盖的 kind:`bola/idor`、`sqli`、`ssti`、`ssrf`、`xss/reflection`、`path/lfi/traversal`、
`upload`、`jwt`、`open-redirect/redirect`、`exposure/git/backup`、`cors`。

**两条自我约束:**

- **没有模板就拒绝**:未知 kind 产出一条"没有可用模板,未生成文本(不臆造利用)"的 fact,
  而不是编一个听起来合理的利用。
- **PoC 里没有一个真实值**:全是占位符;文末固定写"本文是方案,不是已发生的事实:youkai 没有发送下面任何请求"。

真机产出(本机靶场,批准后生成):

```
# 利用方案:Git 配置可读
- 位置:http://127.0.0.1:18080/.git/config
> 本文是方案,不是已发生的事实:youkai 没有发送下面任何请求。
## ② PoC 骨架(占位符,由你自行运行)
curl -s "<TARGET>/.git/config" | head -20
```

## 模块二 · 修复建议进报告

- `FindingReport.Remediation`,按 kind 从 `RemediationFor` 取(18 种 kind + 兜底);
- **未知 kind 返回空**,不编 —— 空着比"看起来对"的建议诚实;
- 报告 MD/HTML 从"④ 反证说明"扩成"④ 反证 + ⑤ 修复建议",披露包里同样有;
- 发现页每条卡片下面直接显示"修复建议:…"。

## 模块三 · 接进对话与发现页

- 发现页每条候选旁边:「生成利用方案(文本)」按钮 → `POST /findings/{id}/plan`
  → 建一条**档 2** intent(带 kind/where/param/method/request_id),**等你批准**才生成;
- 托管收尾的那句小结,现在会点名**最该先看的一条**(按严重度)+ 它的一句话修法,
  并说明"点生成方案,我只写文件、不发请求";
- 纯假设(没有证据/已判 false-positive)不排队列 —— 没有证据就没有利用可讲。

## 模块四 · 二进制方案做深(轻量)

`pwn_template` 接受 `hypotheses`(binflow 的线索),骨架从通用占位变成**针对性**:

- `argv → system` → 讲命令执行面怎么先无害试探;
- `argv → strcpy` → 讲先用 pwn_cyclic 找偏移、在 gdb 里真跑而不是静态猜;
- `printf` → 先 `%p.%p.%p` 观察栈,不直接写内存;
- 末尾给修复方向(输入长度/字符白名单 + 编译期加固)。

仍然**只写文本,从不执行**。

## 验收

```
web    TestExploitPlanRefusesUnknownKind   未知类型 → 拒绝,且不含 payload
       TestExploitPlanIsTextOnly          四段齐全、占位符在、没声称已发送
       TestExploitPlanCoversTheDetectionKinds  18 个 kind 都有模板
       TestExploitPlanSendsNothing        环境里没有 guard 也能跑(它根本不联网)
api    TestExploitPlanIsQueuedAsATierTwoStep  端点建的是档 2 intent,需批准,未执行
       TestExploitPlanUnknownFindingIs404
binary TestPwnTemplateUsesBinflowLeads      线索 → 针对性段落(命令执行面/无界拷贝面)
真机   批准 → 生成 .md(1012 字节),四段 + 占位符 + "未发送"
```

## 没做的(如实)

- **二进制方案仍是骨架级**:没有读 checksec 结果去自动选打法(那需要把样本分析串起来,留待下一版)。
- **对话里没有直接的"生成方案"按钮**:按钮在发现页;对话小结只做指引(避免在聊天里塞交互组件)。
- **报告里的 remediation 是通用文本**:没有按目标技术栈细化(例如"用 Go 的 database/sql 参数化" vs "用 PHP PDO")。
- **bench 没有加"发现→方案"样例**(模块五的一半)。

## 一句话

它现在能把"怎么打"讲清楚 —— 讲给**人**听,由人决定要不要打。这就是"会分析"和"会动手"的区别。
