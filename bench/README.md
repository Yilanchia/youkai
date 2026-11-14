# bench —— 本机靶场基准

```bash
export YOUKAI_BENCH_DSN="postgres://youkai:youkai_dev_pw@127.0.0.1:55432/youkai_test?sslmode=disable"
go run ./bench -port 18088 -max-steps 12
```

它做三件事,然后如实报告:

1. 起 `scripts/lab-target.py` 作为子进程(本机环回);
2. 用一个**临时作业**(`allow_private`、只读方法、预算 500)跑**真正的引擎 + 真正的 dispatcher**,所以 guard 在路径上,
   和线上是同一条代码路径;
3. 读回账本,对 ground truth 算 recall / precision、每次发现消耗多少请求、以及**越界请求数**(必须 0)。

结果写到 `bench/results/<date>.json`,并打印一行摘要。跑完默认删掉这次作业(加 `-keep` 保留以便检查)。

## 口径(重要)

- **只声明本机靶场。** recall=1.0 的含义是"对这个故意留了这些问题的靶场,该找到的都找到了",
  **不是**对任意目标的检出率。任何把这里的数字外推成"产品能力"的用法都是错的。
- **只测档 1(匿名只读链)。** 档 2(param/waf/登录/播种)按设计需要人批 + 签署记录;
  基准要是伪造这两个条件,测的就是另一个产品了。所以成本口径是"只读链的请求成本",
  不含人工审批的时间成本。
- **ground truth 来自靶场源码,不来自上一次运行。** 条目写在 `bench/main.go` 的 `groundTruth()`:
  `/ .git/config` 可读、`q` 反射、四个安全头缺失、版本号暴露 —— 每一项都能在
  `scripts/lab-target.py` 里指出来。
- **precision 只对得上 ground truth 的发现计为真。** 靶场的默认路由对任何路径都返回 200,
  但暴露面检查要求内容签名(`[core]`),所以 `/.env`、`/backup.zip` 那些 200 不会变成发现 ——
  这条是靶场设计,不是漏报。
- **越界请求 = 0 是硬断言。** 一旦有 blocked 审计行,bench 以非零退出码结束:
  一个"授权靶场"上出现越界请求,数字再好看也不算数。

## 当前结果(2026-11-14,本机 Windows)

| 指标 | 值 |
|---|---|
| recall | 1.000(7/7 ground truth) |
| precision | 1.000 |
| 请求(允许/阻断) | 10 / 0 |
| 每发现请求成本 | 1.43 |
| 停止点 | needs_approval(param,档 2 转人工) |

可复现性:同一靶场、同一 `-max-steps` 下请求数与命中集合稳定;发现的 id 会随账本增长而变化,
所以 JSON 里记录的是 id 供追溯,不是稳定性依据。
