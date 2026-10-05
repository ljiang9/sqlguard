# sqlguard

LLM 生成 SQL 的静态安全检查器：SQL 丢进来，危险报告出来。

LLM 写 SQL 又快又自信，但它也会自信地写出 `DELETE` 不带 `WHERE`、或者把 `OR 1=1`
直接拼进查询。sqlguard 在你把 SQL 交给数据库**之前**先扫一遍，纯本地、纯标准库、
零依赖、毫秒级。

## 快速开始

```bash
python3 -m sqlguard query.sql        # 检查文件
python3 -m sqlguard --text "SELECT * FROM users"
cat query.sql | python3 -m sqlguard --stdin
python3 -m sqlguard query.sql --json # 机器可读输出
python3 -m sqlguard --explain        # 看每条规则为什么存在
```

## 示例

```bash
$ python3 -m sqlguard examples/dangerous.sql
规则            | 严重程度 | 说明                                       | 语句/片段
----------------+----------+--------------------------------------------+---------------------------
SELECT *        | 警告     | SELECT * 返回全部列……                     | #1 SELECT * FROM users WHERE '1'='1' OR 1=1
恒真条件（OR 1=1）| 危险    | 检测到 OR 1=1 / '1'='1' 类恒真条件……      | #1 SELECT * FROM users WHERE '1'='1' OR 1=1
恒真 WHERE      | 危险     | WHERE 条件恒为真……                        | #1 SELECT * FROM users WHERE '1'='1' OR 1=1
DROP 删除对象   | 危险     | 检测到 DROP……                             | #2 DROP TABLE users
无 WHERE 的 DELETE | 危险  | DELETE 没有 WHERE 条件……                  | #3 DELETE FROM orders
SQL 注释        | 警告     | 检测到 SQL 注释……                         | #1 -- 危险示例：一次塞了好几种风险…
堆叠查询        | 危险     | 一次输入包含 3 条语句……                   | - 共 3 条语句

⛔ 危险：发现 5 个危险问题，请勿执行
```

退出码：`0` 安全 / `2` 危险 / `1` 仅警告（`--warn-ok` 可让警告也 exit 0，方便 CI）。
`--strict`：任何发现（含警告）都 exit 2，适合做流水线门禁。

## 规则（16 条）

`--explain` 会逐条解释为什么。覆盖：DROP / 无 WHERE 的 DELETE / 无 WHERE 的 UPDATE /
TRUNCATE / ALTER / GRANT / OR 1=1 恒真 / WHERE 1=1 / 堆叠查询 / UNION SELECT /
SQL 注释 / SELECT * / LOAD_FILE-INTO OUTFILE / SLEEP-BENCHMARK 时间盲注 /
xp_cmdshell / SHUTDOWN。

## 诚实说明

- **这是启发式检查，不是真正的 SQL 解析器。** 正则看不懂嵌套、方言差异和复杂语义，
  会有误报和漏报。它适合做"最后一道 cheap 的 sanity check"，不适合做唯一防线。
- **真正的安全靠**：参数化查询 / 预编译语句、最小权限的数据库账号、Code Review。
  sqlguard 通过不代表 SQL 真的安全。
- 注释规则（`--`）在带注释的正常 SQL 里也会报警告，这是故意的：让你看一眼。

## License

MIT，Copyright (c) 2026 ljiang9
