#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sqlguard - LLM 生成 SQL 的静态安全检查器。

纯本地、纯标准库：SQL 丢进来，危险报告出来。
注意：这是基于正则的启发式分析，不是真正的 SQL 解析器，
不能替代参数化查询和数据库权限控制。
"""

import argparse
import json
import re
import sys

__version__ = "0.1.0"

SEV_DANGER = "危险"
SEV_WARN = "警告"

# ---------------------------------------------------------------------------
# 输入预处理
# ---------------------------------------------------------------------------

_STRING_RE = re.compile(
    r"'(?:[^'\\]|\\.|'')*'"      # 单引号字符串（含转义、'' 转义）
    r'|"(?:[^"\\]|\\.)*"'        # 双引号
    r"|`(?:[^`\\]|\\.)*`",       # 反引号
    re.DOTALL,
)


def strip_strings(sql):
    """把字符串字面量替换成占位符，得到"代码视图"（结构分析用）。"""
    return _STRING_RE.sub("STR", sql)


def split_statements(sql):
    """按分号切分语句，忽略字符串字面量里的分号。"""
    parts, cur, in_str, esc = [], [], None, False
    for ch in sql:
        if in_str:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == in_str:
                in_str = None
        else:
            if ch in ("'", '"', "`"):
                in_str, esc = ch, False
                cur.append(ch)
            elif ch == ";":
                text = "".join(cur).strip()
                if text:
                    parts.append(text)
                cur = []
            else:
                cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


# ---------------------------------------------------------------------------
# 规则
# ---------------------------------------------------------------------------

def _snip(stmt, n=60):
    s = re.sub(r"\s+", " ", stmt).strip()
    return s if len(s) <= n else s[:n] + "…"


def _finding(rule, snippet, statement=0):
    return {
        "rule": rule["id"],
        "name": rule["name"],
        "severity": rule["severity"],
        "message": rule["message"],
        "statement": statement,
        "snippet": snippet,
    }


def _check_delete_no_where(stmt, code, idx):
    if re.match(r"\s*DELETE\b", code, re.I) and not re.search(r"\bWHERE\b", code, re.I):
        return True
    return False


def _check_update_no_where(stmt, code, idx):
    if re.match(r"\s*UPDATE\b", code, re.I) and not re.search(r"\bWHERE\b", code, re.I):
        return True
    return False


_TAUTOLOGY_RE = re.compile(
    r"\bOR\b\s*(?:"
    r"'1'\s*=\s*'1'"
    r"|\"1\"\s*=\s*\"1\""
    r"|\b1\s*=\s*1\b"
    r"|'([^']+)'\s*=\s*'\1'"      # OR 'abc'='abc' 这类恒真比较
    r")",
    re.I,
)


def _check_tautology(stmt, code, idx):
    return bool(_TAUTOLOGY_RE.search(stmt))  # 原始视图：字符串里的注入形状也要抓


def _check_stacked(statements):
    if len(statements) > 1:
        return {
            "rule": "stacked",
            "name": "堆叠查询",
            "severity": SEV_DANGER,
            "message": "一次输入包含 %d 条语句，堆叠查询是 SQL 注入的经典手法" % len(statements),
            "statement": 0,
            "snippet": "共 %d 条语句" % len(statements),
        }
    return None


RULES = [
    {
        "id": "drop", "name": "DROP 删除对象", "severity": SEV_DANGER,
        "message": "检测到 DROP，可能永久删除表/库/视图等对象",
        "why": "DROP 会永久删除数据库对象，出现在 LLM 生成的查询类 SQL 里基本就是事故。",
        "pattern": re.compile(r"\bDROP\s+(TABLE|DATABASE|SCHEMA|VIEW|INDEX)\b", re.I),
    },
    {
        "id": "delete-no-where", "name": "无 WHERE 的 DELETE", "severity": SEV_DANGER,
        "message": "DELETE 没有 WHERE 条件，会清空整张表",
        "why": "没有 WHERE 的 DELETE 会删除全表数据，是最常见的“删库”误操作之一。",
        "custom": _check_delete_no_where,
    },
    {
        "id": "update-no-where", "name": "无 WHERE 的 UPDATE", "severity": SEV_DANGER,
        "message": "UPDATE 没有 WHERE 条件，会改写整张表",
        "why": "没有 WHERE 的 UPDATE 会把全表每一行都改掉，破坏面极大。",
        "custom": _check_update_no_where,
    },
    {
        "id": "truncate", "name": "TRUNCATE", "severity": SEV_DANGER,
        "message": "检测到 TRUNCATE，会清空表且通常不可回滚",
        "why": "TRUNCATE 直接清空表，在很多数据库里是 DDL、不可回滚，比 DELETE 更危险。",
        "pattern": re.compile(r"\bTRUNCATE\b", re.I),
    },
    {
        "id": "alter", "name": "ALTER 改结构", "severity": SEV_DANGER,
        "message": "检测到 ALTER，会修改表/库结构",
        "why": "ALTER 改变表结构（加列、改类型、删列），查询场景下不应出现。",
        "pattern": re.compile(r"\bALTER\s+(TABLE|DATABASE|SCHEMA|VIEW|INDEX|COLUMN)\b", re.I),
    },
    {
        "id": "grant", "name": "GRANT/REVOKE 权限", "severity": SEV_DANGER,
        "message": "检测到 GRANT/REVOKE，在改动数据库权限",
        "why": "权限变更属于高危运维操作，绝不该出现在 LLM 生成的业务 SQL 里。",
        "pattern": re.compile(r"\b(GRANT|REVOKE)\b", re.I),
    },
    {
        "id": "tautology", "name": "恒真条件（OR 1=1）", "severity": SEV_DANGER,
        "message": "检测到 OR 1=1 / '1'='1' 类恒真条件，典型注入形状",
        "why": "OR 1=1 让 WHERE 恒为真从而绕过鉴权/越权读全表，是最经典的 SQL 注入手法。",
        "custom": _check_tautology, "view": "raw",
    },
    {
        "id": "where-true", "name": "恒真 WHERE", "severity": SEV_DANGER,
        "message": "WHERE 条件恒为真（WHERE 1=1 / WHERE TRUE），等于没有过滤",
        "why": "恒真的 WHERE 等价于全表扫描/全表操作，常被用来绕过条件限制。",
        "pattern": re.compile(r"\bWHERE\b\s*(1\s*=\s*1|TRUE\b|STR\s*=\s*STR)", re.I),
    },
    {
        "id": "stacked", "name": "堆叠查询", "severity": SEV_DANGER,
        "message": "", "why": "",
        "why_text": "一次输入多条语句（堆叠查询）是 SQL 注入的经典手法：第一条正常查询，后面跟恶意语句。",
        "global": True, "custom": _check_stacked,
    },
    {
        "id": "union-select", "name": "UNION SELECT", "severity": SEV_WARN,
        "message": "检测到 UNION SELECT，常见于注入，也可能是正常查询，请人工确认",
        "why": "UNION SELECT 是注入时拼接读取其他表数据的常用形状；但它本身也是合法 SQL，所以只报警告。",
        "pattern": re.compile(r"\bUNION\s+(ALL\s+|DISTINCT\s+)?SELECT\b", re.I),
    },
    {
        "id": "comment", "name": "SQL 注释", "severity": SEV_WARN,
        "message": "检测到 SQL 注释（-- 或 /* */），可能用于截断/隐藏注入",
        "why": "注入常常用 -- 或 /* 把原 SQL 后半截注释掉以闭合语法；正常查询里出现注释也值得看一眼。",
        "pattern": re.compile(r"--[^\n]*|/\*", re.I),
    },
    {
        "id": "select-star", "name": "SELECT *", "severity": SEV_WARN,
        "message": "SELECT * 返回全部列，可能拖慢查询并泄露多余字段",
        "why": "SELECT * 会拉回所有列：性能差，还可能把密码哈希之类敏感列带出来。明确列出需要的列更好。",
        "pattern": re.compile(r"\bSELECT\s+(DISTINCT\s+|ALL\s+)?\*", re.I),
    },
    {
        "id": "file-access", "name": "文件读写", "severity": SEV_DANGER,
        "message": "检测到 LOAD_FILE / INTO OUTFILE，在读写服务器文件",
        "why": "LOAD_FILE 读服务器文件、INTO OUTFILE 写文件（如写 webshell），是注入后的典型提权动作。",
        "pattern": re.compile(r"\bLOAD_FILE\s*\(|\bINTO\s+(OUTFILE|DUMPFILE)\b", re.I),
    },
    {
        "id": "time-based", "name": "时间盲注函数", "severity": SEV_DANGER,
        "message": "检测到 SLEEP / BENCHMARK / WAITFOR DELAY，时间盲注特征",
        "why": "SLEEP()、BENCHMARK()、WAITFOR DELAY 是时间盲注里用来“问”数据库问题的函数，正常业务 SQL 极少用。",
        "pattern": re.compile(r"\b(SLEEP|BENCHMARK)\s*\(|\bWAITFOR\s+DELAY\b", re.I),
    },
    {
        "id": "xp-cmdshell", "name": "xp_cmdshell", "severity": SEV_DANGER,
        "message": "检测到 xp_cmdshell，会在数据库服务器上执行系统命令",
        "why": "xp_cmdshell 直接在 SQL Server 主机上执行操作系统命令，是注入提权的终极目标之一。",
        "pattern": re.compile(r"\bxp_cmdshell\b", re.I),
    },
    {
        "id": "shutdown", "name": "SHUTDOWN", "severity": SEV_DANGER,
        "message": "检测到 SHUTDOWN，会关闭数据库服务",
        "why": "SHUTDOWN 直接停掉数据库服务，属于破坏性操作，查询场景下绝不应出现。",
        "pattern": re.compile(r"\bSHUTDOWN\b", re.I),
    },
]

# 补上 stacked 规则的 message/why（上面占位）
for _r in RULES:
    if _r["id"] == "stacked":
        _r["why"] = _r.pop("why_text")


# ---------------------------------------------------------------------------
# 分析
# ---------------------------------------------------------------------------

def analyze(sql):
    """返回 (statements, findings)。"""
    findings = []
    statements = split_statements(sql)
    for idx, stmt in enumerate(statements, 1):
        code = strip_strings(stmt)
        for rule in RULES:
            if rule.get("global"):
                continue
            hit = False
            if "custom" in rule:
                hit = rule["custom"](stmt, code, idx)
            else:
                m = rule["pattern"].search(code)
                hit = bool(m)
            if hit:
                findings.append(_finding(rule, _snip(stmt), statement=idx))
    for rule in RULES:
        if rule.get("global"):
            hit = rule["custom"](statements)
            if hit:
                findings.append(hit)
    return statements, findings


def verdict(findings):
    dangers = [f for f in findings if f["severity"] == SEV_DANGER]
    warns = [f for f in findings if f["severity"] == SEV_WARN]
    if dangers:
        return "danger", "⛔ 危险：发现 %d 个危险问题，请勿执行" % len(dangers)
    if warns:
        return "warn", "⚠️ 有警告：发现 %d 个警告，人工确认后再执行" % len(warns)
    return "safe", "✅ 安全：未发现已知风险模式"


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------

def print_table(findings):
    rows = [("规则", "严重程度", "说明", "语句/片段")]
    for f in findings:
        stmt = ("#%d" % f["statement"]) if f["statement"] else "-"
        rows.append((f["name"], f["severity"], f["message"], "%s %s" % (stmt, f["snippet"])))
    widths = [max(len(r[i]) for r in rows) for i in range(4)]
    for n, r in enumerate(rows):
        print(" | ".join(c.ljust(widths[i]) for i, c in enumerate(r)))
        if n == 0:
            print("-+-".join("-" * w for w in widths))


def print_explain():
    print("sqlguard 规则说明（共 %d 条）：\n" % len(RULES))
    for r in RULES:
        print("[%s] %s（%s）" % (r["id"], r["name"], r["severity"]))
        print("    为什么：%s\n" % r["why"])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="sqlguard",
        description="LLM 生成 SQL 的静态安全检查器（纯本地、启发式）。",
    )
    p.add_argument("file", nargs="?", help="要检查的 SQL 文件")
    p.add_argument("--stdin", action="store_true", help="从标准输入读取 SQL")
    p.add_argument("--text", help="直接传入 SQL 文本")
    p.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    p.add_argument("--explain", action="store_true", help="解释每条规则为什么存在，然后退出")
    p.add_argument("--strict", action="store_true",
                   help="严格模式：任何发现（含警告）都以 exit 2 退出")
    p.add_argument("--warn-ok", action="store_true",
                   help="仅有警告时 exit 0（默认 exit 1），方便 CI 流水线")
    p.add_argument("--version", action="version", version="sqlguard " + __version__)
    return p


def read_input(args):
    if args.text is not None:
        return args.text
    if args.stdin:
        return sys.stdin.read()
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                return fh.read()
        except FileNotFoundError:
            print("error: 文件不存在：%s" % args.file, file=sys.stderr)
            sys.exit(1)
        except OSError as e:
            print("error: 读取文件失败：%s" % e, file=sys.stderr)
            sys.exit(1)
    return None


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.explain:
        print_explain()
        return 0

    sql = read_input(args)
    if sql is None:
        build_parser().print_help(sys.stderr)
        return 1
    if not sql.strip():
        print("error: 输入为空，没有可检查的 SQL。", file=sys.stderr)
        return 1

    statements, findings = analyze(sql)
    level, line = verdict(findings)

    if args.json:
        print(json.dumps({
            "verdict": level,
            "message": line,
            "statements": len(statements),
            "findings": findings,
        }, ensure_ascii=False, indent=2))
    else:
        if findings:
            print_table(findings)
            print()
        print(line)

    if level == "danger":
        return 2
    if level == "warn":
        if args.strict:
            return 2
        return 0 if args.warn_ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
