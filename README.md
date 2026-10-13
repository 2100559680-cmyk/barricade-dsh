# barricade-dsh

[Barricade](https://github.com/JohnXu22786/safety-net) 的 **dsh 适配版**：在工具执行前对
破坏性命令（`rm -rf`、`git reset --hard`、`git push --force`、`mkfs`、`dd`、fork 炸弹 …）
做语义判定，命中则**拒绝**或**走 harness 的标准 approval 确认**。

上游包的 `plugin.js` 在本机 DSH 版本上加载失败并被插件管理器回滚（见下文
[为什么需要这个适配层](#为什么需要这个适配层)）。本包**原样复用上游的判定引擎**
（`vendor/`，SHA256 与上游 `src/` 逐字节一致），只重写了集成层。

## 文件结构

```
barricade-dsh/
├── plugin.js                 # 适配层：tools/pre-execute waterfall + deny/ask 映射
├── cordis.patch.yml          # 插入 barricade 插件行的配置补丁
├── vendor/                   # 上游判定引擎原样拷贝（零依赖纯 ESM）
│   ├── analyzer.js  verdict.js  rules.js  tokenizer.js  utils.js  policy.js
├── upstream-plugin.js.orig   # 上游 plugin.js 原件，供对照
├── test/apply.test.js        # 用假 ctx 验证与 harness 的契约（next() / ask / deny）
├── test/interceptor.test.js  # 直接驱动 createInterceptor 的判定测试
├── test/probe.js             # 只读探针：打印一批真实命令的判定结果
└── README.md
```

## 与上游插件的行为差异

| 项 | 上游 `dsh-barricade` | 本适配版 |
|---|---|---|
| `tools/pre-execute` 监听器 | `(call) => …; return call`，从不调用 `next()` | `(exec, next) => …`，放行时 `return next()` |
| 人工确认 | 直接调 `ctx.approval`（取不到服务，且请求形状与 `ApprovalService.request` 不符） | 返回 `{ kind: 'ask', reason }`，由 harness 的 `serviceAsk` 走标准 approval 流程 |
| 命令文本来源 | `args.command` | `arguments.command`（DSH 实际形状），仍兼容 `args.command` / `input.command` / `command` |
| 缺命令字段 | 拒绝 | 拒绝（失败安全，行为一致） |
| 包装命令长选项 | 漏判（见下） | 归一化后补一次分析，取更严的一侧 |
| 判定引擎 | `src/` | `vendor/` 逐字节相同（SHA256 已核对） |

### 上游引擎的包装长选项漏判（已在本适配层兜住）

上游的包装拆解只认短选项形态，实测（`node test/probe.js`，引擎原样调用）：

| 命令 | 上游引擎 | 本适配版 |
|---|---|---|
| `sudo -u root rm -rf /` | deny ✅ | deny |
| `sudo --user root rm -rf /` | allow ❌ | **deny** |
| `env FOO=1 rm -rf /` | deny ✅ | deny |
| `env --global x rm -rf /` | allow ❌ | **deny** |

本适配层把已知包装命令（`sudo`/`doas`/`env`/`nice`/`timeout`/`stdbuf`/`taskset`）的长选项
改写为等效短选项后再分析一次，与原判定取更严一侧——只可能提高严重度。实测该归一化不会
给良性命令（`sudo --user root systemctl restart nginx`、`timeout --signal TERM 30 pnpm test` 等）
引入误报。**这仍是一个补丁而非完备修复**：未收录的包装命令或未知长选项仍可能漏判，向
上游提 issue 更合适。

### 为什么需要这个适配层

本机 `.dsh-market/log.ndjson` 记录（2026-10-13 22:09:27）：

```
warn  github:JohnXu22786/safety-net#49ad74fa…: rolled back manifest residue of the failed run: dsh-barricade
error github:JohnXu22786/safety-net#49ad74fa… exit=1 err=…cordis/lib/index.js:1068:24 (#barricade ← #include)
```

即：pnpm 装包成功，但随后的加载自检失败，管理器把 `package.json` / lockfile 条目回滚。
另外上游 `cordis.patch.yml` 只声明 `inject: ['tools']`，而 `tools/pre-execute` 在本版本是
**waterfall**（未处置必须 `return next()`），原版监听器返回的是 `call` 而非 `next()` 的结果。

## 安装

需要安装到 **profile 级**（当前 profile 目录：`C:\Users\Joey\.dsh\profiles\desktop`）。
不要在 profile 目录里手跑 pnpm，也不要直接编辑 `package.json` / `cordis.yml`——
交给插件管理器做，它会写入依赖、打补丁、做加载自检，失败则自动回滚（不会弄坏 profile）。

任选一种：

1. **Web UI 插件页**：Plugin Manager → 从本地目录安装 → 选择
   `C:\Users\Joey\Documents\deepseek-harness\default-workspace\barricade-dsh`
2. **CLI**：`dsh plugin --profile desktop add C:\Users\Joey\Documents\deepseek-harness\default-workspace\barricade-dsh`

安装后出现插件行 `id: barricade / name: barricade-dsh`。判定引擎的配置写在策略文件里
（见下），改完策略需重启 profile 生效。

## 配置

`cordis.patch.yml` 里的 `config` 全部可省略：

| 键 | 默认 | 含义 |
|---|---|---|
| `mode` | `ask` | `ask` = 高危/致命命令请求人工确认；`deny` = 命中即硬拒绝，不询问 |
| `level` | 策略文件 | `relaxed` / `balanced` / `vigilant` |
| `tools` | profile 的 shell 工具（`bash`、`bash_persistent`、`pwsh`、`pwsh_persistent` 等） | 只拦截这些工具名 |
| `commandPath` | 依次尝试 `arguments.command` → `args.command` → `input.command` → `command` | 命令文本的点路径 |
| `policyFiles` | `{ user: ~/.barricade/barricade.json, project: <cwd>/.barricade.json }` | 策略文件路径 |

等级与严重度的动作映射（`vendor/rules.js`）：`relaxed` 中危放行、`balanced` 中危确认、
`vigilant` 另加"无法解析也要确认"；**致命规则不可降级为放行**。

## 策略文件

```json
{
  "version": 1,
  "level": "balanced",
  "allowlist": ["git status", "git log", "Get-ChildItem"],
  "overrides": { "git/tag-delete": "allow" },
  "rules": [
    { "id": "custom/dropdb-force", "command": "dropdb", "args": ["--force"], "severity": "high", "reason": "强制删除数据库" }
  ]
}
```

项目级 `.barricade.json` 优先于用户级 `~/.barricade/barricade.json`；
环境变量 `BARRICADE_HOME` / `BARRICADE_POLICY` / `BARRICADE_LEVEL` /
`BARRICADE_FAIL_CLOSED` / `BARRICADE_TOOLS` 可覆盖（等级只升不降）。
旁路查看单条命令的判定（不改任何状态）：

```powershell
node test/probe.js        # 打印本适配版对一批真实命令的最终判定
```

上游 CLI（`barricade analyze --json -c "<命令>"`）随残留目录一起被插件管理器清理掉了；
需要它时从 [上游仓库](https://github.com/JohnXu22786/safety-net) 重新取，或直接看
`test/probe.js` 的输出。

## 测试

```powershell
node test/interceptor.test.js   # 17 项：判定映射、失败安全、字段形状、归一化
node test/apply.test.js         # 7 项：与 harness 的契约（next() / ask / deny / 日志）
```

覆盖：放行无误报、`ask`/`deny` 两档模式、致命规则不可降级、非 shell 工具不干预、
缺字段失败安全、多种命令字段形状、包装长选项归一化与实际修复的绕过用例、
放行必须继续 waterfall、ask/deny 必须中断链路。

## 已知边界（与上游一致，务必知情）

- **不是沙箱，也不是权限边界。** 它只看得到工具调用里的命令文本：把危险操作写进脚本文件、
  或绕过 shell 工具（用 `write` 工具直接改文件、手工在容器外执行）不在保护范围内。
- **静态分析固有上限**：`bash <未知脚本>`、`eval "$X"` 这类运行时内容无法审查；
  `vigilant` 等级下会要求确认，`balanced` 下默认放行。
- **POSIX 语义**：分析按 POSIX 路径语义进行；在 Windows 上 `rm -rf` 规则照常生效，
  但 PowerShell 专有语义（如 `Remove-Item -LiteralPath` 的复杂组合）覆盖有限。
- **审批依赖**：`mode: ask` 需要 profile 里有可用的 approval answerer（本 profile 已配置）。
  没有 answerer 时 harness 按失败关闭处理——即拒绝，不会静默放行。

## 许可

适配层与上游同为 MIT。判定引擎与 `LICENSE` 来自
[JohnXu22786/safety-net](https://github.com/JohnXu22786/safety-net)（MIT）。
