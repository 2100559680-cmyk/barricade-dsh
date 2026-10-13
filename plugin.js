// Barricade 的 dsh 适配层（重写版）。
//
// 与原版 dsh-barricade/plugin.js 的差异，全部对应 DSH 当前契约：
//   1. `tools/pre-execute` 是 waterfall：监听器签名 (exec, next)，
//      未处置时必须 `return next()`；原版是 (call) 且 `return call`。
//   2. 人工确认不再直接调 ctx.approval（原版取不到服务、请求形状也不对），
//      改为返回 `{ kind: 'ask', reason }`，由 harness 的 serviceAsk 走
//      标准 approval 流程；用户拒绝即拒绝。
//   3. 命令文本读 `exec.arguments`（原版读 `args.command`），并兼容
//      config.commandPath 与若干常见形状。
//   4. 判定引擎原样复用（./vendor/），只重写集成层。
//
// 判定映射：
//   verdict.action === 'allow' → return next()
//   verdict.action === 'ask'   → { kind: 'ask',  reason }（或 mode=deny 时降级为 deny）
//   verdict.action === 'deny'  → { kind: 'deny', reason }

import path from 'node:path'
import os from 'node:os'
import { analyzeCommand } from './vendor/analyzer.js'
import { Policy } from './vendor/policy.js'
import { sanitizeForDisplay } from './vendor/utils.js'

export const name = 'barricade'

/** 依赖工具注册表；缺失该服务的 profile 里本插件保持不激活而不是抛错。 */
export const inject = ['tools']

/** 默认拦截的 shell 类工具（本 profile 实际注册 bash / pwsh 及其 persistent 变体）。 */
export const DEFAULT_TOOLS = [
  'bash', 'bash_persistent',
  'pwsh', 'pwsh_persistent',
  'sh', 'zsh', 'shell', 'terminal',
  'powershell', 'cmd',
  'run_command', 'exec',
]

/** 命令字段候选：优先 config.commandPath，其次这些点路径。 */
const COMMAND_PATHS = [
  'arguments.command',
  'args.command',
  'input.command',
  'parameters.command',
  'command',
]

/**
 * 构造一个不依赖具体 harness 的判定函数。
 * @param {object} config 见 README 的 config 表
 * @param {object} env    环境变量（默认 process.env）
 * @returns {(exec: object) => Promise<{kind: string, reason?: string}>}
 */
export function createInterceptor(config = {}, env = process.env) {
  const mode = config.mode === 'ask' ? 'ask' : 'deny'
  const level = config.level
  const toolNames = resolveTools(config.tools ?? config.toolNames, env)
  const commandPaths = resolveCommandPaths(config, env)

  const loaded = Policy.load({
    env,
    cwd: process.cwd(),
    files: config.policyFiles ?? null,
  })
  const policy = config.level ? loaded.policy.withLevel(config.level) : loaded.policy

  const intercept = async (exec) => {
    if (!exec || typeof exec !== 'object') return { kind: 'allow' }
    const toolName = exec.name ?? exec.tool ?? exec.toolName
    if (typeof toolName !== 'string' || !toolNames.has(toolName)) return { kind: 'allow' }

    const command = readCommand(exec, commandPaths)
    if (command === MISSING) {
      // 目标是 shell 工具却没有可读的命令字段：失败安全，不静默放行。
      return {
        kind: 'deny',
        reason: `Barricade: 工具 ${toolName} 的调用缺少字符串命令字段（尝试过 ${commandPaths.join(', ')}），已拒绝执行`,
      }
    }
    if (command.trim() === '') return { kind: 'allow' }

    const cwd = resolveCwd(exec)
    const verdict = analyzeCommand(command, { policy, cwd, home: os.homedir(), env })

    // 上游引擎对「包装命令 + 长选项」漏判（sudo --user root rm -rf / → allow），
    // 这里把长选项归一化为等效短选项后补一次分析，取更严的一侧。只增不减。
    const normalized = normalizeWrapperFlags(command)
    const verdicts = normalized === command
      ? [verdict]
      : [verdict, analyzeCommand(normalized, { policy, cwd, home: os.homedir(), env })]
    const action = worstAction(verdicts)
    const reason = worstVerdict(verdicts, action).format()

    if (action === 'allow') return { kind: 'allow' }
    if (action === 'deny') return { kind: 'deny', reason }
    // ask
    return mode === 'ask' ? { kind: 'ask', reason } : { kind: 'deny', reason }
  }

  intercept.policy = policy
  intercept.warnings = loaded.warnings
  intercept.config = { mode, level: policy.level, tools: [...toolNames], commandPaths }
  return intercept
}

const MISSING = Symbol('barricade-missing-command')

/** 解析命令文本；字段存在但不是字符串也算缺失（失败安全）。 */
function readCommand(exec, commandPaths) {
  for (const dotPath of commandPaths) {
    const found = getByPath(exec, dotPath)
    if (found === undefined || found === null) continue
    if (typeof found === 'string') return found
    return MISSING
  }
  return MISSING
}

function getByPath(obj, dotPath) {
  let cur = obj
  for (const part of String(dotPath).split('.')) {
    if (cur === null || typeof cur !== 'object') return undefined
    cur = cur[part]
  }
  return cur
}

/** 工具调用自带 cwd 时优先使用；越出真实工作区的一律忽略（防降级绕过）。 */
function resolveCwd(exec) {
  const real = process.cwd()
  const args = exec.arguments ?? exec.args ?? exec.input
  const claimed = typeof args?.cwd === 'string' ? args.cwd : typeof args?.workdir === 'string' ? args.workdir : null
  if (!claimed) return real
  const rel = path.relative(real, claimed)
  if (rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel)) return real
  return claimed
}

function resolveTools(configured, env) {
  const raw = env.BARRICADE_TOOLS ?? (Array.isArray(configured) ? configured.join(',') : typeof configured === 'string' ? configured : null)
  const parsed = raw ? String(raw).split(',').map((s) => s.trim()).filter(Boolean) : []
  return new Set(parsed.length > 0 ? parsed : DEFAULT_TOOLS)
}

function resolveCommandPaths(config, env) {
  const configured = env.BARRICADE_COMMAND_PATH ?? config.commandPath
  if (typeof configured === 'string' && configured.trim() !== '') {
    const rest = COMMAND_PATHS.filter((p) => p !== configured)
    return [configured.trim(), ...rest]
  }
  return COMMAND_PATHS
}

// ---------------------------------------------------------------------------
// 包装命令「长选项」归一化
//
// 上游引擎的包装拆解只认短选项形态：`sudo -u root rm -rf /` 会被拒绝，而
// `sudo --user root rm -rf /` 得到 allow（`env --global x rm -rf /` 同理）。
// 这里把已知包装命令的长选项改写为等效短选项（或直接删去），再让引擎分析一次，
// 两次判定取更严的一侧——只可能提高严重度，不会放行原本被拦的命令。
// ---------------------------------------------------------------------------

/** 长选项 → 短选项；值为 null 表示该选项自带走值。 */
const WRAPPER_LONG_FLAGS = {
  sudo: { '--user': '-u', '--group': '-g', '--prompt': '-p', '--close-from': '-C', '--chdir': '-D', '--role': '-r', '--type': '-t' },
  doas: { '--user': '-u' },
  env: { '--unset': '-u', '--chdir': '-C', '--global': '-u' },
  nice: { '--adjustment': '-n' },
  timeout: { '--signal': '-s', '--kill-after': '-k' },
  stdbuf: { '--input': '-i', '--output': '-o', '--error': '-e' },
  taskset: { '--cpu-list': '-c' },
}

/** 仅做保守改写：包装命令词出现在头部或分隔符之后，才替换该命令的长选项。 */
export function normalizeWrapperFlags(command) {
  const cmd = String(command ?? '')
  if (!cmd) return cmd

  const prefixes = []
  if (/\bsudo\b/.test(cmd)) prefixes.push('sudo')
  if (/\bdoas\b/.test(cmd)) prefixes.push('doas')
  if (/(^|[;&|]\s*|\bsudo\s+|\bdoas\s+|\benv\s+|\btimeout\s+|\bnice\s+|\bxargs\s+)env\s/.test(cmd)) prefixes.push('env')
  if (/\bnice\s/.test(cmd)) prefixes.push('nice')
  if (/\btimeout\s/.test(cmd)) prefixes.push('timeout')
  if (/\bstdbuf\s/.test(cmd)) prefixes.push('stdbuf')
  if (/\btaskset\s/.test(cmd)) prefixes.push('taskset')

  let out = cmd
  for (const tool of prefixes) {
    const map = WRAPPER_LONG_FLAGS[tool]
    if (!map) continue
    const names = Object.keys(map).join('|')
    // 只把「位于本包装命令词之后」的长选项换成等效短选项，其余文本原样保留；
    // 目标命令随之暴露给引擎的常规包装拆解。
    const re = new RegExp(
      `(^|[;&|]\\s*)((?:[\\w./-]*\\/)?${tool})((?:(?!\\s(?:&&|\\|\\||[;&|])).)*?)(${names})(?=[=\\s]|$)`,
      'gm',
    )
    out = out.replace(re, (match, lead, word, between, flag) => `${lead}${word}${between}${map[flag]}`)
  }
  return out
}

/** allow < ask < deny；致命规则已由引擎固定为 deny，不会出现在这里被降级。 */
function worstAction(verdicts) {
  let worst = 'allow'
  for (const v of verdicts) {
    if (v?.action === 'deny') return 'deny'
    if (v?.action === 'ask') worst = 'ask'
  }
  return worst
}

/** 取严重度最高的判定（同档时取原始命令那一份，保持原因文本指向用户所写命令）。 */
function worstVerdict(verdicts, action) {
  if (action === 'allow') return verdicts[0]
  const candidates = verdicts.filter((v) => v?.action !== 'allow')
  const rank = { critical: 3, high: 2, medium: 1 }
  return candidates.reduce((best, v) => ((rank[v.severity] ?? 0) > (rank[best.severity] ?? 0) ? v : best), candidates[0])
}

/**
 * 向 profile 日志写一行；logger 形状随版本/组合变化，因此完全防御式，
 * 绝不因为日志本身让插件加载失败。
 */
function log(ctx, level, message) {
  try {
    const logger = ctx?.logger
    if (!logger) return
    const sink = typeof logger === 'function' ? logger.call(ctx, 'barricade') : logger
    if (typeof sink?.[level] === 'function') sink[level](message)
  } catch {
    /* 日志失败不影响判定 */
  }
}

/** Cordis 插件入口。 */
export function apply(ctx, config = {}) {
  const interceptor = createInterceptor(config)

  for (const warning of interceptor.warnings) log(ctx, 'warn', warning)

  ctx.on('tools/pre-execute', async (exec, next) => {
    const decision = await interceptor(exec)
    if (decision.kind === 'allow') return next()
    if (decision.kind === 'deny') {
      log(ctx, 'info', `denied ${exec?.name ?? '?'}: ${sanitizeForDisplay(exec?.arguments?.command ?? '', 200)}`)
      return { kind: 'deny', reason: decision.reason }
    }
    // kind === 'ask'：交给 harness 的 approval 流程
    return decision.reason === undefined ? { kind: 'ask' } : { kind: 'ask', reason: decision.reason }
  })
}
