// 纯逻辑测试：直接驱动 createInterceptor，不经 harness。
// 运行: node test/interceptor.test.js
import assert from 'node:assert/strict'
import { createInterceptor, DEFAULT_TOOLS } from '../plugin.js'

const env = { ...process.env, BARRICADE_HOME: '/nonexistent-barricade-home' }
const interceptor = createInterceptor({ mode: 'ask' }, env)
const hard = createInterceptor({ mode: 'deny' }, env)

const call = (command, extra = {}) => ({ name: 'pwsh', arguments: { command, ...extra }, agent: {} })

let passed = 0
const check = async (label, fn) => {
  await fn()
  passed += 1
  console.log(`ok  ${label}`)
}

await check('benign PowerShell command allows', async () => {
  assert.equal((await interceptor(call('Get-ChildItem -Force'))).kind, 'allow')
})

await check('mkdir/npm style command allows', async () => {
  assert.equal((await interceptor(call('pnpm install --frozen-lockfile'))).kind, 'allow')
})

await check('git reset --hard asks under mode=ask', async () => {
  const d = await interceptor(call('git reset --hard HEAD~3'))
  assert.equal(d.kind, 'ask')
  assert.match(d.reason, /git\/reset-hard/)
})

await check('git reset --hard denies under mode=deny', async () => {
  assert.equal((await hard(call('git reset --hard HEAD~3'))).kind, 'deny')
})

await check('rm -rf inside workspace asks', async () => {
  assert.equal((await interceptor(call('rm -rf ./build'))).kind, 'ask')
})

await check('rm -rf / denies (fatal rule cannot be downgraded)', async () => {
  const d = await interceptor(call('rm -rf /'))
  assert.equal(d.kind, 'deny')
  assert.match(d.reason, /fs\/rm-root/)
})

await check('non-shell tool is untouched', async () => {
  assert.equal((await interceptor({ name: 'read', arguments: { file_path: 'x' } })).kind, 'allow')
})

await check('missing command field on a shell tool fails closed', async () => {
  const d = await interceptor({ name: 'pwsh', arguments: {} })
  assert.equal(d.kind, 'deny')
  assert.match(d.reason, /缺少字符串命令字段/)
})

await check('non-string command field fails closed', async () => {
  assert.equal((await interceptor({ name: 'pwsh', arguments: { command: 42 } })).kind, 'deny')
})

await check('args.command shape is recognised', async () => {
  assert.equal((await interceptor({ name: 'pwsh', args: { command: 'git clean -fd' } })).kind, 'ask')
})

await check('top-level command shape is recognised', async () => {
  assert.equal((await interceptor({ name: 'bash', command: 'git push --force origin main' })).kind, 'ask')
})

await check('interceptor still returns allow for allow verdicts', async () => {
  assert.equal((await interceptor(call('echo hello'))).kind, 'allow')
})

await check('wrapper stripping still runs (env --global ... rm -rf /)', async () => {
  // 长选项包装 + 危险命令：上游引擎会漏判，适配层的归一化必须把它挡下来
  const d = await interceptor(call('env --global x rm -rf /'))
  assert.equal(d.kind, 'deny')
})

await check('long-form wrapper flags are normalised (sudo --user)', async () => {
  assert.equal((await interceptor(call('sudo --user root rm -rf /'))).kind, 'deny')
  assert.equal((await interceptor(call('doas --user root rm -rf /'))).kind, 'deny')
  assert.equal((await interceptor(call('nice --adjustment 5 rm -rf /'))).kind, 'deny')
  assert.equal((await interceptor(call('timeout --signal KILL 5 rm -rf /'))).kind, 'deny')
})

await check('normalisation does not invent verdicts on benign commands', async () => {
  for (const benign of [
    'sudo --user root systemctl restart nginx',
    'env --unset FOO npm run build',
    'nice --adjustment 5 make -j4',
    'timeout --signal TERM 30 pnpm test',
  ]) {
    const d = await interceptor(call(benign))
    assert.equal(d.kind, 'allow', `${benign} -> ${d.kind}`)
  }
})

await check('normalizeWrapperFlags is exported and idempotent', async () => {
  const { normalizeWrapperFlags } = await import('../plugin.js')
  const once = normalizeWrapperFlags('sudo --user root rm -rf /')
  assert.equal(once, 'sudo -u root rm -rf /')
  assert.equal(normalizeWrapperFlags(once), once)
})

await check('DEFAULT_TOOLS covers this profile shells', async () => {
  for (const t of ['bash', 'pwsh', 'pwsh_persistent', 'bash_persistent']) {
    assert.ok(DEFAULT_TOOLS.includes(t), `${t} missing`)
  }
})

assert.equal(interceptor.warnings.length, 0)
console.log(`\n${passed} checks passed`)
