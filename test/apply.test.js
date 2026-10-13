// 插件接线测试：用假 ctx 驱动 apply()，验证与 harness 的契约。
// 运行: node test/apply.test.js
import assert from 'node:assert/strict'
import { apply, inject, name } from '../plugin.js'

let passed = 0
const check = (label, fn) => {
  fn()
  passed += 1
  console.log(`ok  ${label}`)
}

/** 最小假 ctx：记录事件注册，提供 logger 与可计数的 next()。 */
function fakeCtx() {
  const handlers = new Map()
  const logs = []
  const loggerFor = (ns) => ({
    info: (m) => logs.push({ level: 'info', ns, m }),
    warn: (m) => logs.push({ level: 'warn', ns, m }),
  })
  const ctx = {
    logger: (ns) => loggerFor(ns),
    on(event, handler) {
      handlers.set(event, handler)
      return () => handlers.delete(event)
    },
  }
  return { ctx, handlers, logs }
}

check('plugin exports the cordis shape', () => {
  assert.equal(name, 'barricade')
  assert.deepEqual(inject, ['tools'])
  assert.equal(typeof apply, 'function')
})

const { ctx, handlers, logs } = fakeCtx()
apply(ctx, { mode: 'ask' })
const handler = handlers.get('tools/pre-execute')
assert.ok(handler, 'tools/pre-execute listener registered')

await (async () => {
  // 放行必须继续 waterfall：next() 被调用，且其结果原样返回
  let nextCalls = 0
  const downstream = { kind: 'downstream-marker' }
  const allowed = await handler({ name: 'pwsh', arguments: { command: 'Get-ChildItem' } }, async () => {
    nextCalls += 1
    return downstream
  })
  check('allow delegates to next() and returns its result', () => {
    assert.equal(nextCalls, 1)
    assert.equal(allowed, downstream)
  })

  // ask：不得调用 next()，返回 harness 认识的 { kind: 'ask', reason }
  let askNext = 0
  const asked = await handler({ name: 'pwsh', arguments: { command: 'git reset --hard HEAD~1' } }, async () => {
    askNext += 1
    return { kind: 'allow' }
  })
  check('ask returns { kind: "ask", reason } and stops the chain', () => {
    assert.equal(askNext, 0)
    assert.equal(asked.kind, 'ask')
    assert.equal(typeof asked.reason, 'string')
    assert.ok(asked.reason.length > 0)
  })

  // deny：同上，且 reason 存在
  let denyNext = 0
  const denied = await handler({ name: 'pwsh', arguments: { command: 'rm -rf /' } }, async () => {
    denyNext += 1
    return { kind: 'allow' }
  })
  check('deny returns { kind: "deny", reason } and stops the chain', () => {
    assert.equal(denyNext, 0)
    assert.equal(denied.kind, 'deny')
    assert.match(denied.reason, /fs\/rm-root/)
  })

  check('deny is written to the profile log', () => {
    assert.ok(logs.some((l) => l.level === 'info' && l.ns === 'barricade' && /denied/.test(l.m)))
  })

  // 只返回 harness 认识的 kind 取值
  check('every returned kind is allow/ask/deny', () => {
    for (const d of [allowed, asked, denied]) {
      assert.ok(['allow', 'ask', 'deny', 'downstream-marker'].includes(d.kind))
    }
  })

  // 没有 logger 的 ctx 也不能让插件崩
  const bare = fakeCtx()
  apply(bare.ctx, { mode: 'deny' })
  const bareHandler = bare.handlers.get('tools/pre-execute')
  const r = await bareHandler({ name: 'pwsh', arguments: { command: 'git clean -fd' } }, async () => ({ kind: 'allow' }))
  check('works with an empty ctx.logger', () => {
    assert.equal(r.kind, 'deny')
  })

  console.log(`\n${passed} checks passed`)
})()
