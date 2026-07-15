import { test, expect, type Page } from '@playwright/test'

const TOKEN = 'e2e-token'

async function connect(page: Page) {
  await page.goto('/dashboard/')
  await page.getByTestId('token-input').fill(TOKEN)
  await page.getByTestId('connect-btn').click()
  await expect(page.getByTestId('chain-chip')).toBeVisible()
}

test('login gate rejects a bad token', async ({ page }) => {
  await page.goto('/dashboard/')
  await page.getByTestId('token-input').fill('wrong-token')
  await page.getByTestId('connect-btn').click()
  await expect(page.getByTestId('gate-error')).toContainText('Invalid admin token')
})

test('connects and shows the trace board + chain status', async ({ page }) => {
  await connect(page)
  // header: the chain chip is per-plane, so a single-ledger deployment
  // reports the local chain by name.
  await expect(page.getByTestId('chain-chip')).toContainText('local chain ok')
  await expect(page.getByTestId('role-chip')).toHaveText('admin')
  // trace board: live stream on the left, alert center in the center
  await expect(page.getByTestId('stream')).toBeVisible()
  await expect(page.getByTestId('alert-center')).toBeVisible()
  // seeded events are present
  expect(await page.getByTestId('event').count()).toBeGreaterThan(3)
})

test('alert center carries only blocked and held commands, with context', async ({ page }) => {
  await connect(page)
  const cards = page.getByTestId('alert-card')
  await expect(async () => {
    const pills = await page.locator('[data-testid="alert-card"] .pill').allInnerTexts()
    expect(pills.length).toBeGreaterThanOrEqual(3)
    expect(pills.every((p) => ['block', 'ask'].includes(p.toLowerCase()))).toBeTruthy()
  }).toPass()
  // a block names its rule; a hold with no block reason falls back to the label
  await expect(cards.filter({ hasText: 'TOOL_DENIED' })).toContainText('sess-acme-1')
  await expect(cards.filter({ hasText: 'tool:send_email' })).toContainText('held for approval')
  // an alert card opens the same receipt detail the stream does
  await cards.filter({ hasText: 'TOOL_DENIED' }).first().click()
  await expect(page.getByTestId('detail')).toContainText('tool:exec_shell')
})

test('performance board shows posture, trends, and latency percentiles', async ({ page }) => {
  await connect(page)
  await page.getByTestId('tab-performance').click()
  await expect(page.getByTestId('perf-board')).toBeVisible()
  await expect(page.getByTestId('trends-svg')).toBeVisible()
  await expect(page.getByTestId('rate-chart')).toBeVisible()
  await expect(page.getByTestId('posture')).toBeVisible()
  // seeded receipts carry latency_ms, so the percentiles resolve to real numbers
  await expect(page.getByTestId('latency-chart')).toBeVisible()
  await expect(page.getByTestId('latency-tile')).not.toContainText('n/a')
  await expect(page.getByTestId('posture')).toContainText('verified')
})

test('selecting a receipt opens detail and verifies its signature', async ({ page }) => {
  await connect(page)
  // click the tool-policy block receipt (row shows its block reason)
  await page.getByTestId('event').filter({ hasText: 'TOOL_DENIED' }).first().click()
  const detail = page.getByTestId('detail')
  await expect(detail).toContainText('TOOL_DENIED')
  await expect(detail).toContainText('tool:exec_shell')
  await expect(detail).toContainText('ASI02')
  // in-place verify
  await page.getByTestId('verify-btn').click()
  await expect(page.getByTestId('verify-result')).toContainText('Signature verified')
})

test('search filters the stream', async ({ page }) => {
  await connect(page)
  await page.getByTestId('search-input').fill('INJECTION')
  await expect(async () => {
    const count = await page.getByTestId('event').count()
    expect(count).toBeGreaterThan(0)
    expect(count).toBeLessThan(5)
  }).toPass()
  await expect(page.getByTestId('stream')).toContainText('INJECTION_BLOCKED')
})

test('verdict filter narrows to blocks only', async ({ page }) => {
  await connect(page)
  await page.getByTestId('verdict-filter').selectOption('block')
  await expect(async () => {
    const pills = await page.locator('[data-testid="event"] .pill').allInnerTexts()
    expect(pills.length).toBeGreaterThan(0)
    expect(pills.every((p) => p.toLowerCase() === 'block')).toBeTruthy()
  }).toPass()
})

test('org filter scopes to a tenant', async ({ page }) => {
  await connect(page)
  const orgFilter = page.getByTestId('org-filter')
  await expect(orgFilter).toBeVisible()  // multiple orgs seeded
  await orgFilter.selectOption('acme')
  await expect(async () => {
    const actors = await page.locator('[data-testid="event"] .actor').allInnerTexts()
    expect(actors.length).toBeGreaterThan(0)
    expect(actors.every((a) => a.startsWith('spiffe://acme/'))).toBeTruthy()
  }).toPass()
})

test('theme toggle switches to light', async ({ page }) => {
  await connect(page)
  await page.getByLabel('toggle theme').click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
})
