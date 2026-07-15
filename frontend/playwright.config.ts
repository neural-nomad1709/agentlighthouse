import { defineConfig, devices } from '@playwright/test'

// e2e against the BUILT dashboard served by the control plane (real artifact).
// The webServer seeds evidence + serves /dashboard/ and /api on :8899.
export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  expect: { timeout: 7_000 },
  fullyParallel: false,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:8899',
    trace: 'off',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'uv run python frontend/e2e/serve.py',
    cwd: '..',
    url: 'http://127.0.0.1:8899/healthz',
    reuseExistingServer: true,
    timeout: 60_000,
  },
})
