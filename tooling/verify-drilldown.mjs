// Visual verification of the on-host attack path drill-down.
//
// Must be run from inside the CompromiseCanvas checkout (it imports
// @playwright/test, so bare-specifier resolution needs that node_modules):
//   cp tools/verify-drilldown.mjs /path/to/CompromiseCanvas/.verify.mjs
//   cd /path/to/CompromiseCanvas && node .verify.mjs <path-to-canvas.json>
//
// Expects the app already serving on :3010 (`next start -p 3010`).
// Writes screenshots to ./shots/ and prints any console errors.
import { chromium } from "@playwright/test"
import { mkdirSync } from "node:fs"
import { resolve } from "node:path"

const jsonPath = resolve(process.argv[2] ?? "/opt/lab-docs/compromise-canvas/sample-c-host.json")
const shots = resolve("shots")
mkdirSync(shots, { recursive: true })

const browser = await chromium.launch()
const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } })

const problems = []
page.on("console", (m) => {
  if (m.type() === "error") problems.push(`console: ${m.text()}`)
})
page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`))

await page.goto("http://localhost:3010/", { waitUntil: "networkidle", timeout: 120_000 })

// The app may open with a welcome / template dialog — close anything modal.
for (const label of ["Start from scratch", "Close", "Skip"]) {
  const b = page.getByRole("button", { name: label, exact: false }).first()
  if (await b.count() && await b.isVisible().catch(() => false)) {
    await b.click().catch(() => {})
    await page.waitForTimeout(400)
    break
  }
}
await page.keyboard.press("Escape").catch(() => {})
await page.waitForTimeout(500)

// Import the generated JSON: the handler creates an <input type=file> on the fly.
const chooser = page.waitForEvent("filechooser", { timeout: 30_000 })
await page.getByRole("button", { name: "Import JSON file" }).click()
await (await chooser).setFiles(jsonPath)
await page.waitForTimeout(2500)
await page.screenshot({ path: `${shots}/1-canvas.png`, fullPage: false })

// Find the host node and drill into it.
const host = page.locator(".react-flow__node").filter({ hasText: "secdis" }).first()
const found = await host.count()
console.log("host node found on canvas:", found > 0)
if (found) {
  await host.scrollIntoViewIfNeeded().catch(() => {})
  await host.dblclick()
  await page.waitForTimeout(2000)
}

const dialog = page.getByRole("dialog")
const open = await dialog.count() && await dialog.first().isVisible().catch(() => false)
console.log("drill-down dialog open:", open)
await page.screenshot({ path: `${shots}/2-drilldown.png` })

if (open) {
  const title = (await dialog.first().innerText().catch(() => "")).split("\n").slice(0, 4).join(" | ")
  console.log("dialog header:", title)
  const steps = await page.locator(".react-flow__node").count()
  console.log("nodes rendered inside dialog view:", steps)
}

console.log(problems.length ? "\nPROBLEMS:\n" + problems.join("\n") : "\nno console/page errors")
await browser.close()
