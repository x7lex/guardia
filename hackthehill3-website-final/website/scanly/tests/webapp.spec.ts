import { test, expect } from "@playwright/test"
import { execFileSync } from "node:child_process"
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { fileURLToPath } from "node:url"

const root = fileURLToPath(new URL("../../../../", import.meta.url))
const executable = execFileSync(join(root, ".venv/bin/python"), ["-c",
    "import runpy,sys; sys.stdout.buffer.write(runpy.run_path('tests/test_api.py')['minimal_pe']())"], { cwd: root })
const upload = { name: "demo.exe", mimeType: "application/octet-stream", buffer: executable }

test("real upload, report details, persistence, and reselect on rescan", async ({ page }) => {
    const errors: string[] = []
    page.on("pageerror", error => errors.push(error.message))
    await page.goto("/")
    await page.getByLabel("Choose files", { exact: true }).setInputFiles([upload, {
        name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("not a PE"),
    }])
    await page.getByRole("button", { name: "Scan All (1)" }).click()
    await expect(page.getByText("1 files skipped — show details")).toBeVisible()
    await expect(page.getByText("demo.exe", { exact: true })).toBeVisible()
    await page.getByText("demo.exe", { exact: true }).click()
    await expect(page.getByRole("dialog", { name: "Report for demo.exe" })).toBeVisible()
    await expect(page.getByText("/10 triage score", { exact: false })).toBeVisible()
    await expect(page.getByText("Static capabilities are not observed behavior", { exact: false })).toBeVisible()
    await page.getByRole("button", { name: "Close report" }).click()
    await page.getByRole("button", { name: "Home", exact: true }).click()
    await page.reload()
    await page.getByRole("button", { name: /^Open scan of Selected files/ }).click()
    await expect(page.getByText("demo.exe", { exact: true })).toBeVisible()
    await page.getByRole("button", { name: "↻ Rescan" }).click()
    await expect(page.getByRole("alert").filter({ hasText: "Choose these files again" })).toBeVisible()
    expect(errors).toEqual([])
})

test("folder uploads preserve nested paths and duplicate basenames", async ({ page }) => {
    const directory = mkdtempSync(join(tmpdir(), "guardia-browser-"))
    try {
        mkdirSync(join(directory, "nested"))
        writeFileSync(join(directory, "demo.exe"), executable)
        writeFileSync(join(directory, "nested/demo.exe"), executable)
        await page.goto("/")
        await page.getByLabel("Choose folder", { exact: true }).setInputFiles(directory)
        await page.getByRole("button", { name: "Scan All (1)" }).click()
        await expect(page.getByText("demo.exe", { exact: true })).toHaveCount(2)
        await page.getByRole("button", { name: "Expand filters sidebar" }).click()
        await expect(page.getByLabel("Scan summary", { exact: true })).toContainText("2 files")
        await page.getByLabel("Search files").fill("nested/")
        await expect(page.getByText("demo.exe", { exact: true })).toHaveCount(1)
    } finally {
        rmSync(directory, { recursive: true, force: true })
    }
})

test("unsupported uploads finish with an explicit empty result", async ({ page }) => {
    await page.goto("/")
    await page.getByLabel("Choose files", { exact: true }).setInputFiles({ name: "empty.txt", mimeType: "text/plain", buffer: Buffer.alloc(0) })
    await page.getByRole("button", { name: "Scan All (1)" }).click()
    await expect(page.getByText("No supported PE files were reported.", { exact: false })).toBeVisible()
    await page.getByText("1 files skipped — show details").click()
    await expect(page.getByText("empty.txt: File is empty")).toBeVisible()
})

test("connection failures are actionable and leave the selection available", async ({ page }) => {
    await page.route("**/api/scan?*", route => route.fulfill({ status: 502, json: { detail: "Scanner unavailable. Start the Python backend and try again." } }))
    await page.goto("/")
    await page.getByLabel("Choose files", { exact: true }).setInputFiles(upload)
    await page.getByRole("button", { name: "Scan All (1)" }).click()
    await expect(page.getByRole("alert").filter({ hasText: "Scanner unavailable" })).toBeVisible()
    await expect(page.getByRole("button", { name: "Scan All (1)" })).toBeEnabled()
})

test("cancel stops the queue and ignores late responses", async ({ page }) => {
    let release: () => void = () => {}
    const pending = new Promise<void>(resolve => { release = resolve })
    let requests = 0
    await page.route("**/api/scan?*", async route => {
        requests++
        await pending
        await route.fulfill({ json: { status: "skipped", file: "demo.exe", reason: "Test response" } }).catch(() => {})
    })
    await page.goto("/")
    await page.getByLabel("Choose files", { exact: true }).setInputFiles([upload, { ...upload, name: "second.exe" }])
    await page.getByRole("button", { name: "Scan All (1)" }).click()
    await expect.poll(() => requests).toBe(1)
    await page.getByRole("button", { name: "Cancel scan" }).click()
    release()
    await expect(page.getByRole("button", { name: "Scan All (1)" })).toBeEnabled()
    await expect(page.getByText("No scans yet.", { exact: false })).toBeVisible()
    expect(requests).toBe(1)
})

test("Gemini review sends report JSON, displays response, and reuses it when reopened", async ({ page }) => {
    let calls = 0
    await page.route("**/api/review", async route => {
        const report = route.request().postDataJSON()
        expect(report.analysis.file.file_name).toBe("demo.exe")
        expect(report.risk_assessment.risk).toHaveProperty("points")
        expect(report).not.toHaveProperty("API_TOKEN")
        calls++
        await route.fulfill({ json: { model: "gemini-3.8-flash", review: "Assessment\nCoverage is limited.\nKey evidence\nNo import table was available." } })
    })
    await page.goto("/")
    await page.getByLabel("Choose files", { exact: true }).setInputFiles(upload)
    await page.getByRole("button", { name: "Scan All (1)" }).click()
    await page.getByText("demo.exe", { exact: true }).click()
    await page.getByRole("button", { name: "✦ Review with Gemini" }).click()
    await expect(page.getByText("No import table was available.", { exact: false })).toBeVisible()
    await page.getByRole("button", { name: "Hide Gemini review" }).click()
    await page.getByRole("button", { name: "Open Gemini review" }).click()
    await expect(page.getByText("No import table was available.", { exact: false })).toBeVisible()
    expect(calls).toBe(1)
    const icon = page.locator('link[rel="icon"][type="image/svg+xml"]')
    await expect(icon).toHaveAttribute("href", /icon\.svg/)
    expect(await page.locator('link[rel="icon"][href="/favicon.ico"]').count()).toBe(0)
})

test("Gemini quota errors offer retry without losing the scan", async ({ page }) => {
    await page.route("**/api/review", route => route.fulfill({ status: 429, json: { detail: "Gemini's rate limit or quota was reached." } }))
    await page.goto("/")
    await page.getByLabel("Choose files", { exact: true }).setInputFiles(upload)
    await page.getByRole("button", { name: "Scan All (1)" }).click()
    await page.getByText("demo.exe", { exact: true }).click()
    await page.getByRole("button", { name: "✦ Review with Gemini" }).click()
    await expect(page.getByRole("alert").filter({ hasText: "quota was reached" })).toBeVisible()
    await expect(page.getByRole("button", { name: "Retry review" })).toBeEnabled()
    await expect(page.getByRole("dialog", { name: "Report for demo.exe" })).toBeVisible()
})


test("Gemini depleted-credit errors link to billing", async ({ page }) => {
    await page.route("**/api/review", route => route.fulfill({ status: 402, json: { detail: "Gemini prepaid credits are depleted. Add credits in Google AI Studio, then retry." } }))
    await page.goto("/")
    await page.getByLabel("Choose files", { exact: true }).setInputFiles(upload)
    await page.getByRole("button", { name: "Scan All (1)" }).click()
    await page.getByText("demo.exe", { exact: true }).click()
    await page.getByRole("button", { name: "✦ Review with Gemini" }).click()
    await expect(page.getByRole("alert").filter({ hasText: "credits are depleted" })).toBeVisible()
    await expect(page.getByRole("link", { name: "Manage Gemini billing" })).toHaveAttribute("href", "https://ai.studio/projects")
})

test("opaque files show an inconclusive verdict and separate visibility from threat", async ({ page }, testInfo) => {
    const packed = Buffer.from(executable)
    packed.write("UPX1\0\0\0\0", 0x178, "binary")
    for (let index = 512; index < 1024; index++) packed[index] = index % 256
    await page.goto("/")
    await page.getByLabel("Choose files", { exact: true }).setInputFiles({ name: "ordinary.exe", mimeType: "application/octet-stream", buffer: packed })
    await page.getByRole("button", { name: "Scan All (1)" }).click()
    await expect(page.getByText("INCONCLUSIVE", { exact: true })).toBeVisible()
    await page.getByText("ordinary.exe", { exact: true }).click()
    const dialog = page.getByRole("dialog", { name: "Report for ordinary.exe" })
    await expect(dialog.getByText("SEVERELY LIMITED", { exact: true })).toBeVisible()
    await expect(dialog.getByText("Threat evidence", { exact: true })).toBeVisible()
    await expect(dialog.getByText("0/10", { exact: true })).toBeVisible()
    await expect(dialog.getByText("Visibility review floor", { exact: true })).toBeVisible()
    await expect(dialog.getByText("Publisher verified", { exact: true })).toBeVisible()
    await page.screenshot({ path: testInfo.outputPath("visibility-report.png") })
    await page.getByRole("button", { name: "Close report" }).click()
    await page.getByRole("button", { name: "Expand filters sidebar" }).click()
    await page.getByLabel("Filter by risk").selectOption("safe")
    await expect(page.getByText("No files match these filters.")).toBeVisible()
    await page.getByLabel("Filter by risk").selectOption("review")
    await expect(page.getByText("ordinary.exe", { exact: true })).toBeVisible()
})
