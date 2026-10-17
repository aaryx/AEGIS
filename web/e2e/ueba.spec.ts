import { test, expect } from "@playwright/test";

async function login(page: import("@playwright/test").Page, username: string) {
  await page.goto("/");
  await page.getByLabel("Username", { exact: true }).fill(username);
  await page.getByLabel("Password", { exact: true }).fill(process.env.AEGIS_E2E_PASSWORD!);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Dashboard", exact: true })).toBeVisible();
}

test("UEBA real worker produces explainable evidence and audited analyst actions", async ({ page }) => {
  test.skip(!process.env.AEGIS_UEBA_E2E, "Requires isolated UEBA history fixture and worker");
  await login(page, process.env.AEGIS_E2E_USERNAME!);
  await page.getByRole("navigation").getByRole("button", { name: "UEBA", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Behavioral risk intelligence" })).toBeVisible();
  await page.getByRole("button", { name: "Analyze previous day", exact: true }).click();
  await expect(page.getByText(/Saved: PENDING|Saved: COMPLETED/)).toBeVisible();
  await expect.poll(async () => {
    const result = await page.request.get("/api/v1/ueba/jobs");
    return (await result.json()).items[0]?.state;
  }, { timeout: 30000 }).toBe("COMPLETED");
  await page.reload();
  await page.getByLabel("Entity", { exact: true }).fill("synthetic-admin");
  await page.getByLabel("Detector", { exact: true }).selectOption("failure_then_success");
  const finding = page.locator("table").first();
  await expect(finding.locator("tbody tr")).toHaveCount(1);
  await finding.getByRole("button", { name: /^Open / }).click();
  await expect(page.getByRole("heading", { name: "Evidence references" })).toBeVisible();
  await expect(page.getByText(/does not confirm an attack/)).toBeVisible();
  await page.getByLabel("Decision reason").fill("Reviewed actual evidence in browser validation");
  for (const status of ["ACKNOWLEDGED", "SUPPRESSED", "RESOLVED"]) {
    const response = page.waitForResponse(r => r.url().endsWith("/status") && r.request().method() === "POST");
    await page.getByRole("button", { name: status, exact: true }).click();
    expect((await response).status()).toBe(200);
    await expect(page.getByRole("heading", { name: new RegExp(`failure_then_success.*${status}`) })).toBeVisible();
  }
  await page.getByRole("button", { name: "View entity profile", exact: true }).click();
  await expect(page.getByText(/"risk_history"/)).toBeVisible();
  await page.screenshot({ path: "test-results/ueba-finding.png", fullPage: true });
  const detail = await page.request.get("/api/v1/ueba/findings/" + page.url().split("/").at(-1));
  const data = await detail.json();
  expect(data.evidence.length).toBeGreaterThan(0);
  expect(data.related.storylines.length).toBeGreaterThan(0);
  await page.getByRole("button", { name: data.related.storylines[0], exact: true }).click();
  await expect(page.getByRole("heading", { name: "Behavioral findings" })).toBeVisible();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
});

test("UEBA reader permissions, foreign tenant emptiness and recoverable API failure", async ({ page }) => {
  test.skip(!process.env.AEGIS_UEBA_E2E, "Requires isolated UEBA users");
  await login(page, "ueba-viewer");
  await page.goto("/#/ueba");
  await expect(page.getByRole("heading", { name: "Behavioral risk intelligence" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Analyze previous day" })).toHaveCount(0);
  await page.route("**/api/v1/ueba/findings?*", route => route.fulfill({ status: 503, contentType: "application/json", body: JSON.stringify({ error: { message: "Validation outage" } }) }));
  await page.reload();
  await expect(page.getByText("Validation outage")).toBeVisible({ timeout: 15000 });
  await page.unroute("**/api/v1/ueba/findings?*");
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByText("Validation outage")).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: "test-results/ueba-mobile.png", fullPage: true });
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await login(page, "ueba-outsider");
  await page.goto("/#/ueba");
  await expect(page.getByText("0 behavioral profiles")).toBeVisible();
  await expect(page.getByText("No results found").first()).toBeVisible();
});
