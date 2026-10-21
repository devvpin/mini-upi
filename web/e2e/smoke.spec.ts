import { test, expect } from "@playwright/test";

test("login opens the wallet and payment tamper control", async ({ page }) => {
  await page.route("**/health", async (route) => route.fulfill({ status: 200, body: "ok" }));
  await page.route("**/ready", async (route) => route.fulfill({ status: 200, body: "ok" }));
  await page.route("**/api/v1/auth/login", async (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ access_token: "smoke-token" }) }),
  );
  await page.goto("/");
  await page.getByLabel("College ID").fill("22IT002");
  await page.getByLabel("Password").fill("password");
  await page.getByRole("button", { name: "Enter campus wallet" }).click();
  await expect(page.getByText("Good morning, Diya.")).toBeVisible();
  await page.getByRole("button", { name: "Pay" }).first().click();
  await page.getByLabel("Pay to VPA").fill("22it001@gcet");
  await page.getByRole("button", { name: "1" }).click();
  await page.getByRole("button", { name: "Review payment" }).click();
  await expect(page.getByLabel("Demo tamper test")).toBeVisible();
});
