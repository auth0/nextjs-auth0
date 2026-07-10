import { test as setup } from "@playwright/test"
import path from "path"
import { fileURLToPath } from "url"
import { loginWithAuth0 } from "./helpers"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const authFile = path.join(__dirname, ".auth/user.json")

setup("authenticate", async ({ page }) => {
  await loginWithAuth0(page, "/app-router/server")
  await page.context().storageState({ path: authFile })
})
