import { test, expect } from "@playwright/test";
import {
  assertSelectValue,
  assertSwitchIsChecked,
  switchOn,
} from "../utils/form.ts";
import { login } from "../utils/login.ts";
import { goToIdentityProviders } from "../utils/sidebar.ts";
import { SERVER_URL } from "../utils/constants.ts";
import { fillOIDCProvider } from "./main.ts";

test.describe("OAuth 2.0 identity provider settings", () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
    await goToIdentityProviders(page);
    // the OAuth 2.0 form takes the same metadata
    await fillOIDCProvider(page, "oauth2", "123");
  });

  test("should show the pushed authorization request, request object, DPoP and issuer settings", async ({
    page,
  }) => {
    await page.getByText("Show metadata").click();
    await expect(page.getByTestId("config.issuer")).toHaveValue(
      `${SERVER_URL}/realms/master`,
    );
    // from authorization_response_iss_parameter_supported
    await assertSwitchIsChecked(
      page,
      "#config\\.authorizationResponseIssuerRequired",
    );
    await expect(page.locator("#config\\.dpopEnabled")).toBeEnabled();

    await switchOn(page, "#config\\.pushedAuthorizationRequestsEnabled");
    await expect(
      page.getByTestId("config.pushedAuthorizationRequestUrl"),
    ).toHaveValue(
      `${SERVER_URL}/realms/master/protocol/openid-connect/ext/par/request`,
    );

    await switchOn(page, "#config\\.requestObjectEnabled");
    await assertSelectValue(
      page.locator("#config\\.requestObjectSigningAlg"),
      "PS256",
    );
  });
});
