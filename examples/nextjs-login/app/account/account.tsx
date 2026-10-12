"use client";

import { createAccount } from "@iamkit/js";
import { AccountProvider, ApiKeys, OrganizationSwitcher, UserProfile, UserSecurity, UserSessions } from "@iamkit/react";
import "@iamkit/react/widgets.css";
import { useMemo } from "react";
import { reauthenticate, selectOrganization } from "../actions";

export function Account(props: { issuer: string; environmentId: string; audience: string; organizationId: string }) {
  const account = useMemo(
    () =>
      createAccount({
        baseUrl: props.issuer,
        environmentId: props.environmentId,
        audience: props.audience,
        // Called before every request: the token of the app's session.
        getAccessToken: async () => {
          const res = await fetch("/account/token", { cache: "no-store" });
          if (!res.ok) {
            window.location.assign("/");
            throw new Error("signed out");
          }
          return res.text();
        },
      }),
    [props.issuer, props.environmentId, props.audience],
  );
  return (
    // One provider: every widget shares the client and the re-sign-in hook.
    <AccountProvider account={account} onReauthenticate={() => void reauthenticate()}>
      <nav aria-label="Account">
        <a href="/">Home</a>
      </nav>
      <p data-testid="account-organization">{props.organizationId}</p>
      <OrganizationSwitcher onSelect={(organization) => selectOrganization(organization)} />
      <UserProfile />
      <UserSecurity
        // IAMKit gives the secret and the otpauth:// URI; draw a QR code
        // with the library of your choice (none is bundled).
        renderQRCode={(uri) => <p data-testid="qr-uri">{uri}</p>}
      />
      <UserSessions />
      <ApiKeys />
    </AccountProvider>
  );
}
