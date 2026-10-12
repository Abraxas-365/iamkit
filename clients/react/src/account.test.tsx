// @vitest-environment jsdom
import { createAccount, type Account } from "@iamkit/js";
import { act, cleanup, fireEvent, render, renderHook, screen, waitFor, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  AccountProvider,
  ApiKeys,
  OrganizationSwitcher,
  UserProfile,
  UserSecurity,
  UserSessions,
  useAccount,
  useApiKeys,
  useFactors,
  useOrganizations,
  useSessions,
} from "./index";
import { json } from "./testing";

afterEach(cleanup);

type Handler = (body: any, url: URL) => Response;

function setup(routes: Record<string, Handler>) {
  const calls: { route: string; body: any; auth: string | null }[] = [];
  const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const route = `${init?.method ?? "GET"} ${url.pathname}`;
    const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
    calls.push({ route, body, auth: new Headers(init?.headers).get("Authorization") });
    const handler = routes[route];
    return handler ? handler(body, url) : json(404, { error: { code: "NOT_FOUND", message: route } });
  }) as typeof fetch;
  const account = createAccount({ baseUrl: "https://id.example.com", environmentId: "env", audience: "api", getAccessToken: () => "at", fetch: fetcher });
  return { account, calls, count: (route: string) => calls.filter((c) => c.route === route).length };
}

const reauth = (extra: Record<string, unknown> = {}) => json(403, { error: { code: "REAUTHENTICATION_REQUIRED", message: "sign in again", details: extra } });
const none = () => new Response(null, { status: 204 });

const profile = {
  id: "u1",
  name: "Ada",
  email: "ada@example.com",
  email_verified: true,
  username: "ada",
  avatar_url: "",
  phone: "",
  phone_verified: false,
  organization_id: "org1",
};

const wrap = (account: Account, onReauthenticate?: () => void) => ({ children }: { children: ReactNode }) => (
  <AccountProvider account={account} onReauthenticate={onReauthenticate}>
    {children}
  </AccountProvider>
);

describe("UserProfile", () => {
  const routes = (): Record<string, Handler> => ({
    "GET /identity/v1/me": () => json(200, profile),
    "GET /identity/v1/me/profile": () => json(200, { profile: { company: "Acme", seats: 3 } }),
    "PATCH /identity/v1/me": () => none(),
    "PATCH /identity/v1/me/profile": (b) => json(200, { profile: b.profile }),
  });

  it("shows name, read-only username and saves name and avatar", async () => {
    const f = setup(routes());
    render(<UserProfile account={f.account} classNames={{ button: "btn" }} />);
    const name = (await screen.findByLabelText("Name")) as HTMLInputElement;
    expect(name.value).toBe("Ada");
    expect((screen.getByLabelText("Username") as HTMLInputElement).readOnly).toBe(true);
    fireEvent.change(name, { target: { value: "Ada L" } });
    fireEvent.change(screen.getByLabelText("Avatar URL"), { target: { value: "https://img.example.com/a.png" } });
    await act(async () => {
      fireEvent.click(screen.getAllByRole("button", { name: "Save" })[0]!);
    });
    expect(f.calls.find((c) => c.route === "PATCH /identity/v1/me")?.body).toMatchObject({ name: "Ada L", avatar_url: "https://img.example.com/a.png", environment_id: "env", audience: "api" });
    expect((await screen.findByRole("status")).textContent).toBe("Profile saved.");
    expect(screen.getAllByRole("button", { name: "Save" })[0]!.className).toBe("btn");
  });

  it("edits custom properties inferred from the profile or listed in `fields`", async () => {
    const f = setup(routes());
    render(<UserProfile account={f.account} fields={[{ name: "company" }, { name: "seats", type: "number" }, { name: "beta", type: "boolean", label: "Beta" }]} />);
    const company = (await screen.findByLabelText("company")) as HTMLInputElement;
    expect(company.value).toBe("Acme");
    fireEvent.change(company, { target: { value: "Globex" } });
    fireEvent.click(screen.getByLabelText("Beta"));
    await act(async () => {
      fireEvent.click(screen.getAllByRole("button", { name: "Save" })[1]!);
    });
    expect(f.calls.find((c) => c.route === "PATCH /identity/v1/me/profile")?.body.profile).toEqual({ company: "Globex", seats: 3, beta: true });
  });

  it("verifies a phone number: send a code, then verify", async () => {
    const f = setup({
      ...routes(),
      "POST /identity/v1/me/phone": () => json(200, { destination: "+1•••99", expires_at: "2030-01-01T00:00:00Z" }),
      "POST /identity/v1/me/phone/verify": () => none(),
    });
    render(<UserProfile account={f.account} />);
    fireEvent.change(await screen.findByLabelText("Phone number (with country code)"), { target: { value: "+15550199" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Send code" }));
    });
    expect(await screen.findByText("We sent a code to +1•••99.")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Code"), { target: { value: "123456" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Verify phone" }));
    });
    expect(f.calls.find((c) => c.route === "POST /identity/v1/me/phone/verify")?.body).toMatchObject({ phone: "+15550199", code: "123456" });
    expect(await screen.findByText("Phone verified.")).toBeTruthy();
  });

  it("calls onReauthenticate when the phone change needs a recent sign-in", async () => {
    const onReauthenticate = vi.fn();
    const f = setup({ ...routes(), "POST /identity/v1/me/phone": () => reauth() });
    render(<UserProfile account={f.account} onReauthenticate={onReauthenticate} />);
    fireEvent.change(await screen.findByLabelText("Phone number (with country code)"), { target: { value: "+15550199" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Send code" }));
    });
    expect(onReauthenticate).toHaveBeenCalledTimes(1);
    expect((await screen.findByRole("alert")).textContent).toContain("sign in again");
  });
});

describe("UserSecurity", () => {
  const factors = (list: unknown[] = []) => ({ factors: list, recovery_codes_remaining: list.length ? 8 : 0 });

  it("changes the password and reports the ended sessions", async () => {
    const f = setup({
      "GET /identity/v1/me/factors": () => json(200, factors()),
      "POST /identity/v1/me/password": () => json(200, { sessions_revoked: 2 }),
    });
    render(<UserSecurity account={f.account} sections={["password"]} />);
    fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "old" } });
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "new-secret-1" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Change password" }));
    });
    expect(f.calls.find((c) => c.route === "POST /identity/v1/me/password")?.body).toMatchObject({ current_password: "old", new_password: "new-secret-1" });
    expect((await screen.findByRole("status")).textContent).toBe("Password changed. 2 other sessions were signed out.");
  });

  it("shows a refused password in an alert and asks to sign in again on reauthentication", async () => {
    const onReauthenticate = vi.fn();
    let first = true;
    const f = setup({
      "POST /identity/v1/me/password": () => {
        if (first) {
          first = false;
          return json(422, { error: { code: "INVALID_CURRENT_PASSWORD", message: "current password is wrong" } });
        }
        return reauth();
      },
    });
    render(<UserSecurity account={f.account} sections={["password"]} onReauthenticate={onReauthenticate} />);
    const submit = async () => {
      fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "x" } });
      fireEvent.change(screen.getByLabelText("New password"), { target: { value: "y" } });
      await act(async () => {
        fireEvent.click(screen.getByRole("button", { name: "Change password" }));
      });
    };
    await submit();
    expect((await screen.findByRole("alert")).textContent).toBe("current password is wrong");
    expect(onReauthenticate).not.toHaveBeenCalled();
    await submit();
    await waitFor(() => expect(onReauthenticate).toHaveBeenCalledTimes(1));
  });

  it("enrolls an authenticator: secret and URI shown, renderQRCode used, recovery codes shown once", async () => {
    let enrolled = false;
    const f = setup({
      "GET /identity/v1/me/factors": () => json(200, factors(enrolled ? [{ id: "f1", kind: "totp", created_at: "2030-01-01T00:00:00Z", confirmed_at: "2030-01-01T00:00:00Z", last_used_at: null }] : [])),
      "POST /identity/v1/me/factors/totp": () => json(200, { factor_id: "f1", otpauth_uri: "otpauth://totp/x?secret=ABC", secret: "ABCDEF" }),
      "POST /identity/v1/me/factors/totp/confirm": () => {
        enrolled = true;
        return json(200, { recovery_codes: ["aaaa-bbbb", "cccc-dddd"] });
      },
    });
    render(<UserSecurity account={f.account} renderQRCode={(uri) => <svg data-testid="qr" data-uri={uri} />} />);
    const target = await screen.findByRole("button", { name: "Set up an authenticator app" });
    await act(async () => {
      fireEvent.click(target);
    });
    expect((await screen.findByTestId("totp-secret")).textContent).toBe("ABCDEF");
    expect(screen.getByTestId("otpauth").getAttribute("href")).toBe("otpauth://totp/x?secret=ABC");
    expect(screen.getByTestId("qr").getAttribute("data-uri")).toBe("otpauth://totp/x?secret=ABC");
    fireEvent.change(screen.getByLabelText("Enter the 6-digit code to finish."), { target: { value: "123456" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    });
    expect(await screen.findByText("aaaa-bbbb")).toBeTruthy();
    expect(await screen.findByText("Authenticator app")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "I saved my codes" }));
    expect(screen.queryByText("aaaa-bbbb")).toBeNull();
  });

  it("removes a factor with a proof code; a stale sign-in calls onReauthenticate", async () => {
    const onReauthenticate = vi.fn();
    let status = 204;
    const f = setup({
      "GET /identity/v1/me/factors": () => json(200, factors([{ id: "f1", kind: "email", created_at: "2030-01-01T00:00:00Z", confirmed_at: "2030-01-01T00:00:00Z", last_used_at: null }])),
      "DELETE /identity/v1/me/factors/email": () => (status === 204 ? none() : reauth()),
    });
    render(<UserSecurity account={f.account} onReauthenticate={onReauthenticate} sections={["factors"]} />);
    fireEvent.click(await screen.findByRole("button", { name: "Remove: Email codes" }));
    fireEvent.change(screen.getByLabelText("Code or recovery code"), { target: { value: "000111" } });
    status = 403;
    await act(async () => {
      fireEvent.click(screen.getAllByRole("button", { name: "Remove" })[0]!);
    });
    expect(onReauthenticate).toHaveBeenCalledTimes(1);
    status = 204;
    await act(async () => {
      fireEvent.click(screen.getAllByRole("button", { name: "Remove" })[0]!);
    });
    expect(f.calls.filter((c) => c.route === "DELETE /identity/v1/me/factors/email").pop()?.body).toMatchObject({ code: "000111" });
    expect(await screen.findByText("Second factor removed.")).toBeTruthy();
  });

  it("adds an SMS factor in two steps", async () => {
    const f = setup({
      "GET /identity/v1/me/factors": () => json(200, factors()),
      "POST /identity/v1/me/factors/sms": () => json(200, { destination: "+1•••99", expires_at: "x", factor: "sms" }),
      "POST /identity/v1/me/factors/sms/confirm": () => json(200, { recovery_codes: [] }),
    });
    render(<UserSecurity account={f.account} sections={["factors"]} />);
    fireEvent.click(await screen.findByRole("button", { name: "Add text message codes" }));
    fireEvent.change(screen.getByLabelText("Phone number (with country code)"), { target: { value: "+15550199" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Send code" }));
    });
    expect(f.calls.find((c) => c.route === "POST /identity/v1/me/factors/sms")?.body).toMatchObject({ phone: "+15550199" });
    fireEvent.change(await screen.findByLabelText("Code"), { target: { value: "654321" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    });
    expect(await screen.findByText("Second factor added.")).toBeTruthy();
  });

  it("lists passkeys and security keys and regenerates recovery codes with a proof", async () => {
    const f = setup({
      "GET /identity/v1/me/factors": () =>
        json(200, factors([{ id: "k1", kind: "webauthn", name: "YubiKey", passkey: false, created_at: "2030-01-01T00:00:00Z", confirmed_at: "2030-01-01T00:00:00Z", last_used_at: null }])),
      "POST /identity/v1/me/factors/recovery-codes": () => json(200, { recovery_codes: ["new1-code"] }),
    });
    render(<UserSecurity account={f.account} sections={["passkeys", "recovery"]} />);
    expect(await screen.findByText("YubiKey")).toBeTruthy();
    expect(screen.getByText("8 recovery codes left.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Generate new codes" }));
    fireEvent.change(screen.getByLabelText("Code or recovery code"), { target: { value: "123456" } });
    await act(async () => {
      fireEvent.click(screen.getAllByRole("button", { name: "Generate new codes" })[0]!);
    });
    expect(await screen.findByText("new1-code")).toBeTruthy();
  });

  it("explains when WebAuthn is not available in the browser", async () => {
    const f = setup({ "GET /identity/v1/me/factors": () => json(200, factors()), "POST /identity/v1/me/factors/webauthn": () => json(200, { webauthn_session: "s", options: {}, expires_at: "x" }) });
    render(<UserSecurity account={f.account} sections={["passkeys"]} />);
    const target = await screen.findByRole("button", { name: "Add a passkey" });
    await act(async () => {
      fireEvent.click(target);
    });
    expect((await screen.findByRole("alert")).textContent).toContain("WebAuthn is not available");
  });
});

describe("UserSessions", () => {
  const sessions = {
    items: [
      { id: "s1", current: true, user_agent: "Firefox", ip_address: "1.1.1.1", authenticated_at: "2030-01-01T00:00:00Z", organization: { id: "org1", name: "Acme" }, application: { id: "a", name: "App" } },
      { id: "s2", current: false, user_agent: "Safari", ip_address: "2.2.2.2", authenticated_at: "2030-01-01T00:00:00Z", organization: { id: "org1", name: "Acme" }, application: { id: "a", name: "App" } },
    ],
    page: { limit: 20, offset: 0, total: 2 },
  };

  it("marks the current session, revokes one and revokes the others", async () => {
    const f = setup({
      "GET /identity/v1/me/sessions": () => json(200, sessions),
      "DELETE /identity/v1/me/sessions/s2": () => none(),
      "POST /identity/v1/me/sessions/revoke-others": () => json(200, { count: 1 }),
    });
    render(<UserSessions account={f.account} />);
    const current = (await screen.findByText("Firefox")).closest("li")!;
    expect(current.getAttribute("data-current")).toBe("true");
    expect(within(current).getByText("This session")).toBeTruthy();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Sign out: Safari" }));
    });
    expect(f.count("DELETE /identity/v1/me/sessions/s2")).toBe(1);
    expect(f.count("GET /identity/v1/me/sessions")).toBe(2);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Sign out of all other sessions" }));
    });
    expect(await screen.findByText("1 other sessions were signed out.")).toBeTruthy();
  });

  it("is empty and quiet without a provider failing: an error shows as an alert", async () => {
    const f = setup({ "GET /identity/v1/me/sessions": () => json(500, { error: { code: "INTERNAL", message: "boom" } }) });
    render(<UserSessions account={f.account} />);
    expect((await screen.findByRole("alert")).textContent).toBe("boom");
  });
});

describe("ApiKeys", () => {
  const options = { enabled: true, max_ttl_days: 90, resources: [{ id: "res1", name: "Invoices API", audience: "api", permissions: ["invoices:read", "invoices:write"] }] };
  const key = { id: "k1", name: "ci", state: "active", obfuscated_value: "ik_key_••••abcd", permissions: ["invoices:read"], resource_name: "Invoices API", expires: false, expires_at: "", last_used_at: null, revoked_at: null };

  it("creates a key with permissions and expiry, shows the value once with copy, then revokes", async () => {
    const copy = vi.fn();
    let created = false;
    const f = setup({
      "GET /identity/v1/me/api-keys/options": () => json(200, options),
      "GET /identity/v1/me/api-keys": () => json(200, { items: created ? [key] : [], page: { limit: 20, offset: 0, total: 0 } }),
      "POST /identity/v1/me/api-keys": () => {
        created = true;
        return json(201, { ...key, value: "ik_key_secretvalue" });
      },
      "DELETE /identity/v1/me/api-keys/k1": () => none(),
    });
    render(<ApiKeys account={f.account} copy={copy} />);
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "ci" } });
    fireEvent.click(screen.getByLabelText("invoices:read"));
    // The policy caps the lifetime at 90 days.
    expect(screen.queryByText("Expires in 365 days")).toBeNull();
    fireEvent.change(screen.getByLabelText("Expires"), { target: { value: "30" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Create key" }));
    });
    expect(f.calls.find((c) => c.route === "POST /identity/v1/me/api-keys")?.body).toEqual({ name: "ci", resource_id: "res1", permissions: ["invoices:read"], expires_in: "720h" });
    expect((await screen.findByTestId("api-key-value")).textContent).toBe("ik_key_secretvalue");
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Copy" }));
    });
    expect(copy).toHaveBeenCalledWith("ik_key_secretvalue");
    expect(await screen.findByRole("button", { name: "Copied" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(screen.queryByTestId("api-key-value")).toBeNull();
    const target = await screen.findByRole("button", { name: "Revoke: ci" });
    await act(async () => {
      fireEvent.click(target);
    });
    expect(f.count("DELETE /identity/v1/me/api-keys/k1")).toBe(1);
  });

  it("needs a permission, and asks to sign in again when creation is stale", async () => {
    const onReauthenticate = vi.fn();
    const f = setup({
      "GET /identity/v1/me/api-keys/options": () => json(200, { ...options, max_ttl_days: null }),
      "GET /identity/v1/me/api-keys": () => json(200, { items: [], page: { limit: 20, offset: 0, total: 0 } }),
      "POST /identity/v1/me/api-keys": () => reauth(),
    });
    render(<ApiKeys account={f.account} onReauthenticate={onReauthenticate} />);
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "ci" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Create key" }));
    });
    expect((await screen.findByRole("alert")).textContent).toBe("Choose at least one permission.");
    expect(f.count("POST /identity/v1/me/api-keys")).toBe(0);
    fireEvent.click(screen.getByLabelText("invoices:write"));
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Create key" }));
    });
    expect(onReauthenticate).toHaveBeenCalledTimes(1);
  });

  it("says so when the environment does not enable user API keys", async () => {
    const f = setup({ "GET /identity/v1/me/api-keys/options": () => json(200, { enabled: false, max_ttl_days: null, resources: [] }) });
    render(<ApiKeys account={f.account} />);
    expect(await screen.findByText("API keys are not enabled.")).toBeTruthy();
    expect(f.count("GET /identity/v1/me/api-keys")).toBe(0);
  });
});

describe("OrganizationSwitcher", () => {
  const orgs = [
    { id: "org1", name: "Acme" },
    { id: "org2", name: "Globex" },
  ];
  const tokens = { access_token: "at2", refresh_token: "rt2", token_type: "Bearer", expires_in: 300 };

  it("marks the current organization and switches, handing over the new tokens", async () => {
    const f = setup({
      "GET /identity/v1/organizations": () => json(200, orgs),
      "GET /identity/v1/me": () => json(200, profile),
      "POST /identity/v1/refresh": () => json(200, tokens),
    });
    const onSwitched = vi.fn();
    const boundary = { environmentId: "env", organizationId: "org1", applicationId: "app", resourceId: "res" };
    render(<OrganizationSwitcher account={f.account} getRefreshToken={() => "rt"} boundary={boundary} onSwitched={onSwitched} />);
    const current = (await screen.findByText("Acme")).closest("li")!;
    expect(current.getAttribute("data-current")).toBe("true");
    expect(within(current).queryByRole("button")).toBeNull();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Switch to Globex" }));
    });
    const body = f.calls.find((c) => c.route === "POST /identity/v1/refresh")?.body;
    expect(body).toMatchObject({ refresh_token: "rt", switch_organization_id: "org2", organization_id: "org1", environment_id: "env" });
    expect(onSwitched).toHaveBeenCalledWith(tokens, "org2");
  });

  it("hands a refused switch to onSignInRequired instead of failing", async () => {
    const f = setup({
      "GET /identity/v1/organizations": () => json(200, orgs),
      "GET /identity/v1/me": () => json(200, profile),
      "POST /identity/v1/refresh": () => reauth({ organization_id: "org2", reason: "sso" }),
    });
    const onSignInRequired = vi.fn();
    const onReauthenticate = vi.fn();
    const onSwitched = vi.fn();
    render(
      <OrganizationSwitcher
        account={f.account}
        getRefreshToken={() => "rt"}
        boundary={{ environmentId: "env", organizationId: "org1", applicationId: "app", resourceId: "res" }}
        onSwitched={onSwitched}
        onSignInRequired={onSignInRequired}
        onReauthenticate={onReauthenticate}
      />,
    );
    const target = await screen.findByRole("button", { name: "Switch to Globex" });
    await act(async () => {
      fireEvent.click(target);
    });
    expect(onSignInRequired).toHaveBeenCalledWith({ organizationId: "org2", reason: "sso" });
    expect(onReauthenticate).not.toHaveBeenCalled();
    expect(onSwitched).not.toHaveBeenCalled();
    expect((await screen.findByRole("status")).textContent).toBe("Globex requires single sign-on. Sign in again to continue.");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("hands the choice to onSelect for OAuth sessions, which cannot switch in place", async () => {
    const f = setup({ "GET /identity/v1/organizations": () => json(200, orgs), "GET /identity/v1/me": () => json(200, profile) });
    const onSelect = vi.fn();
    render(<OrganizationSwitcher account={f.account} onSelect={onSelect} />);
    const target = await screen.findByRole("button", { name: "Switch to Globex" });
    await act(async () => {
      fireEvent.click(target);
    });
    expect(onSelect).toHaveBeenCalledWith("org2");
    expect(f.count("POST /identity/v1/refresh")).toBe(0);
  });

  it("falls back to onReauthenticate when no onSignInRequired is given", async () => {
    const f = setup({
      "GET /identity/v1/organizations": () => json(200, orgs),
      "GET /identity/v1/me": () => json(200, profile),
      "POST /identity/v1/refresh": () => reauth({ organization_id: "org2", reason: "mfa" }),
    });
    const onReauthenticate = vi.fn();
    render(
      <OrganizationSwitcher account={f.account} onReauthenticate={onReauthenticate} getRefreshToken={() => "rt"} boundary={{ environmentId: "env", organizationId: "org1", applicationId: "app", resourceId: "res" }} />,
    );
    const target = await screen.findByRole("button", { name: "Switch to Globex" });
    await act(async () => {
      fireEvent.click(target);
    });
    expect(onReauthenticate).toHaveBeenCalledTimes(1);
  });
});

describe("hooks", () => {
  it("useAccount loads the profile and properties, and refreshes after a change", async () => {
    let name = "Ada";
    const f = setup({
      "GET /identity/v1/me": () => json(200, { ...profile, name }),
      "GET /identity/v1/me/profile": () => json(200, { profile: { company: "Acme" } }),
      "PATCH /identity/v1/me": (b) => {
        name = b.name;
        return none();
      },
    });
    const { result } = renderHook(() => useAccount(), { wrapper: wrap(f.account) });
    await waitFor(() => expect(result.current.profile?.name).toBe("Ada"));
    expect(result.current.properties).toEqual({ company: "Acme" });
    let ok = false;
    await act(async () => {
      ok = await result.current.updateProfile({ name: "Grace" });
    });
    expect(ok).toBe(true);
    await waitFor(() => expect(result.current.profile?.name).toBe("Grace"));
  });

  it("useAccount reports a failing change and calls onReauthenticate", async () => {
    const onReauth = vi.fn();
    const f = setup({ "GET /identity/v1/me": () => json(200, profile), "GET /identity/v1/me/profile": () => json(200, { profile: null }), "POST /identity/v1/me/password": () => reauth() });
    const { result } = renderHook(() => useAccount(), { wrapper: wrap(f.account, onReauth) });
    await waitFor(() => expect(result.current.profile).toBeTruthy());
    await act(async () => {
      expect(await result.current.changePassword("a", "b")).toBeUndefined();
    });
    expect(onReauth).toHaveBeenCalledTimes(1);
    expect(result.current.error).toBeTruthy();
    act(() => result.current.clearError());
    expect(result.current.error).toBeUndefined();
  });

  it("useSessions lists and revokes", async () => {
    const f = setup({
      "GET /identity/v1/me/sessions": () => json(200, { items: [{ id: "s1", current: true }], page: { limit: 20, offset: 0, total: 1 } }),
      "DELETE /identity/v1/me/sessions/s1": () => none(),
    });
    const { result } = renderHook(() => useSessions(), { wrapper: wrap(f.account) });
    await waitFor(() => expect(result.current.sessions).toHaveLength(1));
    await act(async () => {
      expect(await result.current.revoke("s1")).toBe(true);
    });
    expect(f.count("GET /identity/v1/me/sessions")).toBe(2);
  });

  it("useFactors exposes the factor list and the recovery codes left", async () => {
    const f = setup({ "GET /identity/v1/me/factors": () => json(200, { factors: [{ id: "f", kind: "totp" }], recovery_codes_remaining: 5 }) });
    const { result } = renderHook(() => useFactors(), { wrapper: wrap(f.account) });
    await waitFor(() => expect(result.current.factors).toHaveLength(1));
    expect(result.current.recoveryCodesRemaining).toBe(5);
  });

  it("useApiKeys does not list when disabled and returns the issued value from create", async () => {
    const f = setup({
      "GET /identity/v1/me/api-keys/options": () => json(200, { enabled: true, max_ttl_days: null, resources: [] }),
      "GET /identity/v1/me/api-keys": () => json(200, { items: [], page: { limit: 20, offset: 0, total: 0 } }),
      "POST /identity/v1/me/api-keys": () => json(201, { id: "k", name: "n", value: "ik_key_v" }),
    });
    const { result } = renderHook(() => useApiKeys(), { wrapper: wrap(f.account) });
    await waitFor(() => expect(result.current.options?.enabled).toBe(true));
    let issued;
    await act(async () => {
      issued = await result.current.create({ name: "n", resource_id: "r", permissions: ["p"] });
    });
    expect(issued).toMatchObject({ value: "ik_key_v" });
  });

  it("useOrganizations switches and reports a refusal", async () => {
    const f = setup({
      "GET /identity/v1/organizations": () => json(200, [{ id: "org1", name: "Acme" }]),
      "GET /identity/v1/me": () => json(200, profile),
      "POST /identity/v1/refresh": () => reauth({ organization_id: "org9", reason: "mfa" }),
    });
    const onSignInRequired = vi.fn();
    const { result } = renderHook(
      () => useOrganizations({ getRefreshToken: () => "rt", onSignInRequired, boundary: { environmentId: "env", organizationId: "org1", applicationId: "a", resourceId: "r" } }),
      { wrapper: wrap(f.account) },
    );
    await waitFor(() => expect(result.current.currentId).toBe("org1"));
    await act(async () => {
      await result.current.switchTo("org9");
    });
    expect(onSignInRequired).toHaveBeenCalledWith({ organizationId: "org9", reason: "mfa" });
    expect(result.current.refusal).toEqual({ organizationId: "org9", reason: "mfa" });
  });

  it("hooks need a provider", () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => renderHook(() => useSessions())).toThrow(/AccountProvider/);
    err.mockRestore();
  });
});
