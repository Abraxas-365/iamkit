import { describe, expect, it } from "vitest";
import { SignInFlow } from "./flow";
import { authorization, fakeIAM, json, memory, pair, type Routes } from "./testing";

const base: Routes = {
  "GET /identity/v1/authorize/ik_ticket": () => json(200, authorization),
  "POST /identity/v1/discover": () => json(200, { method: "password", required: false }),
  "POST /oauth/authorize/complete": () => json(200, { redirect_to: "https://app.example.com/cb?code=c" }),
};

function setup(routes: Routes, organization: string | null = "org") {
  const { calls, iam } = fakeIAM({ ...base, ...routes }, memory());
  const went: string[] = [];
  const flow = new SignInFlow(iam, { ticket: "ik_ticket", organization: organization ?? undefined, navigate: (u) => went.push(u), returnTo: "https://ui.example.com/login?ticket=ik_ticket" });
  return { calls, flow, went };
}

describe("SignInFlow", () => {
  it("signs in with a password and completes the authorization", async () => {
    const { flow, calls, went } = setup({ "POST /identity/v1/login": () => json(200, pair) });
    await flow.start("");
    expect(flow.state.step).toBe("identify");
    await flow.identify(" ada@example.com ");
    expect(flow.state.step).toBe("password");
    await flow.submitPassword("pw");
    expect(went).toEqual(["https://app.example.com/cb?code=c"]);
    expect(flow.state.step).toBe("redirecting");
    const login = calls.find((c) => c.route === "POST /identity/v1/login")!;
    expect(login.body).toMatchObject({ login: "ada@example.com", organization_id: "org", environment_id: "env", application_id: "app", resource_id: "res" });
    const complete = calls.find((c) => c.route === "POST /oauth/authorize/complete")!;
    expect(complete.body).toEqual({ authorization_ticket: "ik_ticket", approve: true });
  });

  it("routes a verified domain to single sign-on with its organization", async () => {
    const { flow, calls, went } = setup({
      "POST /identity/v1/discover": () => json(200, { method: "sso", organization_id: "acme", connection_id: "okta", required: true, provider: "oidc" }),
      "POST /identity/v1/federation/start": () => json(200, { authorization_url: "https://idp.example.com/auth" }),
    });
    await flow.start("");
    await flow.identify("bob@acme.com");
    expect(went).toEqual(["https://idp.example.com/auth"]);
    const start = calls.find((c) => c.route === "POST /identity/v1/federation/start")!;
    expect(start.body).toMatchObject({ organization_id: "acme", connection_id: "okta", return_to: "https://ui.example.com/login?ticket=ik_ticket" });
    expect(start.body.code_challenge).toHaveLength(43);
  });

  it("asks for a new password when it expired", async () => {
    let n = 0;
    const { flow, calls, went } = setup({
      "POST /identity/v1/login": () => (n++ === 0 ? json(403, { error: { code: "PASSWORD_CHANGE_REQUIRED", message: "expired", type: "forbidden", http_status: 403 } }) : json(200, pair)),
    });
    await flow.start("");
    await flow.identify("ada");
    await flow.submitPassword("old");
    expect(flow.state.step).toBe("new_password");
    expect(flow.state.error).toBeUndefined();
    await flow.changePassword("new-password");
    expect(calls.filter((c) => c.route === "POST /identity/v1/login")[1].body).toMatchObject({ password: "old", new_password: "new-password" });
    expect(went).toHaveLength(1);
  });

  it("runs the second factor and keeps the recovery codes on screen", async () => {
    const { flow, went } = setup({
      "POST /identity/v1/login": () => json(200, { mfa_required: true, mfa_token: "ik_mfa_1", factors: ["totp"], enrollment_required: true, expires_in: 300 }),
      "POST /identity/v1/mfa/enroll": () => json(200, { otpauth_uri: "otpauth://totp/x", secret: "ABC" }),
      "POST /identity/v1/mfa/verify": () => json(200, { ...pair, recovery_codes: ["r1", "r2"] }),
    });
    await flow.start("");
    await flow.identify("ada");
    await flow.submitPassword("pw");
    expect(flow.state.step).toBe("enroll");
    expect(flow.state.enrollment?.secret).toBe("ABC");
    await flow.verifyFactor("123456");
    expect(flow.state.recoveryCodes).toEqual(["r1", "r2"]);
    expect(went).toEqual([]);
    flow.proceed();
    expect(went).toEqual(["https://app.example.com/cb?code=c"]);
  });

  it("signs in with an emailed code when passwords are off", async () => {
    const { flow, calls, went } = setup({
      "GET /identity/v1/authorize/ik_ticket": () => json(200, { ...authorization, methods: { ...authorization.methods, password: false } }),
      "POST /identity/v1/challenges": () => json(202, { challenge_id: "ch", message: "sent", expires_in: 600 }),
      "POST /identity/v1/challenges/verify": () => json(200, pair),
    });
    await flow.start("");
    await flow.identify("ada@example.com");
    expect(flow.state.step).toBe("code");
    await flow.verifyCode(" 12345678 ");
    expect(calls.find((c) => c.route === "POST /identity/v1/challenges/verify")!.body).toMatchObject({ challenge_id: "ch", code: "12345678", purpose: "login" });
    expect(went).toHaveLength(1);
  });

  it("signs up, then signs in with the chosen password into the sign-up organization", async () => {
    const { flow, calls, went } = setup(
      {
        "POST /identity/v1/signup": () => json(202, { challenge_id: "su", message: "sent", expires_in: 600 }),
        "POST /identity/v1/signup/verify": () => json(201, { user_id: "u", organization_id: "signup-org", email: "new@example.com" }),
        "POST /identity/v1/login": () => json(200, pair),
      },
      null,
    );
    await flow.start("");
    flow.beginSignup();
    await flow.signup({ email: "new@example.com", name: "New", password: "pw-long-enough" });
    expect(flow.state.step).toBe("signup_verify");
    await flow.verifySignup("11112222");
    expect(calls.find((c) => c.route === "POST /identity/v1/login")!.body).toMatchObject({ organization_id: "signup-org", login: "new@example.com" });
    expect(went).toHaveLength(1);
  });

  it("reports a missing organization instead of calling IAMKit", async () => {
    const { flow, calls } = setup({}, null);
    await flow.start("");
    await flow.identify("ada");
    expect(flow.state.error?.code).toBe("ORGANIZATION_REQUIRED");
    expect(calls.some((c) => c.route === "POST /identity/v1/login")).toBe(false);
  });

  it("fails the ticket when IAMKit cannot describe it", async () => {
    const { flow } = setup({ "GET /identity/v1/authorize/ik_ticket": () => json(401, { error: { code: "UNAUTHORIZED", message: "binding", type: "unauthorized", http_status: 401 } }) });
    await flow.start("");
    expect(flow.state.step).toBe("failed");
    expect(flow.state.error?.status).toBe(401);
  });

  it("redeems a federation result on the return page", async () => {
    const storage = memory();
    storage.setItem("iamkit.federation.verifier", "v".repeat(64));
    const { calls, iam } = fakeIAM({ ...base, "POST /identity/v1/federation/result": () => json(200, pair) }, storage);
    const went: string[] = [];
    const flow = new SignInFlow(iam, { ticket: "ik_ticket", navigate: (u) => went.push(u) });
    await flow.start("https://ui.example.com/login?ticket=ik_ticket&federation_result=ik_fedres_x");
    expect(calls.find((c) => c.route === "POST /identity/v1/federation/result")!.body).toEqual({ federation_result: "ik_fedres_x", code_verifier: "v".repeat(64) });
    expect(went).toEqual(["https://app.example.com/cb?code=c"]);
  });
});
