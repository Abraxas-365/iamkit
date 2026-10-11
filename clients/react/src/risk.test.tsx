// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Captcha, captchaScripts, IAMKitProvider, SignInFlow, SignInForm } from "./index";
import { authorization, fakeIAM, json, memory, pair, type Routes } from "./testing";

afterEach(() => {
  cleanup();
  delete (globalThis as any).turnstile;
  delete (globalThis as any).hcaptcha;
  document.head.innerHTML = "";
});

const widget = { provider: "turnstile", site_key: "1x00000000000000000000AA" };
const base: Routes = {
  "GET /identity/v1/authorize/ik_ticket": () => json(200, { ...authorization, organization_id: "org", captcha: widget }),
  "POST /oauth/authorize/complete": () => json(200, { redirect_to: "https://app.example.com/cb?code=c" }),
};

function setup(routes: Routes, extra: Routes = {}) {
  const { calls, iam } = fakeIAM({ ...base, ...routes, ...extra }, memory());
  const went: string[] = [];
  const flow = new SignInFlow(iam, { ticket: "ik_ticket", navigate: (u) => went.push(u), returnTo: "https://ui.example.com/login" });
  return { calls, flow, went };
}

const login = (calls: { route: string; body: any }[]) => calls.filter((c) => c.route === "POST /identity/v1/login");

describe("SignInFlow captcha", () => {
  it("pauses at the captcha step, resumes with the token and spends it", async () => {
    const { flow, calls, went } = setup({ "POST /identity/v1/login": () => json(200, pair) });
    await flow.start("");
    expect(flow.state.captcha).toEqual(widget);
    await flow.identify("ada");
    expect(flow.state.step).toBe("password");
    await flow.submitPassword("pw");
    expect(flow.state.step).toBe("captcha");
    expect(login(calls)).toHaveLength(0);
    const round = flow.state.captchaRound;
    await flow.setCaptchaToken("tok-1");
    expect(login(calls)).toHaveLength(1);
    expect(login(calls)[0].body).toMatchObject({ login: "ada", password: "pw", captcha_token: "tok-1" });
    expect(went).toEqual(["https://app.example.com/cb?code=c"]);
    expect(flow.state.captchaToken).toBeUndefined();
    expect(flow.state.captchaRound).toBeGreaterThan(round);
  });

  it("returns to the step it paused from when the call fails", async () => {
    const { flow } = setup({ "POST /identity/v1/login": () => json(401, { error: { code: "UNAUTHORIZED", message: "invalid credentials" } }) });
    await flow.start("");
    await flow.identify("ada");
    await flow.submitPassword("bad");
    await flow.setCaptchaToken("tok-1");
    expect(flow.state.step).toBe("password");
    expect(flow.state.error?.message).toBe("invalid credentials");
    // The token was spent: the next try needs a fresh one.
    await flow.submitPassword("bad");
    expect(flow.state.step).toBe("captcha");
  });

  it("does nothing special without a captcha", async () => {
    const { flow, calls } = setup(
      { "POST /identity/v1/login": () => json(200, pair) },
      { "GET /identity/v1/authorize/ik_ticket": () => json(200, { ...authorization, organization_id: "org" }) },
    );
    await flow.start("");
    await flow.identify("ada");
    await flow.submitPassword("pw");
    expect(login(calls)[0].body).not.toHaveProperty("captcha_token");
  });

  it("asks for the widget after CAPTCHA_REQUIRED when the ticket named none", async () => {
    let n = 0;
    const { flow, calls } = setup(
      {
        "POST /identity/v1/login": () => (n++ === 0 ? json(403, { error: { code: "CAPTCHA_REQUIRED", message: "captcha", details: { provider: "turnstile" } } }) : json(200, pair)),
        "GET /identity/v1/captcha/env": () => json(200, { enabled: true, provider: "turnstile", site_key: "1x00000000000000000000AA", headless: true }),
      },
      { "GET /identity/v1/authorize/ik_ticket": () => json(200, { ...authorization, organization_id: "org" }) },
    );
    await flow.start("");
    await flow.identify("ada");
    await flow.submitPassword("pw");
    expect(flow.state.step).toBe("captcha");
    expect(flow.state.captcha).toEqual(widget);
    await flow.setCaptchaToken("tok-2");
    expect(login(calls)[1].body.captcha_token).toBe("tok-2");
    expect(flow.state.step).toBe("redirecting");
  });

  it("carries the token on code, reset, signup and directory calls", async () => {
    const { flow, calls } = setup({
      "POST /identity/v1/challenges": () => json(202, { challenge_id: "c1", expires_in: 600 }),
      "POST /identity/v1/signup": () => json(202, { challenge_id: "c2", expires_in: 600 }),
    });
    await flow.start("");
    await flow.identify("ada@example.com");
    await flow.setCaptchaToken("t-code");
    await flow.sendCode();
    expect(flow.state.step).toBe("code");
    await flow.setCaptchaToken("t-reset");
    await flow.forgotPassword();
    expect(flow.state.step).toBe("reset");
    await flow.setCaptchaToken("t-signup");
    await flow.signup({ name: "Ada" });
    expect(flow.state.step).toBe("signup_verify");
    const tokens = calls.filter((c) => c.route === "POST /identity/v1/challenges" || c.route === "POST /identity/v1/signup").map((c) => c.body.captcha_token);
    expect(tokens).toEqual(["t-code", "t-reset", "t-signup"]);
  });
});

describe("SignInFlow risk", () => {
  const nocaptcha: Routes = { "GET /identity/v1/authorize/ik_ticket": () => json(200, { ...authorization, organization_id: "org" }) };

  it("answers a risk challenge with the emailed code", async () => {
    const { flow, calls, went } = setup(
      {
        "POST /identity/v1/login": () => json(200, { mfa_required: true, mfa_token: "ik_mfa_x", factors: ["email"], enrollment_required: false, expires_in: 300, reason: "risk_challenge" }),
        "POST /identity/v1/mfa/challenge": () => json(200, { destination: "a***@example.com", expires_in: 300 }),
        "POST /identity/v1/mfa/verify": () => json(200, pair),
      },
      nocaptcha,
    );
    await flow.start("");
    await flow.identify("ada");
    await flow.submitPassword("pw");
    expect(flow.state.step).toBe("risk_challenge");
    expect(flow.state.codeSentTo).toBe("a***@example.com");
    expect(calls.find((c) => c.route === "POST /identity/v1/mfa/challenge")!.body).toEqual({ mfa_token: "ik_mfa_x", factor: "email" });
    await flow.verifyFactor("123456");
    expect(went).toEqual(["https://app.example.com/cb?code=c"]);
  });

  it("keeps ordinary second factors in the mfa step", async () => {
    const { flow } = setup({ "POST /identity/v1/login": () => json(200, { mfa_required: true, mfa_token: "ik_mfa_x", factors: ["totp"], enrollment_required: false, expires_in: 300 }) }, nocaptcha);
    await flow.start("");
    await flow.identify("ada");
    await flow.submitPassword("pw");
    expect(flow.state.step).toBe("mfa");
  });

  it("ends in blocked on SIGN_IN_BLOCKED", async () => {
    const { flow } = setup({ "POST /identity/v1/login": () => json(403, { error: { code: "SIGN_IN_BLOCKED", message: "blocked" } }) }, nocaptcha);
    await flow.start("");
    await flow.identify("ada");
    await flow.submitPassword("pw");
    expect(flow.state.step).toBe("blocked");
    expect(flow.state.error?.code).toBe("SIGN_IN_BLOCKED");
    flow.restart();
    expect(flow.state.step).toBe("identify");
  });
});

describe("<Captcha>", () => {
  function fakeApi(name: "turnstile" | "hcaptcha") {
    const api = { render: vi.fn((_el: HTMLElement, _o: Record<string, unknown>) => "w1"), remove: vi.fn(), reset: vi.fn() };
    (globalThis as any)[name] = api;
    return api;
  }

  it("renders explicitly with the site key and forwards token and expiry", async () => {
    const api = fakeApi("turnstile");
    const tokens: string[] = [];
    let expired = 0;
    const { unmount } = render(<Captcha widget={widget} onToken={(t) => tokens.push(t)} onExpire={() => expired++} options={{ theme: "light" }} />);
    await waitFor(() => expect(api.render).toHaveBeenCalledTimes(1));
    const options = api.render.mock.calls[0][1] as any;
    expect(options).toMatchObject({ sitekey: widget.site_key, theme: "light" });
    options.callback("tok");
    options["expired-callback"]();
    expect(tokens).toEqual(["tok"]);
    expect(expired).toBe(1);
    expect(document.querySelector("[data-iamkit=captcha]")).toBeTruthy();
    unmount();
    expect(api.remove).toHaveBeenCalledWith("w1");
  });

  it("loads each provider's script once", async () => {
    const first = render(<Captcha widget={{ provider: "hcaptcha", site_key: "10000000-ffff-ffff-ffff-000000000001" }} onToken={() => {}} nonce="n0nce" />);
    const second = render(<Captcha widget={{ provider: "hcaptcha", site_key: "10000000-ffff-ffff-ffff-000000000001" }} onToken={() => {}} />);
    await waitFor(() => expect(document.querySelectorAll("script[data-iamkit-captcha=hcaptcha]")).toHaveLength(1));
    const script = document.querySelector("script[data-iamkit-captcha=hcaptcha]") as HTMLScriptElement;
    expect(script.src).toBe(captchaScripts.hcaptcha);
    expect(script.nonce).toBe("n0nce");
    first.unmount();
    second.unmount();
  });

  it("offers a render prop for custom UIs", async () => {
    const api = fakeApi("turnstile");
    render(<Captcha widget={widget} onToken={() => {}}>{({ ref, status }) => <section ref={ref} data-testid="mine" data-status={status} />}</Captcha>);
    await waitFor(() => expect(api.render).toHaveBeenCalled());
    expect(api.render.mock.calls[0][0]).toBe(screen.getByTestId("mine"));
  });

  it("reports an unknown provider", async () => {
    const errors: Error[] = [];
    render(<Captcha widget={{ provider: "nope", site_key: "k" }} onToken={() => {}} onError={(e) => errors.push(e)} />);
    await waitFor(() => expect(errors).toHaveLength(1));
    expect(document.querySelector("[data-status=error]")).toBeTruthy();
  });
});

describe("<SignInForm> bot protection", () => {
  function provider(routes: Routes) {
    const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      const text = await request.text();
      return routes[`${request.method} ${url.pathname}`]?.(text ? JSON.parse(text) : undefined, url) ?? json(404, {});
    };
    return fetcher as typeof fetch;
  }

  it("shows the captcha step, then continues with the answer", async () => {
    const api = { render: vi.fn((_el: HTMLElement, _o: Record<string, unknown>) => "w1"), remove: vi.fn() };
    (globalThis as any).turnstile = api;
    const bodies: any[] = [];
    const went: string[] = [];
    const fetch = provider({
      ...base,
      "POST /identity/v1/discover": () => json(200, { method: "password", required: false }),
      "POST /identity/v1/login": (b) => (bodies.push(b), json(200, pair)),
    });
    render(
      <IAMKitProvider baseUrl="https://id.example.com" fetch={fetch}>
        <SignInForm ticket="ik_ticket" navigate={(u) => went.push(u)} />
      </IAMKitProvider>,
    );
    fireEvent.change(await screen.findByLabelText("Email or username"), { target: { value: "ada" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    });
    fireEvent.change(await screen.findByLabelText("Password"), { target: { value: "pw" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    });
    expect(await screen.findByRole("heading", { name: "Verify you are human" })).toBeTruthy();
    await waitFor(() => expect(api.render).toHaveBeenCalled());
    await act(async () => {
      (api.render.mock.calls[0][1] as any).callback("tok-form");
    });
    await waitFor(() => expect(went).toEqual(["https://app.example.com/cb?code=c"]));
    expect(bodies[0].captcha_token).toBe("tok-form");
  });

  it("shows the blocked step", async () => {
    const fetch = provider({
      "GET /identity/v1/authorize/ik_ticket": () => json(200, { ...authorization, organization_id: "org" }),
      "POST /identity/v1/discover": () => json(200, { method: "password", required: false }),
      "POST /identity/v1/login": () => json(403, { error: { code: "SIGN_IN_BLOCKED", message: "blocked" } }),
    });
    render(
      <IAMKitProvider baseUrl="https://id.example.com" fetch={fetch}>
        <SignInForm ticket="ik_ticket" navigate={() => {}} />
      </IAMKitProvider>,
    );
    fireEvent.change(await screen.findByLabelText("Email or username"), { target: { value: "ada" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    });
    fireEvent.change(await screen.findByLabelText("Password"), { target: { value: "pw" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    });
    expect(await screen.findByRole("heading", { name: "Sign-in not allowed" })).toBeTruthy();
  });
});
