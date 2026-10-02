// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { AcceptInvitation, IAMKitProvider, SignInForm } from "./index";
import { authorization, json, pair, type Routes } from "./testing";

function provider(routes: Routes) {
  const calls: string[] = [];
  const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    const route = `${request.method} ${url.pathname}`;
    calls.push(route);
    const text = await request.text();
    return routes[route]?.(text ? JSON.parse(text) : undefined, url) ?? json(404, {});
  };
  return { calls, fetch: fetcher as typeof fetch };
}

afterEach(cleanup);

describe("SignInForm", () => {
  it("walks identifier → password → client, worded by the ticket's texts", async () => {
    const went: string[] = [];
    const f = provider({
      "GET /identity/v1/authorize/ik_ticket": () => json(200, authorization),
      "POST /identity/v1/discover": () => json(200, { method: "password", required: false }),
      "POST /identity/v1/login": () => json(200, pair),
      "POST /oauth/authorize/complete": () => json(200, { redirect_to: "https://app.example.com/cb?code=c" }),
    });
    render(
      <IAMKitProvider baseUrl="https://id.example.com" fetch={f.fetch}>
        <SignInForm ticket="ik_ticket" organization="org" navigate={(u) => went.push(u)} classNames={{ button: "btn" }} />
      </IAMKitProvider>,
    );
    expect(await screen.findByRole("heading", { name: "Welcome back" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Continue with Google" })).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Email or username"), { target: { value: "ada@example.com" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    });
    const password = await screen.findByLabelText("Password");
    expect(screen.getByRole("button", { name: "Sign in" }).className).toBe("btn");
    fireEvent.change(password, { target: { value: "pw" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    });
    expect(went).toEqual(["https://app.example.com/cb?code=c"]);
    expect(f.calls).toContain("POST /oauth/authorize/complete");
  });

  it("shows IAMKit's error and stays on the step", async () => {
    const f = provider({
      "GET /identity/v1/authorize/ik_ticket": () => json(200, { ...authorization, organization_id: "org" }),
      "POST /identity/v1/discover": () => json(200, { method: "password", required: false }),
      "POST /identity/v1/login": () => json(401, { error: { code: "UNAUTHORIZED", message: "invalid credentials", type: "unauthorized", http_status: 401 } }),
    });
    render(
      <IAMKitProvider baseUrl="https://id.example.com" fetch={f.fetch}>
        <SignInForm ticket="ik_ticket" navigate={() => {}} />
      </IAMKitProvider>,
    );
    fireEvent.change(await screen.findByLabelText("Email or username"), { target: { value: "ada" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    });
    fireEvent.change(await screen.findByLabelText("Password"), { target: { value: "bad" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    });
    expect((await screen.findByRole("alert")).textContent).toBe("invalid credentials");
    expect(screen.getByLabelText("Password")).toBeTruthy();
  });
});

describe("AcceptInvitation", () => {
  it("previews, asks new users for a name and password, and accepts", async () => {
    const f = provider({
      "POST /identity/v1/invitations/preview": () => json(200, { email: "ada@example.com", organization_id: "org", organization_name: "Acme", status: "pending", password_required: true, sso_required: false, expires_at: "2030-01-01T00:00:00Z" }),
      "POST /identity/v1/invitations/accept": (body) => json(200, { user_id: "u", organization_id: "org", email: "ada@example.com", sso_required: false, created: !!body.password }),
    });
    render(
      <IAMKitProvider baseUrl="https://id.example.com" fetch={f.fetch}>
        <AcceptInvitation token="ik_inv_x">{(a) => <a href="/login">{a.created ? "created" : "joined"}</a>}</AcceptInvitation>
      </IAMKitProvider>,
    );
    expect(await screen.findByText("You were invited to join Acme.")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Ada" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret-password" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Join Acme" }));
    });
    expect(await screen.findByText("created")).toBeTruthy();
  });
});
