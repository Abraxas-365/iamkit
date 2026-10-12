// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { IAMKitProvider, SignInFlow, SignInForm } from "./index";
import { authorization, fakeIAM, json, memory, type Routes } from "./testing";

afterEach(cleanup);

const routes = (answer: (body: any) => Response): Routes => ({
  "GET /identity/v1/authorize/ik_ticket": () => json(200, { ...authorization, organization_id: "org", texts: {} }),
  "POST /identity/v1/signup": answer,
});

const listed = () => json(202, { challenge_id: "c0", status: "waitlisted", message: "listed", expires_in: 600 });

function fetcher(table: Routes) {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const url = new URL(request.url);
    const text = await request.text();
    return table[`${request.method} ${url.pathname}`]?.(text ? JSON.parse(text) : undefined, url) ?? json(404, {});
  }) as typeof fetch;
}

describe("waitlist", () => {
  it("moves the flow to waitlisted and sends the approval token", async () => {
    const { calls, iam } = fakeIAM(routes((body) => (body.waitlist_token ? json(202, { challenge_id: "c1", status: "code_sent", message: "sent", expires_in: 600 }) : listed())), memory());
    const plain = new SignInFlow(iam, { ticket: "ik_ticket", navigate: () => {} });
    await plain.start("");
    plain.beginSignup();
    await plain.signup({ email: "a@example.com", name: "A" });
    expect(plain.state.step).toBe("waitlisted");
    expect("waitlist_token" in calls[calls.length - 1].body).toBe(false);

    const approved = new SignInFlow(iam, { ticket: "ik_ticket", navigate: () => {}, waitlistToken: "tok" });
    await approved.start("");
    approved.beginSignup();
    await approved.signup({ email: "a@example.com", name: "A" });
    expect(approved.state.step).toBe("signup_verify");
    expect(calls[calls.length - 1].body.waitlist_token).toBe("tok");
  });

  it("shows the waitlisted state with an overridable text", async () => {
    const table = { ...routes(listed), "POST /identity/v1/discover": () => json(200, { method: "password", required: false }) };
    render(
      <IAMKitProvider baseUrl="https://id.example.com" fetch={fetcher(table)}>
        <SignInForm ticket="ik_ticket" navigate={() => {}} texts={{ "hosted.title.waitlisted": "Hang tight" }} />
      </IAMKitProvider>,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Create account" }));
    fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "Ada" } });
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "ada@example.com" } });
    await act(async () => {
      fireEvent.submit(screen.getByLabelText("Name").closest("form")!);
    });
    expect(await screen.findByRole("heading", { name: "Hang tight" })).toBeTruthy();
    expect(screen.getByText(/ada@example.com can join/)).toBeTruthy();
  });
});
