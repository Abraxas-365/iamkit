import { describe, expect, it } from "vitest";
import { createSignIn } from "./index";

function fake(answer: (body: any) => unknown) {
  const bodies: any[] = [];
  const fetcher = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request = input instanceof Request ? input : new Request(input, init);
    const body = JSON.parse(await request.text());
    bodies.push(body);
    return new Response(JSON.stringify(answer(body)), { status: 202, headers: { "Content-Type": "application/json" } });
  };
  return { bodies, fetch: fetcher as typeof fetch };
}

describe("signup waitlist", () => {
  it("reports waitlisted and code_sent", async () => {
    const f = fake((body) =>
      body.waitlist_token
        ? { challenge_id: "c1", status: "code_sent", message: "sent", expires_in: 600 }
        : { challenge_id: "c0", status: "waitlisted", message: "listed", expires_in: 600 },
    );
    const iam = createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch, deviceId: false });
    const listed = await iam.signup.start({ environmentId: "env", email: "a@example.com", name: "A" });
    expect(listed.status).toBe("waitlisted");
    expect("waitlist_token" in f.bodies[0]).toBe(false);
    const approved = await iam.signup.start({ environmentId: "env", email: "a@example.com", name: "A", waitlistToken: "tok" });
    expect(approved).toMatchObject({ status: "code_sent", challengeId: "c1" });
    expect(f.bodies[1].waitlist_token).toBe("tok");
  });

  it("treats an answer without status as code_sent", async () => {
    const f = fake(() => ({ challenge_id: "c1", expires_in: 600 }));
    const iam = createSignIn({ baseUrl: "https://id.example.com", fetch: f.fetch, deviceId: false });
    expect((await iam.signup.start({ environmentId: "env", email: "a@example.com", name: "A" })).status).toBe("code_sent");
  });
});
