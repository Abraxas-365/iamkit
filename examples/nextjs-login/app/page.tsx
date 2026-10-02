import { signIn, signOut } from "./actions";
import { config } from "@/lib/config";
import { session } from "@/lib/session";

export const dynamic = "force-dynamic";

export default async function Home({ searchParams }: { searchParams: Promise<Record<string, string | undefined>> }) {
  const params = await searchParams;
  const user = await session();
  if (user) {
    return (
      <>
        <h1>Signed in</h1>
        <p data-testid="user">{String(user.sub)}</p>
        <p data-testid="organization">{String(user.organization_id ?? "")}</p>
        <p data-testid="amr">{Array.isArray(user.amr) ? user.amr.join(" ") : ""}</p>
        <form action={signOut}>
          <button type="submit">Sign out</button>
        </form>
      </>
    );
  }
  return (
    <>
      <h1>Invoices</h1>
      {params.error ? (
        <p role="alert" data-iamkit="error">
          {params.error}
        </p>
      ) : null}
      <form action={signIn}>
        {/* Sign in to a given organization (the authorize organization_id
            hint), else the default one or the email's SSO organization. */}
        <input type="hidden" name="organization" value={params.organization ?? config().organizationId ?? ""} />
        <button type="submit">Sign in</button>
      </form>
    </>
  );
}
