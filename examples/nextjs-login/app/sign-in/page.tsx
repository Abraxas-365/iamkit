import { config } from "@/lib/config";
import { SignIn } from "./sign-in";

export const dynamic = "force-dynamic";

/**
 * The custom sign-in page. Reached two ways:
 *  - with the client's authorize query (from the app's sign-in action, or
 *    any OIDC library pointed here): it calls IAMKit's /oauth/authorize
 *    from the browser and continues with the ticket;
 *  - with `?ticket=` (the return from single sign-on).
 * Every IAMKit call runs in the browser with credentials, so the ticket's
 * binding cookie (on IAMKit's origin) stays with this browser; no token is
 * stored anywhere — the access token only completes the authorization.
 */
export default async function SignInPage({ searchParams }: { searchParams: Promise<Record<string, string>> }) {
  const params = await searchParams;
  const c = config();
  return <SignIn issuer={c.issuer} organizationId={c.organizationId} params={params} />;
}
