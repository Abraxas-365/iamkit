import { redirect } from "next/navigation";
import { config } from "@/lib/config";
import { accessToken, session } from "@/lib/session";
import { Account } from "./account";

export const dynamic = "force-dynamic";

/**
 * The account page: IAMKit's account widgets (@iamkit/react) against the
 * self-service API, with the access token the sign-in returned.
 */
export default async function AccountPage() {
  const [user, token] = await Promise.all([session(), accessToken()]);
  if (!user || !token) redirect("/");
  const c = config();
  return <Account issuer={c.issuer} environmentId={token.environmentId} audience={token.audience} organizationId={String(user.organization_id ?? "")} />;
}
