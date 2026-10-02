import { config } from "@/lib/config";
import { Invitation } from "./invitation";

export const dynamic = "force-dynamic";

/** Invitation links of the environment point here (`?token=`). */
export default async function InvitationPage({ searchParams }: { searchParams: Promise<{ token?: string }> }) {
  const { token } = await searchParams;
  if (!token) return <p data-iamkit="error">Missing invitation token.</p>;
  return <Invitation issuer={config().issuer} token={token} />;
}
