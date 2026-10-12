import { NextResponse } from "next/server";
import { accessToken } from "@/lib/session";

/**
 * Hands the widgets (browser) the access token of the app's session. A
 * production app would proxy IAMKit's API through its own backend instead,
 * or keep the token in memory after sign-in; this keeps the example short.
 */
export async function GET() {
  const token = await accessToken();
  if (!token) return new NextResponse(null, { status: 401 });
  return new NextResponse(token.raw, { headers: { "Cache-Control": "no-store", "Content-Type": "text/plain" } });
}
