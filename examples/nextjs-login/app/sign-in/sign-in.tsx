"use client";

import { IAMKitProvider, SignInForm, useIAMKit } from "@iamkit/react";
import { useEffect, useRef, useState } from "react";

export function SignIn(props: { issuer: string; organizationId?: string; params: Record<string, string> }) {
  return (
    <IAMKitProvider baseUrl={props.issuer}>
      <Ticketed {...props} />
    </IAMKitProvider>
  );
}

function Ticketed({ organizationId, params }: { organizationId?: string; params: Record<string, string> }) {
  const iam = useIAMKit();
  const [ticket, setTicket] = useState(params.ticket ?? "");
  const [error, setError] = useState("");
  // One authorize per page: a second one would replace the binding cookie
  // of the first ticket (React's development mode runs effects twice).
  const started = useRef(false);

  useEffect(() => {
    if (ticket || !params.client_id || started.current) return;
    started.current = true;
    // Start the authorization from the browser: IAMKit answers with the
    // ticket and sets its binding cookie (credentials: include). Then keep
    // only the ticket in the address, so a reload or the single sign-on
    // return resumes it.
    iam.authorize(params).then(
      (start) => {
        const url = new URL(window.location.href);
        url.search = new URLSearchParams({ ticket: start.authorization_ticket }).toString();
        window.history.replaceState(null, "", url);
        setTicket(start.authorization_ticket);
      },
      (err: Error) => setError(err.message),
    );
  }, [iam, params, ticket]);

  if (error) {
    return (
      <p role="alert" data-iamkit="error">
        {error}
      </p>
    );
  }
  if (!ticket) {
    return params.client_id ? <p aria-busy="true">…</p> : <p data-iamkit="error">Start the sign-in from the application.</p>;
  }
  return (
    <SignInForm
      ticket={ticket}
      // The organization when the authorize request named none.
      organization={organizationId}
      // Style with classNames (e.g. Tailwind) or, as here, the
      // data-iamkit attributes in globals.css.
      renderQRCode={(uri) => (
        <p data-iamkit="notice">
          <a href={uri} data-testid="otpauth">
            Open in your authenticator app
          </a>
        </p>
      )}
    />
  );
}
