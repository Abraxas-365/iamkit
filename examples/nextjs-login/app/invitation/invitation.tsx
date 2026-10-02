"use client";

import { AcceptInvitation, IAMKitProvider } from "@iamkit/react";

export function Invitation({ issuer, token }: { issuer: string; token: string }) {
  return (
    <IAMKitProvider baseUrl={issuer}>
      <AcceptInvitation token={token}>
        {() => (
          <p>
            <a href="/">Continue to the application</a>
          </p>
        )}
      </AcceptInvitation>
    </IAMKitProvider>
  );
}
