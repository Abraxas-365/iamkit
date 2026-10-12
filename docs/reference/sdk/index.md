# SDKs

Choose an IAMKit client for your application's runtime and integration style.
Browser clients build sign-in and account screens; backend SDKs verify access
tokens and call identity or management APIs.

## Choose your runtime

| Where your code runs | Client | Start here |
| --- | --- | --- |
| Go backend | `sdk/` | [Go SDK](go.md) and [API middleware](middleware.md) |
| Node.js backend | `@iamkit/node` | [Node.js SDK](node.md) |
| Python backend | `iamkit` | [Python SDK](python.md) |
| Browser / TypeScript | `@iamkit/js` | [Custom sign-in UI](../../guides/applications/custom-sign-in-ui.md) |
| React application | `@iamkit/react` | [Sign-in components](../../guides/applications/custom-sign-in-ui.md) and [account widgets](react-widgets.md) |
| Typed HTTP API calls | `@iamkit/api` | [OpenAPI and TypeScript client](../api/openapi.md) |

Package installation and supported operations are documented in the linked
guides. You can use [hosted sign-in](../../guides/applications/hosted-login.md)
without building authentication screens yourself.

## Separate browser and server credentials

Browser clients must not receive management keys or confidential client
secrets. Keep administrative operations on your server and enforce your own
onboarding policy before calling them.

User application tokens are scoped to an environment, organization, application
and resource. Backend verification must check the expected audience,
organization and permissions; see [protect your API](../../start/protect-an-api.md).
Machine tokens have no organization or user session. API keys have their own
owner and scope rules: consult [credentials and boundaries](../../concepts/credentials-and-boundaries.md)
and [token claims](../token-claims.md) before choosing a verifier.

## Explore the Go SDK

The Go documentation separates [authentication](authentication.md),
[management](management.md), [middleware](middleware.md) and [SCIM](scim.md).
Start with the [overview](go.md) for module setup and client construction.

## Tools and examples

- [CLI](../cli.md) — configuration and administrative commands from your terminal.
- [Runnable examples](../../examples/README.md) — complete integration examples.
- [API reference](../api/index.md) — HTTP contracts when an SDK abstraction is not needed.
