# Events and extensibility

Connect identity activity to your application's workflows and operational
tools. Choose the mechanism by when it runs and who owns the data: identity
events, authentication actions and application audit logs serve different needs.

## Choose the right integration

| Your goal | Use |
| --- | --- |
| React after an identity or configuration change | [Events](../../reference/events.md) and [event webhooks](../../reference/event-webhooks.md) |
| Apply an application rule during a supported authentication or management operation | [Actions](actions.md) |
| Record business activity from your own application | [Application audit logs](../audit-logs.md) |
| Export identity events or audit logs to an external destination | [Log streams](log-streams.md) |
| Send IAMKit's transactional emails through your provider | [Email delivery](email-delivery.md) |

## Consume identity events

Start with the [event catalog](../../reference/events.md) and select only the
types your integration needs. Configure an
[event webhook](../../reference/event-webhooks.md), verify its signature on your
server, and handle retries without repeating business side effects.

For example, `connection.test_requested` records that an administrator created a
test sign-in link. It does not mean that the test succeeded or that a user signed
in. Use each event's documented meaning instead of inferring a workflow outcome.

## Extend authentication carefully

[Actions](actions.md) call configured endpoints at supported points in a flow.
Review which inputs and responses each condition supports before using them to
deny a request or change claims. They are not a replacement for authorization
checks in your application's API.

## Configure the platform

- [Email delivery](email-delivery.md) and the [email webhook contract](../../reference/email-webhooks.md) — configure transactional mail.
- [Feature flags](feature-flags.md) — enable supported IAMKit capabilities, not application feature rollouts.
- [Usage and limits](usage-limits.md) — inspect consumption and configure caps.
- [GeoIP](geoip.md) — supply country information for supported risk controls.

## Next steps

Use [observability](../../operations/observability.md) to diagnose delivery and
worker activity. Review [secrets and keys](../../operations/secrets-and-keys.md)
before connecting production destinations.
