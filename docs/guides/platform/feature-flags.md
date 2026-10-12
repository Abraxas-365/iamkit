# Feature flags (beta features)

IAMKit's own beta features can be turned on and off per deployment and,
for some, per environment. These flags are for IAMKit itself; they are not
a feature-flag service for your applications.

## Registered features

| Name | Scope | Default | What it gates |
| --- | --- | --- | --- |
| `beta_languages` | environment | on | The machine-drafted (beta) [languages](../applications/hosted-login.md#language) of hosted pages and emails. Off offers only the reviewed languages (English, Spanish) plus the environment's chosen default language, when the environment has not listed its languages; an explicit list in the login settings always wins |
| `captcha` | environment | on | [Bot protection](../sign-in/bot-protection.md): off skips every CAPTCHA check and renders no widget, keeping the saved configuration. A kill switch for a misbehaving provider |
| `risk_signals` | environment | on | [Risk signals](../sign-in/risk-signals.md): off stops recording sign-in attempts and devices and skips detections, restrictions and the `risk` input of actions |
| `actions` | environment | on | [Actions](actions.md): off skips every sign-in, token and request hook without deleting its targets or executions |
| `saml_idp` | deployment | on | IAMKit as a [SAML identity provider](../applications/saml-apps.md): off unmounts `/saml/:environment/*` and the `…/saml/service-providers` API (404) |

The defaults reproduce IAMKit without flags.

## Where a value comes from

A feature's effective value is, first match wins:

1. the environment's override (environment-scoped features only);
2. the deployment value from `IAMKIT_FEATURES`;
3. IAMKit's default.

`IAMKIT_FEATURES` is a comma-separated list of `name=true|false` (a bare
name means `true`), read at start-up:

```sh
IAMKIT_FEATURES=saml_idp=false,beta_languages=false
IAMKIT_FEATURES=captcha=false     # kill switch for every environment
```

A value other than a boolean stops the server from starting. Names IAMKit
does not know (for example a flag removed in an upgrade) are logged and
ignored, as are stored overrides of removed flags.

## Override per environment

Console: **Settings → Features (beta)** lists every feature with its value
and where it comes from; environment-scoped ones have a switch and a link
back to the deployment value or default. Viewers see the page read-only.

API (under `/management/v1/environments/:environment`):

```sh
curl -H "Authorization: Bearer $IAMKIT_KEY" "$IAMKIT/management/v1/environments/$ENV/features"
curl -X PUT -H "Authorization: Bearer $IAMKIT_KEY" -d '{"enabled":false}' \
  "$IAMKIT/management/v1/environments/$ENV/features/beta_languages"
curl -X DELETE -H "Authorization: Bearer $IAMKIT_KEY" \
  "$IAMKIT/management/v1/environments/$ENV/features/beta_languages"
```

CLI: `iam features list`, `iam features get NAME`,
`iam features set NAME true|false`, `iam features reset NAME`.

SDK: `Features`, `Feature(ctx, name)`, `SetFeature(ctx, name, enabled)` and
`ResetFeature(ctx, name)`.

## Prerequisites and next step

Before enabling a flag in production, verify its deployment value with
`iam features get NAME`, then check the environment's effective source in
**Settings → Features (beta)**. For a rollback, reset the environment override
first (`iam features reset NAME`) or set the deployment value and restart; the
configuration remains stored while the feature is off.

Overrides are audited as the [events](../../reference/events.md)
`feature.updated` (`data.enabled`) and `feature.reset`, subject = the
feature name.
