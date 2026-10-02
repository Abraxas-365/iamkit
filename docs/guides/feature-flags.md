# Feature flags (beta features)

IAMKit's own beta features can be turned on and off per deployment and,
for some, per environment. These flags are for IAMKit itself; they are not
a feature-flag service for your applications.

## Registered features

| Name | Scope | Default | What it gates |
| --- | --- | --- | --- |
| `beta_languages` | environment | on | The machine-drafted (beta) [languages](hosted-login.md#language) of hosted pages and emails. Off offers only the reviewed languages (English, Spanish) plus the environment's chosen default language, when the environment has not listed its languages; an explicit list in the login settings always wins |
| `saml_idp` | deployment | on | IAMKit as a [SAML identity provider](saml-apps.md): off unmounts `/saml/:environment/*` and the `…/saml/service-providers` API (404) |

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

Overrides are audited as the [events](../reference/events.md)
`feature.updated` (`data.enabled`) and `feature.reset`, subject = the
feature name.
