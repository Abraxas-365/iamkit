import { useState } from "react";
import type { ConnectedApp } from "@iamkit/js";
import { AccountScope, useConnectedApps } from "./account-hooks.js";
import { ErrorLine, Notice, kit, when, type AccountWidgetProps, type Kit } from "./widget-kit.js";

export interface ConnectedAppsProps extends AccountWidgetProps {
  /** Lists one organization's connected applications only. */
  organizationId?: string;
}

/**
 * The applications the user let reach protected resources (MCP servers),
 * with disconnect. An application is shown as IAMKit can vouch for it: the
 * verified name of a preset, else the host of its client_id with the name
 * it gives itself marked unverified. Disconnecting asks for confirmation:
 * the application's access ends at once.
 */
export function ConnectedApps(props: ConnectedAppsProps) {
  return (
    <AccountScope account={props.account} onReauthenticate={props.onReauthenticate}>
      <Apps {...props} />
    </AccountScope>
  );
}

/** The key of one app: a client reaches one server per organization. */
function key(app: ConnectedApp): string {
  return `${app.client.id}/${app.protected_resource_id}/${app.organization_id}`;
}

/** The app's display name: verified first, then its host, then its own name. */
function label(app: ConnectedApp): string {
  return app.client.verified_name || app.client.host || app.client.name || app.client.client_id;
}

function Identity(props: { app: ConnectedApp; k: Kit }) {
  const { app } = props;
  const { t, part } = props.k;
  const c = app.client;
  const logo = c.logo_uri && c.verified_name ? <img src={c.logo_uri} alt="" width={24} height={24} {...part("logo")} /> : null;
  if (c.verified_name) {
    return (
      <>
        {logo}
        <strong>{c.verified_name}</strong>
        {c.host ? <span {...part("meta")}> {t("account.apps.at", c.host)}</span> : null}
      </>
    );
  }
  return (
    <>
      <strong>{c.host || c.client_id}</strong>
      {c.name ? (
        <span {...part("meta")} title={t("account.apps.unverified_help", c.name)}>
          {" "}
          {c.name} <span {...part("badge", { "data-unverified": "true" })}>{t("account.apps.unverified")}</span>
        </span>
      ) : null}
    </>
  );
}

function Apps(props: ConnectedAppsProps) {
  const k = kit(props);
  const { t, part } = k;
  const s = useConnectedApps({ organizationId: props.organizationId });
  const [notice, setNotice] = useState("");
  const [confirming, setConfirming] = useState("");
  if (s.loading && s.apps.length === 0 && !s.error) return <div {...part("root")} aria-busy="true" />;
  return (
    <div {...part("root")}>
      <h2 {...part("title")}>{t("account.apps.title")}</h2>
      <ErrorLine error={s.error} k={k} />
      <Notice k={k}>{notice}</Notice>
      {s.apps.length === 0 ? <p {...part("meta")}>{t("account.apps.none")}</p> : null}
      <ul {...part("list")}>
        {s.apps.map((app) => {
          const id = key(app);
          const name = label(app);
          return (
            <li key={id} {...part("item", { "data-client": app.client.id })}>
              <Identity app={app} k={k} />
              <span {...part("meta")}>
                {[
                  t("account.apps.server", app.resource_name || app.resource),
                  app.scopes?.length ? t("account.apps.scopes", app.scopes.join(", ")) : t("account.apps.no_scopes"),
                  app.consented_at ? t("account.apps.connected", when(app.consented_at)) : "",
                  app.last_used_at ? t("account.apps.last_used", when(app.last_used_at)) : "",
                  app.active_sessions ? t("account.apps.sessions", String(app.active_sessions)) : "",
                ]
                  .filter(Boolean)
                  .join(" · ")}
              </span>
              {confirming === id ? (
                <span role="group" aria-label={t("account.apps.confirm", name)} {...part("actions")}>
                  <span {...part("meta")}>{t("account.apps.confirm", name)}</span>
                  <button
                    type="button"
                    disabled={s.busy}
                    onClick={async () => {
                      setNotice("");
                      if (await s.disconnect(app)) {
                        setConfirming("");
                        setNotice(t("account.apps.disconnected", name));
                      }
                    }}
                    {...part("danger")}
                  >
                    {t("account.confirm")}
                  </button>
                  <button type="button" disabled={s.busy} onClick={() => setConfirming("")} {...part("secondary")}>
                    {t("account.cancel")}
                  </button>
                </span>
              ) : (
                <button
                  type="button"
                  disabled={s.busy}
                  aria-label={`${t("account.apps.disconnect")}: ${name}`}
                  onClick={() => {
                    s.clearError();
                    setConfirming(id);
                  }}
                  {...part("secondary")}
                >
                  {t("account.apps.disconnect")}
                </button>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
