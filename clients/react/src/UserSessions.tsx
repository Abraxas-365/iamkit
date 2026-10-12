import { useState } from "react";
import { AccountScope, useSessions } from "./account-hooks.js";
import { ErrorLine, Notice, kit, when, type AccountWidgetProps } from "./widget-kit.js";

export type UserSessionsProps = AccountWidgetProps;

/** The user's live sessions with sign out and "sign out everywhere else"; the current one is marked. */
export function UserSessions(props: UserSessionsProps) {
  return (
    <AccountScope account={props.account} onReauthenticate={props.onReauthenticate}>
      <Sessions {...props} />
    </AccountScope>
  );
}

function Sessions(props: UserSessionsProps) {
  const k = kit(props);
  const { t, part } = k;
  const s = useSessions();
  const [notice, setNotice] = useState("");
  if (s.loading && s.sessions.length === 0 && !s.error) return <div {...part("root")} aria-busy="true" />;
  const others = s.sessions.some((x) => !x.current);
  return (
    <div {...part("root")}>
      <h2 {...part("title")}>{t("account.sessions.title")}</h2>
      <ErrorLine error={s.error} k={k} />
      <Notice k={k}>{notice}</Notice>
      {s.sessions.length === 0 ? <p {...part("meta")}>{t("account.sessions.none")}</p> : null}
      <ul {...part("list")}>
        {s.sessions.map((x) => (
          <li key={x.id} {...part("item", { "data-current": x.current ? "true" : undefined, "data-session": x.id })}>
            <strong>{x.user_agent || t("account.sessions.unknown_device")}</strong>
            {x.current ? <span {...part("badge")}> {t("account.sessions.current")}</span> : null}
            <span {...part("meta")}>
              {[x.ip_address, t("account.sessions.signed_in", when(x.authenticated_at)), x.organization?.name ? t("account.sessions.organization", x.organization.name) : "", x.application?.name ? t("account.sessions.application", x.application.name) : ""]
                .filter(Boolean)
                .join(" · ")}
            </span>
            <button
              type="button"
              disabled={s.busy}
              aria-label={`${t("account.sessions.revoke")}: ${x.user_agent || x.id}`}
              onClick={async () => {
                setNotice("");
                await s.revoke(x.id);
              }}
              {...part("secondary")}
            >
              {t("account.sessions.revoke")}
            </button>
          </li>
        ))}
      </ul>
      {others ? (
        <button
          type="button"
          disabled={s.busy}
          onClick={async () => {
            const n = await s.revokeOthers();
            if (n !== undefined) setNotice(t("account.sessions.revoked_others", String(n)));
          }}
          {...part("button")}
        >
          {t("account.sessions.revoke_others")}
        </button>
      ) : null}
    </div>
  );
}
