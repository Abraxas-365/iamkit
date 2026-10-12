import { AccountScope, useOrganizations, type OrganizationsOptions } from "./account-hooks.js";
import { ErrorLine, Notice, kit, type AccountWidgetProps } from "./widget-kit.js";

export interface OrganizationSwitcherProps extends AccountWidgetProps, OrganizationsOptions {}

/**
 * The organizations the user belongs to, with a switch. The switch needs the
 * session's refresh token (`getRefreshToken`) and hands the new tokens to
 * `onSwitched`. A target that needs a sign-in the session lacks calls
 * `onSignInRequired({organizationId, reason})`: start an authorization with
 * that `organization_id`. Applications whose sessions come from OAuth
 * (code + PKCE) cannot switch in place: pass `onSelect` to start a new
 * authorization with the organization instead.
 */
export function OrganizationSwitcher(props: OrganizationSwitcherProps) {
  return (
    <AccountScope account={props.account} onReauthenticate={props.onReauthenticate}>
      <Switcher {...props} />
    </AccountScope>
  );
}

function Switcher(props: OrganizationSwitcherProps) {
  const k = kit(props);
  const { t, part } = k;
  const { getRefreshToken, onSwitched, onSignInRequired, boundary, onSelect } = props;
  const o = useOrganizations({ getRefreshToken, onSwitched, onSignInRequired, boundary, onSelect });
  if (o.loading && o.organizations.length === 0 && !o.error) return <div {...part("root")} aria-busy="true" />;
  const refused = o.refusal;
  const refusedName = refused ? (o.organizations.find((x) => x.id === refused.organizationId)?.name ?? refused.organizationId) : "";
  const reasonKey = refused ? `account.orgs.sign_in_required.${refused.reason}` : "";
  const reasonText = refused ? (t(reasonKey, refusedName) === reasonKey ? t("account.orgs.sign_in_required", refusedName) : t(reasonKey, refusedName)) : "";
  return (
    <div {...part("root")}>
      <h2 {...part("title")}>{t("account.orgs.title")}</h2>
      {/* A refused switch is explained below, not as a failure. */}
      <ErrorLine error={refused ? undefined : o.error} k={k} />
      <Notice k={k}>{reasonText}</Notice>
      {o.organizations.length === 0 ? <p {...part("meta")}>{t("account.orgs.none")}</p> : null}
      <ul {...part("list")}>
        {o.organizations.map((x) => {
          const current = x.id === o.currentId;
          return (
            <li key={x.id} {...part("item", { "data-current": current ? "true" : undefined, "data-organization": x.id })}>
              <span>{x.name}</span>
              {current ? (
                <span {...part("badge")}> {t("account.orgs.current")}</span>
              ) : (
                <button
                  type="button"
                  disabled={o.busy}
                  aria-label={t("account.orgs.switch", x.name)}
                  onClick={() => void o.switchTo(x.id)}
                  {...part("button")}
                >
                  {t("account.orgs.switch", x.name)}
                </button>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
