import { useState, type FormEvent } from "react";
import { AccountScope, useApiKeys } from "./account-hooks.js";
import { ErrorLine, Field, Notice, kit, when, type AccountWidgetProps } from "./widget-kit.js";

export interface ApiKeysProps extends AccountWidgetProps {
  /** Expiry choices in days offered besides "never" (default 30, 90, 365); capped by the policy's maximum. */
  expiryDays?: number[];
  /** Copies the key's value; default `navigator.clipboard.writeText`. */
  copy?: (value: string) => Promise<void> | void;
}

/**
 * The user's API keys: list, create (permissions from the resource's
 * allowlist, expiry), the value shown once with a copy button, revoke.
 * Creating needs a recent sign-in (`onReauthenticate`).
 */
export function ApiKeys(props: ApiKeysProps) {
  return (
    <AccountScope account={props.account} onReauthenticate={props.onReauthenticate}>
      <Keys {...props} />
    </AccountScope>
  );
}

function Keys(props: ApiKeysProps) {
  const k = kit(props);
  const { t, part } = k;
  const keys = useApiKeys();
  const [issued, setIssued] = useState<{ name: string; value: string }>();
  const [copied, setCopied] = useState(false);
  const [resourceId, setResourceId] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [local, setLocal] = useState<unknown>();

  const options = keys.options;
  if (keys.loading && !options && !keys.error) return <div {...part("root")} aria-busy="true" />;
  const resources = options?.resources ?? [];
  const resource = resources.find((r) => r.id === resourceId) ?? resources[0];
  const maxDays = options?.max_ttl_days ?? null;
  const days = [...new Set([...(props.expiryDays ?? [30, 90, 365]).filter((d) => maxDays === null || d <= maxDays), ...(maxDays !== null ? [maxDays] : [])])].sort((a, b) => a - b);

  const create = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setLocal(undefined);
    if (!resource || picked.length === 0) {
      setLocal(new Error(t("account.keys.pick_permission")));
      return;
    }
    const expiry = String(form.get("expires") ?? "never");
    const out = await keys.create({
      name: String(form.get("name") ?? "").trim(),
      resource_id: resource.id,
      permissions: picked,
      ...(expiry === "never" ? {} : { expires_in: `${Number(expiry) * 24}h` }),
    });
    if (out) {
      setIssued({ name: out.name, value: out.value });
      setCopied(false);
      setPicked([]);
    }
  };

  const copy = async () => {
    if (!issued) return;
    try {
      await (props.copy ?? ((v: string) => navigator.clipboard.writeText(v)))(issued.value);
      setCopied(true);
    } catch (err) {
      setLocal(err);
    }
  };

  return (
    <div {...part("root")}>
      <h2 {...part("title")}>{t("account.keys.title")}</h2>
      <ErrorLine error={local ?? keys.error} k={k} />
      {issued ? (
        <section {...part("section", { "data-state": "issued" })} aria-label={t("account.keys.created")}>
          <h3 {...part("subtitle")}>{t("account.keys.created")}</h3>
          <Notice k={k}>{t("account.keys.created_hint")}</Notice>
          <p>
            <code {...part("secret")} data-testid="api-key-value">
              {issued.value}
            </code>
          </p>
          <button type="button" onClick={() => void copy()} {...part("button")}>
            {copied ? t("account.copied") : t("account.copy")}
          </button>
          <button type="button" onClick={() => setIssued(undefined)} {...part("secondary")}>
            {t("account.done")}
          </button>
        </section>
      ) : null}

      {options && !options.enabled ? <p {...part("meta")}>{t("account.keys.disabled")}</p> : null}

      {options?.enabled ? (
        <>
          {keys.keys.length === 0 ? <p {...part("meta")}>{t("account.keys.none")}</p> : null}
          <ul {...part("list")}>
            {keys.keys.map((key) => (
              <li key={key.id} {...part("item", { "data-key": key.id, "data-state": key.state })}>
                <strong>{key.name}</strong> <code>{key.obfuscated_value}</code>{" "}
                <span {...part("badge")}>{t(`account.keys.${key.state}`) === `account.keys.${key.state}` ? key.state : t(`account.keys.${key.state}`)}</span>
                <span {...part("meta")}>
                  {[
                    key.resource_name,
                    (key.permissions ?? []).join(", "),
                    key.expires ? `${t("account.keys.expires")}: ${when(key.expires_at)}` : `${t("account.keys.expires")}: ${t("account.never")}`,
                    key.last_used_at ? t("account.keys.last_used", when(key.last_used_at)) : t("account.keys.never_used"),
                  ]
                    .filter(Boolean)
                    .join(" · ")}
                </span>
                {!key.revoked_at ? (
                  <button type="button" disabled={keys.busy} aria-label={`${t("account.keys.revoke")}: ${key.name}`} onClick={() => void keys.revoke(key.id)} {...part("secondary")}>
                    {t("account.keys.revoke")}
                  </button>
                ) : null}
              </li>
            ))}
          </ul>

          <form onSubmit={create} {...part("form")} aria-label={t("account.keys.create")}>
            <Field k={k} label={t("account.keys.name")} name="name" required />
            {resources.length > 1 ? (
              <div {...part("field")}>
                <label htmlFor="iamkit-key-resource" {...part("label")}>
                  {t("account.keys.resource")}
                </label>
                <select
                  id="iamkit-key-resource"
                  value={resource?.id ?? ""}
                  onChange={(e) => {
                    setResourceId(e.currentTarget.value);
                    setPicked([]);
                  }}
                  {...part("input")}
                >
                  {resources.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.name}
                    </option>
                  ))}
                </select>
              </div>
            ) : null}
            <fieldset {...part("field")}>
              <legend {...part("label")}>{t("account.keys.permissions")}</legend>
              {(resource?.permissions ?? []).map((p) => (
                <label key={p} {...part("label")}>
                  <input
                    type="checkbox"
                    name="permission"
                    value={p}
                    checked={picked.includes(p)}
                    onChange={(e) => {
                      const on = e.currentTarget.checked;
                      setPicked((cur) => (on ? [...cur, p] : cur.filter((x) => x !== p)));
                    }}
                  />
                  {p}
                </label>
              ))}
            </fieldset>
            <div {...part("field")}>
              <label htmlFor="iamkit-key-expires" {...part("label")}>
                {t("account.keys.expires")}
              </label>
              <select id="iamkit-key-expires" name="expires" defaultValue={maxDays === null ? "never" : String(days[days.length - 1])} {...part("input")}>
                {maxDays === null ? <option value="never">{t("account.never")}</option> : null}
                {days.map((d) => (
                  <option key={d} value={d}>
                    {t("account.keys.expires_in", String(d))}
                  </option>
                ))}
              </select>
            </div>
            <button type="submit" disabled={keys.busy || !resource} {...part("button")}>
              {t("account.keys.create")}
            </button>
          </form>
        </>
      ) : null}
    </div>
  );
}
