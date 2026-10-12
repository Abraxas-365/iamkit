import { useState, type FormEvent } from "react";
import { AccountScope, useAccount } from "./account-hooks.js";
import { ErrorLine, Field, Notice, field, kit, type AccountWidgetProps } from "./widget-kit.js";

/** A custom profile property edited by `<UserProfile>` (the environment's user schema). */
export interface ProfileField {
  name: string;
  label?: string;
  type?: "text" | "number" | "boolean";
}

export interface UserProfileProps extends AccountWidgetProps {
  /**
   * The custom profile properties to edit. Default: the primitive
   * properties the profile already has (IAMKit does not publish the schema
   * to users, so a property never set must be listed here to appear).
   */
  fields?: ProfileField[];
  /** Called after the name, avatar or properties were saved. */
  onSaved?: () => void;
}

function inferFields(properties: Record<string, unknown>): ProfileField[] {
  return Object.entries(properties)
    .filter(([, v]) => ["string", "number", "boolean"].includes(typeof v))
    .map(([name, v]) => ({ name, type: typeof v === "number" ? "number" : typeof v === "boolean" ? "boolean" : "text" }));
}

/**
 * Name, avatar, username (read-only), email, phone verification and the
 * custom profile properties of the signed-in user. Unstyled.
 */
export function UserProfile(props: UserProfileProps) {
  return (
    <AccountScope account={props.account} onReauthenticate={props.onReauthenticate}>
      <Profile {...props} />
    </AccountScope>
  );
}

function Profile(props: UserProfileProps) {
  const k = kit(props);
  const { t, part } = k;
  const me = useAccount();
  const [saved, setSaved] = useState("");
  const [pending, setPending] = useState<{ phone: string; destination: string }>();
  const [phoneNotice, setPhoneNotice] = useState("");
  const profile = me.profile;
  const fields = props.fields ?? inferFields(me.properties);

  if (me.loading && !profile) return <div {...part("root")} aria-busy="true" />;
  if (!profile) {
    return (
      <div {...part("root")}>
        <ErrorLine error={me.error} k={k} />
      </div>
    );
  }

  const saveProfile = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    setSaved("");
    const avatar = field(form, "avatar_url").trim();
    const ok = await me.updateProfile({ name: field(form, "name").trim(), avatarUrl: avatar === "" ? null : avatar });
    if (ok) {
      setSaved(t("account.profile.saved"));
      props.onSaved?.();
    }
  };

  const saveProperties = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    setSaved("");
    const patch: Record<string, unknown> = {};
    for (const f of fields) {
      if (f.type === "boolean") patch[f.name] = (form.elements.namedItem(f.name) as HTMLInputElement).checked;
      else {
        const raw = field(form, f.name).trim();
        patch[f.name] = raw === "" ? null : f.type === "number" ? Number(raw) : raw;
      }
    }
    if (await me.updateProperties(patch)) {
      setSaved(t("account.profile.saved"));
      props.onSaved?.();
    }
  };

  const startPhone = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const phone = field(e.currentTarget, "phone").trim();
    setPhoneNotice("");
    const destination = await me.phone.start(phone);
    if (destination !== undefined) setPending({ phone, destination });
  };

  const verifyPhone = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!pending) return;
    const code = field(e.currentTarget, "code").trim();
    if (await me.phone.verify(pending.phone, code)) {
      setPending(undefined);
      setPhoneNotice(t("account.phone.verified"));
    }
  };

  return (
    <div {...part("root")}>
      <h2 {...part("title")}>{t("account.profile.title")}</h2>
      <ErrorLine error={me.error} k={k} />
      <Notice k={k}>{saved}</Notice>
      <form onSubmit={saveProfile} {...part("form")} aria-label={t("account.profile.title")}>
        <Field k={k} label={t("account.profile.name")} name="name" defaultValue={profile.name} autoComplete="name" required />
        <Field k={k} label={t("account.profile.avatar")} name="avatar_url" type="url" defaultValue={profile.avatar_url} autoComplete="photo" />
        {profile.username ? <Field k={k} label={t("account.profile.username")} name="username" defaultValue={profile.username} readOnly /> : null}
        <Field k={k} label={t("account.profile.email")} name="email" defaultValue={profile.email} readOnly />
        <p {...part("meta")}>{profile.email_verified ? t("account.profile.verified") : t("account.profile.unverified")}</p>
        <button type="submit" disabled={me.busy} {...part("button")}>
          {t("account.save")}
        </button>
      </form>

      {fields.length > 0 ? (
        <form onSubmit={saveProperties} {...part("form")} aria-label={t("account.profile.details")}>
          <h3 {...part("subtitle")}>{t("account.profile.details")}</h3>
          {fields.map((f) =>
            f.type === "boolean" ? (
              <div key={f.name} {...part("field")}>
                <label {...part("label")}>
                  <input type="checkbox" name={f.name} defaultChecked={me.properties[f.name] === true} />
                  {f.label ?? f.name}
                </label>
              </div>
            ) : (
              <Field
                key={f.name}
                k={k}
                label={f.label ?? f.name}
                name={f.name}
                type={f.type === "number" ? "number" : "text"}
                defaultValue={me.properties[f.name] === undefined || me.properties[f.name] === null ? "" : String(me.properties[f.name])}
              />
            ),
          )}
          <button type="submit" disabled={me.busy} {...part("button")}>
            {t("account.save")}
          </button>
        </form>
      ) : null}

      <section {...part("section")} aria-label={t("account.phone.title")}>
        <h3 {...part("subtitle")}>{t("account.phone.title")}</h3>
        <Notice k={k}>{phoneNotice}</Notice>
        {profile.phone ? (
          <p {...part("meta")}>
            <span data-testid="phone">{profile.phone}</span> ({profile.phone_verified ? t("account.profile.verified") : t("account.profile.unverified")}){" "}
            <button
              type="button"
              disabled={me.busy}
              onClick={async () => {
                if (await me.phone.remove()) setPhoneNotice(t("account.phone.removed"));
              }}
              {...part("secondary")}
            >
              {t("account.remove")}
            </button>
          </p>
        ) : (
          <p {...part("meta")}>{t("account.phone.none")}</p>
        )}
        {pending ? (
          <form onSubmit={verifyPhone} {...part("form")} aria-label={t("account.phone.verify")}>
            <Notice k={k}>{t("account.phone.sent", pending.destination)}</Notice>
            <Field k={k} label={t("account.code")} name="code" inputMode="numeric" autoComplete="one-time-code" required />
            <button type="submit" disabled={me.busy} {...part("button")}>
              {t("account.phone.verify")}
            </button>
            <button type="button" onClick={() => setPending(undefined)} {...part("secondary")}>
              {t("account.cancel")}
            </button>
          </form>
        ) : (
          <form onSubmit={startPhone} {...part("form")} aria-label={t("account.phone.send")}>
            <Field k={k} label={t("account.phone.number")} name="phone" type="tel" autoComplete="tel" inputMode="tel" required />
            <button type="submit" disabled={me.busy} {...part("button")}>
              {t("account.phone.send")}
            </button>
          </form>
        )}
      </section>
    </div>
  );
}
