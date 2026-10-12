import type { Factor, Proof, TotpEnrollment } from "@iamkit/js";
import { useState, type FormEvent, type ReactNode } from "react";
import { AccountScope, usePassword, useFactors, type UseFactors } from "./account-hooks.js";
import { ErrorLine, Field, Notice, field, kit, when, type AccountWidgetProps, type Kit } from "./widget-kit.js";

export interface UserSecurityProps extends AccountWidgetProps {
  /** Renders the authenticator URI as a QR code; the secret and the URI are always shown too. */
  renderQRCode?: (otpauthURI: string) => ReactNode;
  /** Which sections to show (default: all). */
  sections?: ("password" | "factors" | "passkeys" | "recovery")[];
}

/**
 * Password change, second factors (authenticator app with an injectable QR
 * code, email and SMS codes), security keys and passkeys, and recovery
 * codes. Changes need a recent sign-in: `REAUTHENTICATION_REQUIRED` calls
 * `onReauthenticate`. Unstyled.
 */
export function UserSecurity(props: UserSecurityProps) {
  const show = (s: NonNullable<UserSecurityProps["sections"]>[number]) => !props.sections || props.sections.includes(s);
  return (
    <AccountScope account={props.account} onReauthenticate={props.onReauthenticate}>
      <div {...kit(props).part("root")}>
        {show("password") ? <PasswordSection {...props} /> : null}
        {show("factors") || show("passkeys") || show("recovery") ? <FactorSections {...props} show={show} /> : null}
      </div>
    </AccountScope>
  );
}

function PasswordSection(props: UserSecurityProps) {
  const k = kit(props);
  const { t, part } = k;
  const pw = usePassword();
  const [notice, setNotice] = useState("");
  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    setNotice("");
    const out = await pw.changePassword(field(form, "current_password"), field(form, "new_password"));
    if (out) {
      form.reset();
      setNotice(t("account.password.changed") + (out.sessions_revoked > 0 ? " " + t("account.password.signed_out", String(out.sessions_revoked)) : ""));
    }
  };
  return (
    <section {...part("section")} aria-label={t("account.password.title")}>
      <h2 {...part("title")}>{t("account.password.title")}</h2>
      <ErrorLine error={pw.error} k={k} />
      <Notice k={k}>{notice}</Notice>
      <form onSubmit={submit} {...part("form")} aria-label={t("account.password.change")}>
        <Field k={k} label={t("account.password.current")} name="current_password" type="password" autoComplete="current-password" required />
        <Field k={k} label={t("account.password.new")} name="new_password" type="password" autoComplete="new-password" required />
        <button type="submit" disabled={pw.busy} {...part("button")}>
          {t("account.password.change")}
        </button>
      </form>
    </section>
  );
}

type Adding = { kind: "totp"; enrollment: TotpEnrollment } | { kind: "email" | "sms"; destination: string } | { kind: "sms-phone" };
type Removing = { factor: Factor; sent?: string };

function factorLabel(f: Factor, t: Kit["t"]): string {
  if (f.kind === "webauthn") return f.name || (f.passkey ? t("account.mfa.passkey") : t("account.mfa.webauthn"));
  const base = t(`account.mfa.${f.kind}`);
  return f.kind === "sms" && f.phone ? `${base} (${f.phone})` : base;
}

function FactorSections(props: UserSecurityProps & { show: (s: "password" | "factors" | "passkeys" | "recovery") => boolean }) {
  const k = kit(props);
  const { t, part } = k;
  const f = useFactors();
  const [adding, setAdding] = useState<Adding>();
  const [removing, setRemoving] = useState<Removing>();
  const [recovering, setRecovering] = useState(false);
  const [codes, setCodes] = useState<string[]>();
  const [notice, setNotice] = useState("");
  const [local, setLocal] = useState<unknown>();

  if (f.loading && !f.summary && !f.error) return <div aria-busy="true" />;

  const kinds = new Set(f.factors.map((x) => x.kind));
  const coded = f.factors.filter((x) => x.kind !== "webauthn");
  const keys = f.factors.filter((x) => x.kind === "webauthn");
  const reset = () => {
    setNotice("");
    setLocal(undefined);
    f.clearError();
  };

  const finish = (out: string[] | undefined) => {
    if (out === undefined) return;
    setAdding(undefined);
    setNotice(t("account.mfa.enabled"));
    if (out.length > 0) setCodes(out);
  };

  const startTotp = async () => {
    reset();
    const enrollment = await f.totp.start();
    if (enrollment) setAdding({ kind: "totp", enrollment });
  };
  const startEmail = async () => {
    reset();
    const sent = await f.email.start();
    if (sent) setAdding({ kind: "email", destination: sent.destination });
  };
  const startSMS = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    reset();
    const sent = await f.sms.start(field(e.currentTarget, "phone").trim());
    if (sent) setAdding({ kind: "sms", destination: sent.destination });
  };
  const confirm = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!adding || adding.kind === "sms-phone") return;
    const code = field(e.currentTarget, "code").trim();
    finish(await f[adding.kind].confirm(code));
  };

  const proofRemove = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!removing) return;
    const proof: Proof = { code: field(e.currentTarget, "proof").trim() };
    const target = removing.factor;
    const ok = target.kind === "webauthn" ? await f.passkeys.remove(target.id, proof) : await f[target.kind as "totp" | "email" | "sms"].remove(proof.code);
    if (ok) {
      setRemoving(undefined);
      setNotice(t("account.mfa.removed"));
    }
  };
  const sendProof = async () => {
    reset();
    const channel = kinds.has("email") ? f.email : kinds.has("sms") ? f.sms : undefined;
    const sent = await channel?.send();
    if (sent && removing) setRemoving({ ...removing, sent: sent.destination });
  };
  const keyProof = async () => {
    if (!removing) return;
    reset();
    const proof = await f.passkeys.assert();
    if (!proof) return;
    const target = removing.factor;
    // The proof only works for security keys and passkeys; others take a code.
    const ok = target.kind === "webauthn" ? await f.passkeys.remove(target.id, proof) : false;
    if (ok) {
      setRemoving(undefined);
      setNotice(t("account.mfa.removed"));
    }
  };

  const proofForm = (title: string, submitLabel: string, onSubmit: (e: FormEvent<HTMLFormElement>) => void, onCancel: () => void, sent?: string) => (
    <form onSubmit={onSubmit} {...part("form")} aria-label={title}>
      <p {...part("subtitle")}>{title}</p>
      {sent ? <Notice k={k}>{t("account.mfa.code_sent", sent)}</Notice> : null}
      <Field k={k} label={t("account.mfa.prove_code")} name="proof" autoComplete="one-time-code" required />
      <button type="submit" disabled={f.busy} {...part("button")}>
        {submitLabel}
      </button>
      {kinds.has("email") || kinds.has("sms") ? (
        <button type="button" disabled={f.busy} onClick={() => void sendProof()} {...part("secondary")}>
          {t("account.mfa.send_proof")}
        </button>
      ) : null}
      {removing?.factor.kind === "webauthn" ? (
        <button type="button" disabled={f.busy} onClick={() => void keyProof()} {...part("secondary")}>
          {t("account.mfa.use_key")}
        </button>
      ) : null}
      <button type="button" onClick={onCancel} {...part("secondary")}>
        {t("account.cancel")}
      </button>
    </form>
  );

  const recover = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    reset();
    const out = await f.recoveryCodes(field(e.currentTarget, "proof").trim());
    if (out) {
      setRecovering(false);
      setCodes(out);
    }
  };

  const addPasskey = async (form: HTMLFormElement | null, passkey: boolean) => {
    if (!form) return;
    reset();
    const name = field(form, "name").trim() || (passkey ? t("account.mfa.passkey") : t("account.mfa.webauthn"));
    const out = await f.passkeys.add(name, { passkey });
    if (out === null) setNotice(t("account.passkeys.dismissed"));
    else if (out) {
      form.reset();
      setNotice(t("account.passkeys.added"));
      if (out.recovery_codes && out.recovery_codes.length > 0) setCodes(out.recovery_codes);
    }
  };

  const factorList = (list: Factor[], none: string) => (
    <>
      {list.length === 0 ? <p {...part("meta")}>{none}</p> : null}
      <ul {...part("list")}>
        {list.map((x) => (
          <li key={x.id} {...part("item", { "data-factor": x.id, "data-kind": x.kind })}>
            <strong>{factorLabel(x, t)}</strong>
            <span {...part("meta")}>
              {[t("account.mfa.added") + " " + when(x.created_at), x.last_used_at ? t("account.mfa.last_used", when(x.last_used_at)) : "", x.locked_until ? t("account.mfa.locked", when(x.locked_until)) : ""].filter(Boolean).join(" · ")}
            </span>
            <button
              type="button"
              disabled={f.busy}
              aria-label={`${t("account.remove")}: ${factorLabel(x, t)}`}
              onClick={() => {
                reset();
                setRemoving({ factor: x });
              }}
              {...part("danger")}
            >
              {t("account.remove")}
            </button>
          </li>
        ))}
      </ul>
    </>
  );

  return (
    <>
      <ErrorLine error={local ?? f.error} k={k} />
      <Notice k={k}>{notice}</Notice>

      {codes ? (
        <section {...part("section", { "data-state": "codes" })} aria-label={t("account.recovery.title")}>
          <h3 {...part("subtitle")}>{t("account.recovery.title")}</h3>
          <Notice k={k}>{t("account.recovery.hint")}</Notice>
          <ul {...part("codes")}>
            {codes.map((c) => (
              <li key={c}>
                <code>{c}</code>
              </li>
            ))}
          </ul>
          <button type="button" onClick={() => setCodes(undefined)} {...part("button")}>
            {t("account.recovery.saved")}
          </button>
        </section>
      ) : null}

      {removing
        ? proofForm(
            t("account.mfa.prove"),
            t("account.remove"),
            (e) => void proofRemove(e),
            () => setRemoving(undefined),
            removing.sent,
          )
        : null}

      {props.show("factors") ? (
        <section {...part("section")} aria-label={t("account.mfa.title")}>
          <h2 {...part("title")}>{t("account.mfa.title")}</h2>
          {f.lockedUntil ? <p {...part("meta")}>{t("account.mfa.locked", when(f.lockedUntil))}</p> : null}
          {factorList(coded, t("account.mfa.none"))}

          {adding?.kind === "totp" ? (
            <form onSubmit={(e) => void confirm(e)} {...part("form")} aria-label={t("account.mfa.add_totp")}>
              <p {...part("subtitle")}>{t("account.mfa.totp_hint")}</p>
              {props.renderQRCode ? props.renderQRCode(adding.enrollment.otpauth_uri) : null}
              <p {...part("notice")}>
                <code {...part("secret")} data-testid="totp-secret">
                  {adding.enrollment.secret}
                </code>
              </p>
              <p>
                <a href={adding.enrollment.otpauth_uri} data-testid="otpauth">
                  {t("account.mfa.totp_uri")}
                </a>
              </p>
              <Field k={k} label={t("account.mfa.enter_code")} name="code" inputMode="numeric" autoComplete="one-time-code" required />
              <button type="submit" disabled={f.busy} {...part("button")}>
                {t("account.confirm")}
              </button>
              <button type="button" onClick={() => setAdding(undefined)} {...part("secondary")}>
                {t("account.cancel")}
              </button>
            </form>
          ) : null}

          {adding?.kind === "email" || adding?.kind === "sms" ? (
            <form onSubmit={(e) => void confirm(e)} {...part("form")} aria-label={t("account.confirm")}>
              <Notice k={k}>{t("account.mfa.code_sent", adding.destination)}</Notice>
              <Field k={k} label={t("account.code")} name="code" inputMode="numeric" autoComplete="one-time-code" required />
              <button type="submit" disabled={f.busy} {...part("button")}>
                {t("account.confirm")}
              </button>
              <button type="button" onClick={() => setAdding(undefined)} {...part("secondary")}>
                {t("account.cancel")}
              </button>
            </form>
          ) : null}

          {adding?.kind === "sms-phone" ? (
            <form onSubmit={(e) => void startSMS(e)} {...part("form")} aria-label={t("account.mfa.add_sms")}>
              <Field k={k} label={t("account.mfa.phone")} name="phone" type="tel" autoComplete="tel" inputMode="tel" required />
              <button type="submit" disabled={f.busy} {...part("button")}>
                {t("account.mfa.send_code")}
              </button>
              <button type="button" onClick={() => setAdding(undefined)} {...part("secondary")}>
                {t("account.cancel")}
              </button>
            </form>
          ) : null}

          {!adding ? (
            <div {...part("field")}>
              {!kinds.has("totp") ? (
                <button type="button" disabled={f.busy} onClick={() => void startTotp()} {...part("button")}>
                  {t("account.mfa.add_totp")}
                </button>
              ) : null}
              {!kinds.has("email") ? (
                <button type="button" disabled={f.busy} onClick={() => void startEmail()} {...part("button")}>
                  {t("account.mfa.add_email")}
                </button>
              ) : null}
              {!kinds.has("sms") ? (
                <button
                  type="button"
                  disabled={f.busy}
                  onClick={() => {
                    reset();
                    setAdding({ kind: "sms-phone" });
                  }}
                  {...part("button")}
                >
                  {t("account.mfa.add_sms")}
                </button>
              ) : null}
            </div>
          ) : null}
        </section>
      ) : null}

      {props.show("passkeys") ? (
        <section {...part("section")} aria-label={t("account.passkeys.title")}>
          <h2 {...part("title")}>{t("account.passkeys.title")}</h2>
          {factorList(keys, t("account.passkeys.none"))}
          <form onSubmit={(e) => e.preventDefault()} {...part("form")} aria-label={t("account.passkeys.add_passkey")}>
            <Field k={k} label={t("account.passkeys.name")} name="name" />
            <button type="button" disabled={f.busy} onClick={(e) => void addPasskey(e.currentTarget.form, true)} {...part("button")}>
              {t("account.passkeys.add_passkey")}
            </button>
            <button type="button" disabled={f.busy} onClick={(e) => void addPasskey(e.currentTarget.form, false)} {...part("secondary")}>
              {t("account.passkeys.add_key")}
            </button>
          </form>
        </section>
      ) : null}

      {props.show("recovery") ? (
        <section {...part("section")} aria-label={t("account.recovery.title")}>
          <h2 {...part("title")}>{t("account.recovery.title")}</h2>
          <p {...part("meta")}>{t("account.recovery.remaining", String(f.recoveryCodesRemaining))}</p>
          {recovering ? (
            <form onSubmit={(e) => void recover(e)} {...part("form")} aria-label={t("account.recovery.regenerate")}>
              <p {...part("subtitle")}>{t("account.recovery.prove")}</p>
              <Field k={k} label={t("account.mfa.prove_code")} name="proof" autoComplete="one-time-code" required />
              <button type="submit" disabled={f.busy} {...part("button")}>
                {t("account.recovery.regenerate")}
              </button>
              <button type="button" onClick={() => setRecovering(false)} {...part("secondary")}>
                {t("account.cancel")}
              </button>
            </form>
          ) : (
            <button type="button" disabled={f.busy || coded.length + keys.length === 0} onClick={() => setRecovering(true)} {...part("button")}>
              {t("account.recovery.regenerate")}
            </button>
          )}
        </section>
      ) : null}
    </>
  );
}

export type { UseFactors };
