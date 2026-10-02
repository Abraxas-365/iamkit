import type { IAMKitError } from "@iamkit/js";
import { type FormEvent, type ReactNode } from "react";
import type { FlowOptions } from "./flow.js";
import { useSignIn } from "./hooks.js";
import { translator, type Translate } from "./texts.js";

/**
 * Class names per part, e.g. Tailwind utilities. Parts without a class are
 * unstyled; every element also carries `data-iamkit="<part>"` for CSS.
 */
export interface ClassNames {
  root?: string;
  title?: string;
  subtitle?: string;
  notice?: string;
  error?: string;
  form?: string;
  label?: string;
  input?: string;
  button?: string;
  secondary?: string;
  link?: string;
  divider?: string;
  codes?: string;
}

export interface SignInFormProps extends FlowOptions {
  /** Text overrides by hosted catalog key (`hosted.form.sign_in`, …). */
  texts?: Record<string, string>;
  classNames?: ClassNames;
  /** Shown when IAMKit refused an action; default: the error message. */
  renderError?: (error: IAMKitError, t: Translate) => ReactNode;
  /** Renders the authenticator URI as a QR code (step `enroll`). */
  renderQRCode?: (otpauthURI: string) => ReactNode;
}

/**
 * A complete sign-in for an authorization ticket, step by step like the
 * hosted pages: identifier, password or emailed code, passkey, single
 * sign-on, second factor and enrollment, expired password, reset and
 * sign-up. Unstyled; style it with `classNames` or `[data-iamkit]`.
 */
export function SignInForm(props: SignInFormProps) {
  const { texts, classNames: cn = {}, renderError, renderQRCode, ...options } = props;
  const { state, flow } = useSignIn(options);
  const authz = state.authorization;
  const t = translator(authz, texts);
  const methods = authz?.methods;
  const busy = state.busy;

  const part = (name: keyof ClassNames) => ({ "data-iamkit": name, className: cn[name] });
  const title = (key: string) => <h1 {...part("title")}>{t(key)}</h1>;
  const subtitle = (text: string) => <p {...part("subtitle")}>{text}</p>;
  const error = state.error ? (
    <p role="alert" {...part("error")}>
      {renderError ? renderError(state.error, t) : state.error.message || t("hosted.error.generic")}
    </p>
  ) : null;
  const submit = (label: string) => (
    <button type="submit" disabled={busy} {...part("button")}>
      {t(label)}
    </button>
  );
  const secondary = (label: string, onClick: () => void, text?: string) => (
    <button type="button" disabled={busy} onClick={onClick} {...part("secondary")}>
      {text ?? t(label)}
    </button>
  );
  const field = (name: string, label: string, props: Record<string, unknown> = {}) => (
    <label {...part("label")}>
      {t(label)}
      <input name={name} required disabled={busy} {...part("input")} {...props} />
    </label>
  );
  const form = (onSubmit: (data: FormData) => void, children: ReactNode) => (
    <form
      {...part("form")}
      onSubmit={(e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        onSubmit(new FormData(e.currentTarget));
      }}
    >
      {children}
    </form>
  );
  const value = (data: FormData, name: string) => String(data.get(name) ?? "");
  const startOver = secondary("hosted.form.other_email", () => flow.restart());

  let body: ReactNode;
  switch (state.step) {
    case "loading":
      body = <p {...part("subtitle")} aria-busy="true" />;
      break;
    case "failed":
      body = (
        <>
          {title("hosted.title.expired")}
          {subtitle(t("hosted.expired"))}
        </>
      );
      break;
    case "identify":
      body = (
        <>
          {title("hosted.title.sign_in")}
          {error}
          {form(
            (d) => void flow.identify(value(d, "login")),
            <>
              {field("login", "hosted.form.login", { type: "text", autoComplete: "username webauthn", defaultValue: state.login, autoFocus: true })}
              {submit("hosted.form.continue")}
            </>,
          )}
          {methods?.passkey ? secondary("hosted.form.passkey", () => void flow.passkey()) : null}
          {authz?.connections?.length ? (
            <>
              <p {...part("divider")}>{t("hosted.form.or")}</p>
              {authz.connections.map((c) => (
                <button key={c.id} type="button" disabled={busy} onClick={() => void flow.connect(c.id)} {...part("secondary")}>
                  {t("hosted.form.continue_with", c.name)}
                </button>
              ))}
            </>
          ) : null}
          {methods?.signup ? secondary("hosted.form.create_account", () => flow.beginSignup()) : null}
        </>
      );
      break;
    case "password":
      body = (
        <>
          {title("hosted.title.sign_in")}
          {subtitle(state.login)}
          {error}
          {form(
            (d) => void flow.submitPassword(value(d, "password")),
            <>
              {field("password", "hosted.form.password", { type: "password", autoComplete: "current-password", autoFocus: true })}
              {submit("hosted.form.sign_in")}
            </>,
          )}
          {methods?.email_code ? secondary("hosted.form.email_code", () => void flow.sendCode()) : null}
          {methods?.password_reset ? secondary("hosted.form.forgot_password", () => void flow.forgotPassword()) : null}
          {startOver}
        </>
      );
      break;
    case "new_password":
      body = (
        <>
          {title("hosted.title.password_expired")}
          {subtitle(t("hosted.subtitle.password_expired"))}
          {error}
          {form(
            (d) => void flow.changePassword(value(d, "new_password")),
            <>
              {field("new_password", "hosted.form.new_password", { type: "password", autoComplete: "new-password", autoFocus: true })}
              {submit("hosted.form.set_password")}
            </>,
          )}
        </>
      );
      break;
    case "code":
      body = (
        <>
          {title("hosted.title.check_email")}
          <p {...part("notice")}>{t("hosted.notice.code_sent", state.login)}</p>
          {error}
          {form(
            (d) => void flow.verifyCode(value(d, "code")),
            <>
              {field("code", "hosted.form.code", { inputMode: "numeric", autoComplete: "one-time-code", autoFocus: true })}
              {submit("hosted.form.verify")}
            </>,
          )}
          {startOver}
        </>
      );
      break;
    case "reset":
      body = (
        <>
          {title("hosted.title.reset")}
          <p {...part("notice")}>{t("hosted.notice.reset_sent", state.login)}</p>
          {error}
          {form(
            (d) => void flow.resetPassword(value(d, "code"), value(d, "new_password")),
            <>
              {field("code", "hosted.form.code", { inputMode: "numeric", autoComplete: "one-time-code", autoFocus: true })}
              {field("new_password", "hosted.form.new_password", { type: "password", autoComplete: "new-password" })}
              {submit("hosted.form.set_password")}
            </>,
          )}
          {startOver}
        </>
      );
      break;
    case "ldap":
      body = (
        <>
          {title("hosted.title.sign_in")}
          {subtitle(t("hosted.directory.hint"))}
          {error}
          {form(
            (d) => void flow.submitDirectoryPassword(value(d, "password")),
            <>
              {field("password", "hosted.form.password", { type: "password", autoComplete: "current-password", autoFocus: true })}
              {submit("hosted.form.sign_in")}
            </>,
          )}
          {startOver}
        </>
      );
      break;
    case "mfa": {
      const factors = state.mfa?.factors ?? [];
      body = (
        <>
          {title("hosted.title.mfa")}
          {subtitle(t("hosted.subtitle.mfa"))}
          {state.codeSentTo ? <p {...part("notice")}>{t("hosted.notice.factor_sent_email", state.codeSentTo)}</p> : null}
          {error}
          {form(
            (d) => void flow.verifyFactor(value(d, "code")),
            <>
              {field("code", "hosted.form.code", { autoComplete: "one-time-code", autoFocus: true })}
              {submit("hosted.form.verify")}
            </>,
          )}
          {factors.includes("webauthn") ? secondary("hosted.form.security_key", () => void flow.securityKey()) : null}
          {factors.includes("email") ? secondary("hosted.form.factor_email", () => void flow.sendFactorCode("email")) : null}
          {factors.includes("sms") ? secondary("hosted.form.factor_sms", () => void flow.sendFactorCode("sms")) : null}
        </>
      );
      break;
    }
    case "enroll":
      body = (
        <>
          {title("hosted.title.enroll")}
          {subtitle(t("hosted.subtitle.enroll"))}
          {state.enrollment && renderQRCode ? renderQRCode(state.enrollment.otpauth_uri) : null}
          {state.enrollment ? (
            <p {...part("notice")}>
              {t("hosted.form.cant_scan")} <code>{state.enrollment.secret}</code>
            </p>
          ) : null}
          {error}
          {form(
            (d) => void flow.verifyFactor(value(d, "code")),
            <>
              {field("code", "hosted.form.six_digit_code", { inputMode: "numeric", autoComplete: "one-time-code", autoFocus: true })}
              {submit("hosted.form.verify_continue")}
            </>,
          )}
        </>
      );
      break;
    case "signup":
      body = <Signup flow={flow} t={t} part={part} error={error} field={field} form={form} submit={submit} value={value} terms={!!methods?.terms} login={state.login} startOver={startOver} />;
      break;
    case "signup_verify":
      body = (
        <>
          {title("hosted.title.check_email")}
          <p {...part("notice")}>{t("hosted.notice.signup_sent", state.login)}</p>
          {error}
          {form(
            (d) => void flow.verifySignup(value(d, "code")),
            <>
              {field("code", "hosted.form.code", { inputMode: "numeric", autoComplete: "one-time-code", autoFocus: true })}
              {submit("hosted.form.verify")}
            </>,
          )}
        </>
      );
      break;
    case "redirecting":
      body = state.recoveryCodes?.length ? (
        <>
          {title("hosted.title.recovery")}
          {subtitle(t("hosted.subtitle.recovery"))}
          <ul {...part("codes")}>
            {state.recoveryCodes.map((c) => (
              <li key={c}>
                <code>{c}</code>
              </li>
            ))}
          </ul>
          <button type="button" onClick={() => flow.proceed()} {...part("button")}>
            {t("hosted.form.codes_saved")}
          </button>
        </>
      ) : (
        <>{title("hosted.title.redirecting")}</>
      );
      break;
  }
  return (
    <div {...part("root")} data-step={state.step} aria-busy={busy}>
      {body}
    </div>
  );
}

function Signup(props: {
  flow: ReturnType<typeof useSignIn>["flow"];
  t: Translate;
  part: (name: keyof ClassNames) => { "data-iamkit": string; className?: string };
  error: ReactNode;
  field: (name: string, label: string, props?: Record<string, unknown>) => ReactNode;
  form: (onSubmit: (data: FormData) => void, children: ReactNode) => ReactNode;
  submit: (label: string) => ReactNode;
  value: (data: FormData, name: string) => string;
  terms: boolean;
  login: string;
  startOver: ReactNode;
}) {
  const { flow, t, part, error, field, form, submit, value, terms, startOver } = props;
  return (
    <>
      <h1 {...part("title")}>{t("hosted.title.signup")}</h1>
      {error}
      {form(
        (d) => void flow.signup({ email: value(d, "email"), name: value(d, "name"), password: value(d, "password") || undefined, acceptTerms: d.get("accept_terms") === "on" }),
        <>
          {field("email", "hosted.form.email", { type: "email", autoComplete: "email", defaultValue: props.login.includes("@") ? props.login : "" })}
          {field("name", "hosted.form.name", { autoComplete: "name", autoFocus: true })}
          <label {...part("label")}>
            {t("hosted.form.password")} {t("hosted.form.optional")}
            <input name="password" type="password" autoComplete="new-password" {...part("input")} />
          </label>
          {terms ? (
            <label {...part("label")}>
              <input name="accept_terms" type="checkbox" required /> {t("hosted.form.accept_terms")}
            </label>
          ) : null}
          {submit("hosted.form.create_account")}
        </>,
      )}
      {startOver}
    </>
  );
}
