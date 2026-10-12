import { IAMKitError, isReauthenticationRequired, type Account } from "@iamkit/js";
import { useId, type ReactNode } from "react";
import { accountTranslator, type AccountTranslate } from "./account-texts.js";

/** Class names per part of the account widgets; every part also carries `data-iamkit="<part>"`. */
export interface AccountClassNames {
  root?: string;
  title?: string;
  section?: string;
  subtitle?: string;
  notice?: string;
  error?: string;
  form?: string;
  field?: string;
  label?: string;
  input?: string;
  button?: string;
  secondary?: string;
  danger?: string;
  list?: string;
  item?: string;
  badge?: string;
  meta?: string;
  codes?: string;
  secret?: string;
}

/** Props every account widget takes. */
export interface AccountWidgetProps {
  /** The self-service client; omit inside an `<AccountProvider>`. */
  account?: Account;
  /** Called on `REAUTHENTICATION_REQUIRED`: sign the user in again (`max_age=0`). */
  onReauthenticate?: () => void;
  /** Text overrides by `account.*` key (`accountTexts`). */
  texts?: Record<string, string>;
  classNames?: AccountClassNames;
}

export interface Kit {
  t: AccountTranslate;
  part: (name: keyof AccountClassNames, extra?: Record<string, string | undefined>) => Record<string, string | undefined>;
}

export function kit(props: Pick<AccountWidgetProps, "texts" | "classNames">): Kit {
  const cn = props.classNames ?? {};
  return {
    t: accountTranslator(props.texts),
    part: (name, extra) => ({ "data-iamkit": name, className: cn[name], ...extra }),
  };
}

/** The message of a failure: the server's, or a generic one. */
export function errorMessage(error: unknown, t: AccountTranslate): string {
  if (isReauthenticationRequired(error)) return t("account.error.reauthentication");
  if (error instanceof IAMKitError) return error.message;
  if (error instanceof Error && error.message) return error.message;
  return t("account.error.generic");
}

/** An error line (`role="alert"`) or nothing. */
export function ErrorLine(props: { error: unknown; k: Kit }) {
  if (!props.error) return <p aria-live="polite" role="presentation" hidden />;
  return (
    <p role="alert" aria-live="assertive" {...props.k.part("error")}>
      {errorMessage(props.error, props.k.t)}
    </p>
  );
}

/** A status line announced politely. */
export function Notice(props: { children?: ReactNode; k: Kit }) {
  if (!props.children) return null;
  return (
    <p role="status" aria-live="polite" {...props.k.part("notice")}>
      {props.children}
    </p>
  );
}

/** A label + input pair with a generated id. */
export function Field(props: {
  k: Kit;
  label: string;
  name: string;
  type?: string;
  defaultValue?: string;
  readOnly?: boolean;
  required?: boolean;
  autoComplete?: string;
  inputMode?: "numeric" | "tel" | "text";
  value?: string;
  onChange?: (value: string) => void;
  placeholder?: string;
}) {
  const id = useId();
  const { k, label, onChange, ...input } = props;
  return (
    <div {...k.part("field")}>
      <label htmlFor={id} {...k.part("label")}>
        {label}
      </label>
      <input id={id} {...k.part("input")} {...input} onChange={onChange ? (e) => onChange(e.currentTarget.value) : undefined} />
    </div>
  );
}

export function when(value: string | null | undefined, fallback = ""): string {
  if (!value) return fallback;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

/** Reads a named string out of a submitted form. */
export function field(form: HTMLFormElement, name: string): string {
  return String(new FormData(form).get(name) ?? "");
}
