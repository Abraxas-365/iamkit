import { IAMKitError } from "@iamkit/js";
import type { FormEvent, ReactNode } from "react";
import { useInvitation } from "./hooks.js";
import type { ClassNames } from "./SignInForm.js";
import { translator } from "./texts.js";

export interface AcceptInvitationProps {
  /** The token from the invitation link. */
  token: string;
  texts?: Record<string, string>;
  classNames?: ClassNames;
  /** Rendered once accepted (e.g. a link to the application's sign-in). */
  children?: (accepted: { email: string; organizationId: string; ssoRequired: boolean; created: boolean }) => ReactNode;
}

const invitationTexts: Record<string, string> = {
  "hosted.invitation.title": "Invitation",
  "hosted.invitation.invalid": "This invitation is invalid or has expired.",
  "hosted.invitation.invited": "You were invited to join %s.",
  "hosted.invitation.join": "Join %s",
  "hosted.invitation.accepted": "Invitation accepted",
  "hosted.invitation.joined": "You joined %s. You can now sign in to the application.",
};

/** The invitation accept step of the hosted pages, unstyled. */
export function AcceptInvitation(props: AcceptInvitationProps) {
  const { token, classNames: cn = {}, children } = props;
  const t = translator(undefined, { ...invitationTexts, ...props.texts });
  const { preview, accepted, accept } = useInvitation(token);
  const part = (name: keyof ClassNames) => ({ "data-iamkit": name, className: cn[name] });
  const message = (err: unknown) => (err instanceof IAMKitError ? err.message : t("hosted.error.generic"));

  if (preview.loading) return <div {...part("root")} aria-busy="true" />;
  const invitation = preview.data;
  if (!invitation || invitation.status !== "pending") {
    return (
      <div {...part("root")}>
        <p role="alert" {...part("error")}>
          {preview.error ? message(preview.error) : t("hosted.invitation.invalid")}
        </p>
      </div>
    );
  }
  if (accepted.data) {
    const a = accepted.data;
    return (
      <div {...part("root")}>
        <h1 {...part("title")}>{t("hosted.invitation.accepted")}</h1>
        <p {...part("subtitle")}>{t("hosted.invitation.joined", invitation.organization_name)}</p>
        {children?.({ email: a.email, organizationId: a.organization_id, ssoRequired: a.sso_required, created: a.created })}
      </div>
    );
  }
  const onSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const d = new FormData(e.currentTarget);
    void accept({ name: String(d.get("name") ?? "") || undefined, password: String(d.get("password") ?? "") || undefined });
  };
  return (
    <div {...part("root")}>
      <h1 {...part("title")}>{t("hosted.invitation.title")}</h1>
      <p {...part("subtitle")}>{t("hosted.invitation.invited", invitation.organization_name)}</p>
      <p {...part("notice")}>{invitation.email}</p>
      {accepted.error ? (
        <p role="alert" {...part("error")}>
          {message(accepted.error)}
        </p>
      ) : null}
      <form onSubmit={onSubmit} {...part("form")}>
        {invitation.password_required ? (
          <>
            <label {...part("label")}>
              {t("hosted.form.name")}
              <input name="name" autoComplete="name" required {...part("input")} />
            </label>
            <label {...part("label")}>
              {t("hosted.form.password")}
              <input name="password" type="password" autoComplete="new-password" required {...part("input")} />
            </label>
          </>
        ) : null}
        <button type="submit" disabled={accepted.loading} {...part("button")}>
          {t("hosted.invitation.join", invitation.organization_name)}
        </button>
      </form>
    </div>
  );
}
