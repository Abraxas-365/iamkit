import { IAMKitError, ErrorCodes, boundaryOf, type Authorization, type Boundary, type Enrollment, type MFAPending, type SignIn, type SignInResult } from "@iamkit/js";

/** The steps of a sign-in, mirroring IAMKit's hosted pages. */
export type Step =
  | "loading" // describing the ticket / redeeming a federation result
  | "identify" // email or username
  | "password"
  | "new_password" // the password expired: choose a new one
  | "code" // an emailed sign-in code was sent
  | "reset" // a password reset code was sent: code + new password
  | "ldap" // the organization's directory password
  | "mfa" // a second factor is pending
  | "enroll" // the organization requires an authenticator: scan, then verify
  | "signup" // name (+ password) for a new account
  | "signup_verify" // the emailed verification code
  | "redirecting" // leaving for the identity provider or back to the client
  | "failed"; // the ticket cannot continue (expired, other browser, …)

export interface FlowState {
  step: Step;
  /** The ticket's description: client, methods, connections, branding, texts. */
  authorization?: Authorization;
  /** The email or username being signed in. */
  login: string;
  /** A pending second factor (step `mfa`/`enroll`). */
  mfa?: MFAPending;
  /** Authenticator enrollment (step `enroll`): show `otpauth_uri` as a QR code. */
  enrollment?: Enrollment;
  /** Where a code was sent (mfa email/sms). */
  codeSentTo?: string;
  /** Recovery codes issued with the first enrollment: show them once. */
  recoveryCodes?: string[];
  /** The last failure; cleared by the next action. */
  error?: IAMKitError;
  /** An action is running. */
  busy: boolean;
  /** Where the browser goes next (step `redirecting`). */
  redirectTo?: string;
}

export interface FlowOptions {
  /** The authorization ticket (`?ticket=` on the page). */
  ticket: string;
  /**
   * The organization to sign in to when the authorize request named none
   * and the email's domain does not route to single sign-on. A function is
   * called with the identifier the user typed (empty for passkeys).
   */
  organization?: string | ((login: string) => string | undefined | Promise<string | undefined>);
  /**
   * The page single sign-on returns to (must be on an `allowed_origins`
   * origin of the client). Defaults to the current URL; the ticket is kept
   * in its query.
   */
  returnTo?: string;
  /** Navigates the browser; defaults to `location.assign`. */
  navigate?: (url: string) => void;
  /** The browser language sent with emailed codes. */
  locale?: string;
}

type Listener = () => void;

/**
 * A framework-free sign-in state machine over `@iamkit/js`: React binds it
 * with `useSignIn`, other UIs can subscribe directly. Every action resolves
 * once the state settled; failures land in `state.error`.
 */
export class SignInFlow {
  private current: FlowState = { step: "loading", login: "", busy: false };
  private listeners = new Set<Listener>();
  private challengeId = "";
  private password = "";
  private boundary?: Boundary;
  private connection = "";

  constructor(
    readonly iam: SignIn,
    private readonly options: FlowOptions,
  ) {}

  get state(): FlowState {
    return this.current;
  }

  subscribe = (listener: Listener): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  getSnapshot = (): FlowState => this.current;

  private set(patch: Partial<FlowState>) {
    this.current = { ...this.current, ...patch };
    for (const l of this.listeners) l();
  }

  private async run(action: () => Promise<void>): Promise<void> {
    if (this.current.busy) return;
    this.set({ busy: true, error: undefined });
    try {
      await action();
      this.set({ busy: false });
    } catch (err) {
      this.set({ busy: false, error: asError(err) });
    }
  }

  /**
   * Describes the ticket, or finishes a single sign-on that returned to
   * `location` (`federation_result` or `error` in its query).
   */
  start(location: string = typeof window !== "undefined" ? window.location.href : ""): Promise<void> {
    return this.run(async () => {
      let authorization: Authorization;
      try {
        authorization = await this.iam.authorization(this.options.ticket);
      } catch (err) {
        this.set({ step: "failed" });
        throw err;
      }
      const login = authorization.login_hint ?? "";
      this.set({ authorization, login, step: "identify" });
      if (location) {
        const back = await this.iam.federation.finish(location).catch((err) => {
          throw asError(err);
        }).finally(() => forget(location));
        if (back) {
          await this.signedIn(back);
        }
      }
    });
  }

  /** The organization to sign in to for this identifier. */
  private async organizationFor(login: string, discovered?: string | null): Promise<Boundary> {
    const authz = this.authorization();
    let organization = authz.organization_id ?? discovered ?? undefined;
    if (!organization) {
      const option = this.options.organization;
      organization = typeof option === "function" ? await option(login) : option;
    }
    if (!organization) {
      throw new IAMKitError(400, "ORGANIZATION_REQUIRED", "no organization to sign in to");
    }
    this.boundary = boundaryOf(authz, organization);
    return this.boundary;
  }

  private authorization(): Authorization {
    if (!this.current.authorization) {
      throw new IAMKitError(400, "NOT_STARTED", "call start() first");
    }
    return this.current.authorization;
  }

  /**
   * First step: routes the identifier. Emails of a domain with an
   * organization connection go to single sign-on (or the LDAP password);
   * the rest to the password step, or to an emailed code when password
   * sign-in is off.
   */
  identify(login: string): Promise<void> {
    return this.run(async () => {
      const authz = this.authorization();
      login = login.trim();
      this.set({ login });
      if (login.includes("@") && authz.methods.organization_sso) {
        const found = await this.iam.discover(authz.environment_id, login);
        if (found.method === "sso" && found.connection_id) {
          const boundary = await this.organizationFor(login, found.organization_id);
          if (found.provider === "ldap") {
            this.connection = found.connection_id;
            this.set({ step: "ldap" });
            return;
          }
          await this.redirectToProvider(boundary, found.connection_id);
          return;
        }
      }
      await this.organizationFor(login);
      if (authz.methods.password) {
        this.set({ step: "password" });
      } else if (authz.methods.email_code) {
        await this.sendCodeNow();
      } else {
        this.set({ step: "password" });
      }
    });
  }

  /** Back to the identifier step. */
  restart(): void {
    this.password = "";
    this.set({ step: "identify", error: undefined, mfa: undefined, enrollment: undefined, codeSentTo: undefined });
  }

  submitPassword(password: string): Promise<void> {
    return this.run(async () => {
      this.password = password;
      try {
        await this.signedIn(await this.iam.login(this.need(), { login: this.current.login, password }));
      } catch (err) {
        if (err instanceof IAMKitError && err.code === ErrorCodes.PasswordChangeRequired) {
          this.set({ step: "new_password" });
          return;
        }
        throw err;
      }
    });
  }

  /** Replaces an expired password (step `new_password`). */
  changePassword(newPassword: string): Promise<void> {
    return this.run(async () => {
      await this.signedIn(await this.iam.login(this.need(), { login: this.current.login, password: this.password, newPassword }));
    });
  }

  /** Emails a sign-in code (step `code`). */
  sendCode(): Promise<void> {
    return this.run(() => this.sendCodeNow());
  }

  private async sendCodeNow(): Promise<void> {
    const sent = await this.iam.sendCode({ environmentId: this.authorization().environment_id, login: this.current.login, purpose: "login", locale: this.options.locale });
    this.challengeId = sent.challengeId;
    this.set({ step: "code" });
  }

  verifyCode(code: string): Promise<void> {
    return this.run(async () => {
      await this.signedIn(await this.iam.verifyCode(this.need(), { challengeId: this.challengeId, code: code.trim() }));
    });
  }

  /** Emails a password reset code (step `reset`). */
  forgotPassword(): Promise<void> {
    return this.run(async () => {
      const sent = await this.iam.sendCode({ environmentId: this.authorization().environment_id, login: this.current.login, purpose: "password_reset", locale: this.options.locale });
      this.challengeId = sent.challengeId;
      this.set({ step: "reset" });
    });
  }

  /** Sets the new password, then signs in with it. */
  resetPassword(code: string, password: string): Promise<void> {
    return this.run(async () => {
      await this.iam.resetPassword({ environmentId: this.authorization().environment_id, challengeId: this.challengeId, code: code.trim(), password });
      this.password = password;
      await this.signedIn(await this.iam.login(this.need(), { login: this.current.login, password }));
    });
  }

  /** The organization's directory password (step `ldap`). */
  submitDirectoryPassword(password: string): Promise<void> {
    return this.run(async () => {
      await this.signedIn(await this.iam.federation.ldap(this.need(), { connectionId: this.connection, email: this.current.login, password }));
    });
  }

  /** Signs in with a passkey; nothing happens when the user dismissed it. */
  passkey(init: { mediation?: CredentialMediationRequirement; signal?: AbortSignal } = {}): Promise<void> {
    return this.run(async () => {
      const boundary = this.boundary ?? (await this.organizationFor(this.current.login));
      const out = await this.iam.passkey(boundary, init);
      if (out) await this.signedIn(out);
    });
  }

  /** Single sign-on with a social or organization connection of the ticket. */
  connect(connectionId: string): Promise<void> {
    return this.run(async () => {
      await this.redirectToProvider(this.boundary ?? (await this.organizationFor(this.current.login)), connectionId);
    });
  }

  private async redirectToProvider(boundary: Boundary, connectionId: string): Promise<void> {
    const url = await this.iam.federation.start(boundary, { connectionId, returnTo: this.returnTo() });
    this.go(url);
  }

  private returnTo(): string {
    if (this.options.returnTo) return this.options.returnTo;
    const here = new URL(window.location.href);
    here.search = "";
    here.hash = "";
    here.searchParams.set("ticket", this.options.ticket);
    return here.toString();
  }

  /** Answers the pending second factor with a code (authenticator, email, SMS, recovery). */
  verifyFactor(code: string): Promise<void> {
    return this.run(async () => {
      await this.signedIn({ status: "signed_in", tokens: await this.iam.mfa.verify(this.pending(), code.trim()) });
    });
  }

  /** Sends a code to the email or phone factor. */
  sendFactorCode(factor: "email" | "sms"): Promise<void> {
    return this.run(async () => {
      const sent = await this.iam.mfa.send(this.pending(), factor);
      this.set({ codeSentTo: sent.destination });
    });
  }

  /** Answers with a security key. */
  securityKey(): Promise<void> {
    return this.run(async () => {
      const tokens = await this.iam.mfa.securityKey(this.pending());
      if (tokens) await this.signedIn({ status: "signed_in", tokens });
    });
  }

  /** Starts authenticator enrollment (step `enroll`). */
  enroll(): Promise<void> {
    return this.run(async () => {
      this.set({ step: "enroll", enrollment: await this.iam.mfa.enroll(this.pending()) });
    });
  }

  /** Opens the sign-up step for the identifier. */
  beginSignup(): void {
    this.set({ step: "signup", error: undefined });
  }

  /** Emails the verification code of a new account. */
  signup(input: { email?: string; name: string; password?: string; acceptTerms?: boolean }): Promise<void> {
    return this.run(async () => {
      const email = (input.email ?? this.current.login).trim();
      this.set({ login: email });
      const sent = await this.iam.signup.start({ environmentId: this.authorization().environment_id, email, name: input.name, password: input.password, acceptTerms: input.acceptTerms, locale: this.options.locale });
      this.challengeId = sent.challengeId;
      this.password = input.password ?? "";
      this.set({ step: "signup_verify" });
    });
  }

  /** Creates the account, then signs in (with the password, else an emailed code). */
  verifySignup(code: string): Promise<void> {
    return this.run(async () => {
      const created = await this.iam.signup.verify({ environmentId: this.authorization().environment_id, challengeId: this.challengeId, code: code.trim() });
      const authz = this.authorization();
      this.boundary = boundaryOf(authz, authz.organization_id ?? created.organization_id);
      if (this.password) {
        await this.signedIn(await this.iam.login(this.boundary, { login: this.current.login, password: this.password }));
      } else {
        await this.sendCodeNow();
      }
    });
  }

  private async signedIn(result: SignInResult): Promise<void> {
    if (result.status === "mfa_required") {
      this.set({ step: "mfa", mfa: result.mfa, codeSentTo: undefined });
      if (result.mfa.enrollment_required) {
        this.set({ step: "enroll", enrollment: await this.iam.mfa.enroll(result.mfa.mfa_token) });
      }
      return;
    }
    this.password = "";
    const tokens = result.tokens;
    const url = await this.iam.complete(this.options.ticket, tokens.access_token);
    if (tokens.recovery_codes?.length) {
      // Shown once; the UI calls proceed() when the user saved them.
      this.set({ step: "redirecting", redirectTo: url, recoveryCodes: tokens.recovery_codes });
      return;
    }
    this.go(url);
  }

  /** Leaves for the client after the recovery codes were shown. */
  proceed(): void {
    if (this.current.redirectTo) this.go(this.current.redirectTo);
  }

  private go(url: string) {
    this.set({ step: "redirecting", redirectTo: url });
    (this.options.navigate ?? ((u) => window.location.assign(u)))(url);
  }
  private need(): Boundary {
    if (!this.boundary) {
      throw new IAMKitError(400, "ORGANIZATION_REQUIRED", "no organization to sign in to");
    }
    return this.boundary;
  }

  private pending(): string {
    if (!this.current.mfa) {
      throw new IAMKitError(400, "NO_PENDING_FACTOR", "no second factor is pending");
    }
    return this.current.mfa.mfa_token;
  }
}

function asError(err: unknown): IAMKitError {
  if (err instanceof IAMKitError) return err;
  return new IAMKitError(0, "NETWORK", err instanceof Error ? err.message : String(err));
}

// forget drops the one-time federation parameters from the address bar, so
// a reload does not redeem a spent result again.
function forget(location: string) {
  if (typeof window === "undefined" || !window.history?.replaceState || location !== window.location.href) return;
  const url = new URL(location);
  let changed = false;
  for (const name of ["federation_result", "error", "error_description"]) {
    if (url.searchParams.has(name)) {
      url.searchParams.delete(name);
      changed = true;
    }
  }
  if (changed) window.history.replaceState(window.history.state, "", url.toString());
}
