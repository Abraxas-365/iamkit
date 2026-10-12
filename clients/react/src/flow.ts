import { IAMKitError, ErrorCodes, RiskChallengeReason, boundaryOf, type Authorization, type Boundary, type CaptchaWidget, type Enrollment, type MFAPending, type SignIn, type SignInResult } from "@iamkit/js";

/** The steps of a sign-in, mirroring IAMKit's hosted pages. */
export type Step =
  | "loading" // describing the ticket / redeeming a federation result
  | "identify" // email or username
  | "password"
  | "new_password" // the password expired: choose a new one
  | "code" // an emailed sign-in code was sent
  | "reset" // a password reset code was sent: code + new password
  | "ldap" // the organization's directory password
  | "captcha" // bot protection: solve the widget (`state.captcha`), the pending action then resumes
  | "risk_challenge" // an unusual sign-in: an emailed code (sent on entry), answered with `verifyFactor`
  | "blocked" // a restriction or risk rule refused the sign-in (`state.error` says why)
  | "mfa" // a second factor is pending
  | "enroll" // the organization requires an authenticator: scan, then verify
  | "signup" // name (+ password) for a new account
  | "signup_verify" // the emailed verification code
  | "waitlisted" // the environment's waitlist took the sign-up: no code was sent, wait for the approval email
  | "redirecting" // leaving for the identity provider or back to the client
  | "failed"; // the ticket cannot continue (expired, other browser, …)

export interface FlowState {
  step: Step;
  /** The ticket's description: client, methods, connections, branding, texts. */
  authorization?: Authorization;
  /** The email or username being signed in. */
  login: string;
  /** A pending second factor (step `mfa`/`enroll`/`risk_challenge`). */
  mfa?: MFAPending;
  /**
   * The bot-protection widget the headless sign-in needs (the ticket's
   * `captcha`, or what a `CAPTCHA_REQUIRED` answer led to). Render it
   * (`<Captcha>`) and hand its answer to `setCaptchaToken`.
   */
  captcha?: CaptchaWidget;
  /** The widget's current answer, spent by the next protected call. */
  captchaToken?: string;
  /** Changes after every protected call: use it as the widget's `key` so it is solved afresh. */
  captchaRound: number;
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
  /**
   * The approval token of a waitlist link (`?waitlist=<token>` on the
   * sign-up page). It is sent with the sign-up, which then skips the
   * waitlist; the email must be the approved one.
   */
  waitlistToken?: string;
}

type Listener = () => void;

/**
 * A framework-free sign-in state machine over `@iamkit/js`: React binds it
 * with `useSignIn`, other UIs can subscribe directly. Every action resolves
 * once the state settled; failures land in `state.error`.
 */
export class SignInFlow {
  private current: FlowState = { step: "loading", login: "", busy: false, captchaRound: 0 };
  private resume?: () => Promise<void>;
  private resumeStep: Step = "identify";
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
      const error = asError(err);
      this.set({ busy: false, error, ...(refused.has(error.code) ? { step: "blocked" as const } : {}) });
    }
  }

  /**
   * Hands over the widget's answer. In step `captcha` the action that was
   * waiting for it resumes; elsewhere it is kept for the next protected
   * call (password, code and reset requests, sign-up, directory login).
   */
  setCaptchaToken(token: string): Promise<void> {
    this.set({ captchaToken: token });
    const resume = this.resume;
    if (this.current.step === "captcha" && resume) {
      this.resume = undefined;
      return this.run(resume);
    }
    return Promise.resolve();
  }

  /** The widget's answer expired or failed: forget it and render a fresh widget. */
  expireCaptcha(): void {
    this.set({ captchaToken: undefined, captchaRound: this.current.captchaRound + 1 });
  }

  /**
   * Runs a call that carries the CAPTCHA answer. Without one (and a widget
   * to solve) the flow moves to step `captcha` and `resume` runs once it is
   * handed over; a `CAPTCHA_REQUIRED` answer does the same with a fresh
   * widget. The answer is single use: it is spent whatever the outcome.
   */
  private async protect(resume: () => Promise<void>, call: (captchaToken: string | undefined) => Promise<void>): Promise<void> {
    if (this.current.captcha && !this.current.captchaToken) {
      this.pause(resume);
      return;
    }
    const token = this.current.captchaToken;
    if (this.current.step === "captcha") {
      // Back to the step the user was on: a failed call stays there.
      this.set({ step: this.resumeStep });
    }
    if (token) {
      this.set({ captchaToken: undefined, captchaRound: this.current.captchaRound + 1 });
    }
    try {
      await call(token);
    } catch (err) {
      if (err instanceof IAMKitError && err.code === ErrorCodes.CaptchaRequired && (await this.askCaptcha())) {
        this.set({ captchaToken: undefined, captchaRound: this.current.captchaRound + 1, error: err });
        this.pause(resume);
        return;
      }
      throw err;
    }
  }

  private pause(resume: () => Promise<void>): void {
    this.resume = resume;
    if (this.current.step !== "captcha") {
      this.resumeStep = this.current.step;
    }
    this.set({ step: "captcha" });
  }

  // askCaptcha makes sure a widget is known after CAPTCHA_REQUIRED: the
  // ticket's, else the environment's public configuration.
  private async askCaptcha(): Promise<boolean> {
    if (this.current.captcha) {
      return true;
    }
    const found = await this.iam.getCaptchaConfig(this.authorization().environment_id).catch(() => undefined);
    if (found?.enabled && found.provider && found.site_key) {
      this.set({ captcha: { provider: found.provider, site_key: found.site_key } });
      return true;
    }
    return false;
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
      this.set({ authorization, login, step: "identify", captcha: authorization.captcha });
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
    this.resume = undefined;
    this.set({ step: "identify", error: undefined, mfa: undefined, enrollment: undefined, codeSentTo: undefined });
  }

  submitPassword(password: string): Promise<void> {
    const attempt = (): Promise<void> =>
      this.protect(attempt, async (captchaToken) => {
        this.password = password;
        try {
          await this.signedIn(await this.iam.login(this.need(), { login: this.current.login, password, captchaToken }));
        } catch (err) {
          if (err instanceof IAMKitError && err.code === ErrorCodes.PasswordChangeRequired) {
            this.set({ step: "new_password" });
            return;
          }
          throw err;
        }
      });
    return this.run(attempt);
  }

  /** Replaces an expired password (step `new_password`). */
  changePassword(newPassword: string): Promise<void> {
    const attempt = (): Promise<void> =>
      this.protect(attempt, async (captchaToken) => {
        await this.signedIn(await this.iam.login(this.need(), { login: this.current.login, password: this.password, newPassword, captchaToken }));
      });
    return this.run(attempt);
  }

  /** Emails a sign-in code (step `code`). */
  sendCode(): Promise<void> {
    return this.run(() => this.sendCodeNow());
  }

  private sendCodeNow(): Promise<void> {
    return this.protect(
      () => this.sendCodeNow(),
      async (captchaToken) => {
        const sent = await this.iam.sendCode({ environmentId: this.authorization().environment_id, login: this.current.login, purpose: "login", locale: this.options.locale, captchaToken });
        this.challengeId = sent.challengeId;
        this.set({ step: "code" });
      },
    );
  }

  verifyCode(code: string): Promise<void> {
    return this.run(async () => {
      await this.signedIn(await this.iam.verifyCode(this.need(), { challengeId: this.challengeId, code: code.trim() }));
    });
  }

  /** Emails a password reset code (step `reset`). */
  forgotPassword(): Promise<void> {
    const attempt = (): Promise<void> =>
      this.protect(attempt, async (captchaToken) => {
        const sent = await this.iam.sendCode({ environmentId: this.authorization().environment_id, login: this.current.login, purpose: "password_reset", locale: this.options.locale, captchaToken });
        this.challengeId = sent.challengeId;
        this.set({ step: "reset" });
      });
    return this.run(attempt);
  }

  /** Sets the new password, then signs in with it. */
  resetPassword(code: string, password: string): Promise<void> {
    let reset = false;
    const attempt = (): Promise<void> => {
      // The code is spent by the reset: a CAPTCHA pause before the sign-in must not repeat it.
      return this.protect(attempt, async (captchaToken) => {
        if (!reset) {
          await this.iam.resetPassword({ environmentId: this.authorization().environment_id, challengeId: this.challengeId, code: code.trim(), password });
          reset = true;
        }
        this.password = password;
        await this.signedIn(await this.iam.login(this.need(), { login: this.current.login, password, captchaToken }));
      });
    };
    return this.run(attempt);
  }

  /** The organization's directory password (step `ldap`). */
  submitDirectoryPassword(password: string): Promise<void> {
    const attempt = (): Promise<void> =>
      this.protect(attempt, async (captchaToken) => {
        await this.signedIn(await this.iam.federation.ldap(this.need(), { connectionId: this.connection, email: this.current.login, password, captchaToken }));
      });
    return this.run(attempt);
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

  /**
   * Emails the verification code of a new account. With the environment's
   * waitlist on (and no valid `waitlistToken`) nothing is sent: the step
   * becomes `waitlisted` instead.
   */
  signup(input: { email?: string; name: string; password?: string; acceptTerms?: boolean }): Promise<void> {
    const attempt = (): Promise<void> =>
      this.protect(attempt, async (captchaToken) => {
        const email = (input.email ?? this.current.login).trim();
        this.set({ login: email });
        const sent = await this.iam.signup.start({ environmentId: this.authorization().environment_id, email, name: input.name, password: input.password, acceptTerms: input.acceptTerms, locale: this.options.locale, waitlistToken: this.options.waitlistToken, captchaToken });
        if (sent.status === "waitlisted") {
          this.set({ step: "waitlisted" });
          return;
        }
        this.challengeId = sent.challengeId;
        this.password = input.password ?? "";
        this.set({ step: "signup_verify" });
      });
    return this.run(attempt);
  }

  /** Creates the account, then signs in (with the password, else an emailed code). */
  verifySignup(code: string): Promise<void> {
    return this.run(async () => {
      const created = await this.iam.signup.verify({ environmentId: this.authorization().environment_id, challengeId: this.challengeId, code: code.trim() });
      const authz = this.authorization();
      this.boundary = boundaryOf(authz, authz.organization_id ?? created.organization_id);
      if (this.password) {
        await this.protect(
          () => this.signInAfterSignup(),
          (captchaToken) => this.signInAfterSignup(captchaToken),
        );
      } else {
        await this.sendCodeNow();
      }
    });
  }

  private async signInAfterSignup(captchaToken?: string): Promise<void> {
    await this.signedIn(await this.iam.login(this.need(), { login: this.current.login, password: this.password, captchaToken }));
  }

  private async signedIn(result: SignInResult): Promise<void> {
    if (result.status === "mfa_required") {
      if (result.mfa.reason === RiskChallengeReason && result.mfa.factors?.includes("email") && !result.mfa.enrollment_required) {
        // An unusual sign-in: the same emailed code as the `code` step, sent at once.
        this.set({ step: "risk_challenge", mfa: result.mfa, codeSentTo: undefined });
        const sent = await this.iam.mfa.send(result.mfa.mfa_token, "email");
        this.set({ codeSentTo: sent.destination });
        return;
      }
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

// Answers that end a sign-in: a restriction or risk rule refused it, or a
// risk challenge cannot be sent. Retrying with the same input cannot help.
const refused = new Set<string>([ErrorCodes.SignInBlocked, ErrorCodes.RiskChallenge, ErrorCodes.ChallengeUnavailable]);

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
