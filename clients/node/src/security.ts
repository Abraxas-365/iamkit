import { invalidArgument } from "./errors.js";
import { Transport, withQuery, type FetchLike } from "./http.js";

export type CaptchaProvider = "turnstile" | "hcaptcha";

/** The environment's CAPTCHA (bot protection) configuration; the secret is never returned. */
export interface CaptchaConfig {
  environment_id: string;
  provider: CaptchaProvider | (string & {});
  site_key: string;
  has_secret: boolean;
  /** Protect the hosted sign-in pages. */
  hosted: boolean;
  /** Ask headless clients for `captcha_token`. */
  headless: boolean;
  /** Extra hostnames accepted for headless widgets. */
  hostnames: string[];
  updated_at: string;
}

/** Saves the CAPTCHA configuration. Omit `secret` on an update to keep the stored one. */
export interface CaptchaInput {
  provider: CaptchaProvider;
  site_key: string;
  secret?: string;
  hosted?: boolean;
  headless?: boolean;
  hostnames?: string[];
}

export type RiskDetection = "ip_velocity" | "user_brute_force" | "impossible_travel" | "new_device" | "stale_account";
export type RiskAction = "off" | "log" | "notify" | "challenge" | "block";

export interface RiskThresholds {
  ip_failures_per_hour: number;
  ip_distinct_logins_per_hour: number;
  user_failures_per_hour: number;
  stale_after_days: number;
  travel_speed_kmh: number;
}

/** The risk policy; `saved` is false for the default (every detection off). */
export interface RiskPolicy {
  environment_id: string;
  actions: Partial<Record<RiskDetection, RiskAction>> & Record<string, string>;
  thresholds: RiskThresholds;
  notify_user: boolean;
  block_if_unverifiable: boolean;
  saved: boolean;
  updated_at?: string;
}

export interface RiskPolicyInput {
  /** Action per detection; missing detections stay off. */
  actions: Partial<Record<RiskDetection, RiskAction>>;
  thresholds?: Partial<RiskThresholds>;
  notify_user?: boolean;
  block_if_unverifiable?: boolean;
}

export type RestrictionKind = "ip" | "country" | "email_domain";

export interface RiskRestriction {
  id: string;
  environment_id: string;
  kind: RestrictionKind | (string & {});
  value: string;
  action: "allow" | "deny" | (string & {});
  note: string;
  created_at: string;
}

export interface NewRiskRestriction {
  kind: RestrictionKind;
  /** An IP or CIDR, an ISO country code or a domain, by `kind`. */
  value: string;
  action: "allow" | "deny";
  note?: string;
}

/** One entry of the sign-in attempt log. The login typed is never stored. */
export interface SignInAttempt {
  id: string;
  environment_id: string;
  user_id?: string;
  organization_id?: string | null;
  ip?: string;
  user_agent?: string;
  country?: string;
  latitude?: number | null;
  longitude?: number | null;
  /** A device id was sent. */
  device: boolean;
  method: string;
  /** `hosted` or `headless`. */
  surface: string;
  /** `success`, `failure`, `blocked`, `challenged` or `captcha_failed`. */
  outcome: string;
  reason?: string;
  detections: string[];
  /** The strongest action taken. */
  action: string;
  /** `passed`, `failed` or `unavailable`; absent when no CAPTCHA applied. */
  captcha?: string;
  created_at: string;
}

export interface SignInAttemptFilter {
  userId?: string;
  ip?: string;
  outcome?: string;
  detection?: string;
  country?: string;
  /** The previous page's `next`. */
  before?: string;
  limit?: number;
}

/** One page of attempts, newest first; pass `next` as `before` for the following page. */
export interface SignInAttemptPage {
  items: SignInAttempt[];
  next?: string;
}

/** A device a user signed in from (never its id). */
export interface UserDevice {
  first_seen_at: string;
  last_seen_at: string;
  last_ip?: string;
  last_country?: string;
  user_agent?: string;
}

/** What the deployment supports for the environment. */
export interface SecurityStatus {
  geoip: {
    /** `none`, `mmdb` or `header`. */
    source: string;
    database?: string;
    header?: string;
    build_date?: string | null;
    countries: boolean;
    travel: boolean;
    error?: string;
  };
  captcha: boolean;
  risk_signals: boolean;
}

export interface SecurityClientOptions {
  baseUrl: string;
  /** An access token (or machine API key) with iam:security:read/write; a function is called per request. */
  token: string | (() => string | undefined | Promise<string | undefined>);
  fetch?: FetchLike;
  timeoutMs?: number;
}

/**
 * Server-side management of bot protection and risk signals (`/api/v1`):
 * the environment's CAPTCHA, risk policy, allow/deny restrictions, the
 * sign-in attempt log, a user's devices and the deployment status. Failures
 * throw IAMKitError.
 */
export class SecurityClient {
  private readonly http: Transport;
  private readonly token: SecurityClientOptions["token"];

  constructor(options: SecurityClientOptions) {
    if (!options.token) {
      throw invalidArgument("token is required");
    }
    this.http = new Transport(options);
    this.token = options.token;
  }

  /** Reads the CAPTCHA configuration (404 `NOT_FOUND` when there is none). */
  async getCaptcha(environmentId: string): Promise<CaptchaConfig> {
    return this.call("GET", `${env(environmentId)}/captcha`);
  }

  /** Creates or replaces the CAPTCHA configuration (the secret is checked with the provider). */
  async setCaptcha(environmentId: string, input: CaptchaInput): Promise<CaptchaConfig> {
    return this.call("PUT", `${env(environmentId)}/captcha`, input);
  }

  /** Removes the CAPTCHA configuration: sign-in no longer asks for it. */
  async deleteCaptcha(environmentId: string): Promise<void> {
    await this.call("DELETE", `${env(environmentId)}/captcha`);
  }

  /** Checks the stored secret with the provider (resolves when accepted; 422 otherwise). */
  async testCaptcha(environmentId: string): Promise<void> {
    await this.call("POST", `${env(environmentId)}/captcha/test`);
  }

  /** Reads the risk policy (the default when none was saved). */
  async getRiskPolicy(environmentId: string): Promise<RiskPolicy> {
    return this.call("GET", `${env(environmentId)}/risk-policy`);
  }

  /** Replaces the risk policy. */
  async setRiskPolicy(environmentId: string, input: RiskPolicyInput): Promise<RiskPolicy> {
    return this.call("PUT", `${env(environmentId)}/risk-policy`, input);
  }

  /** Returns to the default policy (every detection off). */
  async deleteRiskPolicy(environmentId: string): Promise<void> {
    await this.call("DELETE", `${env(environmentId)}/risk-policy`);
  }

  /** Lists the allow/deny rules, optionally by `kind` and `action`. */
  async listRestrictions(environmentId: string, filter: { kind?: RestrictionKind; action?: "allow" | "deny" } = {}): Promise<RiskRestriction[]> {
    const out = await this.call<{ items: RiskRestriction[] | null }>("GET", withQuery(`${env(environmentId)}/risk-restrictions`, { kind: filter.kind, action: filter.action }));
    return out.items ?? [];
  }

  /** Adds a rule (409 for a duplicate kind and value). */
  async createRestriction(environmentId: string, input: NewRiskRestriction): Promise<RiskRestriction> {
    return this.call("POST", `${env(environmentId)}/risk-restrictions`, input);
  }

  /** Removes a rule. */
  async deleteRestriction(environmentId: string, id: string): Promise<void> {
    await this.call("DELETE", `${env(environmentId)}/risk-restrictions/${segment(id, "restriction id")}`);
  }

  /** Reads one page of the sign-in attempt log, newest first. */
  async listAttempts(environmentId: string, filter: SignInAttemptFilter = {}): Promise<SignInAttemptPage> {
    const path = withQuery(`${env(environmentId)}/sign-in-attempts`, {
      user_id: filter.userId,
      ip: filter.ip,
      outcome: filter.outcome,
      detection: filter.detection,
      country: filter.country,
      before: filter.before,
      limit: filter.limit ? String(filter.limit) : undefined,
    });
    const out = await this.call<SignInAttemptPage>("GET", path);
    return { ...out, items: out.items ?? [] };
  }

  /** Reads one attempt. */
  async getAttempt(environmentId: string, id: string): Promise<SignInAttempt> {
    return this.call("GET", `${env(environmentId)}/sign-in-attempts/${segment(id, "attempt id")}`);
  }

  /** What the deployment supports (GeoIP) and whether CAPTCHA and risk signals are on. */
  async getStatus(environmentId: string): Promise<SecurityStatus> {
    return this.call("GET", `${env(environmentId)}/risk/status`);
  }

  /** Lists the devices a user signed in from, newest first. */
  async listUserDevices(environmentId: string, userId: string): Promise<UserDevice[]> {
    const out = await this.call<{ items: UserDevice[] | null }>("GET", `${env(environmentId)}/users/${segment(userId, "user id")}/devices`);
    return out.items ?? [];
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const value = typeof this.token === "function" ? await this.token() : this.token;
    if (!value) {
      throw invalidArgument("token is required");
    }
    const headers: Record<string, string> = { Accept: "application/json", Authorization: `Bearer ${value}` };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    return this.http.send<T>(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  }
}

function segment(value: string, what: string): string {
  if (!value || /[/?#\\.%]/.test(value)) {
    throw invalidArgument(`invalid ${what}`);
  }
  return value;
}

function env(id: string): string {
  return `/api/v1/environments/${segment(id, "environment id")}`;
}
