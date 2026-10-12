import {
  isReauthenticationRequired,
  switchRefusal,
  type Account,
  type ApiKeyFilter,
  type ApiKeyOptions,
  type ApiKey,
  type Boundary,
  type Factor,
  type FactorSummary,
  type IssuedApiKey,
  type NewApiKey,
  type Organization,
  type Page,
  type PasswordChanged,
  type Profile,
  type Proof,
  type Session,
  type SwitchReason,
  type Tokens,
  type TotpEnrollment,
  type WebAuthnRegistration,
  type FactorCodeSent,
} from "@iamkit/js";
import { createContext, createElement, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

interface AccountContext {
  account: Account;
  /** Asks the application to sign the user in again (`max_age=0`). */
  reauthenticate: () => void;
}

const Context = createContext<AccountContext | null>(null);

export interface AccountProviderProps {
  /** `createAccount({...})` of `@iamkit/js`. */
  account: Account;
  /**
   * Called when IAMKit asks for a recent sign-in (`REAUTHENTICATION_REQUIRED`):
   * the application re-runs its sign-in with `max_age=0` (or `prompt=login`).
   */
  onReauthenticate?: () => void;
  children?: ReactNode;
}

/** Provides the self-service client to the account hooks and widgets. */
export function AccountProvider(props: AccountProviderProps) {
  const { account, onReauthenticate, children } = props;
  const latest = useRef(onReauthenticate);
  latest.current = onReauthenticate;
  const value = useMemo<AccountContext>(() => ({ account, reauthenticate: () => latest.current?.() }), [account]);
  return createElement(Context.Provider, { value }, children);
}

/**
 * What the widgets wrap themselves in: their `account` prop (or the
 * provider's) and their `onReauthenticate` (or the provider's).
 */
export function AccountScope(props: { account?: Account; onReauthenticate?: () => void; children?: ReactNode }) {
  const ctx = useContext(Context);
  const account = props.account ?? ctx?.account;
  if (!account) {
    throw new Error("the account widgets need an <AccountProvider> or an `account` prop");
  }
  return createElement(AccountProvider, { account, onReauthenticate: props.onReauthenticate ?? ctx?.reauthenticate, children: props.children });
}

/** The `@iamkit/js` account client of the nearest `AccountProvider`. */
export function useAccountClient(): Account {
  return useAccountContext().account;
}

export function useAccountContext(): AccountContext {
  const ctx = useContext(Context);
  if (!ctx) {
    throw new Error("the account hooks need an <AccountProvider> (or the widget's `account` prop)");
  }
  return ctx;
}

/** The status shared by the account hooks. */
export interface Loadable {
  loading: boolean;
  /** The last failure of loading or of a change (cleared by the next call). */
  error?: unknown;
  /** True while a change is in flight. */
  busy: boolean;
  /** Loads again. */
  refresh: () => void;
  /** Forgets `error`. */
  clearError: () => void;
}

interface Loaded<T> {
  data?: T;
  error?: unknown;
  loading: boolean;
}

function useLoader<T>(load: (account: Account) => Promise<T>, deps: unknown[] = []) {
  const ctx = useAccountContext();
  const [state, setState] = useState<Loaded<T>>({ loading: true });
  const [tick, setTick] = useState(0);
  const loadRef = useRef(load);
  loadRef.current = load;
  useEffect(() => {
    let live = true;
    setState((s) => ({ ...s, loading: true, error: undefined }));
    loadRef.current(ctx.account).then(
      (data) => live && setState({ data, loading: false }),
      (error) => {
        if (isReauthenticationRequired(error)) ctx.reauthenticate();
        if (live) setState((s) => ({ data: s.data, error, loading: false }));
      },
    );
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ctx, tick, ...deps]);
  const refresh = useCallback(() => setTick((t) => t + 1), []);
  return { ...state, refresh };
}

interface RunOptions {
  /** Return true to handle the error yourself (no default reauthentication). */
  handle?: (error: unknown) => boolean;
}

function useAction() {
  const ctx = useAccountContext();
  const [state, setState] = useState<{ busy: boolean; error?: unknown }>({ busy: false });
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  const run = useCallback(
    async <T,>(fn: (account: Account) => Promise<T>, options: RunOptions = {}): Promise<T | undefined> => {
      setState({ busy: true });
      try {
        const value = await fn(ctx.account);
        if (mounted.current) setState({ busy: false });
        return value;
      } catch (error) {
        if (!options.handle?.(error) && isReauthenticationRequired(error)) ctx.reauthenticate();
        if (mounted.current) setState({ busy: false, error });
        return undefined;
      }
    },
    [ctx],
  );
  const clearError = useCallback(() => setState((s) => ({ ...s, error: undefined })), []);
  return { busy: state.busy, error: state.error, run, clearError };
}

// ── useAccount ──

export interface UseAccount extends Loadable {
  profile?: Profile;
  /** Self-service profile properties (the environment's user schema). */
  properties: Record<string, unknown>;
  /** Changes the name and/or avatar (an https URL, `null` clears). */
  updateProfile: (changes: { name?: string; avatarUrl?: string | null }) => Promise<boolean>;
  /** Merges top-level profile properties (`null` removes one). */
  updateProperties: (profile: Record<string, unknown>) => Promise<boolean>;
  phone: {
    /** Texts a code; answers the masked destination. */
    start: (phone: string) => Promise<string | undefined>;
    verify: (phone: string, code: string) => Promise<boolean>;
    remove: () => Promise<boolean>;
  };
  /** Changes the password; answers how many other sessions ended. */
  changePassword: (current: string, next: string) => Promise<PasswordChanged | undefined>;
}

/** The signed-in user's profile, phone and password. */
export function useAccount(): UseAccount {
  const loader = useLoader(async (a) => {
    const [profile, properties] = await Promise.all([a.me(), a.properties().catch(() => ({}) as Record<string, unknown>)]);
    return { profile, properties };
  });
  const action = useAction();
  const done = async <T,>(fn: (a: Account) => Promise<T>): Promise<T | undefined> => {
    const out = await action.run(fn);
    return out;
  };
  const mutate = async (fn: (a: Account) => Promise<unknown>) => {
    const ok = (await action.run(async (a) => (await fn(a), true))) === true;
    if (ok) loader.refresh();
    return ok;
  };
  return {
    profile: loader.data?.profile,
    properties: loader.data?.properties ?? {},
    loading: loader.loading,
    error: action.error ?? loader.error,
    busy: action.busy,
    refresh: loader.refresh,
    clearError: action.clearError,
    updateProfile: (changes) => mutate((a) => a.updateMe(changes)),
    updateProperties: (profile) => mutate((a) => a.updateProperties(profile)),
    phone: {
      start: async (phone) => (await done((a) => a.phone.start(phone)))?.destination,
      verify: (phone, code) => mutate((a) => a.phone.verify(phone, code)),
      remove: () => mutate((a) => a.phone.remove()),
    },
    changePassword: (current, next) => done((a) => a.changePassword(current, next)),
  };
}

// ── usePassword ──

export interface UsePassword {
  busy: boolean;
  error?: unknown;
  clearError: () => void;
  /** Changes the password; answers how many other sessions ended, undefined on failure. */
  changePassword: (current: string, next: string) => Promise<PasswordChanged | undefined>;
}

/** Just the password change (no profile loading). */
export function usePassword(): UsePassword {
  const action = useAction();
  return {
    busy: action.busy,
    error: action.error,
    clearError: action.clearError,
    changePassword: (current, next) => action.run((a) => a.changePassword(current, next)),
  };
}

// ── useSessions ──

export interface UseSessions extends Loadable {
  sessions: Session[];
  page?: Page;
  /** Ends one session (the current one too). */
  revoke: (sessionId: string) => Promise<boolean>;
  /** Ends every other session; answers how many ended. */
  revokeOthers: () => Promise<number | undefined>;
}

/** The user's live sessions. */
export function useSessions(page: { limit?: number; offset?: number } = {}): UseSessions {
  const loader = useLoader((a) => a.sessions.list(page), [page.limit, page.offset]);
  const action = useAction();
  return {
    sessions: loader.data?.items ?? [],
    page: loader.data?.page,
    loading: loader.loading,
    error: action.error ?? loader.error,
    busy: action.busy,
    refresh: loader.refresh,
    clearError: action.clearError,
    revoke: async (id) => {
      const ok = (await action.run(async (a) => (await a.sessions.revoke(id), true))) === true;
      if (ok) loader.refresh();
      return ok;
    },
    revokeOthers: async () => {
      const count = await action.run((a) => a.sessions.revokeOthers());
      if (count !== undefined) loader.refresh();
      return count;
    },
  };
}

// ── useFactors ──

export interface UseFactors extends Loadable {
  /** Every factor, security key and passkey. */
  factors: Factor[];
  recoveryCodesRemaining: number;
  lockedUntil?: string | null;
  summary?: FactorSummary;
  totp: {
    start: () => Promise<TotpEnrollment | undefined>;
    /** Answers the recovery codes (shown once) of a first factor, else `[]`; undefined on failure. */
    confirm: (code: string) => Promise<string[] | undefined>;
    remove: (proof: string) => Promise<boolean>;
  };
  email: {
    start: () => Promise<FactorCodeSent | undefined>;
    confirm: (code: string) => Promise<string[] | undefined>;
    /** Sends a code to prove possession before `remove`. */
    send: () => Promise<FactorCodeSent | undefined>;
    remove: (proof: string) => Promise<boolean>;
  };
  sms: {
    start: (phone: string) => Promise<FactorCodeSent | undefined>;
    confirm: (code: string) => Promise<string[] | undefined>;
    send: () => Promise<FactorCodeSent | undefined>;
    remove: (proof: string) => Promise<boolean>;
  };
  /** New recovery codes (shown once); `proof` is a code of an active factor. */
  recoveryCodes: (proof: string) => Promise<string[] | undefined>;
  passkeys: {
    /** Registers a passkey or security key; `null` when the user dismissed the prompt. */
    add: (name: string, kind: { passkey: boolean }) => Promise<WebAuthnRegistration | null | undefined>;
    rename: (factorId: string, name: string) => Promise<boolean>;
    /** Asks for a key to prove possession; `null` when dismissed. */
    assert: () => Promise<Proof | null | undefined>;
    remove: (factorId: string, proof: Proof) => Promise<boolean>;
  };
}

/** The user's second factors, security keys, passkeys and recovery codes. */
export function useFactors(): UseFactors {
  const loader = useLoader((a) => a.mfa.factors());
  const action = useAction();
  const changed = async <T,>(fn: (a: Account) => Promise<T>): Promise<T | undefined> => {
    const out = await action.run(fn);
    if (out !== undefined) loader.refresh();
    return out;
  };
  const removed = async (fn: (a: Account) => Promise<void>) => (await changed(async (a) => (await fn(a), true))) === true;
  const summary = loader.data;
  return {
    summary,
    factors: summary?.factors ?? [],
    recoveryCodesRemaining: summary?.recovery_codes_remaining ?? 0,
    lockedUntil: summary?.locked_until,
    loading: loader.loading,
    error: action.error ?? loader.error,
    busy: action.busy,
    refresh: loader.refresh,
    clearError: action.clearError,
    totp: {
      start: () => action.run((a) => a.mfa.totp.start()),
      confirm: (code) => changed((a) => a.mfa.totp.confirm(code)),
      remove: (proof) => removed((a) => a.mfa.totp.remove(proof)),
    },
    email: {
      start: () => action.run((a) => a.mfa.email.start()),
      confirm: (code) => changed((a) => a.mfa.email.confirm(code)),
      send: () => action.run((a) => a.mfa.email.send()),
      remove: (proof) => removed((a) => a.mfa.email.remove(proof)),
    },
    sms: {
      start: (phone) => action.run((a) => a.mfa.sms.start(phone)),
      confirm: (code) => changed((a) => a.mfa.sms.confirm(code)),
      send: () => action.run((a) => a.mfa.sms.send()),
      remove: (proof) => removed((a) => a.mfa.sms.remove(proof)),
    },
    recoveryCodes: (proof) => changed((a) => a.mfa.recoveryCodes(proof)),
    passkeys: {
      add: async (name, kind) => {
        const out = await action.run((a) => a.passkeys.add(name, kind));
        if (out) loader.refresh();
        return out;
      },
      rename: async (id, name) => (await changed((a) => a.passkeys.rename(id, name))) !== undefined,
      assert: () => action.run((a) => a.passkeys.assert()),
      remove: (id, proof) => removed((a) => a.passkeys.remove(id, proof)),
    },
  };
}

// ── useApiKeys ──

export interface UseApiKeys extends Loadable {
  keys: ApiKey[];
  page?: Page;
  /** Whether the environment lets users create keys, and what they may grant. */
  options?: ApiKeyOptions;
  /** Creates a key; its `value` is only in this answer. */
  create: (key: NewApiKey) => Promise<IssuedApiKey | undefined>;
  revoke: (keyId: string) => Promise<boolean>;
}

/** The user's API keys and what they may create. */
export function useApiKeys(filter: ApiKeyFilter = {}): UseApiKeys {
  const loader = useLoader(
    async (a) => {
      const options = await a.apiKeys.options();
      if (!options.enabled) return { options, list: { items: [] as ApiKey[], page: undefined as Page | undefined } };
      return { options, list: await a.apiKeys.list(filter) };
    },
    [filter.limit, filter.offset, filter.search, filter.state, filter.resourceId],
  );
  const action = useAction();
  return {
    keys: loader.data?.list.items ?? [],
    page: loader.data?.list.page,
    options: loader.data?.options,
    loading: loader.loading,
    error: action.error ?? loader.error,
    busy: action.busy,
    refresh: loader.refresh,
    clearError: action.clearError,
    create: async (key) => {
      const out = await action.run((a) => a.apiKeys.create(key));
      if (out) loader.refresh();
      return out;
    },
    revoke: async (id) => {
      const ok = (await action.run(async (a) => (await a.apiKeys.revoke(id), true))) === true;
      if (ok) loader.refresh();
      return ok;
    },
  };
}

// ── useOrganizations ──

/** Why a switch needs a new sign-in (`organizationId` is the one to sign in to). */
export interface SignInRequired {
  organizationId: string;
  reason: SwitchReason;
}

export interface OrganizationsOptions {
  /** The refresh token of the current session (the app keeps it). */
  getRefreshToken?: () => string | Promise<string>;
  /** Receives the tokens of the new session: store them (the old ones ended). */
  onSwitched?: (tokens: Tokens, organizationId: string) => void;
  /**
   * The target organization needs a sign-in the session lacks (single
   * sign-on, a second factor, another method): start an authorization with
   * its `organization_id`. Without it `onReauthenticate` is called.
   */
  onSignInRequired?: (required: SignInRequired) => void;
  /** The current boundary when the access token is opaque. */
  boundary?: Boundary;
  /**
   * Replaces the refresh-token switch: called with the chosen organization.
   * Sessions issued through OAuth (code + PKCE) cannot switch in place, so
   * such applications start a new authorization with that `organization_id`
   * here (then `getRefreshToken`/`onSwitched` are not needed).
   */
  onSelect?: (organizationId: string) => void | Promise<void>;
}

export interface UseOrganizations extends Loadable {
  organizations: Organization[];
  /** The organization of the session (from the profile; empty until loaded). */
  currentId: string;
  /** Moves the session into `organizationId`; answers the new tokens. */
  switchTo: (organizationId: string) => Promise<Tokens | undefined>;
  /** The organization of the last refused switch. */
  refusal?: SignInRequired;
}

/** The organizations the user may use, and switching between them. */
export function useOrganizations(options: OrganizationsOptions = {}): UseOrganizations {
  const ctx = useAccountContext();
  const loader = useLoader(async (a) => {
    const [organizations, currentId] = await Promise.all([a.organizations(), a.me().then((p) => p.organization_id, () => "")]);
    return { organizations, currentId };
  });
  const action = useAction();
  const [refusal, setRefusal] = useState<SignInRequired>();
  const latest = useRef(options);
  latest.current = options;
  return {
    organizations: loader.data?.organizations ?? [],
    currentId: loader.data?.currentId ?? "",
    loading: loader.loading,
    error: action.error ?? loader.error,
    busy: action.busy,
    refresh: loader.refresh,
    clearError: () => {
      setRefusal(undefined);
      action.clearError();
    },
    refusal,
    switchTo: async (organizationId) => {
      const o = latest.current;
      if (o.onSelect) {
        await o.onSelect(organizationId);
        return undefined;
      }
      if (!o.getRefreshToken) {
        throw new Error("useOrganizations needs `getRefreshToken` to switch");
      }
      setRefusal(undefined);
      const handle = (error: unknown) => {
        const refused = switchRefusal(error);
        if (!refused) return false;
        setRefusal(refused);
        if (o.onSignInRequired) o.onSignInRequired(refused);
        else ctx.reauthenticate();
        return true;
      };
      const tokens = await action.run(async (a) => a.switchOrganization(await o.getRefreshToken!(), organizationId, o.boundary), { handle });
      if (tokens) {
        o.onSwitched?.(tokens, organizationId);
        loader.refresh();
      }
      return tokens;
    },
  };
}
