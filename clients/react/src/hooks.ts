import { createSignIn, type SignIn, type SignInOptions } from "@iamkit/js";
import { createContext, createElement, useContext, useEffect, useMemo, useState, useSyncExternalStore, type ReactNode } from "react";
import { SignInFlow, type FlowOptions, type FlowState } from "./flow.js";

const Context = createContext<SignIn | null>(null);

/** Provides the IAMKit sign-in client to the hooks below. */
export function IAMKitProvider(props: SignInOptions & { children?: ReactNode }) {
  const { children, baseUrl, fetch, storage } = props;
  const iam = useMemo(() => createSignIn({ baseUrl, fetch, storage }), [baseUrl, fetch, storage]);
  return createElement(Context.Provider, { value: iam }, children);
}

/** The `@iamkit/js` client of the nearest `IAMKitProvider`. */
export function useIAMKit(): SignIn {
  const iam = useContext(Context);
  if (!iam) {
    throw new Error("useIAMKit needs an <IAMKitProvider>");
  }
  return iam;
}

/**
 * Runs a sign-in for an authorization ticket: the current step, the
 * ticket's description and actions to advance (`identify`,
 * `submitPassword`, `verifyFactor`, …). Starts on mount, which also
 * finishes a single sign-on that returned to this page.
 */
export function useSignIn(options: FlowOptions): { state: FlowState; flow: SignInFlow } {
  const iam = useIAMKit();
  const [flow] = useState(() => new SignInFlow(iam, options));
  const state = useSyncExternalStore(flow.subscribe, flow.getSnapshot, flow.getSnapshot);
  useEffect(() => {
    if (flow.state.step === "loading" && !flow.state.busy) {
      void flow.start();
    }
  }, [flow]);
  return { state, flow };
}

/** The status of a one-off async call (preview, accept, …). */
export interface Call<T> {
  data?: T;
  error?: unknown;
  loading: boolean;
}

function useCall<T>(fn: (() => Promise<T>) | null, deps: unknown[]): Call<T> & { reload: () => void } {
  const [state, setState] = useState<Call<T>>({ loading: !!fn });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!fn) return;
    let live = true;
    setState({ loading: true });
    fn().then(
      (data) => live && setState({ data, loading: false }),
      (error) => live && setState({ error, loading: false }),
    );
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  return { ...state, reload: () => setTick((t) => t + 1) };
}

/** Describes an invitation (organization, email, whether a password is needed). */
export function useInvitation(token: string | null | undefined) {
  const iam = useIAMKit();
  const preview = useCall(token ? () => iam.invitation.preview(token) : null, [iam, token]);
  const [accepting, setAccepting] = useState<Call<Awaited<ReturnType<SignIn["invitation"]["accept"]>>>>({ loading: false });
  const accept = async (input: { name?: string; password?: string }) => {
    if (!token) return;
    setAccepting({ loading: true });
    try {
      setAccepting({ data: await iam.invitation.accept({ token, ...input }), loading: false });
    } catch (error) {
      setAccepting({ error, loading: false });
    }
  };
  return { preview, accepted: accepting, accept };
}
