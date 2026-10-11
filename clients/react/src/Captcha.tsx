import type { CaptchaWidget } from "@iamkit/js";
import { useEffect, useRef, useState, type ReactNode } from "react";

/** The widget scripts, loaded once per page on first use (explicit rendering). */
export const captchaScripts: Record<string, string> = {
  turnstile: "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit",
  hcaptcha: "https://js.hcaptcha.com/1/api.js?render=explicit",
};

/** The global each provider's script defines. */
interface Api {
  render(container: HTMLElement, options: Record<string, unknown>): string | number;
  remove?(id: string | number): void;
  reset?(id?: string | number): void;
}

const globals: Record<string, string> = { turnstile: "turnstile", hcaptcha: "hcaptcha" };

function api(provider: string): Api | undefined {
  const name = globals[provider];
  return name ? ((globalThis as unknown as Record<string, Api | undefined>)[name] ?? undefined) : undefined;
}

const loading = new Map<string, Promise<void>>();

/**
 * Loads a provider's widget script once and resolves when its API is ready.
 * Unknown providers reject. `nonce` is set on the script tag for a strict CSP
 * (the page's CSP must also allow the provider's script, frame and connect
 * hosts).
 */
export function loadCaptchaScript(provider: string, nonce?: string): Promise<void> {
  const src = captchaScripts[provider];
  if (!src) {
    return Promise.reject(new Error(`unknown captcha provider: ${provider}`));
  }
  if (api(provider)) {
    return Promise.resolve();
  }
  const known = loading.get(provider);
  if (known) {
    return known;
  }
  const promise = new Promise<void>((resolve, reject) => {
    const script = document.createElement("script");
    script.src = src;
    script.async = true;
    script.defer = true;
    script.dataset.iamkitCaptcha = provider;
    if (nonce) {
      script.nonce = nonce;
    }
    script.onload = () => resolve();
    script.onerror = () => {
      script.remove();
      loading.delete(provider);
      reject(new Error(`could not load the ${provider} script`));
    };
    document.head.appendChild(script);
  });
  loading.set(provider, promise);
  return promise;
}

/** What a custom `children` renderer gets: attach `ref` to the element that hosts the widget. */
export interface CaptchaRenderProps {
  ref: (element: HTMLElement | null) => void;
  /** `loading` until the script is ready, `ready` once rendered, `error` if it could not load. */
  status: "loading" | "ready" | "error";
  /** Clears the widget so the user can solve it again. */
  reset: () => void;
}

export interface CaptchaProps {
  /** The widget to show: the ticket's `captcha` (`state.captcha`) or `getCaptchaConfig`. */
  widget: Pick<CaptchaWidget, "provider" | "site_key">;
  /** Called with the answer; it is single use. */
  onToken: (token: string) => void;
  /** The answer expired, or the widget failed: the token is no longer good. */
  onExpire?: () => void;
  onError?: (error: Error) => void;
  /** Extra provider options (`theme`, `size`, `action`, …). */
  options?: Record<string, unknown>;
  /** Nonce for the script tag when the page has a strict CSP. */
  nonce?: string;
  className?: string;
  /** A custom UI around the widget's container: attach `ref` where it should render. */
  children?: (props: CaptchaRenderProps) => ReactNode;
}

/**
 * Renders the bot-protection widget of Cloudflare Turnstile or hCaptcha.
 * The provider script is loaded once for the page, the widget is rendered
 * explicitly with the site key and removed on unmount. Pass `key` (for
 * example `state.captchaRound`) to get a fresh widget after a token was
 * spent. Unstyled: the container carries `data-iamkit="captcha"`.
 */
export function Captcha(props: CaptchaProps) {
  const { widget, onToken, onExpire, onError, options, nonce, className, children } = props;
  const [element, setElement] = useState<HTMLElement | null>(null);
  const [status, setStatus] = useState<CaptchaRenderProps["status"]>("loading");
  const handle = useRef<string | number | undefined>(undefined);
  const callbacks = useRef({ onToken, onExpire, onError });
  callbacks.current = { onToken, onExpire, onError };
  const optionsKey = JSON.stringify(options ?? {});

  useEffect(() => {
    if (!element) return;
    let live = true;
    setStatus("loading");
    loadCaptchaScript(widget.provider, nonce).then(
      () => {
        const provider = api(widget.provider);
        if (!live || !provider) return;
        handle.current = provider.render(element, {
          ...JSON.parse(optionsKey),
          sitekey: widget.site_key,
          callback: (token: string) => callbacks.current.onToken(token),
          "expired-callback": () => callbacks.current.onExpire?.(),
          "error-callback": () => callbacks.current.onExpire?.(),
        });
        setStatus("ready");
      },
      (error: Error) => {
        if (!live) return;
        setStatus("error");
        callbacks.current.onError?.(error);
      },
    );
    return () => {
      live = false;
      const provider = api(widget.provider);
      if (handle.current !== undefined) {
        provider?.remove?.(handle.current);
        handle.current = undefined;
      }
    };
  }, [element, widget.provider, widget.site_key, nonce, optionsKey]);

  const reset = () => {
    if (handle.current !== undefined) {
      api(widget.provider)?.reset?.(handle.current);
    }
  };

  if (children) {
    return <>{children({ ref: setElement, status, reset })}</>;
  }
  return <div ref={setElement} data-iamkit="captcha" data-status={status} className={className} />;
}
