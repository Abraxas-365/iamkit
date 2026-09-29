// IAMKit hosted pages: security keys and passkeys. Buttons with
// data-webauthn="<options url>" fetch ceremony options, ask the browser,
// then post the answer through the form named by data-form (fields
// webauthn_session and credential). The passkey form also offers passkeys
// in the email field's autofill (conditional mediation).
(function () {
  "use strict";
  if (!window.PublicKeyCredential) {
    document.querySelectorAll("[data-webauthn]").forEach(function (b) { b.hidden = true; });
    return;
  }
  function decode(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var raw = atob(s), out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out.buffer;
  }
  function encode(buf) {
    if (!buf) return undefined;
    var bytes = new Uint8Array(buf), raw = "";
    for (var i = 0; i < bytes.length; i++) raw += String.fromCharCode(bytes[i]);
    return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function requestOptions(o) {
    o.challenge = decode(o.challenge);
    (o.allowCredentials || []).forEach(function (c) { c.id = decode(c.id); });
    return o;
  }
  function answer(c) {
    var r = c.response;
    return JSON.stringify({
      id: c.id, rawId: encode(c.rawId), type: c.type,
      authenticatorAttachment: c.authenticatorAttachment || undefined,
      clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
      response: {
        clientDataJSON: encode(r.clientDataJSON), authenticatorData: encode(r.authenticatorData),
        signature: encode(r.signature), userHandle: encode(r.userHandle)
      }
    });
  }
  function begin(url, ticket) {
    var body = new URLSearchParams();
    body.set("ticket", ticket);
    return fetch(url, { method: "POST", body: body, credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (res) {
        return res.json().then(function (data) {
          if (!res.ok) throw new Error(data.error || "error");
          return data;
        });
      });
  }
  function submit(form, session, credential) {
    form.querySelector("[name=webauthn_session]").value = session;
    form.querySelector("[name=credential]").value = answer(credential);
    form.submit();
  }
  function fail(button, err) {
    if (err && err.name === "AbortError") return;
    var box = document.getElementById("webauthn-error");
    if (box) { box.hidden = false; box.textContent = button.getAttribute("data-failed"); }
  }
  var pending = null;
  function run(button, mediation) {
    var form = document.getElementById(button.getAttribute("data-form"));
    return begin(button.getAttribute("data-webauthn"), form.querySelector("[name=ticket]").value).then(function (data) {
      if (pending) pending.abort();
      pending = new AbortController();
      var request = { publicKey: requestOptions(data.options), signal: pending.signal };
      if (mediation) request.mediation = mediation;
      return navigator.credentials.get(request).then(function (credential) {
        if (credential) submit(form, data.webauthn_session, credential);
      });
    });
  }
  document.querySelectorAll("button[data-webauthn]").forEach(function (button) {
    button.hidden = false;
    button.addEventListener("click", function (e) {
      e.preventDefault();
      run(button).catch(function (err) { fail(button, err); });
    });
    if (button.hasAttribute("data-autofill") && PublicKeyCredential.isConditionalMediationAvailable) {
      PublicKeyCredential.isConditionalMediationAvailable().then(function (ok) {
        if (ok) run(button, "conditional").catch(function () {});
      });
    }
  });
})();
