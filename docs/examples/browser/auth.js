// Framework-neutral same-origin helpers. No persistence, logging or management keys.
async function request(path, body, token) {
  const response = await fetch(`/identity/v1${path}`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  })
  if (!response.ok) throw new Error(`Authentication request failed (${response.status})`)
  return response.status === 204 ? undefined : response.json()
}
export const login = (boundary, email, password) => request('/login', { ...boundary, email, password })
export const initiateOTP = (environment_id, email) => request('/challenges', { environment_id, email, purpose: 'login' })
export const verifyOTP = (boundary, challenge_id, code) => request('/challenges/verify', { ...boundary, challenge_id, code, purpose: 'login' })
// Call serially; replace the previous refresh token atomically after success.
export const refresh = (boundary, refresh_token) => request('/refresh', { ...boundary, refresh_token })
export const logout = (token, environment_id, audience) => request('/logout', { environment_id, audience }, token)
