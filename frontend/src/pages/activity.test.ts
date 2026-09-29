import { expect, it } from 'vitest'
import { describeAction } from './activity'

const env = '/management/v1/environments/83c2749c-cc53-4163-8008-8754b79943a7'
const id = 'ee316dcb-4fd2-49d3-a381-41ce02ef58a7'

it('describes management calls from their method and path', () => {
  expect(describeAction('POST', `${env}/oauth-clients/${id}`)).toBe('Created OAuth client')
  expect(describeAction('PATCH', `${env}/oauth-clients/${id}`)).toBe('Updated OAuth client')
  expect(describeAction('DELETE', `${env}/role-assignments/${id}`)).toBe('Deleted role assignment')
  expect(describeAction('POST', `${env}/group-role-assignments`)).toBe('Created group role assignment')
  expect(describeAction('PUT', `${env}/login-settings/clients/${id}/sign-in`)).toBe('Set sign-in methods')
  expect(describeAction('PATCH', env)).toBe('Updated environment')
})

it('describes action-style routes', () => {
  expect(describeAction('DELETE', `${env}/users/${id}/permanent`)).toBe('Permanently deleted user')
  expect(describeAction('POST', `${env}/organizations/${id}/domains/${id}/verify`)).toBe('Verified domain')
  expect(describeAction('POST', `${env}/organizations/${id}/domains/${id}/force-verify`)).toBe('Marked domain verified')
  expect(describeAction('POST', `${env}/invitations/${id}/resend`)).toBe('Resent invitation')
})

it('describes named events and keeps unknown ones as-is', () => {
  expect(describeAction('mfa.enrolled')).toBe('Second factor enrolled')
  expect(describeAction('signing_key.activate')).toBe('Activated a signing key')
  expect(describeAction('saml.assertion_issued')).toBe('Signed in to a SAML application')
  expect(describeAction('oauth.backchannel_failed')).toBe('Back-channel logout delivery failed')
  expect(describeAction('POST', `${env}/logout-deliveries/42/retry`)).toBe('Retried a logout delivery')
  expect(describeAction('service_account.authentication')).toBe('Changed how a service account authenticates')
  expect(describeAction('federation.jit')).toBe('User signed up through federation')
  expect(describeAction('federation.profile_updated')).toBe('Profile updated from the identity provider')
  expect(describeAction('federation.email')).toBe('User linked by verified email through federation')
  expect(describeAction('federation.other')).toBe('User linked through federation')
  expect(describeAction('something.new')).toBe('something.new')
})
