-- Operator single sign-on to the console through identity providers the
-- deployment configures (IAMKIT_OPERATOR_SSO_*). Providers are never stored:
-- only the identities linked to operators and the in-flight sign-ins.

-- A provider identity linked to an operator. The key is the verified token
-- issuer (per tenant for Microsoft) and subject, so renaming a provider ID
-- in configuration keeps the links. Operators are never created here: the
-- first sign-in links to an existing, invited operator by verified email,
-- later sign-ins match (issuer, subject) only. One identity per issuer per
-- operator, so a reassigned mailbox cannot add a second one.
CREATE TABLE operator_identities (
  issuer        text        NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
  subject       text        NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
  operator_id   uuid        NOT NULL REFERENCES operators(id),
  -- Configuration ID and provider email at link time, for display only.
  provider      text        NOT NULL,
  email         text        NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz,
  PRIMARY KEY (issuer, subject),
  UNIQUE (operator_id, issuer)
);

-- A started operator sign-in awaiting the provider's callback, keyed by the
-- hash of the state parameter and bound to the browser that started it.
CREATE TABLE operator_sso_states (
  secret_hash  bytea       PRIMARY KEY,
  provider     text        NOT NULL,
  binding_hash bytea       NOT NULL,
  nonce        text        NOT NULL,
  verifier     text        NOT NULL,
  expires_at   timestamptz NOT NULL,
  consumed_at  timestamptz
);
CREATE INDEX operator_sso_states_expires ON operator_sso_states(expires_at);
