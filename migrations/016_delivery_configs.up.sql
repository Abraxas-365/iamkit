CREATE TABLE delivery_configs (
  environment_id uuid PRIMARY KEY REFERENCES environments(id),
  webhook_url    text NOT NULL,
  webhook_token  text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
