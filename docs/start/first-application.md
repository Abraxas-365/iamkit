# Your first application

Create a small tenant-aware example: provision InvoiceCloud, sign Alice in to
Acme, and confirm she cannot sign in to a second organization. This is a
throwaway onboarding exercise, not a production provisioning recipe.

## Before you begin

Complete [Docker quickstart](docker-quickstart.md). You need bash, curl, jq, a
trusted shell, and a disposable workspace. `IAMKIT_URL` and `MGMT` must already
be set. Do not use shell tracing.

<a id="run-the-onboarding-example"></a>

## 1. Run the onboarding example

```sh
read -r -s -p 'Demo password (12–72 bytes): ' DEMO_PASSWORD
export DEMO_PASSWORD
export OUTPUT="$PWD/.dev-secrets/invoicecloud.json"
bash docs/examples/onboarding/run.sh
unset DEMO_PASSWORD
```

The script captures real IDs rather than asking you to copy UUID placeholders.
It creates a project/environment, Acme and a second organization, Web App,
Invoices API, the application-resource binding, Alice, her Acme membership and
an `invoices:read` direct grant. It then logs in, introspects the token, and
checks that login into the other organization fails.

**Check:** the final output reports that every check passed. Secrets are written
only to the private output file.

Requests are **not a single transaction**. If one fails, previously created
entities remain. Inspect the failure and existing state instead of blindly
rerunning in a production workspace. This tutorial deliberately creates a new
project on each run and refuses to overwrite its output file.

<a id="what-each-step-establishes"></a>

## 2. Understand what the example created

| Step | Why it matters |
| --- | --- |
| User | Local identity and chosen login methods |
| Organization membership | Which tenant Alice belongs to |
| Application | Which client experience requests access |
| Resource and catalog | API audience and valid permission names |
| Application-resource binding | Which API the app may request |
| Grant or role assignment | Alice's permissions for that organization/resource |
| Login boundary | The exact environment/org/app/resource for this session |

A password alone is insufficient. Removing the membership or grant must prevent
new access; online introspection observes changes while offline JWT validation
cannot see them before expiry.

## Next steps

Run the [protected API example](protect-an-api.md) to verify tenant isolation
when serving API requests, not merely during login. For application-owned
onboarding, see [signup orchestration](../guides/sign-in/signup-and-onboarding.md);
for server automation, see [scoped IAM](../reference/api/scoped-iam.md).

## Cleanup

The example does not delete data automatically. Retain IDs for investigation.
Only destroy the tutorial's dedicated database/volume after checking the Compose
project and volume names. Never use a shared application database for this exercise.
