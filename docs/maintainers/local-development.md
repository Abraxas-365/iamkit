# Local development

Prerequisites: Go matching `go.mod` (and `sdk/go.mod`), Docker for integration
checks, Node/npm compatible with `frontend/package.json`, and Python 3 for docs
checks. Never point tests at customer/development state.

```sh
make build
make test
make vet
make test-e2e
```

`make test` runs root unit tests and the nested SDK tests. Database tests require
`IAMKIT_TEST_E2E=1` and Docker; `make test-e2e` supplies the flag and timeout.
For manual runtime setup use [Docker quickstart](../start/docker-quickstart.md).
The default Compose file provides local infrastructure; select the documented
full-stack file explicitly. For console development use
[management-console setup](../start/management-console.md).

From `frontend/`, install using `npm ci`, then `npm run build`. Keep environment
files and secret mounts outside tracked source. Never use `VITE_*` for server
secrets: Vite embeds such variables into the browser bundle.

Run [documentation checks](testing.md) when editing examples or guides. Preserve
unrelated working-tree changes and inspect diffs before proposing a commit.
