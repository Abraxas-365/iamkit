import assert from "node:assert/strict";
import { test } from "node:test";
import { scopesFor } from "../src/scopes.js";

test("tools/call needs the tool's scope", () => {
  assert.deepEqual(scopesFor({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "add_note" } }), ["notes:write"]);
  assert.deepEqual(scopesFor({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "whoami" } }), []);
});

test("other methods need only a valid token", () => {
  assert.deepEqual(scopesFor({ jsonrpc: "2.0", id: 1, method: "tools/list" }), []);
  assert.deepEqual(scopesFor(undefined), []);
  assert.deepEqual(scopesFor({ method: "tools/call", params: { name: "constructor" } }), []);
});

test("a batch needs every scope once", () => {
  const call = (name: string) => ({ jsonrpc: "2.0", id: name, method: "tools/call", params: { name } });
  assert.deepEqual(scopesFor([call("list_notes"), call("add_note"), call("add_note")]), ["notes:read", "notes:write"]);
});
