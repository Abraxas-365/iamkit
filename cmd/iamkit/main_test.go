package main

import (
	"errors"
	"flag"
	"strings"
	"testing"
)

func TestParseCredentialArgs(t *testing.T) {
	const ws = "11111111-1111-1111-1111-111111111111"
	cases := []struct {
		name    string
		command string
		argv    []string
		want    string // substring of the error; empty = accepted
	}{
		{"bootstrap ok", "bootstrap", []string{"--email", "a@b.co", "--workspace", "W", "--output", "o.json"}, ""},
		{"recover ok", "recover-owner", []string{"--email", "a@b.co", "--workspace", ws, "--output", "o.json"}, ""},
		{"no output", "bootstrap", []string{"--email", "a@b.co", "--workspace", "W"}, "--output is required"},
		{"no email", "bootstrap", []string{"--workspace", "W", "--output", "o.json"}, "--email is required"},
		{"bad email", "bootstrap", []string{"--email", "nope", "--workspace", "W", "--output", "o.json"}, "not a valid email"},
		{"no workspace", "bootstrap", []string{"--email", "a@b.co", "--output", "o.json"}, "name of the workspace to create"},
		{"recover without workspace", "recover-owner", []string{"--email", "a@b.co", "--output", "o.json"}, "UUID of the workspace to recover"},
		{"recover with a name", "recover-owner", []string{"--email", "a@b.co", "--workspace", "W", "--output", "o.json"}, "not a workspace UUID"},
		{"recover with the zero UUID", "recover-owner", []string{"--email", "a@b.co", "--workspace", "00000000-0000-0000-0000-000000000000", "--output", "o.json"}, "not a workspace UUID"},
		{"stray argument", "bootstrap", []string{"--email", "a@b.co", "--workspace", "W", "--output", "o.json", "extra"}, `unexpected argument "extra"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseCredentialArgs(c.command, c.argv)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("error = %v, want it to contain %q", err, c.want)
			}
		})
	}
}

func TestParseCredentialArgsFlagErrors(t *testing.T) {
	if _, err := parseCredentialArgs("bootstrap", []string{"--bogus"}); !errors.Is(err, errReported) {
		t.Fatalf("unknown flag: error = %v, want errReported (the flag package already printed it)", err)
	}
	if _, err := parseCredentialArgs("bootstrap", []string{"--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("--help: error = %v, want flag.ErrHelp", err)
	}
}
