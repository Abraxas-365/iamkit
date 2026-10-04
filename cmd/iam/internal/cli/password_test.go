package cli

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadLine(t *testing.T) {
	cases := []struct {
		name, in, want, err string
	}{
		{"line", "secret-value\n", "secret-value", ""},
		{"crlf", "secret-value\r\n", "secret-value", ""},
		{"no trailing newline", "secret-value", "secret-value", ""},
		{"empty line", "\n", "", "empty value"},
		{"nothing", "", "", "no value"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := readLine(bufio.NewReader(strings.NewReader(c.in)))
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("error = %v, want %q", err, c.err)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got %q, %v; want %q", got, err, c.want)
			}
		})
	}
}

func TestReadLineKeepsTheSecondLine(t *testing.T) {
	in := bufio.NewReader(strings.NewReader("current\nnew\n"))
	first, _ := readLine(in)
	second, _ := readLine(in)
	if first != "current" || second != "new" {
		t.Fatalf("got %q, %q", first, second)
	}
}

func TestPasswordIsSet(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"set":true,"usable":true}`:  true,
		"{\n  \"set\": true\n}":       true,
		`{"set":false,"usable":true}`: false,
		`{"usable":true}`:             false,
		``:                            false,
	} {
		if got := passwordIsSet([]byte(raw)); got != want {
			t.Errorf("passwordIsSet(%q) = %v, want %v", raw, got, want)
		}
	}
}
