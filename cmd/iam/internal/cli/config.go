package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// iamDir returns ~/.iam, creating it if needed.
func iamDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".iam")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("cannot create %s: %w", dir, err)
	}
	return dir, nil
}

// iniFile represents a simple INI file with [section] headers and key=value lines.
// Sections map to profile names: [default], [profile production], etc.
type iniFile struct {
	sections map[string]map[string]string
	order    []string // preserve section order
}

func newINI() *iniFile {
	return &iniFile{sections: make(map[string]map[string]string)}
}

// parseINI reads a simple INI file. Missing files return an empty iniFile.
func parseINI(path string) *iniFile {
	ini := newINI()
	f, err := os.Open(path)
	if err != nil {
		return ini
	}
	defer f.Close()

	section := "default"
	ini.ensureSection(section)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			// [profile foo] → "foo", [default] → "default"
			section = strings.TrimPrefix(section, "profile ")
			ini.ensureSection(section)
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			ini.sections[section][strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return ini
}

func (ini *iniFile) ensureSection(name string) {
	if _, ok := ini.sections[name]; !ok {
		ini.sections[name] = make(map[string]string)
		ini.order = append(ini.order, name)
	}
}

func (ini *iniFile) get(section, key string) string {
	if s, ok := ini.sections[section]; ok {
		return s[key]
	}
	return ""
}

func (ini *iniFile) set(section, key, value string) {
	ini.ensureSection(section)
	ini.sections[section][key] = value
}

// write serializes the INI file to disk.
func (ini *iniFile) write(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for i, section := range ini.order {
		if i > 0 {
			fmt.Fprintln(w)
		}
		if section == "default" {
			fmt.Fprintln(w, "[default]")
		} else {
			fmt.Fprintf(w, "[profile %s]\n", section)
		}
		kv := ini.sections[section]
		// Write in a stable key order
		for _, key := range []string{"url", "environment", "key"} {
			if v, ok := kv[key]; ok && v != "" {
				fmt.Fprintf(w, "%s = %s\n", key, v)
			}
		}
		// Any remaining keys
		for k, v := range kv {
			if k != "url" && k != "environment" && k != "key" && v != "" {
				fmt.Fprintf(w, "%s = %s\n", k, v)
			}
		}
	}
	return w.Flush()
}

// profile holds resolved config for a single profile.
type profile struct {
	URL         string
	Key         string
	Environment string
}

// loadProfile reads config + credentials for the given profile name.
// Resolution: flag > env var > config file.
func loadProfile(profileName string) profile {
	dir, err := iamDir()
	if err != nil {
		return profile{}
	}

	cfg := parseINI(filepath.Join(dir, "config"))
	creds := parseINI(filepath.Join(dir, "credentials"))

	return profile{
		URL:         cfg.get(profileName, "url"),
		Key:         creds.get(profileName, "key"),
		Environment: cfg.get(profileName, "environment"),
	}
}
