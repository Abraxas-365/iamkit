package riskgeo

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// build writes a tiny City-shaped database mapping each network to a
// country and coordinates.
func build(t *testing.T, path, dbType string, entries map[string][3]any) {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: dbType, RecordSize: 28, IncludeReservedNetworks: true})
	if err != nil {
		t.Fatal(err)
	}
	for cidr, e := range entries {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		rec := mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(e[0].(string))}}
		if dbType == "GeoLite2-City" {
			rec["location"] = mmdbtype.Map{"latitude": mmdbtype.Float64(e[1].(float64)), "longitude": mmdbtype.Float64(e[2].(float64))}
		}
		if err := w.Insert(n, rec); err != nil {
			t.Fatal(err)
		}
	}
	// Replaced by rename like geoipupdate does: rewriting a mapped file in
	// place would change (or fault) the reader's view.
	f, err := os.CreateTemp(filepath.Dir(path), "mmdb-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteTo(f); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f.Name(), path); err != nil {
		t.Fatal(err)
	}
}

func replace(t *testing.T, path string, data []byte, at time.Time) {
	t.Helper()
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmp, at, at); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestDatabaseLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "city.mmdb")
	build(t, path, "GeoLite2-City", map[string][3]any{
		"203.0.113.0/24":  {"PE", -12.04, -77.03},
		"198.51.100.0/24": {"ES", 40.41, -3.70},
	})
	g := New(path, "")
	defer g.Close()
	loc, ok := g.Locate("203.0.113.9", "")
	if !ok || loc.Country != "PE" || !loc.Located() || *loc.Latitude != -12.04 {
		t.Fatalf("lookup = %+v %v", loc, ok)
	}
	if _, ok := g.Locate("192.0.2.1", ""); ok {
		t.Fatal("unknown address located")
	}
	if _, ok := g.Locate("not an ip", ""); ok {
		t.Fatal("bad address located")
	}
	st := g.Status()
	if st.Source != risk.GeoMMDB || !st.Travel || !st.Countries || st.Database != "GeoLite2-City" || st.BuildDate == nil || st.Error != "" {
		t.Fatalf("status = %+v", st)
	}
}

func TestCountryDatabaseHasNoTravel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "country.mmdb")
	build(t, path, "GeoLite2-Country", map[string][3]any{"203.0.113.0/24": {"PE", 0.0, 0.0}})
	g := New(path, "")
	defer g.Close()
	loc, ok := g.Locate("203.0.113.9", "")
	if !ok || loc.Country != "PE" || loc.Located() {
		t.Fatalf("lookup = %+v", loc)
	}
	if st := g.Status(); st.Travel || !st.Countries {
		t.Fatalf("status = %+v", st)
	}
}

func TestReloadOnModTimeChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "city.mmdb")
	build(t, path, "GeoLite2-City", map[string][3]any{"203.0.113.0/24": {"PE", -12.04, -77.03}})
	now := time.Now()
	g := New(path, "")
	defer g.Close()
	g.SetClock(func() time.Time { return now }, time.Minute)

	build(t, path, "GeoLite2-City", map[string][3]any{"203.0.113.0/24": {"CL", -33.45, -70.66}})
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	// Inside the interval the old data answers.
	if loc, _ := g.Locate("203.0.113.9", ""); loc.Country != "PE" {
		t.Fatalf("reloaded too early: %+v", loc)
	}
	now = now.Add(2 * time.Minute)
	if loc, _ := g.Locate("203.0.113.9", ""); loc.Country != "CL" {
		t.Fatalf("not reloaded: %+v", loc)
	}
}

func TestBrokenReloadKeepsDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "city.mmdb")
	build(t, path, "GeoLite2-City", map[string][3]any{"203.0.113.0/24": {"PE", -12.04, -77.03}})
	now := time.Now()
	g := New(path, "")
	defer g.Close()
	g.SetClock(func() time.Time { return now }, time.Minute)
	replace(t, path, []byte("garbage"), time.Now().Add(time.Hour))
	now = now.Add(2 * time.Minute)
	if loc, ok := g.Locate("203.0.113.9", ""); !ok || loc.Country != "PE" {
		t.Fatalf("lost the database: %+v", loc)
	}
	if st := g.Status(); st.Error == "" || st.Source != risk.GeoMMDB {
		t.Fatalf("status = %+v", st)
	}
}

func TestMissingDatabaseReportsError(t *testing.T) {
	g := New(filepath.Join(t.TempDir(), "absent.mmdb"), "")
	if st := g.Status(); st.Source != risk.GeoNone || st.Error == "" || st.Travel || st.Countries {
		t.Fatalf("status = %+v", st)
	}
}

func TestHeaderMode(t *testing.T) {
	g := New("", "CF-IPCountry")
	loc, ok := g.Locate("203.0.113.9", "pe")
	if !ok || loc.Country != "PE" || loc.Located() {
		t.Fatalf("lookup = %+v %v", loc, ok)
	}
	if _, ok := g.Locate("203.0.113.9", ""); ok {
		t.Fatal("empty header located")
	}
	if st := g.Status(); st.Source != risk.GeoHeader || st.Header != "CF-IPCountry" || !st.Countries || st.Travel {
		t.Fatalf("status = %+v", st)
	}
}

func TestDatabaseWinsOverHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "city.mmdb")
	build(t, path, "GeoLite2-City", map[string][3]any{"203.0.113.0/24": {"PE", -12.04, -77.03}})
	g := New(path, "CF-IPCountry")
	defer g.Close()
	if loc, _ := g.Locate("203.0.113.9", "ES"); loc.Country != "PE" {
		t.Fatalf("header won: %+v", loc)
	}
	// An address the database does not know falls back to the header.
	if loc, _ := g.Locate("192.0.2.1", "ES"); loc.Country != "ES" {
		t.Fatalf("no fallback: %+v", loc)
	}
}

func TestNone(t *testing.T) {
	if New("", "") != nil {
		t.Fatal("no source must build nothing")
	}
}
