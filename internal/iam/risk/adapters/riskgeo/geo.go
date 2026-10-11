// Package riskgeo locates client addresses: from a MaxMind-format database
// file (reloaded when its modification time changes) and/or from the
// country header a trusted proxy sets. It is the only package that imports
// the database reader.
package riskgeo

import (
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Abraxas-365/iamkit/internal/config"
	"github.com/Abraxas-365/iamkit/internal/iam/risk"
	"github.com/oschwald/maxminddb-golang/v2"
)

var _ risk.Geo = (*Geo)(nil)

// Geo implements risk.Geo. The zero Source (no file, no header) is not
// built: bootstrap leaves risk.Geo nil instead.
type Geo struct {
	path   string
	header string
	now    func() time.Time
	every  time.Duration

	mu       sync.Mutex
	reader   *maxminddb.Reader
	modTime  time.Time
	checked  time.Time
	loadErr  string
	meta     maxminddb.Metadata
	hasCity  bool
	reported bool
}

// New builds the locator; either argument may be empty (both empty: nil).
// An unreadable database is not fatal: the error shows in Status and the
// header (when set) keeps answering; loading is retried on the reload
// interval.
func New(database, header string) *Geo {
	if database == "" && header == "" {
		return nil
	}
	g := &Geo{path: database, header: strings.TrimSpace(header), now: time.Now, every: config.GeoIPReloadInterval}
	g.mu.Lock()
	g.reload()
	g.mu.Unlock()
	return g
}

// SetClock replaces the clock and the reload interval (tests).
func (g *Geo) SetClock(now func() time.Time, every time.Duration) { g.now, g.every = now, every }

// Close releases the database.
func (g *Geo) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.reader == nil {
		return nil
	}
	err := g.reader.Close()
	g.reader = nil
	return err
}

// reload (mu held) opens the file when it changed since the last load.
func (g *Geo) reload() {
	g.checked = g.now()
	if g.path == "" {
		return
	}
	info, err := os.Stat(g.path)
	if err != nil {
		g.fail(err)
		return
	}
	if g.reader != nil && info.ModTime().Equal(g.modTime) {
		return
	}
	r, err := maxminddb.Open(g.path)
	if err != nil {
		g.fail(err)
		return
	}
	if g.reader != nil {
		// Lookups hold mu, so nobody reads the old mapping.
		_ = g.reader.Close()
	}
	g.reader, g.modTime, g.loadErr, g.reported = r, info.ModTime(), "", false
	g.meta = r.Metadata
	g.hasCity = strings.Contains(strings.ToLower(g.meta.DatabaseType), "city")
}

func (g *Geo) fail(err error) {
	g.loadErr = err.Error()
	if !g.reported {
		g.reported = true
		slog.Warn("GeoIP database could not be loaded; the previous one (if any) stays in use", "path", g.path, "err", err)
	}
}

func (g *Geo) refresh() {
	if g.path != "" && g.now().Sub(g.checked) >= g.every {
		g.reload()
	}
}

// record is the part of City and Country databases risk reads.
type record struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Location struct {
		Latitude  *float64 `maxminddb:"latitude"`
		Longitude *float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// Locate returns where ip is. The database wins; the header country (set
// by a trusted proxy, already validated by identity.ClientInfo) answers
// when there is no database or it does not know the address.
func (g *Geo) Locate(ip, headerCountry string) (risk.Location, bool) {
	var out risk.Location
	if g.path != "" {
		if addr, err := netip.ParseAddr(ip); err == nil {
			g.mu.Lock()
			g.refresh()
			if g.reader != nil {
				var rec record
				res := g.reader.Lookup(addr.Unmap())
				if res.Found() && res.Decode(&rec) == nil {
					out.Country = strings.ToUpper(rec.Country.ISOCode)
					out.Latitude, out.Longitude = rec.Location.Latitude, rec.Location.Longitude
				}
			}
			g.mu.Unlock()
		}
	}
	if out.Country == "" && g.header != "" {
		out.Country = strings.ToUpper(headerCountry)
	}
	return out, out.Country != "" || out.Located()
}

// Status describes the source: a database (with its type and build date),
// else the header.
func (g *Geo) Status() risk.GeoStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.refresh()
	st := risk.GeoStatus{Source: risk.GeoNone}
	if g.header != "" {
		st.Source, st.Header, st.Countries = risk.GeoHeader, g.header, true
	}
	if g.path != "" {
		st.Error = g.loadErr
		if g.reader != nil {
			built := g.meta.BuildTime().UTC()
			st.Source, st.Database, st.BuildDate = risk.GeoMMDB, g.meta.DatabaseType, &built
			st.Countries, st.Travel = true, g.hasCity
			st.Header = g.header
		} else if g.header == "" {
			st.Source = risk.GeoNone
		}
	}
	return st
}
