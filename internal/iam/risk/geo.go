package risk

import (
	"math"
	"time"
)

// GeoIP sources (deployment-wide).
const (
	GeoNone   = "none"
	GeoMMDB   = "mmdb"   // IAMKIT_GEOIP_DB: a MaxMind-format database file
	GeoHeader = "header" // IAMKIT_GEOIP_HEADER: a country header set by a trusted proxy
)

// Location is where an address is, as far as GeoIP knows. Coordinates come
// only from a City database.
type Location struct {
	Country   string
	Latitude  *float64
	Longitude *float64
}

// Located reports whether the location has coordinates.
func (l Location) Located() bool { return l.Latitude != nil && l.Longitude != nil }

// GeoStatus describes the deployment's GeoIP (GET …/risk/status).
type GeoStatus struct {
	Source string `json:"source"`
	// Database is the database type (e.g. GeoLite2-City); BuildDate when
	// it was built. Header: the header name.
	Database  string     `json:"database,omitempty"`
	Header    string     `json:"header,omitempty"`
	BuildDate *time.Time `json:"build_date,omitempty"`
	// Countries / Travel say what the source supports: country rules, and
	// impossible travel (coordinates).
	Countries bool `json:"countries"`
	Travel    bool `json:"travel"`
	// Error is why the database could not be read ("" = fine).
	Error string `json:"error,omitempty"`
}

// Status is GET …/risk/status.
type Status struct {
	GeoIP GeoStatus `json:"geoip"`
	// Captcha / RiskSignals are the feature flags as they apply to the
	// environment.
	Captcha     bool `json:"captcha"`
	RiskSignals bool `json:"risk_signals"`
}

// DistanceKm is the great-circle distance between two points.
func DistanceKm(lat1, lon1, lat2, lon2 float64) float64 {
	const earth = 6371.0
	rad := func(d float64) float64 { return d * math.Pi / 180 }
	dLat, dLon := rad(lat2-lat1), rad(lon2-lon1)
	a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(rad(lat1))*math.Cos(rad(lat2))*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earth * math.Asin(math.Min(1, math.Sqrt(a)))
}

// Traveled reports whether going from last to here by now needs
// more than speedKmh. Closer than minKm is never impossible (GeoIP city
// precision).
func Traveled(last Last, here Location, now time.Time, speedKmh, minKm float64) bool {
	if !here.Located() {
		return false
	}
	km := DistanceKm(last.Latitude, last.Longitude, *here.Latitude, *here.Longitude)
	if km < minKm {
		return false
	}
	hours := now.Sub(last.At).Hours()
	if hours <= 0 {
		return true
	}
	return km/hours > speedKmh
}
