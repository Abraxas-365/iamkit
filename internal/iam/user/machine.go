package user

// Kind tells people from machines. A machine user has no email, username,
// password, phone or second factor: no sign-in path can match it, and it
// authenticates only with API keys (apikey module) and keys (user_keys).
type Kind string

const (
	KindHuman   Kind = "human"
	KindMachine Kind = "machine"
)

// Valid reports a known kind ("" is human).
func (k Kind) Valid() bool { return k == "" || k == KindHuman || k == KindMachine }
