package console

// Config contains the configuration of a client
type Config struct {
	Region         string
	BaseConsoleURL string
	UAAURL         string
	Scopes         []string
	Debug          bool
	DebugLog       string
}
