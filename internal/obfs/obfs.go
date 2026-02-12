package obfs

type Mode string

const (
	ModeNone     Mode = "none"
	ModePreamble Mode = "preamble"
)

type Config struct {
	Mode             Mode
	MaxPreamble      int
	PreambleTemplate string
}

func (c Config) Enabled() bool {
	return c.Mode != ModeNone && c.MaxPreamble > 0
}
