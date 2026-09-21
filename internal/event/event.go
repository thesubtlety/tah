// Package event is the sensor-agnostic normalized event: the contract every
// adapter (eslogger now; osquery/Sysmon/ETW later) emits into the core.
package event

type Kind string

const (
	Exec    Kind = "process_exec"
	Fork    Kind = "process_fork"
	Exit    Kind = "process_exit"
	Open    Kind = "file_open"
	Connect Kind = "net_connect"
	DNS     Kind = "dns_query"
)

// Actor identifies a running process by pid + Apple pidversion (audit token).
type Actor struct {
	PID        int `json:"pid"`
	PIDVersion int `json:"pidversion"`
}

// Identity is the multi-level identity captured at exec / carried on ES events.
type Identity struct {
	ExecPath   string `json:"exec_path"`
	CDHash     string `json:"cdhash"`
	SigningID  string `json:"signing_id"`
	TeamID     string `json:"team_id"`
	IsPlatform bool   `json:"is_platform"`
}

// Event is one normalized observation.
type Event struct {
	TS       int64  `json:"ts"` // epoch ms
	HostID   string `json:"host_id"`
	Sensor   string `json:"sensor"`
	Fidelity string `json:"fidelity"` // high|med|low
	Kind     Kind   `json:"kind"`
	Actor    Actor  `json:"actor"`

	// process_exec / fork
	Parent      *Actor   `json:"parent,omitempty"`
	Responsible *Actor   `json:"responsible,omitempty"`
	Child       *Actor   `json:"child,omitempty"`
	Identity    Identity `json:"identity"`
	Argv        []string `json:"argv,omitempty"`
	CWD         string   `json:"cwd,omitempty"`
	ExitCode    int      `json:"exit_code,omitempty"`

	// file_open
	Path  string `json:"path,omitempty"`
	Read  bool   `json:"read,omitempty"`
	Write bool   `json:"write,omitempty"`

	// net_connect
	Proto      string `json:"proto,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	LocalPort  int    `json:"local_port,omitempty"`

	// dns_query
	QName   string   `json:"qname,omitempty"`
	QType   string   `json:"qtype,omitempty"`
	Answers []string `json:"answers,omitempty"`
}
