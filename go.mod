module github.com/DvGils/notenv

go 1.26.4

require (
	filippo.io/age v1.3.1
	github.com/BurntSushi/toml v1.6.0
	github.com/spf13/cobra v1.10.2
	golang.org/x/sys v0.46.0
	golang.org/x/term v0.44.0
)

require (
	filippo.io/hpke v0.4.0 // indirect
	github.com/fzipp/gocyclo v0.6.0 // indirect
	github.com/gordonklaus/ineffassign v0.2.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/telemetry v0.0.0-20260611141451-d61e87d5f4a3 // indirect
	golang.org/x/tools v0.46.0 // indirect
	golang.org/x/vuln v1.4.0 // indirect
)

tool (
	github.com/fzipp/gocyclo/cmd/gocyclo
	github.com/gordonklaus/ineffassign
	golang.org/x/vuln/cmd/govulncheck
)
