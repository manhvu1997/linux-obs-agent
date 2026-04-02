module github.com/manhvu1997/linux-obs-agent

go 1.26

require (
	github.com/cilium/ebpf v0.21.0
	github.com/prometheus/client_golang v1.20.0
	golang.org/x/sys v0.37.0
	gopkg.in/yaml.v3 v3.0.1
)

tool github.com/cilium/ebpf/cmd/bpf2go
