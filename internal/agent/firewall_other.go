//go:build !linux && !windows

package agent

func detectFirewall() firewall { return noFirewall{} }
