package server

import (
	"context"
	"log/slog"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/monitoring"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

func normalizeMAC(mac string) string {
	return strings.ToLower(strings.ReplaceAll(mac, "-", ":"))
}

func addressIP(address string) string {
	ip, _, _ := strings.Cut(address, "/")
	return ip
}

func matchInterface(bridged *vbox.BridgedIf, interfaces []monitoring.Interface) string {
	if mac := normalizeMAC(bridged.HardwareAddress); mac != "" {
		for i := range interfaces {
			if normalizeMAC(interfaces[i].MACAddress) == mac {
				return interfaces[i].Link
			}
		}
	}
	if bridged.IPAddress == "" || bridged.IPAddress == "0.0.0.0" {
		return ""
	}
	for i := range interfaces {
		for _, address := range interfaces[i].Addresses {
			if addressIP(address) == bridged.IPAddress {
				return interfaces[i].Link
			}
		}
	}
	return ""
}

func (s *Server) bridgedJoin(ctx context.Context, interfaces []monitoring.Interface) map[string]string {
	joined := map[string]string{}
	exe := machines.VBoxManagePath(ctx)
	if exe == "" {
		return joined
	}
	bridged, err := vbox.ListBridgedIfs(ctx, exe)
	if err != nil {
		slog.Debug("list bridged interfaces for the interface join", "error", err)
		return joined
	}
	for i := range bridged {
		if link := matchInterface(&bridged[i], interfaces); link != "" {
			joined[bridged[i].Name] = link
		}
	}
	return joined
}

func (s *Server) describeInterfaces(ctx context.Context, interfaces []monitoring.Interface) {
	descriptions := map[string]string{}
	for name, link := range s.bridgedJoin(ctx, interfaces) {
		descriptions[link] = name
	}
	for i := range interfaces {
		interfaces[i].Description = descriptions[interfaces[i].Link]
	}
}

func (s *Server) bridgedInterfaceNames(ctx context.Context, raw map[string]string) map[string]string {
	if !machines.HasBridgedNIC(raw) {
		return map[string]string{}
	}
	interfaces, err := s.monitor.Sampler().Interfaces(ctx)
	if err != nil {
		slog.Debug("read interfaces for the bridged adapter join", "error", err)
		return map[string]string{}
	}
	return s.bridgedJoin(ctx, interfaces)
}
