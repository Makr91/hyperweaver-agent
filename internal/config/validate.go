package config

import (
	"fmt"
	"net"
	"strings"
)

// logLevelValid reports whether s is part of the logging level vocabulary.
func logLevelValid(s string) bool {
	switch s {
	case "error", "warn", "info", "debug":
		return true
	default:
		return false
	}
}

func (c *Config) validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port %d out of range 1-65535", c.Server.Port)
	}
	if c.Server.HTTPSPort < 1 || c.Server.HTTPSPort > 65535 {
		return fmt.Errorf("server.https_port %d out of range 1-65535", c.Server.HTTPSPort)
	}
	if c.Server.BindAddress != "" && net.ParseIP(c.Server.BindAddress) == nil {
		return fmt.Errorf("server.bind_address %q is not an IP address", c.Server.BindAddress)
	}
	if !logLevelValid(c.Logging.Level) {
		return fmt.Errorf("logging.level %q must be one of error, warn, info, debug", c.Logging.Level)
	}
	for category, level := range c.Logging.Categories {
		if !logLevelValid(level) {
			return fmt.Errorf("logging.categories.%s %q must be one of error, warn, info, debug",
				category, level)
		}
	}
	if c.APIKeys.HashRounds < 4 || c.APIKeys.HashRounds > 20 {
		return fmt.Errorf("api_keys.hash_rounds %d out of range 4-20", c.APIKeys.HashRounds)
	}
	if c.APIKeys.KeyLength < 16 || c.APIKeys.KeyLength > 256 {
		return fmt.Errorf("api_keys.key_length %d out of range 16-256", c.APIKeys.KeyLength)
	}
	if c.Tasks.PollIntervalSeconds < 1 || c.Tasks.PollIntervalSeconds > 60 {
		return fmt.Errorf("tasks.poll_interval_seconds %d out of range 1-60", c.Tasks.PollIntervalSeconds)
	}
	if c.Tasks.MaxConcurrent < 1 || c.Tasks.MaxConcurrent > 64 {
		return fmt.Errorf("tasks.max_concurrent %d out of range 1-64", c.Tasks.MaxConcurrent)
	}
	switch c.Tasks.Output.Mode {
	case "full", "circular":
	default:
		return fmt.Errorf("tasks.output.mode %q must be full or circular", c.Tasks.Output.Mode)
	}
	if c.Tasks.Output.CircularMaxLines < 100 {
		return fmt.Errorf("tasks.output.circular_max_lines %d must be at least 100", c.Tasks.Output.CircularMaxLines)
	}
	if c.Tasks.Output.FlushIntervalSeconds < 1 || c.Tasks.Output.FlushIntervalSeconds > 300 {
		return fmt.Errorf("tasks.output.flush_interval_seconds %d out of range 1-300", c.Tasks.Output.FlushIntervalSeconds)
	}
	if c.Tasks.DefaultPaginationLimit < 1 || c.Tasks.DefaultPaginationLimit > 1000 {
		return fmt.Errorf("tasks.default_pagination_limit %d out of range 1-1000", c.Tasks.DefaultPaginationLimit)
	}
	if c.Tasks.RetentionDays < 1 || c.Tasks.RetentionDays > 3650 {
		return fmt.Errorf("tasks.retention_days %d out of range 1-3650", c.Tasks.RetentionDays)
	}
	if c.Machines.DiscoveryInterval < 10 || c.Machines.DiscoveryInterval > 86400 {
		return fmt.Errorf("machines.discovery_interval %d out of range 10-86400", c.Machines.DiscoveryInterval)
	}
	if c.Machines.ServerIDStart < 1 || c.Machines.ServerIDStart > 99999999 {
		return fmt.Errorf("machines.server_id_start %d out of range 1-99999999", c.Machines.ServerIDStart)
	}
	if c.Machines.ShutdownTimeout < 5 || c.Machines.ShutdownTimeout > 3600 {
		return fmt.Errorf("machines.shutdown_timeout %d out of range 5-3600", c.Machines.ShutdownTimeout)
	}
	if c.Cleanup.Interval < 60 || c.Cleanup.Interval > 86400 {
		return fmt.Errorf("cleanup.interval %d out of range 60-86400", c.Cleanup.Interval)
	}
	if c.Monitoring.CollectionInterval < 5 || c.Monitoring.CollectionInterval > 3600 {
		return fmt.Errorf("monitoring.collection_interval %d out of range 5-3600", c.Monitoring.CollectionInterval)
	}
	if c.Monitoring.RetentionDays < 1 || c.Monitoring.RetentionDays > 365 {
		return fmt.Errorf("monitoring.retention_days %d out of range 1-365", c.Monitoring.RetentionDays)
	}
	if c.Assets.MaxUploadGB < 1 || c.Assets.MaxUploadGB > 1024 {
		return fmt.Errorf("assets.max_upload_gb %d out of range 1-1024", c.Assets.MaxUploadGB)
	}
	switch c.Provisioning.DefaultSyncMethod {
	case "rsync", "scp":
	default:
		return fmt.Errorf("provisioning.default_sync_method %q must be rsync or scp",
			c.Provisioning.DefaultSyncMethod)
	}
	if c.Provisioning.PlaybookTimeoutSeconds < 60 {
		return fmt.Errorf("provisioning.playbook_timeout_seconds %d must be at least 60",
			c.Provisioning.PlaybookTimeoutSeconds)
	}
	if c.Provisioning.AnsibleInstallTimeoutSeconds < 60 {
		return fmt.Errorf("provisioning.ansible_install_timeout_seconds %d must be at least 60",
			c.Provisioning.AnsibleInstallTimeoutSeconds)
	}
	if c.Provisioning.SSH.TimeoutSeconds < 10 {
		return fmt.Errorf("provisioning.ssh.timeout_seconds %d must be at least 10",
			c.Provisioning.SSH.TimeoutSeconds)
	}
	if c.Provisioning.SSH.PollIntervalSeconds < 1 {
		return fmt.Errorf("provisioning.ssh.poll_interval_seconds %d must be at least 1",
			c.Provisioning.SSH.PollIntervalSeconds)
	}
	if c.Provisioning.Network.Enabled {
		if _, _, err := net.ParseCIDR(c.Provisioning.Network.Subnet); err != nil {
			return fmt.Errorf("provisioning.network.subnet %q is not CIDR notation", c.Provisioning.Network.Subnet)
		}
		for field, value := range map[string]string{
			"host_ip":          c.Provisioning.Network.HostIP,
			"netmask":          c.Provisioning.Network.Netmask,
			"dhcp_server_ip":   c.Provisioning.Network.DHCPServerIP,
			"dhcp_range_start": c.Provisioning.Network.DHCPRangeStart,
			"dhcp_range_end":   c.Provisioning.Network.DHCPRangeEnd,
		} {
			if net.ParseIP(value) == nil {
				return fmt.Errorf("provisioning.network.%s %q is not an IP address", field, value)
			}
		}
	}
	for i := range c.TemplateSources.Sources {
		if c.TemplateSources.Sources[i].Name == "" || c.TemplateSources.Sources[i].URL == "" {
			return fmt.Errorf("template_sources.sources[%d] needs both name and url", i)
		}
	}
	return c.Database.SQLiteOptions.validate()
}

// validate checks the SQLite tuning values against SQLite's own vocabularies.
func (o *SQLiteOptionsConfig) validate() error {
	switch strings.ToUpper(o.JournalMode) {
	case "DELETE", "TRUNCATE", "PERSIST", "MEMORY", "WAL", "OFF":
	default:
		return fmt.Errorf("database.sqlite_options.journal_mode %q must be one of DELETE, TRUNCATE, PERSIST, MEMORY, WAL, OFF",
			o.JournalMode)
	}
	switch strings.ToUpper(o.Synchronous) {
	case "OFF", "NORMAL", "FULL", "EXTRA":
	default:
		return fmt.Errorf("database.sqlite_options.synchronous %q must be one of OFF, NORMAL, FULL, EXTRA",
			o.Synchronous)
	}
	switch strings.ToUpper(o.TempStore) {
	case "DEFAULT", "FILE", "MEMORY":
	default:
		return fmt.Errorf("database.sqlite_options.temp_store %q must be one of DEFAULT, FILE, MEMORY",
			o.TempStore)
	}
	if o.CacheSizeMB < 1 || o.CacheSizeMB > 8192 {
		return fmt.Errorf("database.sqlite_options.cache_size_mb %d out of range 1-8192", o.CacheSizeMB)
	}
	if o.MmapSizeMB < 0 || o.MmapSizeMB > 16384 {
		return fmt.Errorf("database.sqlite_options.mmap_size_mb %d out of range 0-16384", o.MmapSizeMB)
	}
	if o.BusyTimeoutMS < 100 || o.BusyTimeoutMS > 600000 {
		return fmt.Errorf("database.sqlite_options.busy_timeout_ms %d out of range 100-600000", o.BusyTimeoutMS)
	}
	if o.WALAutocheckpoint < 0 || o.WALAutocheckpoint > 1000000 {
		return fmt.Errorf("database.sqlite_options.wal_autocheckpoint %d out of range 0-1000000", o.WALAutocheckpoint)
	}
	return nil
}
