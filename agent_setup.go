package main

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"time"

	"github.com/Makr91/hyperweaver-agent/internal/assets"
	"github.com/Makr91/hyperweaver-agent/internal/config"
	"github.com/Makr91/hyperweaver-agent/internal/db"
	"github.com/Makr91/hyperweaver-agent/internal/hostname"
	"github.com/Makr91/hyperweaver-agent/internal/hostpower"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
	"github.com/Makr91/hyperweaver-agent/internal/monitoring"
	"github.com/Makr91/hyperweaver-agent/internal/netaddr"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
	"github.com/Makr91/hyperweaver-agent/internal/secrets"
	"github.com/Makr91/hyperweaver-agent/internal/server"
	"github.com/Makr91/hyperweaver-agent/internal/sshrun"
	"github.com/Makr91/hyperweaver-agent/internal/tasks"
)

// agentSystems bundles everything setupTasks builds over the databases —
// the task queue, machine subsystem, provisioner registry, monitoring
// service, the open database handles (for the /database endpoints), and
// their closer.
type agentSystems struct {
	queue        *tasks.Queue
	machines     *machines.Store
	provisioners *provisioner.Registry
	assets       *assets.Store
	artifactSvc  *assets.Service
	reconciler   *machines.Reconciler
	snapshots    *machines.SnapshotRotation
	monitor      *monitoring.Service
	dbs          []server.DBHandle
	closeDBs     func()
}

// setupTasks opens the agent's databases and builds the task queue, the
// machine subsystem, the provisioner registry, and the monitoring service
// on top of them:
// tasks.sqlite carries the queue, agent.sqlite the machine registry, and —
// only when monitoring.storage_enabled — the per-datatype telemetry files
// carry stored samples. Every executor is registered before the queue ever
// starts. The returned closer releases every database handle.
func setupTasks(cfg *config.Config, secretsStore *secrets.Store) (*agentSystems, error) {
	tasksPath, err := cfg.TasksDBPath()
	if err != nil {
		return nil, err
	}
	agentPath, err := cfg.AgentDBPath()
	if err != nil {
		return nil, err
	}
	taskLogDir, err := cfg.TaskLogDir()
	if err != nil {
		return nil, err
	}

	// database.sqlite_options applies to both agent databases.
	sqliteOpts := cfg.Database.SQLiteOptions
	dbOptions := db.Options{
		JournalMode:       sqliteOpts.JournalMode,
		Synchronous:       sqliteOpts.Synchronous,
		CacheSizeMB:       sqliteOpts.CacheSizeMB,
		TempStore:         sqliteOpts.TempStore,
		MmapSizeMB:        sqliteOpts.MmapSizeMB,
		BusyTimeoutMS:     sqliteOpts.BusyTimeoutMS,
		WALAutocheckpoint: sqliteOpts.WALAutocheckpoint,
		Optimize:          sqliteOpts.Optimize,
	}

	// Startup-scoped, not request-scoped — Background is correct here.
	// A restart-spawned successor retries while its predecessor releases the
	// database file locks — same handshake the port bind uses; the databases
	// open before the port, so without this a restart races the dying
	// process's SQLite locks (observed as "disk I/O error (1546)").
	openDB := func(path string, migrations []string) (*sql.DB, error) {
		attempts := 1
		if os.Getenv("HYPERWEAVER_RESTART") == "1" {
			attempts = 20
		}
		var lastErr error
		for i := 0; i < attempts; i++ {
			database, oerr := db.Open(context.Background(), path, &dbOptions, migrations)
			if oerr == nil {
				return database, nil
			}
			lastErr = oerr
			if attempts > 1 {
				time.Sleep(500 * time.Millisecond)
			}
		}
		return nil, lastErr
	}

	tasksDB, err := openDB(tasksPath, tasks.Migrations)
	if err != nil {
		return nil, err
	}
	// agent.sqlite carries every core-state family in ONE ordered list —
	// user_version tracking is positional, so new scripts APPEND at the end
	// (whichever family arrived latest rides last for exactly that reason).
	// ProfileTombstone appears TWICE by design: once holding the removed
	// feature's original slot (position must survive removal), once appended
	// so existing databases actually drop the table.
	agentMigrations := append(append([]string{}, machines.Migrations...), assets.Migrations...)
	agentMigrations = append(agentMigrations, machines.TemplateMigrations...)
	agentMigrations = append(agentMigrations, machines.ProfileTombstone...)
	agentMigrations = append(agentMigrations, assets.MergeMigrations...)
	agentMigrations = append(agentMigrations, machines.ProfileTombstone...)
	agentMigrations = append(agentMigrations, machines.HypervisorMigration...)
	agentDB, err := openDB(agentPath, agentMigrations)
	if err != nil {
		_ = tasksDB.Close()
		return nil, err
	}

	// Every open handle lands here — the /database endpoints operate across
	// them all, and the closer releases them in reverse-open order.
	handles := []server.DBHandle{
		{Name: "tasks.sqlite", Path: tasksPath, DB: tasksDB, Tables: []string{"tasks"}},
		{Name: "agent.sqlite", Path: agentPath, DB: agentDB, Tables: []string{"machines", "artifacts", "artifact_locations", "templates"}},
	}
	closer := func() {
		for i := len(handles) - 1; i >= 0; i-- {
			if cerr := handles[i].DB.Close(); cerr != nil {
				slog.Error("close database", "name", handles[i].Name, "error", cerr)
			}
		}
	}

	// Telemetry storage (monitoring.storage_enabled): one database file per
	// data family so telemetry write churn never contends with the main
	// databases — Mark's ruling, 2026-07-05.
	var monitorStore *monitoring.Store
	if cfg.Monitoring.StorageEnabled {
		kinds := []struct {
			kind       string
			table      string
			migrations []string
		}{
			{"cpu", "cpu_samples", monitoring.CPUMigrations},
			{"memory", "memory_samples", monitoring.MemoryMigrations},
			{"network", "network_samples", monitoring.NetworkMigrations},
		}
		opened := make([]*sql.DB, 0, len(kinds))
		for _, k := range kinds {
			path, perr := cfg.MonitoringDBPath(k.kind)
			if perr != nil {
				closer()
				return nil, perr
			}
			database, oerr := openDB(path, k.migrations)
			if oerr != nil {
				closer()
				return nil, oerr
			}
			opened = append(opened, database)
			handles = append(handles, server.DBHandle{
				Name:   "monitoring-" + k.kind + ".sqlite",
				Path:   path,
				DB:     database,
				Tables: []string{k.table},
			})
		}
		monitorStore = monitoring.NewStore(opened[0], opened[1], opened[2])
	}
	monitor := monitoring.NewService(monitoring.NewSampler(), monitorStore,
		time.Duration(cfg.Monitoring.CollectionInterval)*time.Second,
		cfg.Monitoring.RetentionDays)

	store := tasks.NewStore(tasksDB)
	output := tasks.NewOutputManager(store, tasks.OutputConfig{
		Enabled:          cfg.Tasks.Output.Enabled,
		Mode:             cfg.Tasks.Output.Mode,
		CircularMaxLines: cfg.Tasks.Output.CircularMaxLines,
		FlushInterval:    time.Duration(cfg.Tasks.Output.FlushIntervalSeconds) * time.Second,
		PersistLogFile:   cfg.Tasks.Output.PersistLogFile,
		LogDirectory:     taskLogDir,
	})
	queue := tasks.NewQueue(store, output, tasks.QueueConfig{
		PollInterval:         time.Duration(cfg.Tasks.PollIntervalSeconds) * time.Second,
		MaxConcurrent:        cfg.Tasks.MaxConcurrent,
		RetentionDays:        cfg.Tasks.RetentionDays,
		CleanupInterval:      time.Duration(cfg.Cleanup.Interval) * time.Second,
		ResumePendingOnStart: cfg.Tasks.ResumePendingOnStart,
	})

	// Provisioner package registry (architecture §8): the directory is the
	// source of truth — scanned live, seeded after the port is owned.
	provisionersDir, err := cfg.ProvisionersDir()
	if err != nil {
		closer()
		return nil, err
	}
	provisioners := provisioner.NewRegistry(provisionersDir)
	catalogSources := make([]provisioner.CatalogSource, 0, len(cfg.CatalogSources.Sources))
	for _, source := range cfg.CatalogSources.Sources {
		catalogSources = append(catalogSources, provisioner.CatalogSource{
			Name:    source.Name,
			URL:     source.URL,
			Enabled: source.Enabled,
			Default: source.Default,
			CAFile:  source.CAFile,
		})
	}
	provisioner.RegisterExecutors(queue, provisioners, secretsStore.GitToken, catalogSources)

	// The merged artifact system (artifact_storage.enabled): typed storage
	// locations + the hash-verified registry every mounted file passes
	// through. The store always exists (the /database endpoints see the
	// tables); a nil handle in ProvisionEnv is what "disabled" means to the
	// pipeline. The service (location sync, expectation seeding, startup +
	// periodic scans) initializes in run once this process owns the port.
	artifactsRoot, err := cfg.ArtifactsRootDir()
	if err != nil {
		closer()
		return nil, err
	}
	assetsStore := assets.NewStore(agentDB, artifactsRoot)
	assets.RegisterExecutors(queue, assetsStore, secretsStore.ResourceAuth, secretsStore,
		cfg.ArtifactStorage.Scanning.SupportedExtensions)
	servicePaths := make([]assets.PathConfig, 0, len(cfg.ArtifactStorage.Paths))
	for _, entry := range cfg.ArtifactStorage.Paths {
		servicePaths = append(servicePaths, assets.PathConfig{
			Name: entry.Name, Path: entry.Path, Type: entry.Type, Enabled: entry.Enabled,
		})
	}
	artifactSvc := assets.NewService(assetsStore, assets.ServiceConfig{
		Enabled:      cfg.ArtifactStorage.Enabled,
		Root:         artifactsRoot,
		Paths:        servicePaths,
		Extensions:   cfg.ArtifactStorage.Scanning.SupportedExtensions,
		ScanInterval: cfg.ArtifactStorage.Scanning.PeriodicScanInterval,
	})
	var pipelineAssets *assets.Store
	if cfg.ArtifactStorage.Enabled {
		pipelineAssets = assetsStore
	}

	machinesDir, err := cfg.MachinesDir()
	if err != nil {
		closer()
		return nil, err
	}
	templatesDir, err := cfg.TemplatesDir()
	if err != nil {
		closer()
		return nil, err
	}

	// The agent's own provisioning SSH key (the base generates one at
	// startup): the pipeline's auth fallback of LAST RESORT — used only when
	// the document supplies neither a key path nor a password. Nothing
	// auto-injects it into guests (the base-session correction: cloud-init
	// sshkey comes only from the document's own cloud_init.sshkey). A
	// generation failure only degrades the fallback.
	provisionKeyPath := cfg.ProvisionKeyPath()
	if _, kerr := sshrun.EnsureProvisionKey(provisionKeyPath); kerr != nil {
		slog.Warn("provisioning SSH key setup failed; document credentials required", "error", kerr)
	}

	templateSources := make([]machines.TemplateSource, 0, len(cfg.TemplateSources.Sources))
	for _, source := range cfg.TemplateSources.Sources {
		templateSources = append(templateSources, machines.TemplateSource{
			Name:      source.Name,
			URL:       source.URL,
			Enabled:   source.Enabled,
			Default:   source.Default,
			AuthToken: source.AuthToken,
			CAFile:    source.CAFile,
		})
	}

	machineStore := machines.NewStore(agentDB)
	reconciler := machines.NewReconciler(machineStore, store,
		cfg.Machines.AutoDiscovery,
		time.Duration(cfg.Machines.DiscoveryInterval)*time.Second,
		machinesDir, cfg.GuestAgent.Enabled)
	machines.RegisterExecutors(queue, machineStore, reconciler,
		time.Duration(cfg.Machines.ShutdownTimeout)*time.Second,
		&machines.ProvisionEnv{
			Registry:                provisioners,
			SecretsVars:             secretsStore.TemplateVars,
			MachinesDir:             machinesDir,
			Assets:                  pipelineAssets,
			CACertPath:              cfg.SSLCACertPath(),
			CAKeyPath:               cfg.SSLCAKeyPath(),
			DefaultSyncMethod:       cfg.Provisioning.DefaultSyncMethod,
			GuestAgentEnabled:       cfg.GuestAgent.Enabled,
			HostHooks:               cfg.Provisioning.HostHooks,
			VRDECertRoot:            cfg.VRDECertRoot(),
			DefaultNetworkInterface: cfg.Provisioning.DefaultNetworkInterface,
			TemplatesDir:            templatesDir,
			TemplateSources:         templateSources,
			ProvisionKeyPath:        provisionKeyPath,
			SSHTimeout:              time.Duration(cfg.Provisioning.SSH.TimeoutSeconds) * time.Second,
			SSHPollInterval:         time.Duration(cfg.Provisioning.SSH.PollIntervalSeconds) * time.Second,
			AnsibleInstallTimeout:   time.Duration(cfg.Provisioning.AnsibleInstallTimeoutSeconds) * time.Second,
			PlaybookTimeout:         time.Duration(cfg.Provisioning.PlaybookTimeoutSeconds) * time.Second,
			Network: machines.NetworkEnv{
				Enabled:        cfg.Provisioning.Network.Enabled,
				Subnet:         cfg.Provisioning.Network.Subnet,
				HostIP:         cfg.Provisioning.Network.HostIP,
				Netmask:        cfg.Provisioning.Network.Netmask,
				DHCPServerIP:   cfg.Provisioning.Network.DHCPServerIP,
				DHCPRangeStart: cfg.Provisioning.Network.DHCPRangeStart,
				DHCPRangeEnd:   cfg.Provisioning.Network.DHCPRangeEnd,
			},
		})

	// Host power operations run through the queue too (config-gated at the
	// HTTP surface; registering the executors unconditionally is harmless —
	// no handler queues them while the surface is disabled).
	hostpower.RegisterExecutors(queue, hostpower.LookupCommand)

	// set_hostname (the /network/hostname surface's async half — the
	// converged wire, sync 2026-07-17).
	hostname.RegisterExecutors(queue)

	// The /network/addresses mutations (zoneweaver's address ops — Mark's
	// build order 2026-07-19 replaced the 501 stubs).
	netaddr.RegisterExecutors(queue)

	// Scheduled snapshot rotation (snapshots.enabled — zoneweaver's
	// Snapshoter.sh replacement, VBox-conservative defaults): visible
	// snapshot_take rows through the queue, per-machine policy overrides read
	// live from configuration.snapshots.
	defaultTiers := map[string]machines.SnapshotTier{}
	for tier, entry := range cfg.Snapshots.DefaultPolicy.Tiers {
		defaultTiers[tier] = machines.SnapshotTier{Keep: entry.Keep}
	}
	snapshotRotation := machines.NewSnapshotRotation(machineStore, store,
		machines.SnapshotRotationConfig{
			Enabled:  cfg.Snapshots.Enabled,
			Interval: time.Duration(cfg.Snapshots.IntervalMinutes) * time.Minute,
			DefaultPolicy: machines.SnapshotPolicy{
				Type:       cfg.Snapshots.DefaultPolicy.Type,
				Quiesce:    cfg.Snapshots.DefaultPolicy.Quiesce,
				Keep:       cfg.Snapshots.DefaultPolicy.Keep,
				MaxAgeDays: cfg.Snapshots.DefaultPolicy.MaxAgeDays,
				Tiers:      defaultTiers,
			},
		})

	return &agentSystems{
		queue:        queue,
		machines:     machineStore,
		provisioners: provisioners,
		assets:       assetsStore,
		artifactSvc:  artifactSvc,
		reconciler:   reconciler,
		snapshots:    snapshotRotation,
		monitor:      monitor,
		dbs:          handles,
		closeDBs:     closer,
	}, nil
}
