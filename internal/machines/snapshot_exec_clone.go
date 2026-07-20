package machines

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Makr91/hyperweaver-agent/internal/tasks"
	"github.com/Makr91/hyperweaver-agent/internal/utm"
	"github.com/Makr91/hyperweaver-agent/internal/vbox"
)

// cloneCurrentMetadata is machine_clone_current's metadata: the SOURCE machine
// plus the identity-stripped spec the clone row stores (the handler strips
// server_id/consoleport/macs/addressing exactly like the spec-rebuild clone).
type cloneCurrentMetadata struct {
	Source string `json:"source"`
	Spec   *Spec  `json:"spec"`
	// Snapshot names a source snapshot to clone from ("" = current state).
	Snapshot string `json:"snapshot,omitempty"`
	// Linked makes a differencing clone against Snapshot instead of a full
	// copy (VirtualBox requires a snapshot for linked clones).
	Linked bool `json:"linked,omitempty"`
}

// cloneCurrent executes machine_clone_current: `VBoxManage clonevm` copies
// the source's CURRENT disk state (the base's clone semantics — its ZFS
// snapshot copy), then the clone's identity is fixed up: fresh NAT ssh
// port-forward (the copied rule would collide with the source's host port),
// VRDE off (consoleport was stripped), and the registry row lands with the
// stripped spec. The task's MachineName is the CLONE.
func (e *executors) cloneCurrent(ctx context.Context, task *tasks.Task, out *tasks.OutputWriter) error {
	if len(task.Metadata) == 0 {
		return errors.New("clone task has no metadata")
	}
	var meta cloneCurrentMetadata
	if err := json.Unmarshal(task.Metadata, &meta); err != nil {
		return fmt.Errorf("parse clone metadata: %w", err)
	}
	if meta.Source == "" || meta.Spec == nil {
		return errors.New("clone task metadata needs source and spec")
	}
	// The utm branch keys on the SOURCE row's hypervisor — the clone's own row
	// does not exist yet, so dispatchUTM cannot answer here. Load errors fall
	// through: the VBox path re-loads and reports them.
	if source, serr := e.store.Get(ctx, meta.Source); serr == nil && source.Hypervisor == HypervisorUTM {
		return e.cloneCurrentUTM(ctx, task, &meta, source, out)
	}
	vboxExe := VBoxManagePath(ctx)
	if vboxExe == "" {
		return errors.New("VirtualBox is not installed")
	}

	source, err := e.store.Get(ctx, meta.Source)
	if err != nil {
		return fmt.Errorf("source machine %s: %w", meta.Source, err)
	}
	sourceTarget := source.VBoxTarget()
	info, err := vbox.ShowVMInfo(ctx, vboxExe, sourceTarget)
	if err != nil {
		return fmt.Errorf("source machine %s has no VM to clone: %w", meta.Source, err)
	}
	if meta.Snapshot == "" && MapVBoxState(info.State) == StatusRunning {
		return errors.New("source machine is running — stop it, or clone from a snapshot (snapshot parameter)")
	}

	e.taskProgress(task, 10, "cloning_vm")
	out.Write("stdout", "Cloning "+meta.Source+" → "+task.MachineName+" (VBoxManage clonevm — current state)\n")
	if cerr := vbox.CloneVM(ctx, vboxExe, sourceTarget, task.MachineName,
		e.env.MachinesDir, meta.Snapshot, meta.Linked); cerr != nil {
		return cerr
	}
	cleanup := func(step string, ferr error) error {
		out.Write("stderr", step+" failed — unregistering the half-made clone\n")
		if uerr := vbox.UnregisterVM(ctx, vboxExe, task.MachineName, true); uerr != nil {
			out.Write("stderr", "Unregister failed: "+uerr.Error()+"\n")
		}
		return ferr
	}

	cloneInfo, err := vbox.ShowVMInfo(ctx, vboxExe, task.MachineName)
	if err != nil {
		return cleanup("clone inspection", err)
	}

	// Clones are DATA-COMPLETE (Mark's ruling, sync 2026-07-18): clonevm
	// copied every attached disk into the clone's own folder — those copies
	// are the clone's OWN media and stamp "clone" so delete destroys them.
	// Anything outside the clone folder (referenced ISOs, shared media) stays
	// unstamped/foreign. Stamp failures narrate — an unstamped copy is merely
	// preserved at delete, never destroyed wrongly.
	e.taskProgress(task, 40, "stamping_media")
	clonePrefix := strings.ToLower(filepath.Clean(cloneInfo.Home)) + string(filepath.Separator)
	for key, value := range cloneInfo.Raw {
		if value == "none" || value == "emptydrive" || value == "" {
			continue
		}
		if attachmentPattern.FindStringSubmatch(key) == nil || strings.Contains(key, "ImageUUID") {
			continue
		}
		if !filepath.IsAbs(value) ||
			!strings.HasPrefix(strings.ToLower(filepath.Clean(value)), clonePrefix) {
			continue
		}
		if perr := stampMedium(ctx, vboxExe, value, "clone", out); perr != nil {
			out.Write("stderr", "Stamping "+value+" failed (preserved at delete): "+perr.Error()+"\n")
		} else {
			out.Write("stdout", "Stamped clone medium "+value+"\n")
		}
	}

	// Fresh provisioning transport: the copied natpf1 ssh rule carries the
	// SOURCE's host port — delete it and forward a newly allocated one.
	e.taskProgress(task, 50, "fixing_identity")
	sshPort, perr := allocateLocalPort(ctx)
	if perr != nil {
		return cleanup("ssh port-forward allocation", perr)
	}
	if derr := vbox.ModifyVM(ctx, vboxExe, task.MachineName,
		[]string{"--natpf1", "delete", "ssh"}); derr != nil {
		out.Write("stderr", "No copied ssh forward to delete (continuing): "+derr.Error()+"\n")
	}
	flags := []string{
		fmt.Sprintf("--natpf1=ssh,tcp,127.0.0.1,%d,,22", sshPort),
		// consoleport was stripped from the spec — the copied VRDE port would
		// collide with the source's; the user re-enables via modify.
		"--vrde=off",
	}
	if merr := vbox.ModifyVM(ctx, vboxExe, task.MachineName, flags); merr != nil {
		return cleanup("clone identity fix-up", merr)
	}
	out.Write("stdout", fmt.Sprintf("Provisioning SSH port-forward: 127.0.0.1:%d → guest 22\n", sshPort))

	e.taskProgress(task, 80, "creating_database_record")
	rawSpec, err := json.Marshal(meta.Spec)
	if err != nil {
		return cleanup("spec serialization", err)
	}
	serverID := ""
	if meta.Spec.Settings != nil {
		serverID = stringOr(meta.Spec.Settings["server_id"], "")
	}
	if _, cerr := e.store.Create(ctx, &NewMachine{
		Name:     task.MachineName,
		Host:     source.Host,
		Home:     cloneInfo.Home,
		ServerID: serverID,
		Spec:     rawSpec,
	}); cerr != nil {
		return cleanup("create machine row", cerr)
	}
	if cloneInfo.UUID != "" {
		if uerr := e.store.SetUUID(ctx, task.MachineName, cloneInfo.UUID); uerr != nil {
			return uerr
		}
	}
	e.syncLiveConfiguration(ctx, task.MachineName, vboxExe, task.MachineName, out)
	e.refreshStatus(task.MachineName, vboxExe)

	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Machine "+task.MachineName+" cloned from "+meta.Source+" (current state)\n")
	return nil
}

// cloneCurrentUTM is machine_clone_current's utm branch — UTM has no clonevm,
// so the copy is Export (source stopped) → Import → Customize (name + spec
// resources) → fresh MAC on NIC 0 → inherited forwards cleared and a fresh
// ssh forward on the first emulated interface → the registry row, exactly the
// VBox clone's landing (Hypervisor utm, UUID = the imported id).
func (e *executors) cloneCurrentUTM(ctx context.Context, task *tasks.Task,
	meta *cloneCurrentMetadata, source *Machine, out *tasks.OutputWriter,
) error {
	if meta.Snapshot != "" || meta.Linked {
		return errors.New("linked/snapshot clones are VirtualBox mechanisms — utm clones copy current state")
	}
	utmctlPath := UTMCtlPath(ctx)
	if utmctlPath == "" {
		return errors.New("UTM is not installed")
	}
	sourceTarget := source.VBoxTarget()
	status, err := utm.Status(ctx, utmctlPath, sourceTarget)
	if err != nil {
		return fmt.Errorf("source machine %s has no VM to clone: %w", meta.Source, err)
	}
	if utm.MapUTMState(status) != StatusStopped {
		return errors.New("source machine is " + status + " — utm export needs it stopped; stop it first")
	}

	workdir := e.machineWorkdir(task.MachineName)
	if merr := os.MkdirAll(workdir, 0o750); merr != nil {
		return merr
	}
	exportPath := filepath.Join(workdir, "clone-export.utm")

	e.taskProgress(task, 10, "exporting_source")
	out.Write("stdout", "Cloning "+meta.Source+" → "+task.MachineName+" (utm export → import — current state)\n")
	if xerr := utm.Export(ctx, sourceTarget, exportPath); xerr != nil {
		return fmt.Errorf("source export failed: %w", xerr)
	}
	defer func() {
		if rerr := os.RemoveAll(exportPath); rerr != nil {
			out.Write("stderr", "Temp export cleanup failed: "+rerr.Error()+"\n")
		}
	}()

	e.taskProgress(task, 30, "importing_clone")
	id, err := utm.Import(ctx, exportPath)
	if err != nil {
		return fmt.Errorf("clone import failed: %w", err)
	}
	cleanup := func(step string, ferr error) error {
		out.Write("stderr", step+" failed — deleting the half-made clone\n")
		if derr := utm.Delete(ctx, utmctlPath, id); derr != nil {
			out.Write("stderr", "Delete failed: "+derr.Error()+"\n")
		}
		return ferr
	}

	e.taskProgress(task, 50, "fixing_identity")
	settings := map[string]any{}
	if meta.Spec.Settings != nil {
		settings = meta.Spec.Settings
	}
	// Only spec-carried resources apply — an absent key keeps the source's
	// exported value (Customize skips zero fields).
	opts := utm.CustomizeOptions{Name: task.MachineName}
	if v, ok := settings["vcpus"]; ok {
		opts.CPUs = int(VCPUCount(v, 2))
	}
	if v, ok := settings["memory"]; ok {
		opts.MemoryMB = int(memoryToMB(v))
	}
	if cerr := utm.Customize(ctx, id, opts); cerr != nil {
		return cleanup("clone identity fix-up", cerr)
	}
	if merr := utm.SetMACAddress(ctx, id, 0, utm.RandomMAC()); merr != nil {
		return cleanup("mac address", merr)
	}

	nics, nerr := utm.ReadNetworkInterfaces(ctx, id)
	if nerr != nil {
		return cleanup("read network interfaces", nerr)
	}
	emulatedIndex := -1
	for index, mode := range nics {
		if mode == "emulated" && (emulatedIndex < 0 || index < emulatedIndex) {
			emulatedIndex = index
		}
	}
	if emulatedIndex < 0 {
		return cleanup("network interfaces",
			errors.New("clone has no emulated network interface — port forwards need one"))
	}
	// The copied forwards carry the SOURCE's host ports — clear them before
	// the fresh allocation (the VBox path's natpf1-delete rule).
	forwards, ferr := utm.ReadForwardedPorts(ctx, id)
	if ferr != nil {
		return cleanup("read forwarded ports", ferr)
	}
	stale := []int{}
	for _, fw := range forwards {
		if fw.NIC == emulatedIndex {
			stale = append(stale, fw.HostPort)
		}
	}
	if cerr := utm.ClearPortForwards(ctx, id, emulatedIndex, stale); cerr != nil {
		return cleanup("clear inherited forwards", cerr)
	}
	sshPort, perr := allocateLocalPort(ctx)
	if perr != nil {
		return cleanup("ssh port-forward allocation", perr)
	}
	if aerr := utm.AddPortForwards(ctx, id, emulatedIndex, []utm.ForwardedPort{{
		Protocol: "tcp", GuestPort: 22, HostIP: "127.0.0.1", HostPort: sshPort,
	}}); aerr != nil {
		return cleanup("ssh port-forward", aerr)
	}
	out.Write("stdout", fmt.Sprintf("Provisioning SSH port-forward: 127.0.0.1:%d → guest 22\n", sshPort))

	e.taskProgress(task, 80, "creating_database_record")
	rawSpec, err := json.Marshal(meta.Spec)
	if err != nil {
		return cleanup("spec serialization", err)
	}
	if _, cerr := e.store.Create(ctx, &NewMachine{
		Name:       task.MachineName,
		Host:       source.Host,
		Home:       workdir,
		ServerID:   stringOr(settings["server_id"], ""),
		Hypervisor: HypervisorUTM,
		Spec:       rawSpec,
	}); cerr != nil {
		return cleanup("create machine row", cerr)
	}
	if uerr := e.store.SetUUID(ctx, task.MachineName, id); uerr != nil {
		return uerr
	}
	e.refreshStatusUTM(task.MachineName, utmctlPath)

	e.taskProgress(task, 100, "completed")
	out.Write("stdout", "Machine "+task.MachineName+" cloned from "+meta.Source+" (current state)\n")
	return nil
}
