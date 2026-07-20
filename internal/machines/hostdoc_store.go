package machines

import (
	"context"
	"encoding/json"
	"time"
)

// Configuration keys the agent owns — discovery merges the live hypervisor
// view AROUND these; they are never clobbered (zoneweaver's zone sync merges
// the same way).
var preservedConfigKeys = []string{
	"settings", "zones", "networks", "disks", "metadata",
	"provisioner", "provisioner_state", "pending_changes", "guest_info",
	"snapshots", "host_hooks_confirmed",
}

// StampProvisionerState records a successful provision on the machine row —
// the base's fresh-read + merge rule: parse failure never clobbers the
// configuration document. Only the provisioner_state section re-encodes;
// every other section's bytes ride verbatim.
func (s *Store) StampProvisionerState(ctx context.Context, name string) error {
	machine, err := s.Get(ctx, name)
	if err != nil {
		return err
	}
	sections := ParseRawConfiguration(machine)
	state := rawSectionMap(sections, "provisioner_state")
	state["last_provisioned_at"] = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	sections["provisioner_state"] = raw
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return err
	}
	return s.SetConfiguration(ctx, name, merged)
}

// SetGuestInfo records the discovery sweep's guest-agent observation on the
// machine row — configuration.guest_info ({ips[], agent_responding,
// checked_at}): the machine LIST carries it, so the UI gates direct RDP/SSH
// buttons off data it already polls instead of querying per machine. nil
// clears the section (stopped machines, honest absence). Same fresh-read +
// merge rule as every configuration write.
func (s *Store) SetGuestInfo(ctx context.Context, name string, info map[string]any) error {
	machine, err := s.Get(ctx, name)
	if err != nil {
		return err
	}
	sections := ParseRawConfiguration(machine)
	if info == nil {
		if _, ok := sections["guest_info"]; !ok {
			return nil
		}
		delete(sections, "guest_info")
	} else {
		raw, merr := json.Marshal(info)
		if merr != nil {
			return merr
		}
		sections["guest_info"] = raw
	}
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return err
	}
	return s.SetConfiguration(ctx, name, merged)
}

// SetSnapshotPolicy stores (or clears, on nil) the machine's per-machine
// snapshot retention policy — configuration.snapshots, the PUT `snapshots`
// field (zoneweaver's setSnapshotPolicy: an object with a type stores
// verbatim, null clears back to the agent default). Same fresh-read + merge
// rule as every configuration write.
func (s *Store) SetSnapshotPolicy(ctx context.Context, name string, policy map[string]any) error {
	machine, err := s.Get(ctx, name)
	if err != nil {
		return err
	}
	sections := ParseRawConfiguration(machine)
	if policy == nil {
		if _, ok := sections["snapshots"]; !ok {
			return nil
		}
		delete(sections, "snapshots")
	} else {
		raw, merr := json.Marshal(policy)
		if merr != nil {
			return merr
		}
		sections["snapshots"] = raw
	}
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return err
	}
	return s.SetConfiguration(ctx, name, merged)
}

// MergeConfigurationSections merges document sections into a machine's
// configuration (create-finalize's storeInfrastructureConfig and PUT's
// provisioner store share it): existing keys survive unless the update
// carries them. Each incoming value marshals INDIVIDUALLY — a
// json.RawMessage value passes through byte-verbatim, which is how the PUT
// provisioner path stores the request's own key order.
func (s *Store) MergeConfigurationSections(ctx context.Context, name string, updates map[string]any) error {
	machine, err := s.Get(ctx, name)
	if err != nil {
		return err
	}
	sections := ParseRawConfiguration(machine)
	for key, value := range updates {
		raw, merr := json.Marshal(value)
		if merr != nil {
			return merr
		}
		sections[key] = raw
	}
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return err
	}
	return s.SetConfiguration(ctx, name, merged)
}

// MergeSettingsKeys merges individual keys INTO configuration.settings (PUT's
// DB-immediate credentials family — the base's provisioner-store rule applied
// one level deeper: the rest of the settings section survives untouched).
// A nil or empty-string value deletes the key.
func (s *Store) MergeSettingsKeys(ctx context.Context, name string, keys map[string]any) error {
	machine, err := s.Get(ctx, name)
	if err != nil {
		return err
	}
	sections := ParseRawConfiguration(machine)
	settings := rawSectionMap(sections, "settings")
	for key, value := range keys {
		if value == nil {
			delete(settings, key)
			continue
		}
		if text, ok := value.(string); ok && text == "" {
			delete(settings, key)
			continue
		}
		settings[key] = value
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	sections["settings"] = raw
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return err
	}
	return s.SetConfiguration(ctx, name, merged)
}

// MergePendingChanges merges an accrued modify body into
// configuration.pending_changes (the accrue-changes contract: per top-level
// key the last edit wins; hardware merges per section.key so successive
// edits of different knobs coexist) and returns the merged set.
func (s *Store) MergePendingChanges(ctx context.Context, name string, updates map[string]any) (map[string]any, error) {
	machine, err := s.Get(ctx, name)
	if err != nil {
		return nil, err
	}
	sections := ParseRawConfiguration(machine)
	pending := rawSectionMap(sections, "pending_changes")
	for key, value := range updates {
		if key != "vbox" {
			pending[key] = value
			continue
		}
		vboxSection, _ := pending["vbox"].(map[string]any)
		if vboxSection == nil {
			vboxSection = map[string]any{}
		}
		for sectionName, raw := range mapOr(value) {
			// serial[]/parallel[]/directives are arrays — they replace whole.
			section, ok := raw.(map[string]any)
			if !ok {
				vboxSection[sectionName] = raw
				continue
			}
			merged, _ := vboxSection[sectionName].(map[string]any)
			if merged == nil {
				merged = map[string]any{}
			}
			for k, v := range section {
				merged[k] = v
			}
			vboxSection[sectionName] = merged
		}
		pending["vbox"] = vboxSection
	}
	raw, err := json.Marshal(pending)
	if err != nil {
		return nil, err
	}
	sections["pending_changes"] = raw
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return nil, err
	}
	return pending, s.SetConfiguration(ctx, name, merged)
}

// ClearPendingChanges drops the accrued set (the cancel path, and the
// executor's apply-success cleanup).
func (s *Store) ClearPendingChanges(ctx context.Context, name string) error {
	machine, err := s.Get(ctx, name)
	if err != nil {
		return err
	}
	sections := ParseRawConfiguration(machine)
	if _, ok := sections["pending_changes"]; !ok {
		return nil
	}
	delete(sections, "pending_changes")
	merged, err := marshalRawConfig(sections)
	if err != nil {
		return err
	}
	return s.SetConfiguration(ctx, name, merged)
}

// MergeLiveConfiguration overlays the hypervisor's live view onto a stored
// configuration document, preserving the agent-owned section keys — the zone
// sync's merge rule: discovery refreshes reality, never the stored document.
// Preserved keys copy as RAW bytes from the existing document, so the stored
// provisioner sections never re-encode (and never alphabetize) on a sweep.
func MergeLiveConfiguration(existing, live json.RawMessage) json.RawMessage {
	merged := map[string]json.RawMessage{}
	if len(live) > 0 {
		if err := json.Unmarshal(live, &merged); err != nil {
			merged = map[string]json.RawMessage{}
		}
	}
	if len(existing) > 0 {
		previous := map[string]json.RawMessage{}
		if err := json.Unmarshal(existing, &previous); err == nil {
			for _, key := range preservedConfigKeys {
				if value, ok := previous[key]; ok {
					if _, overwritten := merged[key]; !overwritten {
						merged[key] = value
					}
				}
			}
		}
	}
	raw, err := marshalRawConfig(merged)
	if err != nil {
		return existing
	}
	return raw
}
