package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Makr91/hyperweaver-agent/internal/auth"
	"github.com/Makr91/hyperweaver-agent/internal/machines"
)

// applyModifyNotes handles the notes field (the base's immediate DB update:
// falsy clears). False return = response already written.
func (s *Server) applyModifyNotes(w http.ResponseWriter, r *http.Request, machineName string, body map[string]any) bool {
	value := body["notes"]
	var notes *string
	if text, ok := value.(string); ok && text != "" {
		notes = &text
	} else if value != nil {
		if _, ok := value.(string); !ok {
			taskError(w, http.StatusBadRequest, "notes must be a string or null")
			return false
		}
	}
	if err := s.machines.SetNotes(r.Context(), machineName, notes); err != nil {
		slog.Error("update machine notes", "machine", machineName, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to update machine notes")
		return false
	}
	return true
}

// applyModifyTags handles the tags field (the base's immediate DB update:
// non-array clears; this agent's empty-clears convention matches its own
// tags endpoint). False return = response already written.
func (s *Server) applyModifyTags(w http.ResponseWriter, r *http.Request, machineName string, body map[string]any) bool {
	tags := []string{}
	if list, ok := body["tags"].([]any); ok {
		for _, entry := range list {
			if tag, tok := entry.(string); tok && tag != "" {
				tags = append(tags, tag)
			}
		}
	}
	var stored json.RawMessage
	if len(tags) > 0 {
		encoded, err := json.Marshal(tags)
		if err != nil {
			slog.Error("serialize machine tags", "error", err)
			taskError(w, http.StatusInternalServerError, "Failed to update machine tags")
			return false
		}
		stored = encoded
	}
	if err := s.machines.SetTags(r.Context(), machineName, stored); err != nil {
		slog.Error("update machine tags", "machine", machineName, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to update machine tags")
		return false
	}
	return true
}

// applyRemoveOnCompletionFlips extracts remove_on_completion from nics[]
// entries (the converged flip wire, sync 2026-07-18 — the badged provisional
// row's toggle) and applies each flip DB-IMMEDIATELY: adapter 1 (the
// intrinsic NAT transport, which has no document entry) flips
// configuration.settings.remove_transport_on_completion; adapters 2+ flip
// the document networks[adapter-2] entry's own remove_on_completion. The key
// strips from each entry so the infrastructure path never sees it; an entry
// left with only its adapter drops whole — a flip-only PUT queues nothing.
// False return = response already written.
func (s *Server) applyRemoveOnCompletionFlips(w http.ResponseWriter, r *http.Request,
	machine *machines.Machine, body map[string]any,
) bool {
	entries, has := body["nics"].([]any)
	if !has {
		return true
	}
	networksLen := len(machines.ParseConfiguration(machine).List("networks"))
	kept := []any{}
	for _, raw := range entries {
		entry, eok := raw.(map[string]any)
		if !eok {
			kept = append(kept, raw)
			continue
		}
		if value, present := entry["remove_on_completion"]; present {
			flag, bok := value.(bool)
			if !bok {
				taskError(w, http.StatusBadRequest, "nics[].remove_on_completion must be a boolean")
				return false
			}
			adapter := int(machines.DocInt(entry["adapter"], 0))
			if adapter < 1 {
				taskError(w, http.StatusBadRequest,
					"nics[] entries carrying remove_on_completion need adapter (1-8)")
				return false
			}
			delete(entry, "remove_on_completion")
			if adapter == 1 {
				if err := s.machines.MergeSettingsKeys(r.Context(), machine.Name, map[string]any{
					"remove_transport_on_completion": flag,
				}); err != nil {
					slog.Error("flip transport remove_on_completion", "machine", machine.Name, "error", err)
					taskError(w, http.StatusInternalServerError, "Failed to update remove_on_completion")
					return false
				}
			} else {
				if adapter-2 >= networksLen {
					taskError(w, http.StatusBadRequest, "adapter "+strconv.Itoa(adapter)+
						" has no document networks[] entry to carry remove_on_completion")
					return false
				}
				if err := s.machines.SetNetworkRemoveFlag(r.Context(), machine.Name, adapter-2, flag); err != nil {
					slog.Error("flip networks remove_on_completion", "machine", machine.Name,
						"adapter", adapter, "error", err)
					taskError(w, http.StatusInternalServerError, "Failed to update remove_on_completion")
					return false
				}
			}
			slog.Info("remove_on_completion flipped", "machine", machine.Name,
				"adapter", adapter, "value", flag, "by", auth.FromContext(r.Context()).Name)
		}
		if len(entry) == 1 {
			if _, only := entry["adapter"]; only {
				continue // flip-only entry — consumed whole
			}
		}
		kept = append(kept, entry)
	}
	if len(kept) > 0 {
		body["nics"] = kept
	} else {
		delete(body, "nics")
	}
	return true
}

// applyModifyBootPriority stores settings.boot_priority into the machine's
// spec (1-100; DB-immediate — orchestration reads it, VirtualBox never does).
// False return = response already written.
func (s *Server) applyModifyBootPriority(w http.ResponseWriter, r *http.Request,
	machine *machines.Machine, body map[string]any,
) bool {
	priority := int(machines.DocInt(body["boot_priority"], 0))
	if priority < 1 || priority > 100 {
		taskError(w, http.StatusBadRequest, "boot_priority must be 1-100")
		return false
	}
	spec, err := machines.ParseSpec(machine)
	if err != nil {
		taskError(w, http.StatusBadRequest,
			"Only machines this agent created carry a spec to hold boot_priority (discovered VM)")
		return false
	}
	if spec.Settings == nil {
		spec.Settings = map[string]any{}
	}
	spec.Settings["boot_priority"] = priority
	raw, err := json.Marshal(spec)
	if err != nil {
		taskError(w, http.StatusInternalServerError, "Failed to update boot priority")
		return false
	}
	serverID := machines.DocString(spec.Settings["server_id"], "")
	if err := s.machines.SetSpec(r.Context(), machine.Name, raw, serverID); err != nil {
		slog.Error("update boot priority", "machine", machine.Name, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to update boot priority")
		return false
	}
	return true
}

// applyModifySnapshots handles the snapshots field — the per-machine
// snapshot retention override (zoneweaver's setSnapshotPolicy contract,
// DB-immediate): an object with a valid type stores verbatim into
// configuration.snapshots (unknown extra keys ride along, ignored by the
// rotation service); null or a typeless object clears back to the agent
// default. False return = response already written.
func (s *Server) applyModifySnapshots(w http.ResponseWriter, r *http.Request, machineName string, body map[string]any) bool {
	value := body["snapshots"]
	var policy map[string]any
	if value != nil {
		object, ok := value.(map[string]any)
		if !ok {
			taskError(w, http.StatusBadRequest, "snapshots must be an object or null")
			return false
		}
		kind, _ := object["type"].(string)
		switch kind {
		case "":
			// A typeless object clears, exactly like null (the base's rule).
		case "none", "simple", "age", "rotation":
			policy = object
		default:
			taskError(w, http.StatusBadRequest,
				"snapshots.type must be one of none, simple, age, rotation")
			return false
		}
	}
	if err := s.machines.SetSnapshotPolicy(r.Context(), machineName, policy); err != nil {
		slog.Error("update snapshot policy", "machine", machineName, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to update snapshot policy")
		return false
	}
	slog.Info("snapshot policy updated", "machine", machineName,
		"cleared", policy == nil, "by", auth.FromContext(r.Context()).Name)
	return true
}

// applyModifyCredentials merges the credentials family into
// configuration.settings key-by-key (the provisioner document's DB-immediate
// rule, one level deeper — the rest of settings survives). Empty string or
// null deletes a key. False return = response already written.
func (s *Server) applyModifyCredentials(w http.ResponseWriter, r *http.Request, machineName string, body map[string]any) bool {
	updates := map[string]any{}
	for _, field := range credentialFields {
		value, ok := body[field]
		if !ok {
			continue
		}
		if value != nil {
			if _, sok := value.(string); !sok {
				taskError(w, http.StatusBadRequest, field+" must be a string or null")
				return false
			}
		}
		updates[field] = value
	}
	if err := s.machines.MergeSettingsKeys(r.Context(), machineName, updates); err != nil {
		slog.Error("update ssh credentials", "machine", machineName, "error", err)
		taskError(w, http.StatusInternalServerError, "Failed to update SSH credentials")
		return false
	}
	slog.Info("ssh credentials updated", "machine", machineName,
		"by", auth.FromContext(r.Context()).Name)
	return true
}
