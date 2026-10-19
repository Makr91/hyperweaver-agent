package config

import "fmt"

// runningValue is one leaf the file answers with the value the agent runs with: the pointer segments into the file and the value, written when the file holds no value there.
type runningValue struct {
	name  string
	path  []string
	value any
}

func rawAt(document map[string]any, path []string) (any, bool) {
	var node any = document
	for _, segment := range path {
		object, ok := node.(map[string]any)
		if !ok {
			return nil, false
		}
		node, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return node, true
}

func nestedPatch(patch map[string]any, path []string, value any) {
	node := patch
	for _, segment := range path[:len(path)-1] {
		child, ok := node[segment].(map[string]any)
		if !ok {
			child = map[string]any{}
			node[segment] = child
		}
		node = child
	}
	node[path[len(path)-1]] = value
}

func (c *Config) runningValues() ([]runningValue, error) {
	logFile, err := c.LogFilePath()
	if err != nil {
		return nil, err
	}
	taskLogDir, err := c.TaskLogDir()
	if err != nil {
		return nil, err
	}
	dataDir, err := c.DataDir()
	if err != nil {
		return nil, err
	}
	provisionersDir, err := c.ProvisionersDir()
	if err != nil {
		return nil, err
	}
	machinesDir, err := c.MachinesDir()
	if err != nil {
		return nil, err
	}
	templatesDir, err := c.TemplatesDir()
	if err != nil {
		return nil, err
	}
	artifactsRoot, err := c.ArtifactsRootDir()
	if err != nil {
		return nil, err
	}
	return []runningValue{
		{"app", []string{"ssl", "key_path"}, c.SSLKeyPath()},
		{"app", []string{"ssl", "cert_path"}, c.SSLCertPath()},
		{"app", []string{"ssl", "ca_cert_path"}, c.SSLCACertPath()},
		{"app", []string{"ssl", "ca_key_path"}, c.SSLCAKeyPath()},
		{"app", []string{"logging", "file"}, logFile},
		{"app", []string{"tasks", "output", "log_directory"}, taskLogDir},
		{"app", []string{"data", "dir"}, dataDir},
		{"machines", []string{"provisioning", "provisioners_dir"}, provisionersDir},
		{"machines", []string{"provisioning", "machines_dir"}, machinesDir},
		{"machines", []string{"provisioning", "ssh", "key_path"}, c.ProvisionKeyPath()},
		{"storage", []string{"template_sources", "local_storage_path"}, templatesDir},
		{"storage", []string{"artifact_storage", "dir"}, artifactsRoot},
		{"storage", []string{"artifact_storage", "enabled"}, c.ArtifactStorage.Enabled},
	}, nil
}

// writeRunningValues writes into each file every leaf the agent resolves itself and the file leaves empty or absent, so the file answers the value the agent runs with; the write pends no restart, the running value being the written one.
func (c *Config) writeRunningValues() error {
	values, err := c.runningValues()
	if err != nil {
		return err
	}
	patches := map[string]map[string]any{}
	for _, entry := range values {
		held, present := rawAt(c.engine.Raw(entry.name), entry.path)
		if present {
			if text, isText := held.(string); !isText || text != "" {
				continue
			}
		}
		if patches[entry.name] == nil {
			patches[entry.name] = map[string]any{}
		}
		nestedPatch(patches[entry.name], entry.path, entry.value)
	}
	if len(patches) == 0 {
		return nil
	}
	for _, name := range Names {
		patch, has := patches[name]
		if !has {
			continue
		}
		if _, serr := c.engine.Save(name, patch, "agent"); serr != nil {
			return fmt.Errorf("write running values into %s: %w", name, serr)
		}
	}
	c.engine.ClearRestart()
	return c.fill()
}
