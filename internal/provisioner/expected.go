package provisioner

// ExpectedFile is one file a manifest role defaults to: the role's installer_dir, the kind and the file name the field default names.
type ExpectedFile struct {
	Role     string
	Kind     string
	Filename string
}

// ExpectedFiles answers every file the version's manifest roles default to: for each role declaring files, each kind's answers.name field's default; a role without installer_dir, a kind without a name field or a field without a default contributes none.
func ExpectedFiles(version *Version) []ExpectedFile {
	dsl, problems := ParseFieldDSL(version.Metadata, manifestRoleNames(version.Metadata))
	if len(problems) > 0 || dsl == nil {
		return nil
	}
	defaults := map[string]string{}
	for i := range dsl.Fields {
		if text, ok := dsl.Fields[i].Default.(string); ok && text != "" {
			defaults[dsl.Fields[i].Name] = text
		}
	}
	files := []ExpectedFile{}
	for _, role := range ManifestRoles(version.Metadata) {
		if role.InstallerDir == "" {
			continue
		}
		for kind, file := range role.Files {
			field := file.Answers["name"]
			filename := defaults[field]
			if field == "" || filename == "" {
				continue
			}
			files = append(files, ExpectedFile{Role: role.InstallerDir, Kind: kind, Filename: filename})
		}
	}
	return files
}
