package provisioner

var secretLookup func(id string) (kind string, ok bool)

// SetSecretLookup wires the vault store read a secret field's answer is checked against: the kind of the row the id names, false when none.
func SetSecretLookup(fn func(id string) (kind string, ok bool)) {
	secretLookup = fn
}

// SecretField is one field of type secret: its name, the kind of row it takes, the key the package's roles read its value from and the profile the UI's picker reads.
type SecretField struct {
	Name      string
	Kind      string
	SecretKey string
	Profile   string
}

// SecretFields answers the version's secret fields in form order; a package without a form has none.
func SecretFields(version *Version) ([]SecretField, error) {
	dsl, problems := ParseFieldDSL(version.Metadata, manifestRoleNames(version.Metadata))
	if len(problems) > 0 {
		return nil, &dslError{problems: problems}
	}
	fields := []SecretField{}
	if dsl == nil {
		return fields, nil
	}
	for i := range dsl.Fields {
		if dsl.Fields[i].Type == "secret" {
			fields = append(fields, SecretField{
				Name: dsl.Fields[i].Name, Kind: dsl.Fields[i].Kind,
				SecretKey: dsl.Fields[i].SecretKey, Profile: dsl.Fields[i].Profile,
			})
		}
	}
	return fields, nil
}

type dslError struct {
	problems []string
}

func (e *dslError) Error() string {
	out := "package field DSL is invalid — re-import to see the lint:"
	for _, problem := range e.problems {
		out += " " + problem + ";"
	}
	return out
}

// secretKindMatches reports whether a row of rowKind answers a secret field of fieldKind: a certificate or key field takes any of the vault's certificate, authority, key and ssh_certificate rows, every other field a row of its own kind.
func secretKindMatches(fieldKind, rowKind string) bool {
	switch fieldKind {
	case "certificate", "key":
		switch rowKind {
		case "certificate", "authority", "key", "ssh_certificate":
			return true
		}
		return false
	}
	return fieldKind == rowKind
}
