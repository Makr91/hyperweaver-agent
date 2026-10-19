package machines

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/Makr91/hyperweaver-agent/internal/certs"
	"github.com/Makr91/hyperweaver-agent/internal/provisioner"
)

// notesIDProfile is the profile of a file row that is a Domino ID file, placed under id-files by its extra.id_type.
const notesIDProfile = "notes_id"

var personsOf = func(createdBy string) []string { return []string{createdBy} }

// SetPersonsOf wires the persons a task's created_by key stands for, the readers of the secret rows a render may reach.
func SetPersonsOf(fn func(createdBy string) []string) {
	if fn != nil {
		personsOf = fn
	}
}

var secretReader func(ctx context.Context, id string, persons []string) (*certs.Row, error)

// SetSecretReader wires the vault store read a secret field's answer resolves through: the row the persons may read, or an error.
func SetSecretReader(fn func(ctx context.Context, id string, persons []string) (*certs.Row, error)) {
	secretReader = fn
}

// secretMaterial is what the version's secret fields put into the working copy: the .secrets.yml document, the file rows and the PEM files of the certificate and key rows.
type secretMaterial struct {
	doc   map[string]any
	files []provisioner.SecretFile
	ssls  []provisioner.SSLFile
}

// resolveSecrets reads the row each answered secret field names, as the persons the task's key stands for, and answers the material.
func resolveSecrets(ctx context.Context, version *provisioner.Version, spec *Spec, createdBy string) (*secretMaterial, error) {
	fields, err := provisioner.SecretFields(version)
	if err != nil {
		return nil, err
	}
	material := &secretMaterial{doc: map[string]any{}, files: []provisioner.SecretFile{}, ssls: []provisioner.SSLFile{}}
	persons := personsOf(createdBy)
	for i := range fields {
		id, _ := spec.Properties[fields[i].Name].(string)
		if id == "" {
			continue
		}
		if secretReader == nil {
			return nil, errors.New("secret fields need the certificate store")
		}
		row, rerr := secretReader(ctx, id, persons)
		if rerr != nil {
			return nil, fmt.Errorf("secret %s for %s: %w", id, fields[i].Name, rerr)
		}
		switch {
		case row.Kind == certs.KindFile:
			file, ferr := secretFileOf(fields[i].SecretKey, row, material.doc)
			if ferr != nil {
				return nil, ferr
			}
			material.files = append(material.files, file)
		case certs.SecretKinds[row.Kind]:
			secretDocument(material.doc, fields[i].SecretKey, row)
		default:
			ssl, serr := sslFileOf(ctx, fields[i].SecretKey, row, persons)
			if serr != nil {
				return nil, serr
			}
			material.ssls = append(material.ssls, ssl)
		}
	}
	return material, nil
}

// secretDocument writes one secret row under its key: the first member under the key, every other member of the secret and every member of the extra under <key>_<member>, a custom row's map verbatim under the key.
func secretDocument(doc map[string]any, key string, row *certs.Row) {
	secret := certs.Secret(row)
	if row.Kind == certs.KindCustom {
		doc[key] = secret
	} else {
		first := certs.FirstMember(row.Kind)
		doc[key] = secret[first]
		for member, value := range secret {
			if member != first {
				doc[key+"_"+member] = value
			}
		}
	}
	for member, value := range certs.Extra(row) {
		doc[key+"_"+member] = value
	}
}

// secretFileOf decodes a file row's bytes and names where they land: under id-files by the extra's id_type for a Notes ID, under secrets otherwise; the filename stands under the key and the password under <key>_password.
func secretFileOf(key string, row *certs.Row, doc map[string]any) (provisioner.SecretFile, error) {
	secret := certs.Secret(row)
	extra := certs.Extra(row)
	encoded, _ := secret["bytes"].(string)
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return provisioner.SecretFile{}, fmt.Errorf("secret %s: decode file bytes: %w", row.Name, err)
	}
	filename, _ := secret["filename"].(string)
	if filename == "" {
		filename = row.Name
	}
	password, _ := secret["password"].(string)
	doc[key] = filename
	doc[key+"_password"] = password
	for member, value := range extra {
		doc[key+"_"+member] = value
	}
	file := provisioner.SecretFile{Filename: filename, Data: data}
	if certs.Profile(row) == notesIDProfile {
		file.IDType = extra["id_type"]
		if file.IDType == "" {
			return file, fmt.Errorf("secret %s: a %s file names no extra.id_type", row.Name, notesIDProfile)
		}
	}
	return file, nil
}

func pemOf(kind, b64 string) ([]byte, error) {
	if b64 == "" {
		return nil, nil
	}
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode DER: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), nil
}

// sslFileOf answers the PEM files of a vault row: the certificate from its public DER, the key from its private DER, the CA from the issuer its links name.
func sslFileOf(ctx context.Context, name string, row *certs.Row, persons []string) (provisioner.SSLFile, error) {
	record := certs.RecordMap(row)
	file := provisioner.SSLFile{Name: name}
	var err error
	publicDER, _ := record["public_der_b64"].(string)
	privateDER, _ := record["private_der_b64"].(string)
	if row.Kind != certs.KindKey {
		if file.Cert, err = pemOf("CERTIFICATE", publicDER); err != nil {
			return file, err
		}
	}
	if file.Key, err = pemOf("PRIVATE KEY", privateDER); err != nil {
		return file, err
	}
	links, _ := record["links"].(map[string]any)
	issuerID, _ := links["issuer_id"].(string)
	if issuerID == "" {
		return file, nil
	}
	if issuer, ierr := secretReader(ctx, issuerID, persons); ierr == nil {
		issuerDER, _ := certs.RecordMap(issuer)["public_der_b64"].(string)
		if file.CA, err = pemOf("CERTIFICATE", issuerDER); err != nil {
			return file, err
		}
	}
	return file, nil
}
