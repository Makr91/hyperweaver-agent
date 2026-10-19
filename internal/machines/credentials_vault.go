package machines

import (
	"errors"

	"github.com/Makr91/hyperweaver-agent/internal/certs"
	"github.com/Makr91/hyperweaver-agent/internal/sshrun"
)

// CredentialKinds are the vault kinds a machine credential may be.
var CredentialKinds = map[string]bool{certs.KindPassword: true, certs.KindSSHKey: true, certs.KindKeyPair: true}

// CredentialUses are the uses a machine credential is picked for.
var CredentialUses = map[string]bool{"ssh": true, "rdp": true, "console": true, "vagrant": true}

// CredentialUsername answers the account a vault row signs in as: extra.username, else extra.user, empty when the row names none.
func CredentialUsername(row *certs.Row) string {
	extra := certs.Extra(row)
	if user := extra["username"]; user != "" {
		return user
	}
	return extra["user"]
}

// SSHCredentialOf answers the SSH credential a vault row carries: a password row's password, an ssh_key row's private key and passphrase, the username from the row's extra; a key_pair row carries none.
func SSHCredentialOf(row *certs.Row) (sshrun.Credentials, error) {
	secret := certs.Secret(row)
	credentials := sshrun.Credentials{Username: CredentialUsername(row), Vault: true}
	switch row.Kind {
	case certs.KindPassword:
		credentials.Password, _ = secret["password"].(string)
	case certs.KindSSHKey:
		credentials.PrivateKey, _ = secret["private_key"].(string)
		credentials.Passphrase, _ = secret["passphrase"].(string)
		if credentials.PrivateKey == "" {
			return credentials, errors.New("the ssh_key row carries no private key")
		}
	default:
		return credentials, errors.New("a " + row.Kind + " row carries no SSH credential")
	}
	return credentials, nil
}

// PasswordCredentialOf answers the username and password a vault row carries for a desktop client; only a password row does.
func PasswordCredentialOf(row *certs.Row) (user, password string, err error) {
	if row.Kind != certs.KindPassword {
		return "", "", errors.New("a " + row.Kind + " row carries no password")
	}
	password, _ = certs.Secret(row)["password"].(string)
	return CredentialUsername(row), password, nil
}

// applyCredential overlays a vault row's SSH credential onto the document's: the row's username when it names one, its password or key material in place of the document's key path.
func applyCredential(document *sshrun.Credentials, row *certs.Row) (sshrun.Credentials, error) {
	fromRow, err := SSHCredentialOf(row)
	if err != nil {
		return *document, err
	}
	merged := *document
	if fromRow.Username != "" {
		merged.Username = fromRow.Username
	}
	merged.Password = fromRow.Password
	merged.PrivateKey = fromRow.PrivateKey
	merged.Passphrase = fromRow.Passphrase
	merged.Vault = true
	if fromRow.PrivateKey != "" {
		merged.SSHKeyPath = ""
	}
	return merged, nil
}
