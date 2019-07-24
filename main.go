package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	certUtil "k8s.io/client-go/util/cert"
)

const SealedSecretsKeyLabel = "sealedsecrets.bitnami.com/sealed-secrets-key"

var (
	ErrPrivateKeyNotRSA = errors.New("Private key is not an rsa key")
	keyPrefix           = flag.String("key-prefix", "sealed-secrets-key", "Prefix used to name keys.")
	keySize             = flag.Int("key-size", 4096, "Size of encryption key.")
	validFor            = flag.Duration("key-ttl", 10*365*24*time.Hour, "Duration that certificate is valid for.")
	myCN                = flag.String("my-cn", "", "CN to use in generated certificate.")
	keyRotatePeriod     = flag.Duration("rotate-period", 0, "New key generation period (automatic rotation disabled if 0)")

	// Selector used to find existing public/private key pairs on startup
	keySelector = fields.OneTermEqualSelector(SealedSecretsKeyLabel, "active")
)

func generatePrivateKeyAndCert(keySize int) (*rsa.PrivateKey, *x509.Certificate, error) {
	r := rand.Reader
	privKey, err := rsa.GenerateKey(r, keySize)
	if err != nil {
		return nil, nil, err
	}
	cert, err := signKey(r, privKey)
	if err != nil {
		return nil, nil, err
	}
	return privKey, cert, nil
}

func readKey(secret v1.Secret) (*rsa.PrivateKey, []*x509.Certificate, error) {
	key, err := certUtil.ParsePrivateKeyPEM(secret.Data[v1.TLSPrivateKeyKey])
	if err != nil {
		return nil, nil, err
	}
	switch rsaKey := key.(type) {
	case *rsa.PrivateKey:
		certs, err := certUtil.ParseCertsPEM(secret.Data[v1.TLSCertKey])
		if err != nil {
			return nil, nil, err
		}
		return rsaKey, certs, nil
	default:
		return nil, nil, ErrPrivateKeyNotRSA
	}
}

func writeKey(key *rsa.PrivateKey, certs []*x509.Certificate, namespace, label, prefix string) (v1.Secret, error) {
	certbytes := []byte{}
	for _, cert := range certs {
		certbytes = append(certbytes, certUtil.EncodeCertPEM(cert)...)
	}
	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    namespace,
			GenerateName: prefix,
			Labels: map[string]string{
				label: "active",
			},
		},
		Data: map[string][]byte{
			v1.TLSPrivateKeyKey: certUtil.EncodePrivateKeyPEM(key),
			v1.TLSCertKey:       certbytes,
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		Type: v1.SecretTypeTLS,
	}
	return secret, nil
}

func signKey(r io.Reader, key *rsa.PrivateKey) (*x509.Certificate, error) {

	notBefore := time.Now()

	serialNo, err := rand.Int(r, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	cert := x509.Certificate{
		SerialNumber: serialNo,
		KeyUsage:     x509.KeyUsageEncipherOnly,
		NotBefore:    notBefore.UTC(),
		NotAfter:     notBefore.Add(*validFor).UTC(),
		Subject: pkix.Name{
			CommonName: *myCN,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	data, err := x509.CreateCertificate(r, &cert, &cert, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(data)
}

func myNamespace() string {
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}

	// Fall back to the namespace associated with the service account token, if available
	if data, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if ns := strings.TrimSpace(string(data)); len(ns) > 0 {
			return ns
		}
	}

	return metav1.NamespaceDefault
}

func main2() (string, error) {
	key, cert, err := generatePrivateKeyAndCert(*keySize)
	if err != nil {
		return "", err
	}
	certs := []*x509.Certificate{cert}
	myNS := "kube-system"
	secret, err := writeKey(key, certs, myNS, SealedSecretsKeyLabel, *keyPrefix)
	if err != nil {
		return "", err
	}
	//fmt.Printf("New key written to %s\n", secret.Name)
	//fmt.Printf("Certificate is \n%s\n", certUtil.EncodeCertPEM(cert))
	m, err := json.Marshal(secret)
	fmt.Printf("%s", string(m))
	return secret.String(), nil
}

func main() {
	log.Printf("Making a secret...")

	if _, err := main2(); err != nil {
		panic(err.Error())
	}
}
