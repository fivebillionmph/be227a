package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	gss "github.com/fivebillionmph/gosimpleserver"
	"math/rand"
	"net/http"
	"os"
	"time"
)

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func timestamp() int {
	return int(time.Now().Unix())
}

func requestJSONDecode(r *http.Request, s interface{}) error {
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(s)
	return err
}

func sendJSONResponse(w http.ResponseWriter, s interface{}) {
	json_response, err := json.Marshal(s)
	if err != nil {
		errorResponse(w, 500, "Could not send request")
		return
	}
	w.Header().Set("Content-type", "application/json")
	w.Write(json_response)
}

func sendJSONResponseSuccess(w http.ResponseWriter) {
	json_response := struct {
		Success bool `json:"success"`
	}{
		true,
	}
	sendJSONResponse(w, &json_response)
}

func errorResponse(w http.ResponseWriter, status int, msg string) {
	http.Error(w, msg, status)
}

func publicKeyToUserRequest(r *http.Request, server *gss.Server) (*DBUser, error) {
	type json_request_type struct {
		Public_key string `json:"public_key"`
	}
	json_request := json_request_type{}
	err := requestJSONDecode(r, &json_request)
	if err != nil {
		return nil, err
	}

	public_key, err := stringToPublicKey(json_request.Public_key)
	if err != nil {
		return nil, err
	}

	return DBUser__getByPublicKey(server.RequestDBConnection(), public_key)
}

func userChallengeResponse(w http.ResponseWriter, public_key *rsa.PublicKey, challenge_type string) error {
	challenge, err := UserChallenge__new(public_key, challenge_type)
	if err != nil {
		errorResponse(w, 500, "Error sending challenge")
		return err
	}
	err = challenge.sendJSONResponse(w)
	if err != nil {
		errorResponse(w, 500, "Error sending challenge")
		return err
	}
	return nil
}

func stringToPublicKey(key_str string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(key_str))
	if block == nil {
		return nil, errors.New("Invalid public key")
	}
	return x509.ParsePKCS1PublicKey([]byte(block.Bytes))
}

func derStringToPublicKey(der_str string) (*rsa.PublicKey, error) {
	return x509.ParsePKCS1PublicKey([]byte(der_str))
}

func publicKeyToString(key *rsa.PublicKey) (string, error) {
	der_format := publicKeyToDerString(key)
	pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: []byte(der_format),
		},
	)
	if pem == nil {
		return "", errors.New("invalid public key")
	}
	return string(pem), nil
}

func publicKeyToDerString(key *rsa.PublicKey) string {
	return string(x509.MarshalPKCS1PublicKey(key))
}

func verifyPublicKeySignature(public_key *rsa.PublicKey, message string, signature string) bool {
	// message is the unencrypted string
	// signature is the encrypted string hash signed by the public key

	message_hash := sha256.Sum256([]byte(message))

	err := rsa.VerifyPKCS1v15(public_key, crypto.SHA256, message_hash[:], []byte(signature))

	return err == nil
}

func randomString(length int) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

	b := make([]byte, length)
	for i := range b {
		b[i] = alphabet[rand.Intn(len(alphabet))]
	}

	return string(b)
}
