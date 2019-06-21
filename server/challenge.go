package main

import (
	crand "crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/rand"
	"net/http"
	"strconv"
)

type UserChallenge struct {
	public_key       *rsa.PublicKey
	start_timestamp  int
	expire_timestamp int
	challenge_type   string
	challenge_nonce  string
	global_index     int
}

func UserChallenge__new(public_key *rsa.PublicKey, challenge_type string) (*UserChallenge, error) {
	if challenge_type != "start_session" && challenge_type != "register" {
		return nil, errors.New("invalid challenge type")
	}

	nonce := strconv.Itoa(rand.Int())
	now := timestamp()
	expire := now + 5 // only 5 seconds to reply
	user_challenge := UserChallenge{
		public_key,
		now,
		expire,
		challenge_type,
		nonce,
		0, // global index default to 0
	}
	user_challenge.register()

	return &user_challenge, nil
}

func (self *UserChallenge) register() {
	if self.global_index == 0 {
		for {
			self.global_index = rand.Int()
			_, ok := global_user_challenges[self.global_index]
			if !ok {
				global_user_challenges[self.global_index] = self
				break
			}
		}
	}
}

func (self *UserChallenge) unregister() {
	_, ok := global_user_challenges[self.global_index]
	if ok {
		delete(global_user_challenges, self.global_index)
	}
}

func (self *UserChallenge) sendJSONResponse(w http.ResponseWriter) error {
	type response_type struct {
		Message string `json:"message"`
		Index   int    `json:"index"`
	}

	message := []byte(self.challenge_nonce)
	rng := crand.Reader

	ciphertext, err := rsa.EncryptPKCS1v15(rng, self.public_key, message)
	if err != nil {
		return err
	}

	response := response_type{
		base64.StdEncoding.EncodeToString(ciphertext),
		self.global_index,
	}

	sendJSONResponse(w, &response)
	return nil
}

func (self *UserChallenge) validate(signature string) bool {
	now := timestamp()
	if now > self.expire_timestamp {
		return false
	}

	return verifyPublicKeySignature(self.public_key, self.challenge_nonce, signature)
}

func UserChallenge__getRegistered(index int) *UserChallenge {
	challenge := global_user_challenges[index]
	return challenge
}
