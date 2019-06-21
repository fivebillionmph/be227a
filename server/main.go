package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	gss "github.com/fivebillionmph/gosimpleserver"
	"io/ioutil"
	"log"
	"os"
)

var global_private_key *rsa.PrivateKey
var global_user_challenges map[int]*UserChallenge
var global_user_sessions map[string]*UserSession
var global_host_name string

func main() {
	err := initGlobals()
	if err != nil {
		log.Fatal(err)
	}

	err = loadKeys()
	if err != nil {
		log.Fatal(err)
	}

	server, err := gss.Server__newFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	err = addServerPaths(server)
	if err != nil {
		log.Fatal(err)
	}

	go maintainer()
	fmt.Println("server starting...")
	server.Start()
}

func initGlobals() error {
	var global_host_name = os.Getenv("HOST_NAME")
	if global_host_name == "" {
		return errors.New("host name not specified")
	}

	global_user_challenges = make(map[int]*UserChallenge)
	global_user_sessions = make(map[string]*UserSession)

	return nil
}

func loadKeys() error {
	private_key_file := os.Getenv("KEY_FILE")
	if private_key_file == "" {
		return errors.New("private key file not specified")
	}

	if fileExists(private_key_file) {
		data, err := ioutil.ReadFile(private_key_file)
		if err != nil {
			return err
		}
		global_private_key, err = x509.ParsePKCS1PrivateKey(data)
		return err
	} else {
		var err error
		global_private_key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		private_key_bytes := x509.MarshalPKCS1PrivateKey(global_private_key)
		err = ioutil.WriteFile(private_key_file, private_key_bytes, os.FileMode(int(0600)))
		return err
	}
}

func addServerPaths(server *gss.Server) error {
	err := server.AddStaticRouterPathPrefix("/static", "./static")
	if err != nil {
		return err
	}

	err = server.AddRouterPath("/a/session", "POST", false, handlerStartSession)
	if err != nil {
		return err
	}

	err = server.AddRouterPath("/a/session", "DELETE", false, handlerStopSession)
	if err != nil {
		return err
	}

	err = server.AddRouterPath("/a/session/challenge", "PUT", false, handlerSessionChallenge)
	if err != nil {
		return err
	}

	err = server.AddRouterPath("/a/session/refresh", "POST", false, handlerSessionRefresh)
	if err != nil {
		return err
	}

	err = server.AddRouterPath("/a/register", "PUT", false, handlerRegister)
	if err != nil {
		return err
	}

	err = server.AddRouterPath("/a/register/challenge", "PUT", false, handlerRegisterChallenge)
	if err != nil {
		return err
	}

	err = server.AddRouterPath("/a/sign", "POST", false, handlerAddSignature)
	if err != nil {
		return err
	}

	//err = server.AddRouterPath("/a/revoke", "PUT", false, handlerRevokeSignature)
	//if err != nil {
	//	log.Fatal(err)
	//}

	err = server.AddRouterPath("/a/signatures", "GET", false, handlerGetSignatures)
	if err != nil {
		return err
	}

	err = server.AddRouterPath("/a/sessions", "GET", false, handlerGetSessions)
	if err != nil {
		return err
	}

	err = server.AddRouterPath("/a/keys", "GET", false, handlerGetKeys)
	if err != nil {
		return err
	}

	err = server.AddRouterPath("/", "GET", true, handler404)
	if err != nil {
		return err
	}

	return nil
}
