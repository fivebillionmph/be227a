package main

import (
	"encoding/base64"
	gss "github.com/fivebillionmph/gosimpleserver"
	"net"
	"net/http"
	"strings"
)

func handlerStartSession(w http.ResponseWriter, r *http.Request, server *gss.Server) {
	user, err := publicKeyToUserRequest(r, server)
	if err != nil {
		errorResponse(w, 400, "Invalid request")
		return
	}

	public_key, err := user.publicKey()
	if err != nil {
		errorResponse(w, 500, "Public key error")
		return
	}
	userChallengeResponse(w, public_key, "start_session")
}

func handlerStopSession(w http.ResponseWriter, r *http.Request, server *gss.Server) {
	json_request := struct {
		Session_id string `json:"session_id"`
	}{}
	err := requestJSONDecode(r, &json_request)
	if err != nil {
		errorResponse(w, 400, "Invalid request")
		return
	}
	UserSession__delete(json_request.Session_id)
	sendJSONResponseSuccess(w)
}

func handlerSessionChallenge(w http.ResponseWriter, r *http.Request, server *gss.Server) {
	type json_request_type struct {
		Signature string `json:"signature"`
		Index     int    `json:"index"`
		Port      int    `json:"port"`
	}
	json_request := json_request_type{}
	err := requestJSONDecode(r, &json_request)
	if err != nil {
		errorResponse(w, 400, "Could not read message")
		return
	}

	challenge := UserChallenge__getRegistered(json_request.Index)
	if challenge == nil {
		errorResponse(w, 400, "Challenge does not exist")
		return
	}

	signature, err := base64.StdEncoding.DecodeString(json_request.Signature)
	if err != nil {
		errorResponse(w, 400, "Could not read signature")
		return
	}

	if !challenge.validate(string(signature)) {
		errorResponse(w, 400, "Challenge failed")
		return
	}

	user, err := DBUser__getByPublicKey(server.RequestDBConnection(), challenge.public_key)
	if err != nil {
		errorResponse(w, 400, "Invalid user")
		return
	}

	ip_str := r.Header.Get("X-Forwarded-For")
	ip := net.ParseIP(ip_str)
	if ip == nil {
		errorResponse(w, 400, "Invalid IP")
		return
	}

	session, err := UserSession__new(user, ip, json_request.Port)
	if err != nil {
		errorResponse(w, 400, "Could not create session")
		return
	}

	json_response := struct {
		Session_id string `json:"session_id"`
	}{
		session.id,
	}

	sendJSONResponse(w, &json_response)

	challenge.unregister()
}

func handlerSessionRefresh(w http.ResponseWriter, r *http.Request, server *gss.Server) {
	json_request := struct {
		Session_id string `json"session_id"`
	}{}
	err := requestJSONDecode(r, &json_request)
	if err != nil {
		errorResponse(w, 400, "Could not read message")
		return
	}

	session := UserSession__getRegistered(json_request.Session_id)
	if session == nil {
		errorResponse(w, 400, "Invalid session")
		return
	}

	session.lastcheck_timestamp = timestamp()

	sendJSONResponseSuccess(w)
}

func handlerRegisterChallenge(w http.ResponseWriter, r *http.Request, server *gss.Server) {
	type json_request_type struct {
		Signature    string `json:"signature"`
		Index        int    `json:"index"`
		Name         string `json:"name"`
		Organization string `json:"organization"`
	}
	json_request := json_request_type{}
	err := requestJSONDecode(r, &json_request)
	if err != nil {
		errorResponse(w, 400, "Could not read message")
		return
	}

	challenge := UserChallenge__getRegistered(json_request.Index)
	if challenge == nil {
		errorResponse(w, 400, "Challenge does not exist")
		return
	}

	signature, err := base64.StdEncoding.DecodeString(json_request.Signature)
	if err != nil {
		errorResponse(w, 400, "Could not read signature")
		return
	}

	if !challenge.validate(string(signature)) {
		errorResponse(w, 400, "Challenge failed")
		return
	}

	_, err = DBUser__create(server.RequestDBConnection(), json_request.Name, json_request.Organization, challenge.public_key)
	if err != nil {
		errorResponse(w, 400, "Could not register user")
		return
	}

	sendJSONResponseSuccess(w)
}

func handlerRegister(w http.ResponseWriter, r *http.Request, server *gss.Server) {
	type json_request_type struct {
		Public_key string `json:"public_key"`
	}
	json_request := json_request_type{}
	err := requestJSONDecode(r, &json_request)
	if err != nil {
		errorResponse(w, 400, "Could not parse request")
		return
	}

	public_key, err := stringToPublicKey(json_request.Public_key)
	if err != nil {
		errorResponse(w, 400, "Could not read public key")
		return
	}
	userChallengeResponse(w, public_key, "register")
}

func handlerAddSignature(w http.ResponseWriter, r *http.Request, server *gss.Server) {
	type json_request_type struct {
		Signature         string                     `json:"signature"`
		Message           DBSignature__VerifyMessage `json:"message"`
		Signer_public_key string                     `json:"signer_public_key"`
		Signee_public_key string                     `json:"signee_public_key"`
	}
	json_request := json_request_type{}
	err := requestJSONDecode(r, &json_request)
	if err != nil {
		errorResponse(w, 400, "Could not read request")
		return
	}

	cxn := server.RequestDBConnection()

	signer_public_key, err := stringToPublicKey(json_request.Signer_public_key)
	if err != nil {
		errorResponse(w, 400, "Invalid signer public key")
		return
	}

	signer, err := DBUser__getByPublicKey(cxn, signer_public_key)
	if err != nil {
		errorResponse(w, 400, "Signer not found")
		return
	}

	signee_public_key, err := stringToPublicKey(json_request.Signee_public_key)
	if err != nil {
		errorResponse(w, 400, "Invalid signee key")
		return
	}

	signee, err := DBUser__getByPublicKey(cxn, signee_public_key)
	if err != nil {
		errorResponse(w, 400, "Signee is not found")
		return
	}

	signature, err := base64.StdEncoding.DecodeString(json_request.Signature)
	if err != nil {
		errorResponse(w, 400, "Could not decode signature")
		return
	}

	_, err = DBSignature__create(cxn, signer, signee, json_request.Message, string(signature))

	if err != nil {
		errorResponse(w, 400, "Could not create signature")
		return
	}

	sendJSONResponseSuccess(w)
}

//func handlerRevokeSignature(w http.ResponseWriter, r *http.Request, server *gss.Server) {
//
//}

func handlerGetSignatures(w http.ResponseWriter, r *http.Request, server *gss.Server) {
	json_request := struct {
		Key string `json:"key"`
	}{}
	err := requestJSONDecode(r, &json_request)

	if err != nil {
		errorResponse(w, 400, "Could not read key")
		return
	}

	public_key, err := stringToPublicKey(json_request.Key)
	if err != nil {
		//errorResponse(w, 400, "Invalid public key")
		errorResponse(w, 400, err.Error())
		return
	}

	cxn := server.RequestDBConnection()
	signee, err := DBUser__getByPublicKey(cxn, public_key)
	if err != nil {
		errorResponse(w, 400, "Invalid public key")
		return
	}

	signatures, err := DBSignature__getBySignee(cxn, signee)
	if err != nil {
		errorResponse(w, 500, "Unexpected error")
		return
	}

	type json_signer_info struct {
		Public_key   string `json:"public_key"`
		Name         string `json:"name"`
		Organization string `json"organization"`
	}
	type json_signature struct {
		Signature string           `json:"signature"`
		Message   string           `json:"message"`
		Signer    json_signer_info `json:"signer"`
	}

	json_response := struct {
		Signatures []json_signature `json:"signatures"`
	}{
		Signatures: make([]json_signature, 0, len(signatures)),
	}

	for _, signature := range signatures {
		signer, err := signature.signer(cxn)
		if err != nil {
			continue
		}

		signer_key_string, err := signer.publicKeyString()
		if err != nil {
			continue
		}

		signer_info := json_signer_info{
			Public_key:   signer_key_string,
			Name:         signer.F_name,
			Organization: signer.F_organization,
		}
		jsig := json_signature{
			Signature: signature.base64Signature(),
			Message:   signature.F_message,
			Signer:    signer_info,
		}
		json_response.Signatures = append(json_response.Signatures, jsig)
	}

	sendJSONResponse(w, &json_response)
}

func handlerGetSessions(w http.ResponseWriter, r *http.Request, server *gss.Server) {
	query := strings.ToLower(r.URL.Query().Get("q"))
	type json_session struct {
		Name         string `json:"name"`
		Organization string `json:"organization"`
		IP           string `json:"ip"`
		Port         int    `json:"port"`
		Public_key   string `json:"public_key"`
	}
	json_response := struct {
		Sessions []json_session `json:"sessions"`
	}{
		Sessions: make([]json_session, 0, len(global_user_sessions)),
	}

	for _, gus := range global_user_sessions {
		if query != "" {
			if !strings.Contains(strings.ToLower(gus.db_user.F_name), query) && !strings.Contains(strings.ToLower(gus.db_user.F_organization), query) {
				continue
			}
		}
		public_key_string, err := gus.db_user.publicKeyString()
		if err != nil {
			continue
		}
		js := json_session{
			Name:         gus.db_user.F_name,
			Organization: gus.db_user.F_organization,
			IP:           gus.ip.String(),
			Port:         gus.port,
			Public_key:   public_key_string,
		}
		json_response.Sessions = append(json_response.Sessions, js)
	}

	sendJSONResponse(w, &json_response)
}

func handlerGetKeys(w http.ResponseWriter, r *http.Request, server *gss.Server) {
	query := r.URL.Query().Get("q")
	cxn := server.RequestDBConnection()
	var users []*DBUser
	var err error
	if query == "" {
		users, err = DBUser__getAll(cxn)
		if err != nil {
			errorResponse(w, 500, "Could not get users")
			return
		}
	} else {
		users, err = DBUser__getByQuery(cxn, query)
		if err != nil {
			errorResponse(w, 500, "Could not query users")
			return
		}
	}

	type user_response_type struct {
		Name         string `json:"name"`
		Organization string `json:"organization"`
		Public_key   string `json:"public_key"`
	}
	json_response := struct {
		Users []user_response_type `json:"users"`
	}{
		make([]user_response_type, 0, len(users)),
	}
	for _, user := range users {
		public_key_string, err := user.publicKeyString()
		if err != nil {
			continue
		}
		urt := user_response_type{
			Name:         user.F_name,
			Organization: user.F_organization,
			Public_key:   public_key_string,
		}
		json_response.Users = append(json_response.Users, urt)
	}
	sendJSONResponse(w, &json_response)
}

func handler404(w http.ResponseWriter, r *http.Request, server *gss.Server) {
	errorResponse(w, 404, "Document does not exist")
}
