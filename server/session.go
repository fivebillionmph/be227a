package main

import (
	"errors"
	"net"
)

type UserSession struct {
	db_user             *DBUser
	id                  string
	start_timestamp     int
	lastcheck_timestamp int
	ip                  net.IP
	port                int
}

func UserSession__new(user *DBUser, ip net.IP, port int) (*UserSession, error) {
	now := timestamp()
	if port < 1 || port > 65535 {
		return nil, errors.New("invalid port")
	}

	var session_id string
	for {
		session_id = randomString(12)
		existing_challenge := global_user_sessions[session_id]
		if existing_challenge == nil {
			break
		}
	}

	session := UserSession{
		db_user:             user,
		id:                  session_id,
		start_timestamp:     now,
		lastcheck_timestamp: now,
		ip:                  ip,
		port:                port,
	}

	global_user_sessions[session_id] = &session

	return &session, nil
}

func UserSession__getRegistered(id string) *UserSession {
	user_session := global_user_sessions[id]
	return user_session
}

func UserSession__delete(id string) {
	_, ok := global_user_sessions[id]
	if ok {
		delete(global_user_sessions, id)
	}
}
