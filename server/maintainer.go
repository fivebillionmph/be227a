package main

import (
	"time"
)

/* runs every 5 seconds */
func maintainer() {
	const SESSION_TIME_LIMIT = 3600 // seconds

	for {
		time.Sleep(5 * time.Second)
		now := timestamp()

		/* user challenges */
		for key, user_challenge := range global_user_challenges {
			if now > user_challenge.expire_timestamp {
				delete(global_user_challenges, key)
			}
		}

		/* sessions */
		for key, user_session := range global_user_sessions {
			if now > user_session.lastcheck_timestamp+SESSION_TIME_LIMIT {
				delete(global_user_sessions, key)
			}
		}
	}
}
