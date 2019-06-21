package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	gss "github.com/fivebillionmph/gosimpleserver"
	"strconv"
)

var DBSignature__table string = "signatures"

type DBSignature struct {
	F_id        int
	F_timestamp int
	F_signer_id int
	F_signee_id int
	F_message   string
	F_signature string
}

type DBSignature__VerifyMessage struct {
	Public_key   string `json:"public_key"`
	Start_time   int    `json:"start_time"`
	End_time     int    `json:"end_time"`
	Check_server string `json:"check_server"`
	Message_key  string `json:"message_key"`
	Modifiers    string `json:"modifiers"`
}

func (self DBSignature__VerifyMessage) toStorageString() (string, error) {
	b_array, err := json.Marshal(&self)
	if err != nil {
		return "", err
	}
	return string(b_array), nil
}

func (self DBSignature) message() (*DBSignature__VerifyMessage, error) {
	verify_message := DBSignature__VerifyMessage{}
	err := json.Unmarshal([]byte(self.F_message), &verify_message)
	if err != nil {
		return nil, err
	}
	return &verify_message, nil
}

func (self *DBSignature) readRow(row gss.SQLRowInterface) error {
	err := row.Scan(
		&self.F_id,
		&self.F_timestamp,
		&self.F_signer_id,
		&self.F_signee_id,
		&self.F_message,
		&self.F_signature,
	)

	return err
}

func DBSignature__getByID(cxn *gss.DBConnection, id int) (*DBSignature, error) {
	row := cxn.DB.QueryRow("select * from "+DBSignature__table+" where id = ?", id)

	signature := DBSignature{}
	err := signature.readRow(row)

	return &signature, err
}

func DBSignature__create(cxn *gss.DBConnection, user_signer *DBUser, user_signee *DBUser, message DBSignature__VerifyMessage, signature string) (*DBSignature, error) {
	if !DBSignature__verifyMessage(user_signer, user_signee, message, signature) {
		return nil, errors.New("invalid signing message")
	}

	timestamp := timestamp()

	stmt, err := cxn.DB.Prepare("insert into " + DBSignature__table + " values(NULL, ?, ?, ?, ?, ?)")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	message_string, err := message.toStorageString()
	if err != nil {
		return nil, err
	}

	res, err := stmt.Exec(timestamp, user_signer.F_id, user_signee.F_id, message_string, signature)

	if err != nil {
		return nil, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	return DBSignature__getByID(cxn, int(id))
}

func DBSignature__getBySignee(cxn *gss.DBConnection, signee *DBUser) ([]*DBSignature, error) {
	rows, err := cxn.DB.Query("select * from "+DBSignature__table+" where signee_id = ?", signee.F_id)
	if err != nil {
		return nil, err
	}

	signatures := make([]*DBSignature, 0, 8)
	for rows.Next() {
		sig := DBSignature{}
		err := sig.readRow(rows)
		if err == nil {
			signatures = append(signatures, &sig)
		}
	}

	return signatures, nil
}

func DBSignature__verifyMessage(signer *DBUser, signee *DBUser, message DBSignature__VerifyMessage, signature string) bool {
	signee_public_key_string, err := signee.publicKeyString()
	if err != nil {
		return false
	}
	if signee_public_key_string != message.Public_key {
		return false
	}

	signer_public_key, err := signer.publicKey()
	if err != nil {
		return false
	}

	message_str := message.Public_key + strconv.Itoa(message.Start_time) + strconv.Itoa(message.End_time) + message.Check_server + message.Message_key + message.Modifiers

	return verifyPublicKeySignature(signer_public_key, message_str, signature)
}

func (self *DBSignature) base64Signature() string {
	return base64.StdEncoding.EncodeToString([]byte(self.F_signature))
}

func (self *DBSignature) signer(cxn *gss.DBConnection) (*DBUser, error) {
	return DBUser__getByID(cxn, self.F_signer_id)
}
