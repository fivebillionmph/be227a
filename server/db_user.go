package main

import (
	"crypto/rsa"
	"errors"
	gss "github.com/fivebillionmph/gosimpleserver"
)

var DBUser__table string = "users"

type DBUser struct {
	F_id           int
	F_timestamp    int
	F_name         string
	F_organization string
	F_public_key   string
	F_active       int
	public_key     *rsa.PublicKey
}

func (self *DBUser) readRow(row gss.SQLRowInterface) error {
	err := row.Scan(
		&self.F_id,
		&self.F_timestamp,
		&self.F_name,
		&self.F_organization,
		&self.F_public_key,
		&self.F_active,
	)

	return err
}

func DBUser__getByID(cxn *gss.DBConnection, id int) (*DBUser, error) {
	row := cxn.DB.QueryRow("select * from "+DBUser__table+" where id = ?", id)

	user := DBUser{}
	err := user.readRow(row)

	return &user, err
}

func DBUser__create(cxn *gss.DBConnection, name string, organization string, public_key *rsa.PublicKey) (*DBUser, error) {
	timestamp := timestamp()
	active := 1

	if name == "" {
		return nil, errors.New("name cannot be empty")
	}

	stmt, err := cxn.DB.Prepare("insert into " + DBUser__table + " values(NULL, ?, ?, ?, ?, ?)")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	res, err := stmt.Exec(timestamp, name, organization, publicKeyToDerString(public_key), active)
	if err != nil {
		return nil, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	return DBUser__getByID(cxn, int(id))
}

func DBUser__getByPublicKey(cxn *gss.DBConnection, public_key *rsa.PublicKey) (*DBUser, error) {
	public_key_der := publicKeyToDerString(public_key)
	row := cxn.DB.QueryRow("select * from "+DBUser__table+" where public_key = ?", public_key_der)

	user := DBUser{}
	err := user.readRow(row)

	return &user, err
}

func DBUser__getAll(cxn *gss.DBConnection) ([]*DBUser, error) {
	rows, err := cxn.DB.Query("select * from " + DBUser__table)
	if err != nil {
		return nil, err
	}

	users := make([]*DBUser, 0, 8)
	for rows.Next() {
		user := DBUser{}
		err := user.readRow(rows)
		if err == nil {
			users = append(users, &user)
		}
	}

	return users, nil
}

func DBUser__getByQuery(cxn *gss.DBConnection, query string) ([]*DBUser, error) {
	sql_query := "%" + query + "%"
	rows, err := cxn.DB.Query("select * from "+DBUser__table+" where name like ? or organization like ?", sql_query, sql_query)
	if err != nil {
		return nil, err
	}

	users := make([]*DBUser, 0, 8)
	for rows.Next() {
		user := DBUser{}
		err := user.readRow(rows)
		if err == nil {
			users = append(users, &user)
		}
	}

	return users, nil
}

func (self *DBUser) publicKey() (*rsa.PublicKey, error) {
	if self.public_key == nil {
		var err error
		self.public_key, err = derStringToPublicKey(self.F_public_key)
		if err != nil {
			return nil, err
		}
	}

	return self.public_key, nil
}

func (self *DBUser) publicKeyString() (string, error) {
	public_key, err := self.publicKey()
	if err != nil {
		return "", err
	}

	return publicKeyToString(public_key)
}
