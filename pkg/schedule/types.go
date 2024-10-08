package schedule

// SessionAccessXref is a model for the uxsession_accesstoken xref table data.
type SessionAccessXref struct {
	Id            int    `db:"id"`
	UxsessionId   string `db:"uxsession_uuid"`
	AccesstokenId string `db:"accesstoken_uuid"`
}

// SessionOauthXref is a model for the uxsession_oauthflow xref table data.
type SessionOauthXref struct {
	Id          int    `db:"id"`
	UxsessionId string `db:"uxsession_uuid"`
	OauthflowId string `db:"oauthflwo_uuid"`
}

type AuthcodeAccountXref struct {
	Id          int    `db:"id"`
	AuthcodeId  string `db:"authcode_uuid"`
	AccountUuid string `db:"account_uuid"`
	CreatedAt   string `db:"created_at"`
}
