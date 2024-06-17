package connect

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/jwt"
)

type AuthProvider string

const (
	S2s  AuthProvider = "s2s"
	User AuthProvider = "user"
)

func RespondAuthFailure(auth AuthProvider, err error, w http.ResponseWriter) {

	var unauthorized string
	var forbidden string

	if auth == S2s {
		unauthorized = jwt.S2sUnauthorizedErrMsg
		forbidden = jwt.S2sForbiddenErrMsg
	} else {
		unauthorized = jwt.UserUnauthorizedErrMsg
		forbidden = jwt.UserForbdiddenErrMsg
	}

	if strings.Contains(err.Error(), "unauthorized") {

		e := ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    unauthorized,
		}
		w.WriteHeader(http.StatusUnauthorized)
		e.SendJsonErr(w)
		return
	} else if strings.Contains(err.Error(), "forbidden") {

		e := ErrorHttp{
			StatusCode: http.StatusForbidden,
			Message:    forbidden,
		}
		w.WriteHeader(http.StatusForbidden)
		e.SendJsonErr(w)
		return
	} else {

		e := ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    fmt.Sprintf("internal server error - failed to validate %s token:", auth),
		}
		w.WriteHeader(http.StatusInternalServerError)
		e.SendJsonErr(w)
		return
	}
}
