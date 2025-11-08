package connect

import (
	"net/http"
	"strings"

	"github.com/tdeslauriers/carapace/pkg/jwt"
	"github.com/tdeslauriers/carapace/pkg/permissions"
)

// handle upstream errors returned by the other two above funtions.
// Adds in meta data to the logging from the caller struct.
func (caller *S2sCaller) RespondUpstreamError(err error, w http.ResponseWriter) {

	// checks for expected ErrorHttp type and handles logging and writing to response if different type
	errMsg, ok := err.(*ErrorHttp)
	if !ok {
		e := ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
		return
	}

	// handle ErrorHttp type errors
	switch errMsg.StatusCode {
	case http.StatusBadRequest:
		e := ErrorHttp{
			StatusCode: http.StatusBadRequest,
			Message:    errMsg.Message,
		}
		e.SendJsonErr(w)

	case http.StatusUnauthorized:

		// s2s token unauthorized
		if strings.Contains(errMsg.Message, jwt.S2sUnauthorizedErrMsg) {
			e := ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "internal server error",
			}
			e.SendJsonErr(w)
			break
		}

		// user token unauthorized
		if strings.Contains(errMsg.Message, jwt.UserUnauthorizedErrMsg) {
			e := ErrorHttp{
				StatusCode: http.StatusUnauthorized,
				Message:    "unauthorized",
			}
			e.SendJsonErr(w)
			break
		}

		// all other unauthorized errors
		e := ErrorHttp{
			StatusCode: http.StatusUnauthorized,
			Message:    errMsg.Message,
		}
		e.SendJsonErr(w)

	case http.StatusForbidden:
		// call returned forbidden for s2s token
		if strings.Contains(errMsg.Message, jwt.S2sForbiddenErrMsg) {
			caller.logger.Error(errMsg.Message)
			e := ErrorHttp{
				StatusCode: http.StatusInternalServerError,
				Message:    "internal server error", // this should never happen --> means I didnt provision the service correctly
			}
			e.SendJsonErr(w)
			break
		}

		// call returned forbidden for user token
		if strings.Contains(errMsg.Message, jwt.UserForbdiddenErrMsg) {
			e := ErrorHttp{
				StatusCode: http.StatusForbidden,
				Message:    "forbidden",
			}
			e.SendJsonErr(w)
			break
		}

		// call returned forbidden for permissions
		if strings.Contains(errMsg.Message, permissions.UserForbidden) {
			e := ErrorHttp{
				StatusCode: http.StatusForbidden,
				Message:    "forbidden",
			}
			e.SendJsonErr(w)
			break
		}
	case http.StatusNotFound:
		e := ErrorHttp{
			StatusCode: http.StatusNotFound,
			Message:    errMsg.Message,
		}
		e.SendJsonErr(w)

	case http.StatusMethodNotAllowed:
		e := ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error", // this should never happen -> means calling service was written using wrong method
		}
		e.SendJsonErr(w)

		// returns conflict error from the upstream service, eg. "username unavailable"
	case http.StatusConflict:
		e := ErrorHttp{
			StatusCode: http.StatusConflict,
			Message:    errMsg.Message,
		}
		e.SendJsonErr(w)

		// this returns validation errors from the upstream service
	case http.StatusUnprocessableEntity:
		e := ErrorHttp{
			StatusCode: http.StatusUnprocessableEntity,
			Message:    errMsg.Message,
		}
		e.SendJsonErr(w)

		// this returns data processing errors from the upstream service like "unexpected content type"
	case http.StatusUnsupportedMediaType:
		e := ErrorHttp{
			StatusCode: http.StatusUnsupportedMediaType,
			Message:    errMsg.Message,
		}
		e.SendJsonErr(w)

	case http.StatusServiceUnavailable:
		e := ErrorHttp{
			StatusCode: http.StatusServiceUnavailable,
			Message:    "required service unavailable",
		}
		e.SendJsonErr(w)

	default:
		e := ErrorHttp{
			StatusCode: http.StatusInternalServerError,
			Message:    "internal server error",
		}
		e.SendJsonErr(w)
	}
}
