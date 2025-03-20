package yubikeyotp

type RequestError uint8

const (
	ErrRequestUnknownFailure RequestError = iota
	ErrRequestInvalidFormat
	ErrRequestReplayed
	ErrRequestBadSignature
	ErrRequestMissingParameter
	ErrRequestClientDoesNotExist
	ErrRequestForbidden
	ErrRequestDeadlineExceeded
	ErrRequestBackendError
)

func (e RequestError) Error() string {
	switch e {
	case ErrRequestUnknownFailure:
		return "unknown failure"
	case ErrRequestInvalidFormat:
		return "one time password is in invalid format"
	case ErrRequestReplayed:
		return "one time password was already used in the past"
	case ErrRequestBadSignature:
		return "the request signature did not match"
	case ErrRequestMissingParameter:
		return "the request lacks a parameter"
	case ErrRequestClientDoesNotExist:
		return "client does not exist"
	case ErrRequestForbidden:
		return "client is not allowed to verify one time passwords"
	case ErrRequestDeadlineExceeded:
		return "server could not obtain the requested number of synchronizations before the deadline"
	case ErrRequestBackendError:
		return "server could not process the request"
	default:
		return "unknown error"
	}
}

type ResponseError uint8

const (
	ErrResponseUnknownFailure ResponseError = iota
	ErrResponseBadSignature
)

func (e ResponseError) Error() string {
	switch e {
	case ErrResponseBadSignature:
		return "bad response signature"
	default:
		return "unknown response error"
	}
}
