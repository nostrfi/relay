package errors

import (
	"fmt"
	"net/http"
)

type AppError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Code    int    `json:"-"` // HTTP status code
}

func (e AppError) Error() string {
	return e.Message
}

var (
	ErrNotFound = func(msg string) AppError {
		return AppError{Type: "not_found", Message: msg, Code: http.StatusNotFound}
	}

	ErrBadRequest = func(msg string) AppError {
		return AppError{Type: "bad_request", Message: msg, Code: http.StatusBadRequest}
	}

	ErrInternal = func(msg string) AppError {
		return AppError{Type: "internal_error", Message: msg, Code: http.StatusInternalServerError}
	}
)

func New(msg string, code int) AppError {
	return AppError{
		Type:    "error",
		Message: msg,
		Code:    code,
	}
}

func Wrap(err error, msg string, code int) AppError {
	return AppError{
		Type:    "error",
		Message: fmt.Sprintf("%s: %v", msg, err),
		Code:    code,
	}
}
