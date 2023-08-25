package test

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// WantError assert an error to a given string, if string is empty, it assumes no error case.
func WantError(t *testing.T, want string, got error) {
	if want != "" {
		assert.EqualError(t, got, want)
	} else {
		assert.NoError(t, got)
	}
}
