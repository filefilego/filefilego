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

// WantErrorContains assert an error to a given string, if string is empty, it assumes no error case.
func WantErrorContains(t *testing.T, wantContains string, got error) {
	if wantContains != "" {
		assert.ErrorContains(t, got, wantContains)
	} else {
		assert.NoError(t, got)
	}
}
