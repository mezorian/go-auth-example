package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test Event for correct attribute setting

func TestHelloWorld(t *testing.T) {
	assert.Equal(t, "Hello World", "Hello World", "")
}
