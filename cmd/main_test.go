package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetDefaultConfigPath(t *testing.T) {
	t.Setenv("QUASAR_CONFIG_PATH", "")
	assert.Equal(t, "config.toml", getDefaultConfigPath())

	t.Setenv("QUASAR_CONFIG_PATH", "/custom/path/config.toml")
	assert.Equal(t, "/custom/path/config.toml", getDefaultConfigPath())
}
