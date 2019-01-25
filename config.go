package main

import (
	"github.com/mschro5762/OAuthStudy/oauth"
)

type config struct {
	WebServer        webServerConfig              `json:"server"`
	ClientRegistry   clientRegistryConfig         `json:"clientRegistry"`
	UserService      userServiceConfig            `json:"users"`
	AuthTokenService oauth.AuthTokenServiceConfig `json:"tokens"`
}

type webServerConfig struct {
	Address string `json:"address"`
}

type clientRegistryConfig struct {
	SecretLength int    `json:"secretLength"`
	RepoFilePath string `json:"repoFilePath"`
}

type userServiceConfig struct {
	RepoFilePath string `json:"repoFilePath"`
}
