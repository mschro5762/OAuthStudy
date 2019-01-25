package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	conf "github.com/micro/go-config"
	"go.uber.org/zap"

	"github.com/mschro5762/OAuthStudy/clients"
	"github.com/mschro5762/OAuthStudy/contexthelper"
	"github.com/mschro5762/OAuthStudy/crypto"
	"github.com/mschro5762/OAuthStudy/middleware"
	"github.com/mschro5762/OAuthStudy/oauth"
	"github.com/mschro5762/OAuthStudy/users"
)

func buildConfig() config {
	conf.LoadFile("./config/config.json")

	var config config
	err := conf.Scan(&config)
	if err != nil {
		panic(err)
	}

	return config
}

func startWebServer(ctx context.Context, config config) {
	logger := contexthelper.LoggerFromContext(ctx)

	clientRepo, err := clients.NewFileRepository(config.ClientRegistry.RepoFilePath)
	if err != nil {
		logger.Panic("StartWebServer: Unable to create client repository",
			zap.Error(err))
	}
	clientRegistry, err := clients.NewRegistry(ctx, clientRepo, config.ClientRegistry.SecretLength)
	if err != nil {
		logger.Panic("StartWebServer: Unable to create client registry service",
			zap.Error(err))
	}
	clientEndpoints, err := clients.NewWebEndpoints(ctx, clientRegistry)
	if err != nil {
		logger.Panic("StartWebServer: Unable to create client registry endpoints",
			zap.Error(err))
	}

	userRepo, err := users.NewFileRepository(config.UserService.RepoFilePath)
	if err != nil {
		logger.Panic("StartWebServer: Unable to create user repository",
			zap.Error(err))
	}
	userSvc, err := users.NewUserService(ctx, userRepo)
	if err != nil {
		logger.Panic("StartWebServer: Unable to create user service",
			zap.Error(err))
	}
	userEndpoints, err := users.NewUserEndpoints(ctx, userSvc)
	if err != nil {
		logger.Panic("StartWebServer: Unable to create user registry endpoints",
			zap.Error(err))
	}

	encrypter, err := crypto.NewEncrypter(ctx, config.AuthTokenService.AuthzCodeCrypto)
	if err != nil {
		logger.Panic("StartWebServer: Unable to create user registry endpoints",
			zap.Error(err))
	}
	authzServer := oauth.NewAuthTokenService(ctx, config.AuthTokenService, encrypter)
	oauthEndpoints := oauth.NewWebEndpoints(ctx, authzServer, userSvc, clientRegistry)

	router := mux.NewRouter()

	logger.Info("Registering http paths")

	router.Handle("/clients", middleware.CommonHandlers(middleware.BodyExtractionHandler(
		clientEndpoints.RegisterClient))).Methods("POST")

	router.Handle("/clients/{"+clients.RouteParamClientID+"}/newsecret", middleware.CommonHandlers(
		http.HandlerFunc(clientEndpoints.GenerateNewClientSecret))).Methods("PUT")

	router.Handle("/users", middleware.CommonHandlers(middleware.BodyExtractionHandler(
		userEndpoints.RegisterUser))).Methods("POST")

	router.Handle("/authorize", middleware.CommonHandlers(
		http.HandlerFunc(oauthEndpoints.AuthorizationEndpoint))).Methods("GET", "POST")

	logger.Info("Starting web server")
	serverErr := http.ListenAndServe(fmt.Sprintf("%v", config.WebServer.Address), router)
	logger.Fatal("Error in http.ListenAndServe",
		zap.Error(serverErr))
}

func main() {
	config := buildConfig()

	logger, err := zap.NewProduction()
	if err != nil {
		panic("Main: Unable to create a logger")
	}
	defer logger.Sync()

	ctx := contexthelper.NewContextWithLogger(logger)

	logger.Info("Starting Authorization Server")

	startWebServer(ctx, config)

	logger.Info("Stopping Authorization Server")
}
