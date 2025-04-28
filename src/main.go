package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"LAMBDA-RUNTIME-API-PROXY-EXTENSION-MAIN/golang-lambda-runtime-api-proxy/src/extension"
	"LAMBDA-RUNTIME-API-PROXY-EXTENSION-MAIN/golang-lambda-runtime-api-proxy/src/proxy"
)

const (
	printPrefix     = "[LRAP:Main]"
)

func main() {
	println(printPrefix, "Starting")
	runtimeApiEndpoint := getRuntimeApiEndpoint()
	listenerPort := getListenerPort()
	extensionName := filepath.Base(os.Args[0])

	proxy.StartProxy(runtimeApiEndpoint, listenerPort)
	extensionClient := extension.NewClient(os.Getenv("AWS_LAMBDA_RUNTIME_API"))

	ctx, cancel := context.WithCancel(context.Background())

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		s := <-sigs
		cancel()
		println(printPrefix, "Received", s)
		println(printPrefix, "Exiting")
	}()

	println(printPrefix, "Registering extension")
	res, err := extensionClient.Register(ctx, extensionName)

	if err != nil {
		println(printPrefix, "Error registering extension")
		panic(err)
	}
	println(printPrefix, "Register response:", fmt.Sprintf("%+v",res))
	go extensionClient.NextEvent(ctx)

	<-ctx.Done()
	println(printPrefix, "FINISHED")
}

func getListenerPort() int {
	port := os.Getenv("LRAP_LISTENER_PORT")
	portInt, err := strconv.Atoi(port)
	if (err != nil || portInt == 0) {
		portInt = 9009
	}
	return portInt
}

func getRuntimeApiEndpoint() string {
	endpoint:= os.Getenv("LRAP_RUNTIME_API_ENDPOINT")
	if (endpoint == "") {
		endpoint = os.Getenv("AWS_LAMBDA_RUNTIME_API")
	}
	return endpoint
}
