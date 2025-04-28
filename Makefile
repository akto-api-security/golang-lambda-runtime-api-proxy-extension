BASENAME := $(shell basename $(CURDIR))
ARTIFACTS_DIR ?= out
targetArch := YOUR_LAMBDA_FUNCTION_ARCHITECTURE # e.g., arm64 or amd64 (a.k.a. x86_64)
extensionName := golang-lambda-runtime-api-proxy-extension
FUNCTION_NAME := YOUR_LAMBDA_FUNCTION_NAME
LAYER_NAME := $(extensionName)-layer
AKTO_MIRRORING_URL := YOUR_AKTO_MIRRORING_URL

all: build-GolangRuntimeApiProxyExtensionLayer

.PHONY: clean
clean:
	rm -rf bin/*
	rm -rf out/*

build-GolangRuntimeApiProxyExtensionLayer:
	echo "Building Extension layer for $(targetArch)"
	rm -rf $(ARTIFACTS_DIR)/*
	mkdir -p $(ARTIFACTS_DIR)
	echo "Starting $(targetArch) build"
	GOOS=linux GOARCH=$(targetArch) go build -o $(ARTIFACTS_DIR)/extensions/${extensionName} src/main.go
	cp -R wrapper-script.sh $(ARTIFACTS_DIR)
	chmod +x $(ARTIFACTS_DIR)/extensions/${extensionName}
	chmod +x $(ARTIFACTS_DIR)/wrapper-script.sh
	cd $(ARTIFACTS_DIR) && zip -r extension.zip wrapper-script.sh extensions

	

# Publish layer version (publishLayerVersion target)
.PHONY: publishLayerVersion
publishLayerVersion:
	@echo "> publishLayerVersion"
	$(eval LAYER_VERSION_ARN=$(shell aws lambda publish-layer-version \
		--layer-name $(LAYER_NAME) \
		--zip-file "fileb://$(ARTIFACTS_DIR)/extension.zip" \
		--output text \
		--query 'LayerVersionArn'))
	@echo "Layer Version ARN: $(LAYER_VERSION_ARN)"

.PHONY: updateFunctionConfiguration
updateFunctionConfiguration: publishLayerVersion
	@echo "> updateFunctionConfiguration"
	aws lambda update-function-configuration \
		--function-name $(FUNCTION_NAME) \
		--layers $(LAYER_VERSION_ARN) \
		--environment 'Variables={AWS_LAMBDA_EXEC_WRAPPER=/opt/wrapper-script.sh,AKTO_MIRRORING_URL=${AKTO_MIRRORING_URL}}'

.PHONY: all-and-publish
all-and-publish: build-GolangRuntimeApiProxyExtensionLayer updateFunctionConfiguration
