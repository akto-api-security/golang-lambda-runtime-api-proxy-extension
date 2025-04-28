BASENAME := $(shell basename $(CURDIR))
ARTIFACTS_DIR ?= out
targetArch := amd64
extensionName := golang-lambda-runtime-api-proxy-extension
FUNCTION_NAME := python-lambda
LAYER_NAME := $(extensionName)-layer

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
		--environment 'Variables={AWS_LAMBDA_EXEC_WRAPPER=/opt/wrapper-script.sh,AKTO_MIRRORING_URL=https://e7ed-2404-ba00-fd01-c375-259b-1149-45f-819c.ngrok-free.app/api/ingestData}'

.PHONY: all-and-publish
all-and-publish: build-GolangRuntimeApiProxyExtensionLayer updateFunctionConfiguration
