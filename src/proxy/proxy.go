package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"time"

	"github.com/go-chi/chi/v5"
)


type MirrorData struct {
	Path            string `json:"path"`
	RequestHeaders  string `json:"requestHeaders"`
	ResponseHeaders string `json:"responseHeaders"`
	Method          string `json:"method"`
	RequestPayload  string `json:"requestPayload"`
	ResponsePayload string `json:"responsePayload"`
	IP              string `json:"ip"`
	Time            string `json:"time"`
	StatusCode      string `json:"statusCode"`
	Type            string `json:"type"`
	Status          string `json:"status"`
	AktoAccountId   string `json:"akto_account_id"`
	AktoVxlanId     string `json:"akto_vxlan_id"`
	IsPending       string `json:"is_pending"`
	Source          string `json:"source"`
	Tag          string `json:"tag"`
}


const (
	printPrefix     = "[LRAP:RuntimeApiProxy]"
)

var (
	awsLambdaRuntimeAPI string
	tr = &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }

    client = &http.Client{Transport: tr}
	currentMirrorData = make(map[string]*MirrorData)
)

var Wg sync.WaitGroup

func StartProxy(endpoint string, port int) {
	println(printPrefix, "Starting proxy server")
	awsLambdaRuntimeAPI = endpoint

	r := chi.NewRouter()
	// Lambda runtime API
	r.Use(simpleLogger)
	r.Get("/2018-06-01/runtime/invocation/next", handleNext)
	r.Post("/2018-06-01/runtime/invocation/{requestId}/response", handleResponse)
	r.Post("/2018-06-01/runtime/init/error", handleInitError)
	r.Post("/2018-06-01/runtime/invocation/{requestId}/error", handleInvokeError)

	// NotFound defines a handler to respond whenever a route could
	// not be found.
	r.NotFound(handleError)

	// MethodNotAllowed defines a handler to respond whenever a method is
	// not allowed.
	r.MethodNotAllowed(handleError)

	proxy := &http.Server{
		Addr:           fmt.Sprintf(":%d", port),
		Handler:        r,
		// ReadTimeout:    30 * time.Second,
		// WriteTimeout:   30 * time.Second,
		// MaxHeaderBytes: 1 << 20,
	}

	go func ()  {
		err := proxy.ListenAndServe()
		if err != nil {
			println(printPrefix, "proxy reported error:", fmt.Sprintf("%s", err))
		}
	}()
	println(printPrefix, "Proxy Server Started")
}

func handleNext(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			fmt.Printf("%s Recovered from panic in handleNext: %v", printPrefix, rec)
		}
	}()

	println(printPrefix, "Handle Next Request")

	url := fmt.Sprintf("http://%s/2018-06-01/runtime/invocation/next", awsLambdaRuntimeAPI)

	resp, err := request("GET", url, r.Body, r.Header)
	if err != nil {
		println(printPrefix, "Error during request:", err)
		return
	}
	defer resp.Body.Close()

	body, err := readBody(resp.Body)
	if err != nil {
		println(printPrefix, "Error reading body:", err)
		return
	}

	body, headers := processRequest(body, resp.Header)

	requestId := resp.Header.Get("Lambda-Runtime-Aws-Request-Id")

	var bodyData map[string]interface{}
	err = json.Unmarshal(body, &bodyData)
	if err != nil {
		println(printPrefix, "Error unmarshaling body:", err)
		return
	}

	bodyContent, ok := bodyData["body"].(string)
	if !ok {
		bodyContent = ""
	}

	var path, httpMethod, ip string
	var requestHeaders map[string]interface{}

	// --- STEP 1: Prefer akto_data if present ---
	if aktoData, ok := bodyData["akto_data"].(map[string]interface{}); ok {
		path, _ = aktoData["path"].(string)
		httpMethod, _ = aktoData["method"].(string)
		ip, _ = aktoData["ip"].(string)

		if headers, ok := aktoData["requestHeaders"].(map[string]interface{}); ok {
			requestHeaders = headers
		}

		if payload, ok := aktoData["requestPayload"].(string); ok {
			bodyContent = payload
		}

	} else {
		// --- STEP 2: Fallback to standard method ---
		if val, ok := bodyData["body"].(string); ok {
			bodyContent = val
		} else {
			jsonBytes, err := json.Marshal(bodyData)
			if err != nil {
				bodyContent = ""
			} else {
				bodyContent = string(jsonBytes)
			}
		}

		if requestContext, ok := bodyData["requestContext"].(map[string]interface{}); ok {
			if httpCtx, ok := requestContext["http"].(map[string]interface{}); ok {
				path, _ = httpCtx["path"].(string)
				httpMethod, _ = httpCtx["method"].(string)
				ip, _ = httpCtx["sourceIp"].(string)
			} else {
				path, _ = bodyData["path"].(string)
				httpMethod, _ = bodyData["httpMethod"].(string)
				headers, _ := bodyData["headers"].(map[string]interface{})
				ip, _ = getHeaderCaseInsensitive(headers, "X-Forwarded-For")
			}
		} else {
			path, _ = bodyData["path"].(string)
			httpMethod, _ = bodyData["httpMethod"].(string)
			headers, _ := bodyData["headers"].(map[string]interface{})
			ip, _ = getHeaderCaseInsensitive(headers, "X-Forwarded-For")
		}

		if headers, ok := bodyData["headers"].(map[string]interface{}); ok {
			requestHeaders = headers
		} else {
			requestHeaders = make(map[string]interface{})
		}
	}

	if(len(requestHeaders) == 0) {
		if headers, ok := bodyData["headers"].(map[string]interface{}); ok {
			requestHeaders = headers
		} else {
			println(printPrefix, "Headers are nil or not in expected format.")
			requestHeaders = make(map[string]interface{})
		}
	}

	headersJSON, err := json.MarshalIndent(requestHeaders, "", "   ")
	if err != nil {
		headersJSON = []byte("")
		println(printPrefix, "Error marshaling headers:", err)
	}

	headersString := string(headersJSON)
	now := fmt.Sprintf("%d", makeTimestampSeconds())
	if len(ip) == 0 {
		ip, _ = requestHeaders["X-Forwarded-For"].(string)
	}

	currentMirrorData[requestId] = &MirrorData{
		Path:            path,
		RequestHeaders:  headersString,
		Method:          httpMethod,
		RequestPayload:  bodyContent,
		IP:              ip,
		Time:            now,
		AktoAccountId:   "1000000",
		AktoVxlanId:     "0",
		IsPending:       "false",
		Source:          "MIRRORING",
		Tag:			 "{\n  \"service\": \"lambda\"\n}",
	}

	finalizeResponse(w, body, headers)
	println(printPrefix, "handleNext posted")
}

func handleResponse(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			println(printPrefix, "Recovered from panic in handleResponse:", rec)
		}
	}()

	requestId := chi.URLParam(r, "requestId")
	println(printPrefix, "Handle Response for requestID:", requestId)

	body, err := readBody(r.Body)
	if err != nil {
		println(printPrefix, "Error reading request body:", err)
		return
	}

	body, headers := processResponse(body, r.Header)

	url := fmt.Sprintf("http://%s/2018-06-01/runtime/invocation/%s/response", awsLambdaRuntimeAPI, requestId)
	bodyBuffer := io.NopCloser(bytes.NewReader(body))

	mirrorData, ok := currentMirrorData[requestId]
	if ok && mirrorData != nil {
		var respData map[string]interface{}
		err := json.Unmarshal(body, &respData)
		if err != nil {
			println(printPrefix, "Failed to parse response body:", err)
		} else {
			if b, ok := respData["body"].(string); ok {
				unquotedBody, err := strconv.Unquote(b)
				if err == nil {
					mirrorData.ResponsePayload = unquotedBody
				} else {
					mirrorData.ResponsePayload = b
				}

				mirrorData.Type = "HTTP/1.1"
			} else {
				if mirrorData.ResponsePayload == "" {
					mirrorData.ResponsePayload = toJsonString(respData)
				}
				if mirrorData.StatusCode == "" {
					mirrorData.StatusCode = "200"
				}
				if mirrorData.Status == "" {
					mirrorData.Status = "OK"
				}
				if mirrorData.Type == "" {
					mirrorData.Type = "HTTP/2"
				}
			}

			if h, ok := respData["headers"].(map[string]interface{}); ok {
				headersJson, _ := json.Marshal(h)
				mirrorData.ResponseHeaders = string(headersJson)
			}

			if s, ok := respData["statusCode"].(float64); ok {
				mirrorData.StatusCode = fmt.Sprintf("%.0f", s)
				mirrorData.Status = getStatusText(int(s))
			}
		}
	}

	delete(currentMirrorData, requestId)

	proxyPost(w, headers, url, bodyBuffer)
	println(printPrefix, "handleResponse posted")
	if(currentMirrorData != nil) {
		Wg.Add(1)
		sendMirrorData(mirrorData)
		Wg.Wait()
	}
}

func handleInitError(w http.ResponseWriter, r *http.Request) {
	println(printPrefix, "Handle Init Error")

	url := fmt.Sprintf("http://%s/2018-06-01/runtime/init/error", awsLambdaRuntimeAPI)
	proxyPost(w, r.Header, url, r.Body)

	println(printPrefix, "handleInitError posted")
}

func handleInvokeError(w http.ResponseWriter, r *http.Request) {
	requestId := chi.URLParam(r, "requestId")
	println(printPrefix, "Handle Invoke Error for requestID:", requestId)

	url := fmt.Sprintf("http://%s/2018-06-01/runtime/invocation/%s/error", awsLambdaRuntimeAPI, requestId)
	proxyPost(w, r.Header, url, r.Body)

	println(printPrefix, "handleInvokeError posted")
}

func proxyPost(w http.ResponseWriter, headers http.Header, url string, body io.ReadCloser) {
	resp, err := request("POST", url, body, headers)
	if err != nil {
		return
	}

	respBody, err := readBody(resp.Body)
	if err != nil {
		return
	}

	finalizeResponse(w, respBody, resp.Header)
}

func handleError(w http.ResponseWriter, r *http.Request) {
	println(printPrefix, "Path or Protocol Error")
	http.Error(w, http.StatusText(404), 404)
}

func copyHeaders(original http.Header, target http.Header) {
	for key, value := range original {
  		target[strings.ToLower(key)]  = value
	}
}

func finalizeResponse(w http.ResponseWriter, body []byte, headers http.Header) {
	w.Header().Set("Content-Type", "application/json")
	copyHeaders(headers, w.Header())
	_, err := w.Write(body)
	if err != nil {
		println(printPrefix, "Error writing response body")
		return
	}
}

func readBody(bodyBuffer io.ReadCloser) ([]byte, error) {
	defer bodyBuffer.Close()
	body, err := io.ReadAll(bodyBuffer)
	if err != nil {
		println(printPrefix, "Error reading body", err)
		return nil, err
	}
	return body, nil
}

func unmarshalBody(body []byte) (map[string]interface{}, error) {
	var temp = make(map[string]interface{})
	err := json.Unmarshal(body, &temp)
	if err != nil {
		println(printPrefix, "failed to unmarshal response body:", err)
		return nil, err
	}
	return temp, nil
}

func request(verb string, url string, body io.Reader, headers http.Header) (*http.Response, error) {
	request, err := http.NewRequest(verb, url, body)
	if err != nil {
		println(printPrefix, "Error creating http request")
		return nil, err
	}
	if (headers != nil) {
		copyHeaders(request.Header, headers)
	}
	resp, err := client.Do(request)
	if err != nil {
		fmt.Printf("%s Error doing http request\nHeaders: %+v\nBody: %+v\nURL: %+v\n",
			printPrefix, request.Header, body, url)
		return nil, err
	}
	return resp, nil
}

func simpleLogger(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s proxyRequestMetadata method=%s url=%s\n", printPrefix, r.Method, r.URL)
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

// Assumes body is a JSON object. Expand as needed
func processRequest(body []byte, headers http.Header) ([]byte, http.Header) {
	jsonBody, err := unmarshalBody(body)
	if err != nil {
		println(printPrefix, "Error unmarshalling body, returning original body")
		return body, headers
	}

	newBody, err :=json.Marshal(jsonBody)
	if err != nil {
		println(printPrefix, "Error marshalling body, returning original body")
		return body, headers
	}
	return newBody, headers
}

// Assumes body is a JSON object. Expand as needed
func processResponse(body []byte, headers http.Header) ([]byte, http.Header) {
	jsonBody, err := unmarshalBody(body)
	if err != nil {
		println(printPrefix, "Error unmarshalling body, returning original body")
		return body, headers
	}

	newBody, err :=json.Marshal(jsonBody)
	if err != nil {
		println(printPrefix, "Error marshalling body, returning original body")
		return body, headers
	}
	return newBody, headers
}


func sendMirrorData(mirrorData *MirrorData) {
	if(mirrorData == nil) {
		println(printPrefix, "mirrorData is null.")
		return
	}

	defer func() {
		if rec := recover(); rec != nil {
			fmt.Printf("%s Recovered from panic in sendMirrorData: %+v", printPrefix, rec)
		}
	}()

	// Wrap the mirrorData inside a batchData array
	payload := map[string]interface{}{
		"batchData": []MirrorData{*mirrorData},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("%s Error marshaling mirror data: %+v", printPrefix, err)
		return
	}

	url := os.Getenv("AKTO_MIRRORING_URL")
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		fmt.Printf("%s Error creating request to backend: %+v", printPrefix, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	go func() {
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("%s Error sending data to backend: %+v", printPrefix, err)
			return
		}
		println(printPrefix, "Response from backend:", resp.Status)
		defer resp.Body.Close()
		defer Wg.Done()
	}()

	println(printPrefix, "Successfully sent mirror data.")
}

func makeTimestampSeconds() int64 {
    return int64(float64((float64(nowMillis()) / 1000.0)))
}

func nowMillis() int64 {
    return time.Now().UnixNano() / int64(time.Millisecond)
}

func getStatusText(code int) string {
    friendlyHttpStatus := map[int]string{
        200: "OK",
        201: "Created",
        202: "Accepted",
        203: "Non-Authoritative Information",
        204: "No Content",
        205: "Reset Content",
        206: "Partial Content",
        300: "Multiple Choices",
        301: "Moved Permanently",
        302: "Found",
        303: "See Other",
        304: "Not Modified",
        305: "Use Proxy",
        306: "Unused",
        307: "Temporary Redirect",
        400: "Bad Request",
        401: "Unauthorized",
        402: "Payment Required",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        406: "Not Acceptable",
        407: "Proxy Authentication Required",
        408: "Request Timeout",
        409: "Conflict",
        410: "Gone",
        411: "Length Required",
        412: "Precondition Required",
        413: "Request Entry Too Large",
        414: "Request-URI Too Long",
        415: "Unsupported Media Type",
        416: "Requested Range Not Satisfiable",
        417: "Expectation Failed",
        418: "I'm a teapot",
        429: "Too Many Requests",
        500: "Internal Server Error",
        501: "Not Implemented",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout",
        505: "HTTP Version Not Supported",
    }

    if status, exists := friendlyHttpStatus[code]; exists {
        return status
    }

    return ""
}

func getHeaderCaseInsensitive(headers map[string]interface{}, key string) (string, bool) {
    for k, v := range headers {
        if strings.EqualFold(k, key) {
            strVal, ok := v.(string)
            return strVal, ok
        }
    }
    return "", false
}

func toJsonString(v interface{}) string {
    bytes, _ := json.Marshal(v)
    return string(bytes)
}
