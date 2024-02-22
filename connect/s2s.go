package connect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
)

type S2SCaller interface {
	GetServiceData(endpoint, s2sToken, authToken string, data interface{}) error
	PostToService(endpoint, s2sToken, authToken string, cmd interface{}, data interface{}) error
}

// http getting json formatted data
type S2sCaller struct {
	ServiceUrl  string
	ServiceName string
	S2sClient   TLSClient
}

func NewS2sCaller(url, name string, client TLSClient) *S2sCaller {
	return &S2sCaller{
		ServiceUrl:  url,
		ServiceName: name,
		S2sClient:   client,
	}
}

func (c *S2sCaller) GetServiceData(endpoint, s2sToken, authToken string, data interface{}) error {

	url := fmt.Sprintf("%s/%s", endpoint, c.ServiceUrl)

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("unable to create get request for endpoint '%s': %v", url, err)
	}
	request.Header.Set("Content-Type", "application/json")

	// service token
	if s2sToken != "" {
		request.Header.Set("Service-Token", fmt.Sprintf("Bearer %s", s2sToken))
	}

	// user access token
	if authToken != "" {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken))
	}

	response, err := c.S2sClient.Do(request)
	if err != nil {
		return fmt.Errorf("unable to execute call against endpoint '%s': %v", url, err)
	}
	defer response.Body.Close()

	// error response handling
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("received non-2xx status code: %d, from endpoint: %s", response.StatusCode, url)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body from '%s': %v", url, err)
	}

	err = json.Unmarshal(body, data)
	if err != nil {
		return fmt.Errorf("unable to unmarshal response body json to %v from '%s': %v", reflect.TypeOf(data), url, err)
	}

	return nil
}

func (c *S2sCaller) PostToService(endpoint, s2sToken, authToken string, cmd interface{}, data interface{}) error {

	url := fmt.Sprintf("%s/%s", endpoint, c.ServiceUrl)

	// marshal data
	jsonData, err := json.Marshal(cmd)
	if err != nil {
		return fmt.Errorf("unable to marshall cmd %v to json: %v", reflect.TypeOf(cmd), err)
	}

	// create request
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("unable to create post request for endpoint '%s': %v", url, err)
	}
	request.Header.Set("Content-Type", "application/json")

	// service token
	if s2sToken != "" {
		request.Header.Set("Service-Token", fmt.Sprintf("Bearer %s", s2sToken))
	}

	// user access token
	if authToken != "" {
		request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken))
	}

	// execute post request
	response, err := c.S2sClient.Do(request)
	if err != nil {
		return fmt.Errorf("unable to execute call against endpoint '%s': %v", url, err)
	}
	defer response.Body.Close()

	// error handling: will be built out over time
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("received non-2xx status code: %d, from endpoint: %s", response.StatusCode, url)
	}

	// marshal response from json to struct
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body for endpoint %s: %v", url, err)
	}

	if err = json.Unmarshal(body, data); err != nil {
		return fmt.Errorf("unable to unmarshal s2s response body json to struct %v for endpoint %s: %v", reflect.TypeOf(data), url, err)
	}

	return nil
}
