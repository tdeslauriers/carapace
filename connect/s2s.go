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

	url := fmt.Sprintf("%s%s", c.ServiceUrl, endpoint)

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("unable to create get request for endpoint '%s': %v", url, err)
	}
	request.Header.Set("Content-Type", "application/json")

	// service token
	if s2sToken != "" {
		request.Header.Set("Service-Authorization", fmt.Sprintf("Bearer %s", s2sToken))
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

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body from endpoint '%s': %v", url, err)
	}

	// response handling
	if response.StatusCode >= 200 || response.StatusCode < 300 {

		if err := json.Unmarshal(body, data); err != nil {
			return fmt.Errorf("unable to unmarshal response body json to %v from endpoint '%s': %v", reflect.TypeOf(data), url, err)
		}
	} else {

		var e ErrorHttp
		if err := json.Unmarshal(body, &e); err != nil {
			return fmt.Errorf("unable to unmarshal response body json to %v from endpoint '%s': %v", reflect.TypeOf(&e), url, err)
		}

		return fmt.Errorf("received '%d: %s' from get-service-data call to endpoint %s", e.StatusCode, e.Message, url)
	}

	return nil
}

func (c *S2sCaller) PostToService(endpoint, s2sToken, authToken string, cmd interface{}, data interface{}) error {

	url := fmt.Sprintf("%s%s", c.ServiceUrl, endpoint)

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
		request.Header.Set("Service-Authorization", fmt.Sprintf("Bearer %s", s2sToken))
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

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("unable to read response body for endpoint %s: %v", url, err)
	}

	// response handling
	if response.StatusCode >= 200 || response.StatusCode < 300 {

		if err := json.Unmarshal(body, data); err != nil {
			return fmt.Errorf("unable to unmarshal response body json to %v from endpoint '%s': %v", reflect.TypeOf(data), url, err)
		}
	} else {

		var e ErrorHttp
		if err := json.Unmarshal(body, &e); err != nil {
			return fmt.Errorf("unable to unmarshal response body json to %v from endpoint '%s': %v", reflect.TypeOf(&e), url, err)
		}

		return fmt.Errorf("received '%d: %s' from post-to-service call to endpoint %s", e.StatusCode, e.Message, url)
	}

	return nil
}
