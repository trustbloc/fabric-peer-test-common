/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bddtests

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type HTTPClient struct {
}

// PGet sends a GET request to the given URL
func (c *HTTPClient) Get(url string) ([]byte, int, http.Header, error) {
	resolved, err := ResolveVars(url)
	if err != nil {
		return nil, 0, nil, err
	}

	url = resolved.(string)

	client := &http.Client{}

	if strings.HasPrefix(url, "https") {
		// TODO add tls config https://github.com/trustbloc/fabric-peer-test-common/issues/51
		// TODO !!!!!!!remove InsecureSkipVerify after configure tls for http client
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint: gosec
		}
	}

	httpReq, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, nil, err
	}

	SetAuthTokenHeader(httpReq)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, 0, nil, err
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("Error closing HTTP response from [%s]: %s", url, err)
		}
	}()

	payload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, resp.Header, fmt.Errorf("reading response body failed: %s", err)
	}

	return payload, resp.StatusCode, resp.Header, nil
}

// Post posts the given data to the given URL
func (c *HTTPClient) Post(url string, data []byte, contentType string) ([]byte, int, http.Header, error) {
	client := &http.Client{}

	if strings.HasPrefix(url, "https") {
		// TODO add tls config https://github.com/trustbloc/fabric-peer-test-common/issues/51
		// TODO !!!!!!!remove InsecureSkipVerify after configure tls for http client
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint: gosec
		}
	}

	logger.Infof("Posting request of content-type [%s] to [%s]: %s", contentType, url, data)

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, 0, nil, err
	}

	httpReq.Header.Set("Content-Type", contentType)

	SetAuthTokenHeader(httpReq)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, 0, nil, err
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.Warnf("Error closing HTTP response from [%s]: %s", url, err)
		}
	}()

	payload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, resp.Header, err
	}

	return payload, resp.StatusCode, resp.Header, nil
}
