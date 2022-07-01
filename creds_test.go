/*
Copyright 2015 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package roundtrip

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
)

func TestBasicAuth(t *testing.T) {
	var creds *AuthCreds
	var credsErr error
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		creds, credsErr = ParseAuthHeaders(r)
	})
	t.Cleanup(srv.Close)

	clt := newC(srv.URL, "v1", BasicAuth("user", "pass"))
	_, err := clt.Get(context.Background(), clt.Endpoint("test"), url.Values{})
	require.NoError(t, err)
	require.NoError(t, credsErr)
	require.Equal(t, &AuthCreds{Type: AuthBasic, Username: "user", Password: "pass"}, creds)
}

func TestTokenAuth(t *testing.T) {
	var creds *AuthCreds
	var credsErr error
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		creds, credsErr = ParseAuthHeaders(r)
	})
	t.Cleanup(srv.Close)

	clt := newC(srv.URL, "v1", BearerAuth("token1"))
	_, err := clt.Get(context.Background(), clt.Endpoint("test"), url.Values{})
	require.NoError(t, err)
	require.NoError(t, credsErr)
	require.Equal(t, &AuthCreds{Type: AuthBearer, Password: "token1"}, creds)
}

func TestTokenURIAuth(t *testing.T) {
	var creds *AuthCreds
	var credsErr error
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		creds, credsErr = ParseAuthHeaders(r)
	})
	t.Cleanup(srv.Close)

	clt := newC(srv.URL, "v1")
	_, err := clt.Get(context.Background(), clt.Endpoint("test"), url.Values{AccessTokenQueryParam: []string{"token2"}})
	require.NoError(t, err)
	require.NoError(t, credsErr)
	require.Equal(t, &AuthCreds{Type: AuthBearer, Password: "token2"}, creds)
}

func TestGarbage(t *testing.T) {
	type tc struct {
		Headers map[string][]string
		Error   error
	}
	testCases := []tc{
		// missing auth requests
		{
			Headers: map[string][]string{"Authorization": {""}},
			Error:   &AccessDeniedError{},
		},
		{
			Headers: map[string][]string{"Authorisation": {"Bearer blabla"}},
			Error:   &AccessDeniedError{},
		},
		// corrupted auth requests
		{
			Headers: map[string][]string{"Authorization": {"WAT? blabla"}},
			Error:   &ParameterError{},
		},
		{
			Headers: map[string][]string{"Authorization": {"Basic bad"}},
			Error:   &ParameterError{},
		},
		{
			Headers: map[string][]string{"Authorization": {"Bearer"}},
			Error:   &ParameterError{},
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("test%v", i), func(t *testing.T) {
			var credsErr error
			srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
				_, credsErr = ParseAuthHeaders(r)
			})
			t.Cleanup(srv.Close)

			req, err := http.NewRequest("GET", srv.URL, nil)
			require.NoError(t, err)
			for key, vals := range tc.Headers {
				for _, val := range vals {
					req.Header.Add(key, val)
				}
			}
			_, err = http.DefaultClient.Do(req)
			require.NoError(t, err)

			require.Error(t, credsErr)
			origErr := credsErr.(trace.Error)
			require.IsType(t, tc.Error, origErr.OrigError())
		})
	}
}
