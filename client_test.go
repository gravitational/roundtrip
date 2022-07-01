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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPostPutPatchForm(t *testing.T) {
	var u *url.URL
	var form url.Values
	var method string
	var user, pass string

	ch := make(chan error, 1)
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		user, pass, ok = r.BasicAuth()
		if !ok {
			ch <- errors.New("basic auth headers invalid")
			return
		}

		u = r.URL
		if err := r.ParseForm(); err != nil {
			ch <- fmt.Errorf("parse form: %w", err)
			return
		}

		form = r.Form
		method = r.Method
		io.WriteString(w, "hello back")
		ch <- nil
	})
	t.Cleanup(srv.Close)

	clt := newC(srv.URL, "v1", BasicAuth("user", "pass"))
	values := url.Values{"a": []string{"b"}}
	out, err := clt.PostForm(context.Background(), clt.Endpoint("a", "b"), values)
	require.NoError(t, err)

	// check for server errors (all assertions must be made on the test's goroutine)
	require.NoError(t, <-ch)

	require.Equal(t, "user", user)
	require.Equal(t, "pass", pass)
	require.Equal(t, "hello back", string(out.Bytes()))
	require.Equal(t, "/v1/a/b", u.String())
	require.Equal(t, values, form)
	require.Equal(t, http.MethodPost, method)

	values = url.Values{"a": []string{"b put"}}
	out, err = clt.PutForm(context.Background(), clt.Endpoint("a", "b"), values)
	require.NoError(t, err)

	require.NoError(t, <-ch)

	require.Equal(t, "user", user)
	require.Equal(t, "pass", pass)
	require.Equal(t, "hello back", string(out.Bytes()))
	require.Equal(t, "/v1/a/b", u.String())
	require.Equal(t, values, form)
	require.Equal(t, http.MethodPut, method)

	values = url.Values{"a": []string{"b patch"}}
	out, err = clt.PatchForm(context.Background(), clt.Endpoint("a", "b"), values)
	require.NoError(t, err)

	require.NoError(t, <-ch)

	require.Equal(t, string(out.Bytes()), "hello back")
	require.Equal(t, "/v1/a/b", u.String())
	require.Equal(t, values, form)
	require.Equal(t, http.MethodPatch, method)
	require.Equal(t, "user", user)
	require.Equal(t, "pass", pass)
}

func TestAddAuth(t *testing.T) {
	var user, pass string

	ch := make(chan error, 1)
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		user, pass, ok = r.BasicAuth()
		if !ok {
			ch <- errors.New("basic auth headers invalid")
			return
		}

		io.WriteString(w, "hello back")
		ch <- nil
	})
	t.Cleanup(srv.Close)

	clt := newC(srv.URL, "v1", BasicAuth("user", "pass"))
	req, err := http.NewRequest(http.MethodGet, clt.Endpoint("a", "b"), nil)
	require.NoError(t, err)

	clt.SetAuthHeader(req.Header)
	_, err = clt.HTTPClient().Do(req)
	require.NoError(t, err)

	require.NoError(t, <-ch)

	require.Equal(t, "user", user)
	require.Equal(t, "pass", pass)
}

func TestPostPutPatchJSON(t *testing.T) {
	var data interface{}
	var user, pass string
	var method string

	ch := make(chan error, 1)
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		method = r.Method

		user, pass, ok = r.BasicAuth()
		if !ok {
			ch <- errors.New("basic auth headers invalid")
			return
		}

		ch <- json.NewDecoder(r.Body).Decode(&data)
	})
	t.Cleanup(srv.Close)

	clt := newC(srv.URL, "v1", BasicAuth("user", "pass"))

	values := map[string]interface{}{"hello": "there"}
	_, err := clt.PostJSON(context.Background(), clt.Endpoint("a", "b"), values)
	require.NoError(t, err)

	require.NoError(t, <-ch)

	require.Equal(t, http.MethodPost, method)
	require.Equal(t, "user", user)
	require.Equal(t, "pass", pass)
	require.Equal(t, values, data)

	values = map[string]interface{}{"hello": "there, put"}
	_, err = clt.PutJSON(context.Background(), clt.Endpoint("a", "b"), values)
	require.NoError(t, err)

	require.NoError(t, <-ch)

	require.Equal(t, http.MethodPut, method)
	require.Equal(t, "user", user)
	require.Equal(t, "pass", pass)
	require.Equal(t, values, data)

	values = map[string]interface{}{"hello": "there,patch"}
	_, err = clt.PatchJSON(context.Background(), clt.Endpoint("a", "b"), values)

	require.NoError(t, err)

	require.NoError(t, <-ch)

	require.Equal(t, http.MethodPatch, method)
	require.Equal(t, "user", user)
	require.Equal(t, "pass", pass)
	require.Equal(t, values, data)
}

func TestDelete(t *testing.T) {
	var method string
	var user, pass string

	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ = r.BasicAuth()
		method = r.Method
	})
	t.Cleanup(srv.Close)

	clt := newC(srv.URL, "v1", BasicAuth("user", "pass"))
	re, err := clt.Delete(context.Background(), clt.Endpoint("a", "b"))
	require.NoError(t, err)
	require.Equal(t, http.MethodDelete, method)
	require.Equal(t, http.StatusOK, re.Code())
	require.Equal(t, "user", user)
	require.Equal(t, "pass", pass)
}

func TestDeleteP(t *testing.T) {
	var method string
	var user, pass string
	var query url.Values
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ = r.BasicAuth()
		method = r.Method
		query = r.URL.Query()
	})
	t.Cleanup(srv.Close)

	clt := newC(srv.URL, "v1", BasicAuth("user", "pass"))
	values := url.Values{"force": []string{"true"}}
	re, err := clt.DeleteWithParams(context.Background(), clt.Endpoint("a", "b"), values)
	require.NoError(t, err)
	require.Equal(t, http.MethodDelete, method)
	require.Equal(t, http.StatusOK, re.Code())
	require.Equal(t, "user", user)
	require.Equal(t, "pass", pass)
	require.Equal(t, values, query)
}

func TestGet(t *testing.T) {
	var method string
	var query url.Values
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		query = r.URL.Query()
	})
	t.Cleanup(srv.Close)

	clt := newC(srv.URL, "v1")
	values := url.Values{"q": []string{"1", "2"}}
	_, err := clt.Get(context.Background(), clt.Endpoint("a", "b"), values)
	require.NoError(t, err)
	require.Equal(t, http.MethodGet, method)
	require.Equal(t, values, query)
}

func TestTracer(t *testing.T) {
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {})
	t.Cleanup(srv.Close)

	out := &bytes.Buffer{}
	clt := newC(srv.URL, "v1", Tracer(func() RequestTracer {
		return NewWriterTracer(out)
	}))
	_, err := clt.Get(context.Background(), clt.Endpoint("a", "b"), url.Values{"q": []string{"1", "2"}})
	require.NoError(t, err)
	require.Regexp(t, regexp.MustCompile(".*a/b.*"), out.String())
}

func TestGetFile(t *testing.T) {
	fileName := filepath.Join(t.TempDir(), "file.txt")
	err := os.WriteFile(fileName, []byte("hello there"), 0666)
	require.NoError(t, err)

	var user, pass string
	ch := make(chan error, 1)
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		user, pass, ok = r.BasicAuth()
		if !ok {
			ch <- errors.New("basic auth headers invalid")
			return
		}

		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%v`, "file.txt"))
		http.ServeFile(w, r, fileName)
		ch <- nil
	})
	t.Cleanup(srv.Close)

	clt := newC(srv.URL, "v1", BasicAuth("user", "pass"))
	f, err := clt.GetFile(context.Background(), clt.Endpoint("download"), url.Values{})
	require.NoError(t, err)
	defer f.Close()

	require.NoError(t, <-ch)

	data, err := io.ReadAll(f.Body())
	require.NoError(t, err)
	require.Equal(t, "hello there", string(data))
	require.Equal(t, "file.txt", f.FileName())
	require.Equal(t, user, "user")
	require.Equal(t, pass, "pass")
}

func createFile(t *testing.T, size int64) (*os.File, string) {
	t.Helper()

	out, err := os.CreateTemp(t.TempDir(), "")
	require.NoError(t, err)

	h := sha512.New()

	_, err = io.CopyN(io.MultiWriter(out, h), rand.Reader, size)
	require.NoError(t, err)

	_, err = out.Seek(0, 0)
	require.NoError(t, err)

	return out, fmt.Sprintf("%x", h.Sum(nil))
}

func hashOfReader(r io.Reader) string {
	h := sha512.New()
	_, _ = io.Copy(h, r)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func TestOpenFile(t *testing.T) {
	var fileSize int64 = 32*1024*3 + 7
	file, hash := createFile(t, fileSize) // that's 3 default io.Copy buffer + some nice number to make it less aligned

	now := time.Now().UTC()
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		r.BasicAuth()
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%v`, file.Name()))
		http.ServeContent(w, r, file.Name(), now, file)
	})
	t.Cleanup(srv.Close)

	clt := newC(srv.URL, "v1", BasicAuth("user", "pass"))
	reader, err := clt.OpenFile(context.Background(), clt.Endpoint("download"), url.Values{})
	require.NoError(t, err)
	require.Equal(t, hash, hashOfReader(reader))

	// seek and read again
	_, err = reader.Seek(0, 0)
	require.NoError(t, err)
	require.Equal(t, hash, hashOfReader(reader))

	// seek to half size, concat and test resulting hash
	buf := &bytes.Buffer{}
	_, err = reader.Seek(0, 0)
	require.NoError(t, err)

	_, err = io.Copy(buf, io.LimitReader(reader, fileSize/2))
	require.NoError(t, err)

	_, err = reader.Seek(fileSize/2, 0)
	require.NoError(t, err)

	_, err = io.Copy(buf, reader)
	require.NoError(t, err)
	require.Equal(t, hash, hashOfReader(buf))

	// make sure that double close does not result in error
	require.NoError(t, reader.Close())
	require.NoError(t, reader.Close())
}

func TestReplyNotFound(t *testing.T) {
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		ReplyJSON(w, http.StatusNotFound, map[string]interface{}{"msg": "not found"})
	})
	t.Cleanup(srv.Close)

	clt := newC(srv.URL, "v1")
	re, err := clt.Get(context.Background(), clt.Endpoint("a"), url.Values{})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, re.Code())
	require.Equal(t, "application/json", re.Headers().Get("Content-Type"))
}

func TestCustomClientTimesOut(t *testing.T) {
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
	})
	t.Cleanup(srv.Close)

	clt, err := NewClient(srv.URL, "v1", HTTPClient(&http.Client{Timeout: time.Millisecond}))
	require.NoError(t, err)

	_, err = clt.Get(context.Background(), clt.Endpoint("a"), url.Values{})
	require.Error(t, err)
}

func TestPostMultipartForm(t *testing.T) {
	files := []File{
		{
			Name:     "a",
			Filename: "a.json",
			Reader:   strings.NewReader("file 1"),
		},
		{
			Name:     "a",
			Filename: "b.json",
			Reader:   strings.NewReader("file 2"),
		},
	}
	expected := [][]byte{[]byte("file 1"), []byte("file 2")}
	testPostMultipartForm(t, files, expected)
}

func TestPostMultipartFormLargeFile(t *testing.T) {
	buffer := make([]byte, 1024<<10)
	rand.Read(buffer)
	files := []File{
		{
			Name:     "a",
			Filename: "a.json",
			Reader:   strings.NewReader("file 1"),
		},
		{
			Name:     "a",
			Filename: "b.json",
			Reader:   strings.NewReader("file 2"),
		},
		{
			Name:     "a",
			Filename: "c",
			Reader:   bytes.NewReader(buffer),
		},
	}
	expected := [][]byte{[]byte("file 1"), []byte("file 2"), buffer}
	testPostMultipartForm(t, files, expected)
}

func testPostMultipartForm(t *testing.T, files []File, expected [][]byte) {
	t.Helper()

	var u *url.URL
	var params url.Values
	var method string
	var data [][]byte
	var user, pass string

	ch := make(chan error, 100)
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		defer close(ch)
		user, pass, _ = r.BasicAuth()

		u = r.URL
		if err := r.ParseMultipartForm(64 << 20); err != nil {
			ch <- fmt.Errorf("ParseMultipartForm: %w", err)
			return
		}

		params = r.Form
		method = r.Method

		if r.MultipartForm == nil || len(r.MultipartForm.File["a"]) == 0 {
			ch <- errors.New("multipart form is empty")
			return
		}

		fhs := r.MultipartForm.File["a"]
		for _, fh := range fhs {
			f, err := fh.Open()
			if err != nil {
				ch <- fmt.Errorf("fh.Open: %w", err)
				return
			}
			val, err := io.ReadAll(f)
			if err != nil {
				ch <- fmt.Errorf("io.ReadAll: %w", err)
				return
			}

			data = append(data, val)
		}

		io.WriteString(w, "hello back")

	})
	t.Cleanup(srv.Close)

	clt := newC(srv.URL, "v1", BasicAuth("user", "pass"))
	values := url.Values{"a": []string{"b"}}
	out, err := clt.PostForm(
		context.Background(),
		clt.Endpoint("a", "b"),
		values,
		files...,
	)

	require.NoError(t, err)

	for err := range ch {
		require.NoError(t, err)
	}

	require.Equal(t, "hello back", string(out.Bytes()))
	require.Equal(t, "/v1/a/b", u.String())

	require.Equal(t, http.MethodPost, method)
	require.Equal(t, values, params)
	require.Equal(t, expected, data)

	require.Equal(t, "user", user)
	require.Equal(t, "pass", pass)
}

func TestGetBasicAuth(t *testing.T) {
	var user, pass string
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ = r.BasicAuth()
	})
	t.Cleanup(srv.Close)

	clt := newC(srv.URL, "v1", BasicAuth("user", "pass"))
	_, err := clt.Get(context.Background(), clt.Endpoint("a", "b"), url.Values{})
	require.NoError(t, err)
	require.Equal(t, "user", user)
	require.Equal(t, "pass", pass)
}

func TestCookies(t *testing.T) {
	var capturedRequestCookies []*http.Cookie
	responseCookies := []*http.Cookie{
		{
			Name:  "session",
			Value: "howdy",
			Path:  "/",
		},
	}
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		capturedRequestCookies = r.Cookies()
		for _, c := range responseCookies {
			http.SetCookie(w, c)
		}
	})
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	clt := newC(srv.URL, "v1", CookieJar(jar))

	requestCookies := []*http.Cookie{
		{
			Name:  "hello",
			Value: "here?",
			Path:  "/",
		},
	}
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	jar.SetCookies(u, requestCookies)

	re, err := clt.Get(context.Background(), clt.Endpoint("test"), url.Values{})
	require.NoError(t, err)

	require.Len(t, capturedRequestCookies, len(requestCookies))
	require.Equal(t, requestCookies[0].Name, capturedRequestCookies[0].Name)
	require.Equal(t, requestCookies[0].Value, capturedRequestCookies[0].Value)

	require.Len(t, re.Cookies(), len(responseCookies))
	require.Equal(t, responseCookies[0].Name, re.Cookies()[0].Name)
	require.Equal(t, responseCookies[0].Value, re.Cookies()[0].Value)
}

func TestEndpoint(t *testing.T) {
	client := newC("http://localhost", "v1")
	require.Equal(t, "http://localhost/v1/api/resource", client.Endpoint("api", "resource"))

	client = newC("http://localhost", "")
	require.Equal(t, "http://localhost/api/resource", client.Endpoint("api", "resource"))
}

func TestLimitsWrites(t *testing.T) {
	var buf bytes.Buffer
	w := &limitWriter{&buf, 10}
	input := []byte("The quick brown fox jumps over the lazy dog")
	r := bytes.NewReader(input)
	_, err := io.Copy(w, r)
	require.Equal(t, errShortWrite, err)
	require.Equal(t, input[:10], buf.Bytes())

	out, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, input[10:], out)
}

func TestContext(t *testing.T) {
	// Create a server that blocks for a second before responding.
	srv := serveHandler(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second)
		io.WriteString(w, "hello back")
	})
	t.Cleanup(srv.Close)

	// Create a context that times out after 100 ms.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Make sure the request is canceled due to the context.
	clt := newC(srv.URL, "v1", BasicAuth("user", "pass"))
	_, err := clt.PostJSON(ctx, clt.Endpoint("a", "b"), nil)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func newC(addr, version string, params ...ClientParam) *Client {
	c, err := NewClient(addr, version, params...)
	if err != nil {
		panic(err)
	}
	return c
}

func serveHandler(f http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(f))
}
