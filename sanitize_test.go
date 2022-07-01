/*
Copyright 2018 Gravitational, Inc.

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
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizePath(t *testing.T) {
	for _, test := range []struct {
		inPath string
		assert require.ErrorAssertionFunc
	}{
		{
			inPath: "http://example.com:3080/hello",
			assert: require.NoError,
		},
		{
			inPath: "http://example.com:3080/hello/../world",
			assert: require.Error,
		},
		{
			inPath: fmt.Sprintf("http://localhost:3080/hello/%v/goodbye", url.PathEscape("..")),
			assert: require.Error,
		},
		{
			inPath: "http://example.com:3080/hello?foo=..",
			assert: require.NoError,
		},
		{
			inPath: "http://example.com:3080/a+b",
			assert: require.NoError,
		},
	} {
		t.Run(test.inPath, func(t *testing.T) {
			test.assert(t, isPathSafe(test.inPath))
		})
	}
}
