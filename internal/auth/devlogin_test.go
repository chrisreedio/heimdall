// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !dev

package auth

import (
	"reflect"
	"testing"
)

// The passwordless dev sign-in must not exist in release builds.
func TestNoDevLoginInReleaseBuilds(t *testing.T) {
	if _, ok := reflect.TypeOf(&Service{}).MethodByName("DevLogin"); ok {
		t.Fatal("DevLogin is compiled into a non-dev build")
	}
}
