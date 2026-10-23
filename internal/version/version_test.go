// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestAgainstRealTools checks every pair in testdata/expected-*.txt, whose
// answers come from dpkg, rpm and apk themselves (testdata/expect.sh).
func TestAgainstRealTools(t *testing.T) {
	for _, scheme := range []Scheme{Dpkg, RPM, APK} {
		t.Run(string(scheme), func(t *testing.T) {
			f, err := os.Open("testdata/expected-" + string(scheme) + ".txt")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			n := 0
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				fields := strings.Fields(sc.Text())
				if len(fields) != 3 {
					t.Fatalf("bad line %q", sc.Text())
				}
				want, _ := strconv.Atoi(fields[2])
				got, _ := Compare(scheme, fields[0], fields[1])
				if got != want {
					t.Errorf("%s: compare(%q, %q) = %d, want %d", scheme, fields[0], fields[1], got, want)
				}
				n++
			}
			if n < 100 {
				t.Fatalf("only %d cases; regenerate with testdata/expect.sh", n)
			}
		})
	}
}

// Properties every comparator must have, whatever the input.
func TestAntisymmetry(t *testing.T) {
	inputs := []string{"", "1", "1.0", "1:1.0", "1.0~rc1", "1.0^git", "1.0-r1", "1.0_rc1", "a", "~", "-", "1..0", "0:0", ":"}
	for _, scheme := range []Scheme{Dpkg, RPM, APK} {
		for _, a := range inputs {
			for _, b := range inputs {
				ab, _ := Compare(scheme, a, b)
				ba, _ := Compare(scheme, b, a)
				if ab != -ba {
					t.Errorf("%s: compare(%q,%q)=%d but compare(%q,%q)=%d", scheme, a, b, ab, b, a, ba)
				}
			}
		}
	}
}

func FuzzCompare(f *testing.F) {
	f.Add("1.0~rc1-1", "1:1.0-1")
	f.Add("1.0^git1-1.el9", "1.0-2")
	f.Add("1.2.3_rc1-r0", "1.2.3-r1")
	f.Fuzz(func(t *testing.T, a, b string) {
		for _, scheme := range []Scheme{Dpkg, RPM, APK} {
			ab, _ := Compare(scheme, a, b)
			ba, _ := Compare(scheme, b, a)
			if ab != -ba {
				t.Fatalf("%s: not antisymmetric for %q, %q", scheme, a, b)
			}
			if aa, _ := Compare(scheme, a, a); aa != 0 {
				t.Fatalf("%s: compare(%q, %q) = %d", scheme, a, a, aa)
			}
		}
	})
}
