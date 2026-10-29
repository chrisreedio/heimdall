// SPDX-License-Identifier: AGPL-3.0-or-later

package clientonly

import (
	"maps"
	"testing"
)

func TestSources(t *testing.T) {
	for _, c := range []struct {
		name string
		pkgs []Package
		want map[string]string
	}{
		{"bind9 clients only",
			[]Package{{"bind9-host", "bind9"}, {"bind9-dnsutils", "bind9"}, {"bind9-libs", "bind9"}},
			map[string]string{"bind9": "bind9"}},
		{"bind9 server", []Package{{"bind9-libs", "bind9"}, {"bind9", ""}}, map[string]string{}},
		{"postgres client", []Package{{"postgresql-client-16", "postgresql-16"}, {"libpq5", "postgresql-17"}},
			map[string]string{"postgresql-16": "postgresql-16", "postgresql-17": "postgresql-17"}},
		{"postgres server", []Package{{"postgresql-16", ""}, {"postgresql-client-16", "postgresql-16"}}, map[string]string{}},
		{"mysql server", []Package{{"mysql-client-8.0", "mysql-8.0"}, {"mysql-server-core-8.0", "mysql-8.0"}}, map[string]string{}},
		{"mariadb client", []Package{{"mariadb-client", "mariadb"}, {"libmariadb3", "mariadb"}}, map[string]string{"mariadb": "mariadb-server"}},
		{"mariadb server", []Package{{"mariadb-client", "mariadb"}, {"mariadb-server-core", "mariadb"}}, map[string]string{}},
		{"mysql client", []Package{{"mysql-client-8.0", "mysql-8.0"}, {"libmysqlclient21", "mysql-8.0"}},
			map[string]string{"mysql-8.0": "mysql-server"}},
		{"ssh client", []Package{{"openssh-client", "openssh"}}, map[string]string{"openssh": "openssh-server"}},
		{"ssh server", []Package{{"openssh-client", "openssh"}, {"openssh-server", "openssh"}}, map[string]string{}},
		{"not a rule", []Package{{"curl", ""}, {"libcurl4", "curl"}}, map[string]string{}},
	} {
		if got := Sources(c.pkgs); !maps.Equal(got, c.want) {
			t.Errorf("%s: Sources = %v, want %v", c.name, got, c.want)
		}
	}
}
