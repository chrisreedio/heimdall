// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build race

package store

// raceOn is whether the race detector is on: it slows SQLite-heavy tests
// tens of times over, so scale tests run smaller under it.
const raceOn = true
