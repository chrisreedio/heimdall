VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Static, reproducible-leaning build: no cgo, no local paths, no build ID.
export CGO_ENABLED := 0
GOFLAGS := -trimpath -mod=vendor
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)

# Dev tools run at pinned versions and never enter go.mod or the binary.
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.2
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.9.0

.PHONY: build test fmt vet lint vuln check vendor clean shellcheck test-collector test-versions dist reproducible

build:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/heimdall ./cmd/heimdall

test:
	go test -mod=vendor ./...

fmt:
	@out=$$(gofmt -l cmd internal deploy); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet -mod=vendor ./...

lint:
	go run $(STATICCHECK) ./...

vuln:
	go run $(GOVULNCHECK) ./...

check: fmt vet lint vuln test

# Collector checks need Docker.
SHELLCHECK_IMAGE := koalaman/shellcheck:v0.10.0
COLLECTOR_OUT ?= $(CURDIR)/bin/collector-out

shellcheck:
	docker run --rm -v "$(CURDIR)/collector:/mnt:ro" $(SHELLCHECK_IMAGE) -s sh /mnt/collect.sh /mnt/privilege-watch.sh /mnt/privilege-hook /mnt/login-watch.sh /mnt/test/run-containers.sh /mnt/test/sites-fixture.sh

# Runs collect.sh as an unprivileged user on Debian, Ubuntu, Rocky and
# Alpine, then validates every snapshot with the hub's strict decoder.
test-collector: shellcheck
	rm -rf "$(COLLECTOR_OUT)"
	collector/test/run-containers.sh "$(COLLECTOR_OUT)"
	HEIMDALL_COLLECTOR_OUT="$(COLLECTOR_OUT)" go test -mod=vendor -count=1 -run 'TestCollectorOutput|TestCollectorSites|TestCollectorSiteRepos' -v ./internal/snapshot

# Run after changing dependencies; review the vendor/ diff before committing.
vendor:
	go mod tidy
	go mod verify
	go mod vendor

# Re-derive the version comparison answers from dpkg, rpm and apk
# themselves, then check the Go ports against them.
test-versions:
	internal/version/testdata/expect.sh
	go test -mod=vendor -count=1 ./internal/version

# Builds the hub twice from clean caches and checks the binaries match
# byte for byte (pinned toolchain via go.mod, -trimpath, no build ID).
reproducible:
	rm -rf bin/repro && mkdir -p bin/repro
	# Two clean builds at once, each with its own empty cache.
	GOCACHE=$$(mktemp -d) go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/repro/a ./cmd/heimdall & a=$$!; \
	GOCACHE=$$(mktemp -d) go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/repro/b ./cmd/heimdall & b=$$!; \
	wait $$a && wait $$b
	cmp bin/repro/a bin/repro/b && echo "reproducible: $$(sha256sum bin/repro/a | cut -d' ' -f1)"

# Release artifacts: static hub binaries, the collector, deploy files and
# SHA256SUMS. Servers verify collect.sh against SHA256SUMS before installing.
dist:
	rm -rf dist && mkdir -p dist
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/heimdall-linux-amd64 ./cmd/heimdall & a=$$!; \
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o dist/heimdall-linux-arm64 ./cmd/heimdall & b=$$!; \
	wait $$a && wait $$b
	cp collector/collect.sh collector/collect.ps1 collector/install-windows.ps1 collector/privilege-watch.sh collector/privilege-hook collector/login-watch.sh deploy/heimdall.service deploy/heimdall-collect.service \
		deploy/heimdall-collect.timer deploy/heimdall-collect-boot.timer deploy/heimdall-collect-soon.timer deploy/heimdall-collect-changes.service \
		deploy/heimdall-collect-changes.path deploy/collect.env.example deploy/splash.html dist/
	sed 's/^HEIMDALL_VERSION=dev /HEIMDALL_VERSION=$(VERSION) /' collector/install.sh > dist/install.sh
	sed 's/^HEIMDALL_VERSION=dev /HEIMDALL_VERSION=$(VERSION) /' deploy/install-hub.sh > dist/install-hub.sh
	cd dist && sha256sum * > SHA256SUMS && cat SHA256SUMS

clean:
	rm -rf bin dist
