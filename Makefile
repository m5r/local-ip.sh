FLY_CONFIG ?= fly.staging.toml

# The project is what git sees: tracked files plus untracked files that are not ignored.
# Listing them explicitly keeps ignored scratch directories in a checkout from breaking the build.
GIT_GO_FILES = git ls-files --cached --others --exclude-standard -- '*.go'
GO_FILES := $(wildcard $(shell $(GIT_GO_FILES) 2>/dev/null))
GO_PACKAGES := $(sort $(dir $(addprefix ./,$(GO_FILES))))

.PHONY: check e2e

# Make and the shell split the file list on whitespace and expand special characters, so a path
# outside the plain alphabet below would be skipped silently instead of being checked.
check:
	$(if $(GO_FILES),,$(error no Go files found: "make check" must run inside a git checkout))
	@unsafe="$$($(GIT_GO_FILES) | LC_ALL=C grep -vx '[A-Za-z0-9_./-]*')"; \
	if [ -n "$$unsafe" ]; then \
		echo "Go file paths may only contain ASCII letters, digits, '.', '_', '-' and '/':" >&2; \
		echo "$$unsafe" >&2; \
		exit 1; \
	fi
	@unformatted="$$(gofmt -l $(GO_FILES))" || exit $$?; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:" >&2; \
		echo "$$unformatted" >&2; \
		exit 1; \
	fi
	go vet $(GO_PACKAGES)
	go test -race $(GO_PACKAGES)

# The suite is skipped when E2E_FLY_CONFIG is not set, so a config path that is missing or cannot
# be resolved must fail here rather than turn into a run that tested nothing.
#
# Every network call in the suite has its own deadline, so a run always ends. The timeout is only a
# backstop against a hang: go test's default of ten minutes would cut a slow run against a degraded
# target short with a panic instead of a report.
e2e:
	@test -f "$(FLY_CONFIG)" || { echo "Fly config not found: $(FLY_CONFIG)" >&2; exit 1; }
	@config="$$(realpath -- "$(FLY_CONFIG)")" && test -n "$$config" \
		|| { echo "Cannot resolve the path of $(FLY_CONFIG)" >&2; exit 1; }; \
	E2E_FLY_CONFIG="$$config" go test ./e2e -run '^TestLive$$' -count=1 -v -timeout 1h
