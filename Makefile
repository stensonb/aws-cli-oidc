VERSION := v0.8.0

.PHONY: build
build:
	goreleaser build --clean --auto-snapshot

.PHONY: release
release:
	git tag $(VERSION)
	git push origin $(VERSION)
	./scripts/release.sh
