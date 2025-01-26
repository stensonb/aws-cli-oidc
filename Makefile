VERSION := v0.7.0

.PHONY: build
build:
	goreleaser build --clean --auto-snapshot

.PHONY: release
release:
	git tag $(VERSION)
	git push origin $(VERSION)
	./scripts/release.sh