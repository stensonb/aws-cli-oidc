#!/bin/zsh

GITHUB_TOKEN=$(security find-generic-password -w -a ${USER} -D "application password" -s "github_goreleaser_token") goreleaser release
