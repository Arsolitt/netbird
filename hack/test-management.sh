#!/bin/sh
# Run the netbird management test suites the way CI does, but against the
# local Docker daemon (OrbStack on macOS). The suites run inside a
# golang:1.26 container as root — the same privileges the CI jobs get via
# `-exec sudo` — and the Docker socket is mounted so the postgres/mysql
# store variants can start their database containers as siblings.
#
# CI (golang-test-linux.yml) runs these suites on sqlite only: the other
# stores pull database images from Docker Hub, and anonymous pulls from
# GitHub shared runners are rate-limited. Run the full matrix here before
# rebasing onto upstream.
#
# Usage:
#   hack/test-management.sh unit sqlite                 # CI parity
#   hack/test-management.sh unit all                    # sqlite, postgres, mysql
#   hack/test-management.sh benchmark sqlite
#   hack/test-management.sh api-benchmark sqlite
#   hack/test-management.sh integration sqlite
#   hack/test-management.sh unit postgres -run TestGroup -count=1   # extra go test flags pass through
set -eu

usage() {
	sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
}

[ $# -ge 1 ] || usage
suite=$1
store=${2:-sqlite}
shift 2 2>/dev/null || shift $#

case $suite in
unit)
	command='go test -tags=devcert -timeout 20m ./management/... ./shared/management/...'
	;;
benchmark)
	# The HTTP handlers are benchmarked separately (api-benchmark); see the
	# CI job this mirrors.
	command='go test -tags=devcert -run=^$ -bench=. -timeout 20m ./management/... ./shared/management/... $(go list ./management/... ./shared/management/... | grep -v -e /management/server/http)'
	;;
api-benchmark)
	command='go test -tags=benchmark -run=^$ -bench=. -timeout 20m ./management/server/http/...'
	;;
integration)
	command='go run github.com/magefile/mage/mage@latest integrationtest:all -gotestflags="-timeout 20m"'
	;;
*)
	usage
	;;
esac

[ $# -gt 0 ] && command="$command $*"

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
modcache=$(go env GOMODCACHE)
image=golang:1.26

run_store() {
	echo "==> $suite [$1]"
	docker run --rm \
		-v "$root":/src -w /src \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v "$modcache":/go/pkg/mod \
		-v netbird-fork-gocache:/root/.cache/go-build \
		-e CGO_ENABLED=1 -e CI=true -e NETBIRD_STORE_ENGINE="$1" \
		"$image" sh -c "$command"
}

case $store in
sqlite | postgres | mysql)
	run_store "$store"
	;;
all)
	for s in sqlite postgres mysql; do
		run_store "$s"
	done
	;;
*)
	usage
	;;
esac
