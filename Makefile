.PHONY: build run clean test help

PROJECT_NAME = netid
IMAGE_NAME = netid-runner

build:
	docker build -t ${IMAGE_NAME} .

run:
	docker run --rm ${IMAGE_NAME} $(INPUT)

clean:
	docker rmi ${IMAGE_NAME} || true

test: build
	@echo "=== Testing Indonesian TLD ==="
	@./run.sh tokopedia.co.id && echo "PASS" || echo "FAIL"
	@echo ""
	@echo "=== Testing non-Indonesian ==="
	@./run.sh google.com && echo "FAIL" || echo "PASS"
	@echo ""
	@echo "=== Testing US target ==="
	@./run.sh google.com --target us && echo "PASS" || echo "FAIL"

help:
	@echo "netid - Network Identity Lookup"
	@echo ""
	@echo "Targets:"
	@echo "  make build    - Build Docker image"
	@echo "  make run      - Run with INPUT=example.com"
	@echo "  make clean    - Remove Docker image"
	@echo "  make test     - Run tests"
	@echo ""
	@echo "Examples:"
	@echo "  make run INPUT=tokopedia.co.id"
	@echo "  make run INPUT=google.com TARGETS=us"
