IMAGE  := swiss
CONFIG ?= $(HOME)/.config/swiss/config.json

.PHONY: build test run

build:
	docker build -t $(IMAGE) .

test: build
	docker run --rm \
	    -v "$(CURDIR)/tests:/app/tests" \
	    --entrypoint python3 \
	    $(IMAGE) -m pytest tests/ -v

run: build
	docker run --rm -i \
	    -v "$(CONFIG):/config/swiss.json:ro" \
	    -e SWISS_CONFIG_PATH=/config/swiss.json \
	    $(IMAGE)
