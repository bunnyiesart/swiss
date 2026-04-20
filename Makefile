IMAGE := swiss

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
	    -v "$(CURDIR)/config.json:/app/config.json:ro" \
	    --env-file "$(CURDIR)/.env" \
	    $(IMAGE)
