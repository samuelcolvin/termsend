COMMIT=$(shell git rev-parse HEAD)
BUILD_TIME=$(shell date)

build:
	docker build termsend -t termsend --build-arg COMMIT=$(COMMIT) --build-arg BUILD_TIME="$(BUILD_TIME)"
