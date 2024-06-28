docker_build:
	docker build -t simple .

docker_run:
	docker run -p 8080:8080 simple
