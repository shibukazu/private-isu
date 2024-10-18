.PHONY: init migrate bench
init: webapp/sql/dump.sql.bz2 benchmarker/userdata/img

webapp/sql/dump.sql.bz2:
	cd webapp/sql && \
	curl -L -O https://github.com/catatsuy/private-isu/releases/download/img/dump.sql.bz2

benchmarker/userdata/img.zip:
	cd benchmarker/userdata && \
	curl -L -O https://github.com/catatsuy/private-isu/releases/download/img/img.zip

benchmarker/userdata/img: benchmarker/userdata/img.zip
	cd benchmarker/userdata && \
	unzip -qq -o img.zip

migrate:
	migrate -path webapp/migration -database "mysql://root:root@tcp(localhost:3306)/isuconp" up

bench:
	rm -rf webapp/log/** && \
	rm -rf webapp/public/image/** && \
	cd webapp && \
	docker compose restart mysql nginx && \
	while [ "`docker inspect -f '{{.State.Health.Status}}' private-isu-mysql-1`" != "healthy" ]; do \
		echo "Waiting for MySQL to be healthy..."; \
		sleep 2; \
	done && \
	while [ "`docker inspect -f '{{.State.Health.Status}}' private-isu-nginx-1`" != "healthy" ]; do \
		echo "Waiting for Nginx to be healthy..."; \
		sleep 2; \
	done && \
	cd ../ && \
	cd benchmarker && \
	docker build -t private-isu-benchmarker . && \
	docker run --network host -i private-isu-benchmarker /bin/benchmarker -t http://host.docker.internal -u /opt/userdata | tee result.json && \
	cd ../ && \
	TIMESTAMP=`date +"%Y%m%d%H%M%S"` && \
	mkdir -p webapp/result/$$TIMESTAMP && \
	mv benchmarker/result.json webapp/result/$$TIMESTAMP/ && \
	mkdir -p webapp/result/$$TIMESTAMP/log/mysql webapp/result/$$TIMESTAMP/log/nginx && \
	cp webapp/log/mysql/slow.log webapp/result/$$TIMESTAMP/log/mysql/ && \
	cp webapp/log/nginx/access.log webapp/result/$$TIMESTAMP/log/nginx/ && \
	cp webapp/log/nginx/error.log webapp/result/$$TIMESTAMP/log/nginx/ && \
	alp json --sort sum -r -m "/posts/[0-9]+,/@\w+,/image/\d+" -o count,method,uri,min,avg,max,sum < webapp/result/$$TIMESTAMP/log/nginx/access.log > webapp/result/$$TIMESTAMP/log/nginx/alp.log && \
	pt-query-digest webapp/result/$$TIMESTAMP/log/mysql/slow.log > webapp/result/$$TIMESTAMP/log/mysql/pt-query-digest.log