SHELL := /bin/bash
.PHONY = usage

ROOT_DIR := $(shell pwd)
PROJECT_NAME="cert_epsilon"


usage:
	@echo -e \
		"Usage: \n"\
		"make pypack          - install all python needed packages\n"\
		"make initial_data    - fill tables with initial data(takes some time)\n"\
		"make apt             - install needed system packages\n"\
		"make locale_gather   - runs babel to gather translation strings\n"\
		"make locale_compile  - runs babel to compile strings\n"\
		"make locale_update   - runs babel to update strings(use if you change strings)\n"\
		"make service         - creates cert epsilon as service behind nginx\n"\
		"make run-minimal     - runs cert epsilon (minimal server)\n"\
		"make run             - runs cert epsilon (as service behind nginx)\n"\
		"make run-tests 	  - runs tests\n"\
		
pypack:
	@bash -c "cd ${ROOT_DIR} && sudo apt-get install libpq-dev  && pip install -r requirements.txt";

initial_data:
	@bash -c "\
			cd ${ROOT_DIR}/cert_epsilon/bin && \
			python3 cwe.py && \
			python3 capec.py && \
			python3 cve.py\
		"

apt:
	sudo apt install nginx python3 python3-babel python3-venv postgresql

locale_gather:
	pybabel extract -F ${ROOT_DIR}/babel.cfg -o ${ROOT_DIR}/$(PROJECT_NAME)/static/localization/messages.pot .

locale_compile:
	pybabel compile -d ${ROOT_DIR}/$(PROJECT_NAME)/static/localization/translations

locale_update:
	pybabel update -i ${ROOT_DIR}/$(PROJECT_NAME)/static/localization/messages.pot -d ${ROOT_DIR}/$(PROJECT_NAME)/static/localization/translations

service:
	sudo cp ./$(PROJECT_NAME).service /etc/systemd/system;
	sudo cp ./$(PROJECT_NAME).conf /etc/nginx/sites-available;
	sudo ln -s /etc/nginx/sites-available/$(PROJECT_NAME).conf /etc/nginx/sites-enabled;
	sudo systemctl daemon-reload;

run-minimal:
	uwsgi --ini $(PROJECT_NAME).ini

run:
	sudo systemctl start $(PROJECT_NAME).service;
	sudo systemctl start nginx.service;
	sudo nginx -s reload;

run-tests:
	pytest -c pytest.ini --capture=tee-sys --cov-config=.coveragerc --cov=cert_epsilon tests/

html-report:
	pytest -c pytest.ini --capture=tee-sys --cov-report=html:report --cov-config=.coveragerc --cov=cert_epsilon tests/

clean:
	rm -rf report/
