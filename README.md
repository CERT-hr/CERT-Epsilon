# CERT EPSILON

### To run
* `sudo adduser epsilon` (remember password, default rest)
* `sudo usermod -aG sudo epsilon`
* `su - epsilon`
* `sudo apt install git -y`
* `git clone ssh://vcs@phabricator.razus.carnet.hr/source/cert_epsilon.git`
* `cd cert_epsilon`
* `make apt`
* `python3 -m venv env`
* `source env/bin/activate`
* `mv env.sample .env && mv test.env.sample .test.env`
* **UPDATE YOUR .ENV AND .TEST.ENV VARIABLES!**
* `make pypack`
* `make locale_gather`
* `make locale_compile`
* `make service`
* `make run` (or `make run-minimal` if you dont want to run it as a service)


#### Database and populating the initial data
* `su - postgres`
* `\psql`
* `\i /path/to/build_database.sql`
* change postgres password `ALTER USER postgres with password 'YourNewPassword';`
* `\q`   # exit \psql
* `exit` # go back to initial user
* `cd cert/epsilon/root/`
* `make initial_data` # this will take some time. Relation errors will happen cause of cwe/capec/cve complexity, but its normal



#### Note
if you update local strings you can run `make locale_update` to update .mo files

