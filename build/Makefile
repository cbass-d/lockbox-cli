BIN=../virtual_env/bin

build:
	@python3 -m venv ../virtual_env
	@$(BIN)/python3 -m pip install --upgrade pip; $(BIN)/python3 -m pip install -r ./requirements.txt

reqs:
	@$(BIN)/pip freeze > requirements.txt
