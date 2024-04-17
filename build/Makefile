build:
	@python3 -m venv ../virtual_env
	@make activate; python3 -m pip install --upgrade pip; python3 -m pip install -r ./requirements.txt

activate:
	@. ../virtual_env/bin/activate

reqs:
	@make activate; pip freeze > requirements.txt
