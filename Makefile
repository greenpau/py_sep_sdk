.PHONY: test package pytest pylinttest clean

export USER
PKG_NAME=py_sep_sdk
PKG_NAME_EGG:=$(subst -,_,$(PKG_NAME))
PKG_VERSION:=$(shell cat VERSION | head -1)
GIT_COMMIT:=$(shell git describe --dirty --always)
GIT_BRANCH:=$(shell git rev-parse --abbrev-ref HEAD -- | head -1)
BUILD_USER:=$(shell whoami)
BUILD_DATE:=$(shell date +"%Y-%m-%d")
export PYTHONPATH:=$(shell pwd):$(shell pwd)/$(PKG_NAME):$(PATH)

all:
	@echo "Version: $(PKG_VERSION), Branch: $(GIT_BRANCH), Revision: $(GIT_COMMIT)"
	@echo "Build on $(BUILD_DATE) by $(BUILD_USER)"
	@echo 'the only available options are: test, package, and clean' || false

pylinttest:
	@pylint setup.py
	@pylint $(PKG_NAME)/*.py
	@pylint tests/test_*.py
	@pylint scripts/symc-sep-client

pytest:
	@python tests/test_suite.py

test: pytest pylinttest
	@echo "OK"

clean:
	@find . -name \*.pyc -delete
	@rm -rf dist/

package:
	@sed -i 's/PKG_VERSION =.*/PKG_VERSION = \x27${PKG_VERSION}\x27/' setup.py
	@pandoc --from=markdown --to=rst --output=${PKG_NAME}/README.rst README.md
	@sed -i 's/:arrow._up: //' ${PKG_NAME}/README.rst
	@cp LICENSE ${PKG_NAME}/LICENSE.txt
	@rm -rf dist/
	@python setup.py sdist
	@rm -rf ${PKG_NAME_EGG}.egg-info *.egg build/
	@find . -name \*.pyc -delete
	@tar -tvf dist/${PKG_NAME}-${PKG_VERSION}.tar.gz
