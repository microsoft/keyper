#!/bin/bash

pushd "${VIRTUAL_ENV}/.." > /dev/null

python -m black --line-length 100 keyper tests
python -m pylint --rcfile=pylintrc keyper tests
python -m mypy --ignore-missing-imports keyper/ tests/

popd > /dev/null

