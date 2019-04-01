#!/bin/bash

pushd "${VIRTUAL_ENV}" > /dev/null

python -m pylint --rcfile=pylintrc keyper
python -m mypy --ignore-missing-imports keyper/

python -m pylint --rcfile=pylintrc tests
python -m mypy --ignore-missing-imports tests/

popd > /dev/null

