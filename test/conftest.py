import json
from collections import OrderedDict

import pytest

from fuzzerest.cli import Client
from fuzzerest.config.config import Config
from fuzzerest.mutator import Mutator


@pytest.fixture(scope="session")
def config():
    return Config()


@pytest.fixture(scope="session")
def client():
    return Client()


@pytest.fixture(scope="session")
def mutator(config):
    return Mutator(config.fuzz_db_array)


@pytest.fixture(scope="session")
def model(config):
    with open(config.example_model_file, "r") as model_file:
        return json.loads(model_file.read(), object_pairs_hook=OrderedDict)
