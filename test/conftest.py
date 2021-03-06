import json
from collections import OrderedDict

import pytest

from fuzzerest.cli import Client
from fuzzerest.config.config import Config
from fuzzerest.mutator import Mutator


@pytest.fixture(scope="session")
def config():
    return Config("test")


@pytest.fixture(scope="session")
def client(config):
    return Client(config)


@pytest.fixture(scope="session")
def mutator(config):
    return Mutator(config)


@pytest.fixture(scope="session")
def model(config):
    with open(config.model_file, "r") as model_file:
        return json.loads(model_file.read(), object_pairs_hook=OrderedDict)
