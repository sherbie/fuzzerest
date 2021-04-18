import json
import os.path
from pathlib import Path

import pytest
import yaml

from fuzzerest.schema import validation
from fuzzerest.schema.validation import ValidationError


@pytest.mark.kwparametrize(
    dict(
        schema_object={
            "id": {
                "type": "string",
                "required": True,
            },
            "name": {
                "type": "string",
                "required": False,
            },
        }
    ),
)
@pytest.mark.kwparametrize(
    dict(
        input_object={
            "id": "test",
        },
        strict=True,
        should_pass=True,
    ),
    dict(
        input_object={
            "name": "test",
        },
        strict=False,
        should_pass=False,
    ),
    dict(
        input_object={
            "id": "test",
            "name": "test",
            "test": "test",
        },
        strict=True,
        should_pass=False,
    ),
)
@pytest.mark.kwparametrize(
    dict(
        raise_on_error=False,
    ),
    dict(
        raise_on_error=True,
    ),
)
def test_validate_object_against_schema(
    schema_object, input_object, strict, raise_on_error, should_pass
):
    if raise_on_error and not should_pass:
        with pytest.raises(ValidationError):
            validation.validate_object_against_schema(
                input_object=input_object,
                schema_object=schema_object,
                raise_on_error=raise_on_error,
                strict=strict,
            )
    else:
        status = validation.validate_object_against_schema(
            input_object=input_object,
            schema_object=schema_object,
            raise_on_error=raise_on_error,
            strict=strict,
        )

        assert status.ok if should_pass else not status.ok
        assert status.errors if not should_pass else not status.errors


def test_validate_default_expectations(config):

    with open(config.expectations_path, "r") as f:
        default_expectations = json.load(f)

    with open(config.expectations_schema_path, "r") as handle:
        expectations_schema = yaml.load(handle, Loader=yaml.FullLoader)

    validation.validate_object_against_schema(
        input_object=default_expectations,
        schema_object=expectations_schema,
        raise_on_error=True,
        strict=True,
    )


@pytest.mark.kwparametrize(
    dict(model_file_name="../fuzzerest/models/template.json"),
    dict(model_file_name="../fuzzerest/models/tutorial.json"),
    dict(model_file_name="example_expectations.json"),
)
def test_validate_expectations(config, model_file_name):
    with open(Path(os.path.dirname(__file__)) / model_file_name) as f:
        model = json.load(f)

    with open(config.expectations_schema_path) as f:
        expectations_schema = yaml.load(f, Loader=yaml.FullLoader)

    if model.get("expectations"):
        validation.validate_object_against_schema(
            input_object=model,
            schema_object=expectations_schema,
            raise_on_error=True,
            strict=False,
        )

    for endpoint in model.get("endpoints"):
        if endpoint.get("expectations"):
            validation.validate_object_against_schema(
                input_object=endpoint,
                schema_object=expectations_schema,
                raise_on_error=True,
                strict=False,
            )


@pytest.mark.kwparametrize(
    dict(model_file_name="../fuzzerest/models/template.json"),
    dict(model_file_name="../fuzzerest/models/tutorial.json"),
    dict(model_file_name="example_expectations.json"),
)
def test_validate_models(config, model_file_name):
    with open(Path(os.path.dirname(__file__)) / model_file_name) as f:
        model = json.load(f)

    with open(config.model_schema_path) as f:
        model_schema = yaml.load(f, Loader=yaml.FullLoader)

    validation.validate_object_against_schema(
        input_object=model,
        schema_object=model_schema,
        raise_on_error=True,
        strict=False,
    )
