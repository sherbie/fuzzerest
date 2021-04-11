import pytest

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
