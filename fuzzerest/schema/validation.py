import cerberus


class ValidationError(BaseException):
    pass


class Status:
    def __init__(self, error_object: dict):
        self.errors = error_object
        self.ok = not bool(self.errors)


def validate_object_against_schema(
    input_object: dict,
    schema_object: dict,
    raise_on_error: bool = False,
    strict: bool = True,
) -> Status:
    validator = cerberus.validator.Validator(schema_object)
    validator.allow_unknown = not strict
    validator.validate(input_object)

    status = Status(validator.errors)

    if raise_on_error and not status.ok:
        raise ValidationError(
            f'Object "{input_object}" failed to validate against schema "{schema_object}": {status.errors}',
        )

    return status
