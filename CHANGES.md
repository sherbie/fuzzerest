# 2.1.0

2021-04-28

- Refactor `Config` class to accept a profile argument. This
  makes separation between test and production configurations
  more explicit.
- Allow states and model file paths to be configurable.

# 2.0.0

2021-04-28

- Add Cerberus data validation for models and expectations. Input
  is validated before being used.
- Some tests which previously were run by unittest without the
  `test_` prefix in their method name now are re-enabled after
  being renamed with the same prefix.
- Fixed a flaky test caused by RNG output without a seed constant.

Breaking changes

- Expectations structure is now a list. Overriding order is
  first cli input, then model input, and lastly default input
  ([default_expectations.json](fuzzerest/models/default_expectations.json)).
- The `name` key of the Domain dictionary in the model definition
  was moved into the structure. This allows for easier schema
  definition.

# 1.0.2

2021-04-11

- Create abstraction layer for radamsa binary. The fuzzer can continue
  to operate if radamsa is not found.

# 1.0.1

2021-04-08

- Allow user to configure an optional info header with a constant value.
  This may be useful for users who wish to provide info to observers of
  a fuzzing target, such as admins of a bug bounty project.

# 1.0.0

2021-04-04

- Wrap `requests.Response` object with Summary class
- Replace usages of `result` with `summary` in expectations
  (this breaks existing expectations configurations)
- Prevent slack API calls if connection is not alive

# 0.0.1

2021-04-04

- Replace `.format()` usages with f-strings
- Tidy up readme
- Begin fuzzeREST
