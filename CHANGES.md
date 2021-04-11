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
