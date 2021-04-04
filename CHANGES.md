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
