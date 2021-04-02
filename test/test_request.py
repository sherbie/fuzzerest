import json
import time
import urllib
from collections import OrderedDict
from urllib.parse import urlparse

import requests

from fuzzerest import mutator, request
from fuzzerest.fuzzer import Fuzzer


def _check_url(domain_obj, uri, input_obj):
    url = request.get_encoded_url(domain_obj, uri, input_obj.get("query"))
    parsed_url = urlparse(url)
    assert parsed_url.scheme == domain_obj["protocol"], "protocol should match"
    assert parsed_url.netloc == domain_obj["host"], "host should match"
    assert parsed_url.path == uri, "uri should match"
    if "query" in input_obj:
        assert parsed_url.query == urllib.parse.quote(
            parsed_url.query, safe="/*-._[]&%="
        ), "query syntax should match"


def test_get_encoded_url(model):
    endpoint_obj = Fuzzer.get_endpoints(model["endpoints"], "/query/string")[0]
    domain_obj = model["domains"]["example"]
    _check_url(domain_obj, endpoint_obj["uri"], endpoint_obj["input"])
    url = request.get_encoded_url(
        domain_obj, endpoint_obj["uri"], endpoint_obj["input"]["query"]
    )
    assert "false" in url, "should have a lower-case bool/string"
    assert "False" not in url, "should not have an upper-case bool/string"

    endpoint_obj = Fuzzer.get_endpoints(model["endpoints"], "/complex/qstring")[0]
    _check_url(domain_obj, endpoint_obj["uri"], endpoint_obj["input"])

    endpoint_obj = Fuzzer.get_endpoints(
        model["endpoints"], "/poorly/designed/endpoint"
    )[0]
    _check_url(domain_obj, endpoint_obj["uri"], endpoint_obj["input"])


def test_get_endpoints(model):
    assert (
        Fuzzer.get_endpoints(model["endpoints"]) == model["endpoints"]
    ), "should return same object if no criteria was specified"

    uri = "/multiple"
    nExpected = 3
    endpoints = Fuzzer.get_endpoints(model["endpoints"], uri)
    assert (
        len(endpoints) == nExpected
    ), "should have {0} endpoint definitions for {1}".format(nExpected, uri)

    methods = ["PUT", "PATCH"]
    nExpected = 1
    endpoints = Fuzzer.get_endpoints(model["endpoints"], uri, methods)
    assert (
        len(endpoints) == nExpected
    ), f"should have {nExpected} endpoint definition for {uri} which has methods {methods}"


def test_get_endpoints_uri(model):
    uri = "/multiple"
    endpoints = Fuzzer.get_endpoints(model["endpoints"], uri=uri)
    n_expected = 3
    assert len(endpoints) == n_expected, f"should have {n_expected} {uri} endpoints"

    uri = "asdfasdf"
    endpoints = Fuzzer.get_endpoints(model["endpoints"], uri=uri)
    n_expected = 0
    assert len(endpoints) == n_expected, f"should have {n_expected} {uri} endpoints"


def test_dump_result():
    result = {"result": "abc", "stuff": 123}
    assert "result" not in request.dump_result(result)
    assert "stuff" in request.dump_result(result)

    result = {"stuff": 123}
    assert "result" not in request.dump_result(result)
    assert "stuff" in request.dump_result(result)

    result = {}
    assert "{}" == request.dump_result(result)


def test_construct_curl_query(config, model):
    curl_data_file_path = config.curl_data_file_path
    uri = "/poorly/designed/endpoint"
    method = "GET"
    endpoint = Fuzzer.get_endpoints(model["endpoints"], uri)[0]
    domain_obj = model["domains"]["local"]

    actual_query = request.construct_curl_query(
        curl_data_file_path,
        domain_obj,
        uri,
        method,
        endpoint["headers"],
        endpoint["input"]["body"],
        endpoint["input"]["query"],
    )

    expected_query = "curl -g -K {0}".format(curl_data_file_path)

    assert expected_query == actual_query, "should construct a valid curl query"


def test_get_request_delay():
    requests_per_second = 0.5
    actual_request_delay = request.get_request_delay(requests_per_second)
    expected_request_delay = 2

    assert expected_request_delay == actual_request_delay, "Request delay is incorrect"


def test_delay_request(model):
    endpoint = Fuzzer.get_endpoints(model["endpoints"], "/delayabit")[0]

    request_delay = request.get_request_delay(endpoint["requestsPerSecond"])
    now = time.time()
    response = request.send_request(
        model["domains"]["local"], endpoint["uri"], "GET", delay=request_delay
    )
    request_time = time.time() - now
    expected_delay = 0.4
    assert (
        expected_delay == response["delay"]
    ), "Delay should be represented in the response object"
    tolerance = 0.005
    assert round(request_time - expected_delay, 3) >= round(
        response["time"] - tolerance, 3
    ), (
        "Request time should be equal to the time between building the request to receiving"
        " the response, minus the delay time +/- " + str(tolerance),
    )
    assert round(request_time - expected_delay, 3) <= round(
        response["time"] + tolerance, 3
    ), (
        "Request time should be equal to the time between building the request to receiving"
        " the response, minus the delay time +/- " + str(tolerance),
    )


def test_get_header_size_in_bytes():
    header = {"Accept": "application/json"}
    expected_size = 28
    assert (
        request.get_header_size_in_bytes(header) == expected_size
    ), f"should have size {expected_size}"


def test_send_request_result_size(model):
    method = "GET"
    uri = "/poorly/designed/endpoint"
    endpoint = Fuzzer.get_endpoints(model["endpoints"], uri, methods=[method])[0]
    headers = endpoint["headers"]
    body = endpoint["input"]["body"]
    query = endpoint["input"]["query"]
    result = request.send_request(
        model["domains"]["example"],
        uri,
        method,
        headers_obj=headers,
        body_obj=body,
        query_obj=query,
    )
    expected_url_size = 63
    assert len(result["url"]) == expected_url_size
    expected_body_size = 35
    assert len(json.dumps(result["body"])) == expected_body_size
    expected_header_size = 58
    assert request.get_header_size_in_bytes(result["headers"]) == expected_header_size
    expected_size = expected_url_size + expected_body_size + expected_header_size
    assert result["size"] == expected_size, f"should have size {expected_size}"


def test_truncate_object():
    obj = {"a": "a", "b": "bb"}
    expectedObj = {"a": "", "b": ""}
    n_bytes = 3
    actual_obj = request.truncate_object(obj, n_bytes)
    assert actual_obj == expectedObj, (
        f"{actual_obj} != {expectedObj} - should remove {n_bytes} bytes from object values",
    )

    obj = {"a": "a", "b": 10}
    expectedObj = {"a": "", "b": 10}
    actual_obj = request.truncate_object(obj, n_bytes)
    assert (
        actual_obj == expectedObj
    ), f"{actual_obj} != {expectedObj} - should remove {n_bytes} bytes from object values and ignore non-string values"

    obj = expectedObj
    actual_obj = request.truncate_object(obj, n_bytes, is_header=True)
    assert actual_obj == expectedObj, (
        f"{actual_obj} != {expectedObj} - should not change object if it has already been truncated by same amount of bytes",
    )


HEADER_AUTH = "authorization"
HEADER_CONTENT = "content-type"
HEADER_FUZZER_STATE = "x-fuzzerest-state"
CRITICAL_HEADERS = [HEADER_AUTH, HEADER_CONTENT, HEADER_FUZZER_STATE]


def test_truncate_header_object():
    obj = {HEADER_AUTH: "Bearer my.token", "X-Debug": "abcdefg"}
    expectedObj = {HEADER_AUTH: "Bearer my.token", "X-Debug": ""}
    n_bytes = 30
    actual_obj = request.truncate_object(obj, n_bytes, is_header=True)
    assert (
        actual_obj == expectedObj
    ), f"{actual_obj} != {expectedObj} - should remove {n_bytes} bytes from object values that are not in {CRITICAL_HEADERS}"

    obj = {HEADER_AUTH: "Bearer my.token"}
    expectedObj = obj
    n_bytes = 30
    actual_obj = request.truncate_object(obj, n_bytes, is_header=True)
    assert (
        actual_obj == expectedObj
    ), f"{actual_obj} != {expectedObj} - shouldn't truncate {HEADER_AUTH} field if the value is not longer than {n_bytes}"

    n_bytes = 30
    obj = {HEADER_AUTH: "".join("a" for c in range(n_bytes * 2))}
    expectedObj = {HEADER_AUTH: "".join("a" for c in range(n_bytes))}
    actual_obj = request.truncate_object(obj, n_bytes, is_header=True)
    assert (
        actual_obj == expectedObj
    ), f"{actual_obj} != {expectedObj} - should truncate {HEADER_AUTH} field if the value is longer than {n_bytes}"


def test_sanitize_headers():
    obj = {
        HEADER_AUTH: "Bearer my.token",
        "X-Debug": " aaaa\nbb b\x02 ",
    }
    expectedObj = {
        HEADER_AUTH: "Bearer my.token",
        "X-Debug": "aaaabb b",
    }
    actual_obj = request.sanitize_headers(obj)
    assert (
        actual_obj == expectedObj
    ), f"{actual_obj} != {expectedObj} - should not have control characters, newlines, or leading/trailing whitespace"

    obj = expectedObj
    actual_obj = request.sanitize_headers(obj)
    assert actual_obj == expectedObj, (
        f"{actual_obj} != {expectedObj} - should not change headers if they are already sanitized",
    )

    obj = {"X-Debug": "".join("a" for i in range(request.MAX_REQUEST_SEGMENT_SIZE))}
    size = request.get_header_size_in_bytes(obj)
    expectedSize = len(obj["X-Debug"]) - int(size / request.TRUNCATION_RESIZE_FACTOR)
    expectedObj = {"X-Debug": "".join("a" for i in range(expectedSize))}
    actual_obj = request.sanitize_headers(obj)
    assert actual_obj == expectedObj, (
        f"{actual_obj} != {expectedObj} - should have truncated field with byte length of {expectedSize}",
    )


def test_sanitize_url(model):
    domain_obj = model["domains"]["local"]
    uri = "/i/have/the/best/uri/EVAR"
    size = request.MAX_REQUEST_SEGMENT_SIZE
    query_obj = {"a": "".join("b" for i in range(size))}
    expected_url = request.get_encoded_url(domain_obj, uri, query_obj)[
        : request.MAX_REQUEST_SEGMENT_SIZE
    ]
    actual_obj = request.sanitize_url(domain_obj, uri, query_obj)
    assert actual_obj == expected_url, (
        f"{actual_obj} != {expected_url} - should be equal after truncating to length {len(expected_url)}",
    )


def test_sanitize(model):
    domain_obj = model["domains"]["local"]
    uri = "/i/have/the/best/uri/EVAR"
    headers_obj = {
        HEADER_AUTH: "Bearer my.token",
        "X-Debug": " aaaa\nbb b\x02 ",
    }
    size = request.MAX_REQUEST_SEGMENT_SIZE
    query_obj = {"a": "".join("a" for i in range(size))}

    url, sanitized_headers_obj = request.sanitize(
        domain_obj, uri, query_obj, headers_obj
    )
    url_size = len(url)
    headers_size = request.get_header_size_in_bytes(sanitized_headers_obj)

    assert sanitized_headers_obj == request.sanitize_headers(
        headers_obj
    ), "headers should be sanitized"
    assert url == request.sanitize_url(
        domain_obj, uri, query_obj, url_size
    ), "url should be sanitized"
    assert url_size + headers_size <= request.MAX_REQUEST_SEGMENT_SIZE, (
        f"combined size of sanitized url and headers should be at most {request.MAX_REQUEST_SEGMENT_SIZE}",
    )


def test_sanitize_url_length_limit(model, config):
    domain_obj = model["domains"]["local"]
    base_url = "http://localhost:8080"
    max_length = config.maximum_url_size_in_bytes
    addedLength = max_length - len(base_url + "/")
    uri = "/" + "".join("a" for i in range(addedLength))
    url, _ = request.sanitize(domain_obj, uri)
    assert len(url) == max_length, "URL should be maximum length"

    uri = "/" + "".join("a" for i in range(addedLength + 1))
    url, _ = request.sanitize(domain_obj, uri)
    assert len(url) == max_length, "URL should be truncated to maximum length"

    uri = "/" + "".join("a" for i in range(addedLength - 1))
    url, _ = request.sanitize(domain_obj, uri)
    assert len(url) == max_length - 1, "URL should be one less than maximum length"


def test_send_request(mocker, model):
    expected_text = "text"
    expected_reason = "reason"
    expected_httpcode = 200

    class MockResponse:
        text = expected_text
        reason = expected_reason
        status_code = expected_httpcode

    expected_res = MockResponse()
    mocker.patch.object(requests, "request", return_value=expected_res)

    uri = "/json"
    method = "GET"
    endpoint = Fuzzer.get_endpoints(model["endpoints"], uri)[0]

    res = request.send_request(
        model["domains"]["local"],
        endpoint["uri"],
        method,
        body_obj=endpoint["input"]["body"],
    )

    assert res.get("httpcode") == expected_httpcode
    assert res.get("response") == expected_text
    assert res.get("reason") == expected_reason
    assert res.get("result") == expected_res
    assert res.get("delay") is None
    assert res.get("method") == method
    assert res.get("headers") is None


def test_send_request_timeout(mocker, model):
    expected_reason = "I timed out"

    mocker.patch.object(
        requests, "request", side_effect=requests.exceptions.Timeout(expected_reason)
    )

    uri = "/sleepabit"
    method = "GET"
    endpoint = Fuzzer.get_endpoints(model["endpoints"], uri)[0]
    res = request.send_request(
        model["domains"]["local"],
        endpoint["uri"],
        method,
        timeout=0.1,
        query_obj=endpoint["input"]["query"],
    )
    assert expected_reason in res.get("reason")


def test_send_request_body_and_query(mocker, model):
    class MockResponse:
        text = "text"
        reason = "reason"
        status_code = 200

    mocker.patch.object(requests, "request", return_value=MockResponse())

    uri = "/poorly/designed/endpoint"
    method = "GET"
    endpoint = Fuzzer.get_endpoints(model["endpoints"], uri)[0]
    res = request.send_request(
        model["domains"]["local"],
        endpoint["uri"],
        method,
        timeout=0.1,
        body_obj=endpoint["input"]["body"],
        query_obj=endpoint["input"]["query"],
    )
    assert (
        res["body"] == endpoint["input"]["body"]
    ), "expected response to contain request body"
    assert res["url"] == request.get_encoded_url(
        model["domains"]["local"],
        endpoint["uri"],
        endpoint["input"]["query"],
    ), "expected response to contain url-encoded query"
