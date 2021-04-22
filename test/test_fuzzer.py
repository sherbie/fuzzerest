import json
import logging
import time

import pytest

from fuzzerest import mutator, request
from fuzzerest.fuzzer import DomainNameNotFoundError, Fuzzer
from fuzzerest.request import Summary

root_logger = logging.getLogger()
root_logger.propagate = False
root_logger.setLevel(logging.INFO)

Mutator = mutator.Mutator


domain = "local"


@pytest.fixture(scope="function")
def fuzzer(config):
    return Fuzzer(config.example_json_file, domain)


def test_init_methods(config, fuzzer):
    expected_methods = request.METHODS
    assert (
        fuzzer.methods == expected_methods
    ), "should contain all methods if none were initialized"

    try:
        Fuzzer(
            config.example_json_file,
            domain,
            methods=["GET", "NOT_A_METHOD"],
        )
        raise Exception("should throw RuntimeError because of invalid HTTP method")
    except RuntimeError:
        pass

    try:
        Fuzzer(config.example_json_file, domain, methods="GET, NOT_A_METHOD")
        raise Exception("should throw RuntimeError because of invalid HTTP method")
    except RuntimeError:
        pass

    try:
        Fuzzer(config.example_json_file, domain, methods=0)
        raise Exception("should throw RuntimeError because of invalid HTTP method")
    except RuntimeError:
        pass

    method = "GET"
    fuzzy = Fuzzer(config.example_json_file, domain, methods=method)
    expected_methods = [method]
    assert fuzzy.methods == expected_methods, "should allow string of one HTTP method"

    expected_methods = ["PUT", "PATCH"]
    fuzzy = Fuzzer(config.example_json_file, domain, methods=expected_methods)
    assert fuzzy.methods == expected_methods


def test_init_expectations(fuzzer, config):
    e = fuzzer.default_expectations
    assert e, "default expectations should have loaded from " + config.example_json_file


def test_init_mutator(fuzzer):
    assert fuzzer.mutator is not None, "should have loaded mutator object"


def test_init_logger(fuzzer, config):
    expected_file_name = "_all_uris_all_methods"
    assert expected_file_name in fuzzer.log_file_name

    methods = ["GET", "POST"]
    fuzzy = Fuzzer(config.example_json_file, domain, methods=methods)
    expected_file_name = "_all_uris_" + "_".join(methods)
    assert expected_file_name in fuzzy.log_file_name

    uri = "/json"
    fuzzy = Fuzzer(config.example_json_file, domain, methods=methods, uri=uri)
    expected_file_name = "-json_" + "_".join(methods)
    assert expected_file_name in fuzzy.log_file_name


@pytest.mark.kwparametrize(
    dict(
        domain_name="bad_name",
        expect_exception=DomainNameNotFoundError,
    ),
    dict(
        domain_name="",
        expect_exception=DomainNameNotFoundError,
    ),
    dict(
        domain_name=None,
        expect_exception=DomainNameNotFoundError,
    ),
    dict(
        domain_name="example",
        expect_exception=None,
    ),
)
def test_init_domain(config, domain_name, expect_exception):
    if expect_exception:
        with pytest.raises(expect_exception):
            Fuzzer(config.example_json_file, domain_name)
    else:
        Fuzzer(config.example_json_file, domain_name)


def test_log_last_state_used(fuzzer):
    fuzzer.log_last_state_used(0)


@pytest.mark.kwparametrize(
    dict(
        expectations=["expectation = True"],
        success=True,
    ),
    dict(
        expectations=["expectation = False"],
        success=False,
    ),
)
def test_evaluate_expectations(expectations, success):
    assert (
        Fuzzer.evaluate_expectations(
            expectations,
            Summary(method="GET", headers={}, body={}, timestamp=2, url=""),
        )
        is success
    )


def test_evaluate_endpoint_expectation(config):
    with open(config.example_json_file, "r") as model_file:
        model = json.loads(model_file.read())

    endpoint = next((l for l in model["endpoints"] if l["uri"] == "/sleepabit"), None)
    summary = Summary(method="GET", headers={}, body={}, timestamp=2, url="")
    summary.status_code = 200

    expectations = []
    assert not Fuzzer.evaluate_expectations(
        expectations, summary
    ), "should be false if expectation obj is empty"

    if endpoint.get("expectations", False):
        expectations = endpoint["expectations"]

    assert Fuzzer.evaluate_expectations(
        expectations, summary
    ), "summary should be expected"

    summary = Summary(method="GET", headers={}, body={}, timestamp=2, url="")
    summary.status_code = 500
    assert not Fuzzer.evaluate_expectations(
        expectations, summary
    ), "summary should not be expected because the httpcode does not match"

    summary = Summary(method="GET", headers={}, body={}, timestamp=0.2, url="")
    assert not Fuzzer.evaluate_expectations(
        expectations, summary
    ), "summary should not be expected because the time is incorrect"

    summary = Summary(method="GET", headers={}, body={}, timestamp=2, url="")
    assert not Fuzzer.evaluate_expectations(
        expectations, summary
    ), "summary should not be expected because the httpcode is missing"


def get_expectations(fuzzer, config):
    endpoint = next(
        (l for l in fuzzer.model_obj["endpoints"] if l["uri"] == "/sleepabit"),
        None,
    )
    expectations = fuzzer.get_expectations(endpoint)
    assert len(expectations) == 1, "should only find 1 key in expectation obj"
    assert (
        "local" in expectations.keys()
    ), "should choose the local expectation definition"

    endpoint = next(
        (l for l in fuzzer.model_obj["endpoints"] if l["uri"] == "/complex/qstring"),
        None,
    )
    fuzzer.default_expectations = ["expectation = True"]
    expectations = fuzzer.get_expectations(endpoint)
    assert len(expectations) == 1, "should only find 1 key in expectation obj"
    assert (
        "default" in expectations.keys()
    ), "should choose the default expectation definition"

    fuzzy = Fuzzer(config.example_expectations_file, domain)
    endpoint = next(
        (l for l in fuzzy.model_obj["endpoints"] if l["uri"] == "/json"), None
    )
    expectations = fuzzy.get_expectations(endpoint)
    assert len(expectations) == 1, "should only find 1 key in expectation obj"
    assert "global" in expectations.keys(), (
        "should choose the global expectation definition",
    )


def test_inject_constants(fuzzer):
    token = "{time}"
    constants = {token: "newvalue"}
    assert token in json.dumps(fuzzer.model_obj)
    assert token not in json.dumps(
        Fuzzer.inject_constants(fuzzer.model_obj, constants)
    ), f'"{token}" should have been replaced by "{constants[token]}"'
    assert constants[token] in json.dumps(
        Fuzzer.inject_constants(fuzzer.model_obj, constants)
    ), f'"{constants[token]}" should have replaced "{token}"'

    constants = {token: True}
    assert "true" in json.dumps(
        Fuzzer.inject_constants(fuzzer.model_obj, constants)
    ), f'"true" should have replaced "{token}"'

    constants = {token: 534897}
    assert str(constants[token]) in json.dumps(
        Fuzzer.inject_constants(fuzzer.model_obj, constants)
    ), f'"{constants[token]}" should have replaced "{token}"'


def test_mutate_payload_body(fuzzer):
    payload = fuzzer.mutate_payload(
        next(
            (l for l in fuzzer.model_obj["endpoints"] if l["uri"] == "/json"),
            None,
        )
    )
    assert payload.get("body") is not None, "payload should have a body"


def test_mutate_payload_query(fuzzer):
    payload = fuzzer.mutate_payload(
        next(
            (l for l in fuzzer.model_obj["endpoints"] if l["uri"] == "/query/string"),
            None,
        )
    )
    assert (
        payload.get("body") is None
    ), "payload with only query string should have an empty body"


def test_mutate_payload_body_and_query(fuzzer):
    payload = fuzzer.mutate_payload(
        next(
            (
                l
                for l in fuzzer.model_obj["endpoints"]
                if l["uri"] == "/poorly/designed/endpoint"
            ),
            None,
        )
    )
    assert payload.get("body") is not None, "payload should have a body"
    assert payload.get("query") is not None, "payload should have query input"


@pytest.mark.kwparametrize(
    dict(
        include_extra_info=False,
    ),
    dict(
        include_extra_info=True,
    ),
)
@pytest.mark.kwparametrize(
    dict(
        extra_info="hi_friends@12345.com",
    ),
)
def test_mutate_payload_headers(fuzzer, include_extra_info, extra_info):
    assert (
        fuzzer.config.include_extra_info_in_request_headers is False
    ), "Default should be False"

    fuzzer.config.include_extra_info_in_request_headers = include_extra_info
    fuzzer.config.extra_info = extra_info

    payload = fuzzer.mutate_payload(
        next(
            (l for l in fuzzer.model_obj["endpoints"] if l["uri"] == "/json"),
            None,
        )
    )
    assert payload.get("headers") is not None, "payload should have headers"
    assert (
        payload["headers"].get("Content-Type") is not None
    ), "should have Content-Type header"
    assert (
        payload["headers"]["Content-Type"]
        == "application/x-www-form-urlencoded; charset=UTF-8"
    ), "Content-Type header should not be mutated because it does not have a placeholder"
    assert (
        payload["headers"]["Authorization"] is not None
    ), "should have Authorization header"
    assert (
        "Bearer " in payload["headers"]["Authorization"]
    ), "Authorization header should have intact non-placeholder string"
    assert "{token}" not in payload["headers"]["Authorization"], (
        "Authorization header should have mutated token placeholder",
    )
    assert (
        payload["headers"].get("X-Extra-Info") == extra_info
        if include_extra_info
        else payload["headers"].get("X-Extra-Info") is None
    )


def test_mutate_payload_header_state(fuzzer):
    payload = fuzzer.mutate_payload(
        next(
            (l for l in fuzzer.model_obj["endpoints"] if l["uri"] == "/watch"),
            None,
        )
    )
    assert payload.get("headers") is not None, "payload should have headers"
    assert (
        payload["headers"].get("X-fuzzeREST-State") is not None
    ), "payload should have X-fuzzeREST-State header"
    assert payload["headers"]["X-fuzzeREST-State"] == str(
        fuzzer.state
    ), "X-fuzzeREST-State header should have mutator state"
    fuzzer.state += 1
    payload = fuzzer.mutate_payload(
        next(
            (l for l in fuzzer.model_obj["endpoints"] if l["uri"] == "/watch"),
            None,
        )
    )
    assert payload["headers"]["X-fuzzeREST-State"] == str(
        fuzzer.state
    ), "X-fuzzeREST-State header should have mutator state after mutator state was incremented"


def test_mutate_payload_uri(fuzzer):
    payload = fuzzer.mutate_payload(
        next(
            (l for l in fuzzer.model_obj["endpoints"] if l["uri"] == "/{someId}"),
            None,
        )
    )
    assert payload.get("uri") is not None, "payload should have a uri"
    assert "/{someId}" != payload["uri"], "uri with placeholder should mutate"
    payload = fuzzer.mutate_payload(
        next(
            (l for l in fuzzer.model_obj["endpoints"] if l["uri"] == "/json"),
            None,
        )
    )
    assert payload.get("uri") is not None, "payload should have a uri"
    assert "/json" == payload["uri"], "uri without placeholder should not mutate"


def _get_n_expected_summaries(endpoints, n_iterations, uri=None, methods=None):
    n_summaries = 0
    for e in endpoints:
        if e["uri"] == uri or uri is None:
            n_methods = len(
                list(set(e.get("methods", request.METHODS)).intersection(methods))
                if methods
                else e.get("methods", request.METHODS)
            )
            n_summaries += n_methods * n_iterations
    return n_summaries


def test_iterate_endpoints_uri(config):
    fuzzer = Fuzzer(
        config.example_json_file,
        domain,
        global_timeout=True,
        timeout=5,
        uri="/multiple",
    )
    n_times = 1
    expected_n_summaries = _get_n_expected_summaries(
        fuzzer.model_obj["endpoints"], n_times, fuzzer.uri
    )

    summaries = fuzzer.iterate_endpoints()
    assert (
        len(summaries) == expected_n_summaries
    ), f"should only iterate {expected_n_summaries} times over {fuzzer.uri} endpoint with all methods"

    for summary in summaries:
        assert (
            fuzzer.uri in summary.url
        ), f"expected iteration {json.dumps(summary)} to contain {fuzzer.uri}"


def test_iterate_endpoints_methods(config):
    fuzzer = Fuzzer(
        config.example_json_file,
        domain,
        global_timeout=True,
        timeout=5,
        methods=["GET", "POST"],
    )
    n_times = 1
    expected_n_summaries = _get_n_expected_summaries(
        fuzzer.model_obj["endpoints"], n_times, methods=fuzzer.methods
    )

    summaries = fuzzer.iterate_endpoints()
    assert (
        len(summaries) == expected_n_summaries
    ), f"should only iterate {expected_n_summaries} times over all endpoints with methods {fuzzer.methods}"

    for summary in summaries:
        assert (
            summary.method in fuzzer.methods
        ), f"expected iteration {json.dumps(summary)} to contain one of methods {fuzzer.methods}"


def test_iterate_endpoints_uri_methods(config):
    fuzzer = Fuzzer(
        config.example_json_file,
        domain,
        global_timeout=True,
        timeout=5,
        methods=["GET", "POST"],
        uri="/multiple",
    )
    n_times = 1
    expected_n_summaries = _get_n_expected_summaries(
        fuzzer.model_obj["endpoints"], n_times, fuzzer.uri, fuzzer.methods
    )

    summaries = fuzzer.iterate_endpoints()
    assert (
        len(summaries) == expected_n_summaries
    ), f"should only iterate {expected_n_summaries} times over all endpoints with methods {fuzzer.methods}"

    for summary in summaries:
        assert (
            summary.method in fuzzer.methods
        ), f"expected iteration {json.dumps(summary)} to contain one of methods {fuzzer.methods}"

    placeholder = "{otherId}"
    original_uri = "/" + placeholder
    expected_constant = "shoop"
    expected_uri = "/" + expected_constant
    fuzzer = Fuzzer(
        config.example_json_file,
        domain,
        constants={placeholder: expected_constant},
        uri=original_uri,
    )
    summaries = fuzzer.iterate_endpoints()
    assert expected_uri in json.dumps([str(summary) for summary in summaries]), (
        f"should find a request with uri {original_uri} that was changed to {expected_uri} after injecting {expected_constant} "
        "as a constant"
    )

    placeholder = "{something_that_doesnt_exist}"
    original_uri = "/" + placeholder
    expected_uri = "/" + expected_constant
    fuzzer = Fuzzer(
        config.example_json_file,
        domain,
        constants={placeholder: expected_constant},
        uri=original_uri,
    )
    summaries = fuzzer.iterate_endpoints()
    assert expected_uri not in json.dumps(summaries), (
        f"should not find a request with uri {original_uri} that was changed to {expected_uri} after injecting {expected_constant} "
        "as a constant"
    )


def test_iterate_endpoints_all(config):
    fuzzer = Fuzzer(config.example_json_file, domain, global_timeout=True, timeout=5)
    n_times = 1
    expected_n_summaries = _get_n_expected_summaries(
        fuzzer.model_obj["endpoints"], n_times
    )

    summaries = fuzzer.iterate_endpoints()
    assert (
        len(summaries) == expected_n_summaries
    ), f"should only iterate {expected_n_summaries} times over all endpoints and methods"


def test_iterate_endpoints_log_summary_uri(config):
    method = "GET"
    uri = "/{someId}"
    fuzzer = Fuzzer(
        config.example_json_file,
        domain,
        global_timeout=True,
        timeout=0.1,
        methods=[method],
        uri=uri,
    )

    def check_summary(message):
        summary = fuzzer.iterate_endpoints()[0]
        # reason is not part of the assertion because it is not easy to assert
        expected_summary = 'state={0} method={1} uri={2} code={3} error="{4}"'.format(
            summary.headers["X-fuzzeREST-State"],
            method,
            uri,
            summary.status_code,
            summary.error,
        )
        with open(fuzzer.log_file_name, "r") as file:
            log_content = file.read()
        assert expected_summary in log_content, f"{fuzzer.log_file_name}: {message}"

    check_summary("should contain summary for request")

    constants = {"{someId}": "some_constant"}
    fuzzer = Fuzzer(
        config.example_json_file,
        domain,
        global_timeout=True,
        timeout=0.1,
        methods=[method],
        uri=uri,
        constants=constants,
    )

    check_summary(
        "summary for request should have a url which is logged without the injected constant"
    )


def test_check_for_model_update(fuzzer):
    model = fuzzer.model_obj
    fuzzer._check_for_model_update()
    assert (
        model == fuzzer.model_obj
    ), f"should not change since elapsed time ({fuzzer.time_since_last_model_check}s) has not exceeded reload interval ({fuzzer.model_reload_rate}s)"

    fuzzer.time_since_last_model_check = fuzzer.model_reload_rate + 1
    fuzzer._check_for_model_update()
    assert (
        fuzzer.time_since_last_model_check == 0.0
    ), "should reset to 0.0 after exceeding reload interval"
    assert model == fuzzer.model_obj, "should not change since file was not changed"

    fuzzer.time_since_last_model_check = fuzzer.model_reload_rate + 1
    model = {"random": "new", "model": 0}
    fuzzer.model_obj = model  # this simulates a change in the model
    fuzzer._check_for_model_update()
    assert (
        fuzzer.model_obj != model
    ), "should change because the model in memory differs from what was loaded from the model file"


def test_fuzz_requests_by_incremental_state(config):
    fuzzer = Fuzzer(
        config.example_json_file,
        domain,
        global_timeout=True,
        timeout=5,
        uri="/any/method",
        methods=["GET"],
    )
    n_times = 5
    expected_fuzzer_state = n_times

    fuzzer.fuzz_requests_by_incremental_state(n_times)
    assert fuzzer.state == expected_fuzzer_state


def test_fuzz_requests_by_state_list(config):
    fuzzer = Fuzzer(
        config.example_json_file,
        domain,
        global_timeout=True,
        timeout=5,
        uri="/any/method",
        methods=["GET"],
    )
    states = [5, 2345, 3409, 222, 6]

    summaries = fuzzer.fuzz_requests_by_state_list(states)
    for summary in summaries:
        assert int(summary.headers["X-fuzzeREST-State"]) in states, (
            "fuzzer should have iterated this state",
        )


def _run_parallel_fuzzers(
    test_config, n_iterations, fuzzer_1_state=0, fuzzer_2_state=0
):

    fuzzer1 = Fuzzer(
        test_config.example_json_file,
        domain,
        global_timeout=True,
        timeout=5,
        state=fuzzer_1_state,
        constants={"{time}": "1m1s"},
        uri="/json",
        methods=["POST"],
    )
    fuzzer2 = Fuzzer(
        test_config.example_json_file,
        domain,
        global_timeout=True,
        timeout=5,
        state=fuzzer_2_state,
        constants={"{time}": "1m1s"},
        uri="/json",
        methods=["POST"],
    )
    summaries1 = fuzzer1.fuzz_requests_by_incremental_state(n_iterations)
    summaries2 = fuzzer2.fuzz_requests_by_incremental_state(n_iterations)

    return summaries1, summaries2


def test_identical_output(mocker, config):
    n_times = 10

    mocker.patch.object(time, "time", return_value=0)
    summaries1, summaries2 = _run_parallel_fuzzers(config, n_times)

    for i in range(n_times):
        # do not compare error messages since they are always different due to object address
        summaries1[i].error = ""
        summaries2[i].error = ""
        str1 = json.dumps(dict(summaries1[i]))
        str2 = json.dumps(dict(summaries2[i]))
        assert (
            str1 == str2
        ), "fuzzers with same initial state should produce identical output"


def test_different_output(config):
    n_times = 10
    summaries1, summaries2 = _run_parallel_fuzzers(
        config, n_times, fuzzer_1_state=1, fuzzer_2_state=2
    )

    for i in range(n_times):
        # do not compare error messages since they are always different due to object address
        summaries1[i].error = ""
        summaries2[i].error = ""
        str1 = json.dumps(dict(summaries1[i]))
        str2 = json.dumps(dict(summaries2[i]))
        assert str1 != str2, (
            "fuzzers with different initial state should produce different request bodies",
        )


def test_state_iteration(config):
    n_times = 1
    state = 0
    fuzzer = Fuzzer(
        config.example_json_file,
        domain,
        global_timeout=True,
        timeout=0.1,
        state=state,
    )
    summaries = fuzzer.fuzz_requests_by_incremental_state(n_times)

    for summary in summaries:
        assert (
            int(summary.headers["X-fuzzeREST-State"]) == state
        ), f"state for each endpoint should be {state} for the first iteration"

    state += 1
    summaries = fuzzer.fuzz_requests_by_incremental_state(n_times)
    for summary in summaries:
        assert (
            int(summary.headers["X-fuzzeREST-State"]) == state
        ), f"state for each endpoint should be {state} for the second iteration"

    summaries = fuzzer.fuzz_requests_by_incremental_state(n_times)
    for summary in summaries:
        assert (
            int(summary.headers["X-fuzzeREST-State"]) != state
        ), f"state for each endpoint should be {state + 1} for the third iteration"


def test_get_states_from_file(config):
    expected_states = [234, 812, 1, 999909, 234, 22222893428923498, 9]
    states = Fuzzer.get_states_from_file(config.example_states_file)
    assert states == expected_states, (
        "states should have loaded from " + config.example_states_file
    )


def test_send_delayed_request_local(config):
    fuzzer = Fuzzer(
        config.example_json_file,
        domain,
        global_timeout=True,
        timeout=0.1,
        uri="/delayabit",
        methods=["GET"],
    )
    summaries = fuzzer.fuzz_requests_by_incremental_state(1)
    expected_requests_per_second = 2.5
    expected_delay = request.get_request_delay(expected_requests_per_second)
    assert (
        summaries[0].delay == expected_delay
    ), f"local request rate defined in endpoint should have delay of {expected_delay}"


def test_send_delayed_request_global(config):
    fuzzer = Fuzzer(
        config.example_json_file,
        domain,
        global_timeout=True,
        timeout=0.1,
        uri="/delayabit",
        methods=["GET"],
    )
    fuzzer.model_obj["requestsPerSecond"] = 10.1
    summaries = fuzzer.fuzz_requests_by_incremental_state(1)
    expected_requests_per_second = 2.5
    expected_delay = request.get_request_delay(expected_requests_per_second)
    assert (
        summaries[0].delay == expected_delay
    ), f"local request rate should override global definition with delay of {expected_delay}"

    fuzzer = Fuzzer(
        config.example_json_file,
        domain,
        global_timeout=True,
        timeout=0.1,
        uri="/poorly/designed/endpoint",
        methods=["GET"],
    )
    summaries = fuzzer.fuzz_requests_by_incremental_state(1)
    expected_delay = request.get_request_delay(fuzzer.model_obj["requestsPerSecond"])
    assert (
        summaries[0].delay == expected_delay
    ), f"global definition should have delay of {expected_delay}"


def test_get_curl_query_string(fuzzer):
    try:
        fuzzer.methods = ["GET"]
        fuzzer.get_curl_query_string()
        raise Exception("should raise RuntimeError since uri is empty")
    except RuntimeError:
        pass
    try:
        fuzzer.uri = "/json"
        fuzzer.get_curl_query_string()
        raise Exception(
            "should raise RuntimeError since method could not be found with uri in model"
        )
    except RuntimeError:
        pass
    fuzzer.methods = ["POST"]
    fuzzer.get_curl_query_string()


def test_get_curl_query_string_constants(fuzzer, config):
    curl_file = config.curl_data_file_path
    fuzzer.methods = ["GET"]
    placeholder = "{someId}"
    fuzzer.uri = "/" + placeholder
    fuzzer.constants = {placeholder: "berb"}
    expectedUri = "/" + fuzzer.constants[placeholder]
    fuzzer.get_curl_query_string()

    with open(curl_file, "r") as file:
        assert (
            expectedUri in file.read()
        ), "should contain uri which was not fuzzed due to constant injection"

    fuzzer.constants = None
    expectedUri = fuzzer.uri
    fuzzer.get_curl_query_string()

    with open(curl_file, "r") as file:
        assert (
            expectedUri not in file.read()
        ), "should not contain uri because it was fuzzed without constant injection"


def test_get_model_with_constants(fuzzer, config):
    fuzzer.model_file_path = ""
    try:
        fuzzer.load_model()
        raise Exception(
            "should throw error because the file path for the model was invalid"
        )
    except FileNotFoundError:
        pass

    fuzzer.model_file_path = config.example_json_file
    fuzzer.load_model()  # testing the constant injection feature is done in inject_constants


def test_mutate_headers(config, fuzzer):
    with open(config.example_json_file, "r") as model_file:
        model = json.loads(model_file.read())

    header_to_drop = "Authorization"
    endpoint = Fuzzer.get_endpoints(model["endpoints"], "/json")[0]

    mutated_headers = fuzzer.mutate_headers(
        endpoint["headers"], config.default_placeholder_pattern
    )

    assert header_to_drop in mutated_headers, "Authorization header should exist"

    header_drop_state = 1
    fuzzer.change_state(header_drop_state)
    mutated_headers = fuzzer.mutate_headers(
        endpoint["headers"], config.default_placeholder_pattern
    )

    assert (
        header_to_drop not in mutated_headers
    ), "Authorization header should be dropped"


def test_slack_status_update(config, mocker):
    mock_summary = Summary(
        method="GET",
        headers={"X-fuzzeREST-State": 0},
        body={},
        delay=0,
        timestamp=1,
        url="http://nowhere",
    )
    mock_summary.status_code = 200

    mocker.patch.object(request, "send_request", return_value=mock_summary)

    _update_interval = config.slack_status_update_interval_seconds

    fuzzer = Fuzzer(
        config.example_json_file,
        domain,
        global_timeout=True,
        timeout=5,
        uri="/sleepabit",
    )
    last_update_time = 0
    fuzzer.last_slack_status_update = last_update_time
    config.slack_status_update_interval_seconds = 0
    fuzzer.iterate_endpoints()
    assert fuzzer.last_slack_status_update != last_update_time, (
        f"should change because the update interval was exceeded: fuzzer.last_slack_status_update={fuzzer.last_slack_status_update}",
    )

    last_update_time = fuzzer.last_slack_status_update
    config.slack_status_update_interval_seconds = _update_interval
    fuzzer.iterate_endpoints()
    assert fuzzer.last_slack_status_update == last_update_time, (
        "should be the same because the update interval was not yet exceeded",
    )


def test_slack_error_throttle(config, mocker):
    mock_summary = Summary(
        method="GET",
        headers={"X-fuzzeREST-State": 0},
        body={},
        delay=0,
        timestamp=1,
        url="http://nowhere",
    )
    mock_summary.status_code = 200

    mocker.patch.object(request, "send_request", return_value=mock_summary)

    fuzzer = Fuzzer(
        config.example_json_file,
        domain,
        global_timeout=True,
        timeout=5,
        uri="/query/string",
    )
    expected_errors = fuzzer.slack_errors + 1
    fuzzer.last_hour = time.localtime().tm_hour
    fuzzer.iterate_endpoints()
    assert fuzzer.slack_errors == expected_errors, "should increment by 1"

    fuzzer.slack_errors = config.slack_errors_per_hour
    expected_errors = fuzzer.slack_errors
    fuzzer.last_hour = time.localtime().tm_hour
    fuzzer.iterate_endpoints()
    assert fuzzer.slack_errors == expected_errors, (
        "should match because errors per hour limit was reached",
    )

    fuzzer.last_hour += 1
    fuzzer.iterate_endpoints()
    expected_errors = 1
    assert fuzzer.slack_errors == expected_errors, (
        "should reset to 0 and increment to 1 because hour changed",
    )
