import json
import os
import sys

argparse_args = ["-m", os.path.join("."), "-d", "test"]


def test_validate_printcurl_args(client):
    def evaluate_args(additional_args):
        client.parsed_args = client.parser.parse_args(argparse_args + additional_args)
        try:
            client._validate_printcurl_args()
            raise Exception("should raise SystemExit")
        except SystemExit as ex:
            assert ex.code == 1

    evaluate_args(["--printcurl"])
    evaluate_args(["--printcurl", "--method", "POST"])
    evaluate_args(["--printcurl", "--uri", "/test"])

    client.parsed_args = client.parser.parse_args(
        argparse_args + ["--printcurl", "--uri", "/test", "--method", "POST"]
    )
    client._validate_printcurl_args()


def test_set_logging_level(client):
    def evaluate_log_level_arg(level):
        client.parsed_args = client.parser.parse_args(
            argparse_args + ["-l", str(level)]
        )
        client._set_logging_level()
        msg = f"should be log level {client.config.logging_levels[level]} when level was set to {level}"
        assert (
            client.config.root_logger.level == client.config.logging_levels[level]
        ), msg

        client.parsed_args = client.parser.parse_args(
            argparse_args + ["--loglevel", str(level)]
        )
        client._set_logging_level()
        msg = f"should be log level {client.config.logging_levels[level]} when level was set to {level}"
        assert (
            client.config.root_logger.level == client.config.logging_levels[level]
        ), msg

    for i in range(0, len(client.config.logging_levels)):
        evaluate_log_level_arg(i)


def test_get_cmd_string(client):
    args = ["./cli.py"] + argparse_args
    sys.argv = args
    assert client._get_cmd_string().strip(" ") == " ".join(sys.argv).strip(
        " "
    ), "should reproduce command line input as a string"

    jsonargs = ["-c", '{"my": "test", "json": "arg"}']
    sys.argv = args + jsonargs
    actual = client._get_cmd_string().strip(" ")
    expected = " ".join(args + [jsonargs[0]]) + f" '{jsonargs[1]}'"
    assert (
        actual == expected
    ), "should reproduce input with json arg surrounded with quotes"


def test_set_constants(client):
    jsonfile = client.config.example_json_file
    jsonfile_args = ["-C", jsonfile]
    args = argparse_args + jsonfile_args
    client.parsed_args = client.parser.parse_args(args)
    client._set_constants()
    with open(jsonfile, "r") as file:
        jsonfile_constants = json.loads(file.read())
    assert client.constants == jsonfile_constants, (
        "should load constants from " + jsonfile
    )

    jsonstring_args = ["-c", '{"{otherPlaceholder}":5}']
    args += jsonstring_args
    client.parsed_args = client.parser.parse_args(args)
    client._set_constants()
    constants = client.constants
    constants.update(json.loads(jsonstring_args[1]))
    assert client.constants == constants, (
        "should combine constants from "
        + jsonfile
        + " with args from "
        + str(jsonstring_args)
    )

    jsonstring_args = ["-c", '{"{otherPlaceholder}":5, "{placeholder}":"test"}']
    args = argparse_args + jsonfile_args + jsonstring_args
    client.parsed_args = client.parser.parse_args(args)
    client._set_constants()
    constants = client.constants
    constants.update(json.loads(jsonstring_args[1]))
    assert client.constants == constants, (
        "should overwrite constants from "
        + jsonfile
        + " with args from "
        + str(jsonstring_args)
    )


def test_parse_cli_args(client):
    model_file = client.config.example_json_file
    cmdline_args = ["./cli.py", "-d", "test", "-m", os.path.join("..", model_file)]
    sys.argv = cmdline_args
    client.parse_cli_args()
    assert (
        client.states == []
    ), "should have empty state list since no state file was provided"
    with open(client.model_file_path, "r"):
        pass

    state_file = client.config.example_states_file
    sys.argv = cmdline_args + ["--statefile", state_file]
    client.parse_cli_args()
    expected_states = [234, 812, 1, 999909, 234, 22222893428923498, 9]
    assert client.states.sort() == expected_states.sort()


def test_parse_default_cli_args(client, config):
    model_file = client.config.example_json_file
    model_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "..", model_file
    )
    assert os.path.exists(model_path), model_path
    cmdline_args = ["./cli.py", "-m", model_path]
    sys.argv = cmdline_args
    client.parse_cli_args()

    script_dir = os.path.realpath(__file__)

    actual_path = os.path.realpath(client.parsed_args.model_path)
    assert os.path.exists(actual_path), actual_path
    expected_path = os.path.join(
        script_dir, "..", os.path.realpath(config.example_json_file)
    )
    assert os.path.exists(expected_path), expected_path
    assert (
        actual_path == expected_path
    ), f"actual={actual_path}, expected={expected_path}"
    assert client.parsed_args.domain == config.default_model_domain_name
    assert not client.parsed_args.gtimeout, client.parsed_args.gtimeout
    assert client.parsed_args.state == 0
    assert client.parsed_args.timeout, client.parsed_args.timeout
    assert client.constants == {}, client.constants
    assert not client.parsed_args.uri, client.parsed_args.uri
    assert not client.parsed_args.method, client.parsed_args.method
    assert client.config, client.config


def test_run_fuzzer(client):
    model_file = client.config.example_json_file
    state_file = client.config.example_states_file
    cmdline_args = [
        "./cli.py",
        "-d",
        "local",
        "-m",
        model_file,
        "-u",
        "/json",
        "--method",
        "POST",
    ]
    sys.argv = cmdline_args + ["--statefile", state_file]
    client.parse_cli_args()
    client.run_fuzzer()
    expected_nstates = 7
    assert len(client.request_summaries) == expected_nstates, (
        "should execute "
        + str(expected_nstates)
        + " iterations (each state in the state file)"
    )

    sys.argv = cmdline_args + ["-i", str(expected_nstates)]
    client.parse_cli_args()
    client.run_fuzzer()
    assert len(client.request_summaries) == expected_nstates, (
        "should execute " + str(expected_nstates) + " iterations"
    )
