import copy
import json
import os
import re
import sys
from collections import OrderedDict

import pytest

from fuzzerest.fuzzer import Fuzzer
from fuzzerest.mutator import Radamsa

n_times = 10000
tolerance = 0.015
sample = "abcdef0123456789öåä!#€%&/()=?©@£$∞§|[]≈±´~^¨*abcdef0123456789öåä!#€%&/()=?©@£$∞§|[]≈±´~^¨*"


@pytest.mark.kwparametrize(
    dict(
        override_path=True,
    ),
    dict(
        override_path=False,
    ),
)
def test_radamsa_config(config, mocker, override_path):
    if override_path:
        mocker.patch.object(os.environ, "get", return_value="bad/path")
    radamsa = Radamsa(config)
    assert not radamsa.ready if override_path else radamsa.ready
    byte_output = radamsa.get("test", "unicode_escape", 1)

    # If this block fails, the radamsa binary may have changed. A new
    # seed number might be required so that radamsa does not create
    # empty data
    assert (
        not byte_output if override_path else byte_output
    ), f"Radamsa tried to load from path {radamsa.bin_path}. Ready={radamsa.ready}"


def test_chance(mutator):
    expected_probability = 0.1
    result = {True: 0, False: 0}
    for _ in range(n_times):
        r = mutator.chance(expected_probability)
        result[r] += 1
        mutator.change_state(_ + 1)
    diff = abs(result[True] / n_times - expected_probability)
    assert (
        tolerance >= diff
    ), f"{diff} exceeded tolerance of {tolerance} for probability {expected_probability}"


def test_chance_identity(mutator):
    list1 = []
    list2 = []
    probability = 0.5
    for _ in range(n_times):
        list1.append(mutator.chance(probability))
        list2.append(mutator.chance(probability))
    assert (
        list1 == list2
    ), "both lists should contain the same output since the mutator state never changed"


def test_roll_dice(mutator):
    result = [0, 0, 0, 0, 0, 0]  # total hits for each die face
    faces = len(result)
    expected_probability = 1 / faces
    for _ in range(n_times):
        r = mutator.roll_dice(1, faces)
        result[r - 1] += 1
        mutator.change_state(_ + 1)
    for n in range(faces):
        diff = abs(result[n] / n_times - expected_probability)
        assert (
            tolerance >= diff
        ), f"{diff} exceeded tolerance of {tolerance} for probability {expected_probability}"


def test_roll_dice_identity(mutator):
    list1 = []
    list2 = []
    minimum = 0
    maximum = 10
    for _ in range(n_times):
        list1.append(mutator.roll_dice(minimum, maximum))
        list2.append(mutator.roll_dice(minimum, maximum))
    assert list1 == list2, (
        "both lists should contain the same output since the mutator state never changed",
    )


def test_juggle_type(mutator):
    result = {str: 0, bool: 0, int: 0, list: 0, dict: 0, type(None): 0}
    expected_probability = 1 / len(result)
    for _ in range(n_times):
        value = mutator.juggle_type(0)
        result[type(value)] += 1
        mutator.change_state(_ + 1)
    for key, _ in result.items():
        diff = abs(result[key] / n_times - expected_probability)
        assert (
            tolerance >= diff
        ), f"{diff} exceeded tolerance of {tolerance} for probability {expected_probability}"


def test_mutate_radamsa_state_change(mutator):
    n_times = 100
    previous_value = None
    for n in range(n_times):
        mutator.change_state(n)
        value = mutator.mutate_radamsa(sample)
        assert (
            previous_value != value
        ), "mutator output should differ if the state changes, last state was " + str(
            mutator.state
        )
        previous_value = value


def test_mutate_radamsa_state_static(mutator):
    n_times = 100
    for _ in range(n_times):
        mutator.change_state(0)
        value = mutator.mutate_radamsa(sample)
        assert mutator.mutate_radamsa(sample) == value, (
            "mutator output should remain the same if state != -1 and remains constant",
        )


def test_mutate_radamsa_nondeterministic(mutator):
    mutator.mutate_radamsa(sample)


def test_mutate_radamsa_encoding_change(mutator):
    defaultEncodingMutation = mutator.mutate_radamsa(sample)
    assert (
        mutator.mutate_radamsa(sample) == defaultEncodingMutation
    ), "should be equal output for same state and encoding"
    mutator.byte_encoding = "utf-16"
    asciiEncodingMutation = mutator.mutate_radamsa(sample)
    assert defaultEncodingMutation != asciiEncodingMutation, (
        "should have different output for same state and different encoding",
    )


def test_mutate_val_state_static(mutator):
    n_times = 100
    for _ in range(n_times):
        mutator.change_state(0)
        value = mutator.mutate_val(sample)
        assert mutator.mutate_val(sample) == value, (
            "mutator output should remain the same if state != -1 and remains constant",
        )


def test_mutate_val_nondeterministic(mutator):
    mutator.mutate_val(sample)


def test_list_obj_iterable(mutator):
    dictionary = {1: 0}
    assert mutator.list_obj_iterable(dictionary) == dictionary, (
        "should no-op if input is a dict",
    )
    lst = [1, 1]
    assert mutator.list_obj_iterable([1, 1]) == range(
        len(lst)
    ), "iteration range should be the length of the list"
    string = "11"
    assert mutator.list_obj_iterable(string) == range(
        len(string)
    ), "iteration range should be the length of the string"


def test_walk_and_mutate(mutator):
    obj = {"1": {"2": {"3": [0, 1]}}}
    assert mutator.walk_and_mutate(obj, False, None) != obj, "dict should mutate"

    lst = [0, 1, 2]
    assert mutator.walk_and_mutate(lst, False, None) != lst, "list should mutate"


def test_walk_and_mutate_strict(mutator, config):
    placeholder_str = "{placeholder}"
    plain_str = " text outside of placeholder"
    obj = {"1": placeholder_str + plain_str}
    mutated_obj = copy.deepcopy(obj)
    mutator.walk_and_mutate(mutated_obj, True, config.default_placeholder_pattern)
    assert mutated_obj != obj, "dict should mutate"
    assert plain_str in mutated_obj["1"], (
        "string mutation should only apply for pattern in strict mode",
    )
    assert (
        placeholder_str not in mutated_obj["1"]
    ), "string mutation not apply for plain text in strict mode"

    mutated_obj = copy.deepcopy(obj)
    mutator.walk_and_mutate(mutated_obj, False, config.default_placeholder_pattern)
    assert mutated_obj != obj, "dict should mutate"
    assert (
        plain_str in mutated_obj["1"]
    ), "string mutation should only apply for pattern in non-strict mode"
    assert (
        placeholder_str not in mutated_obj["1"]
    ), "string mutation not apply for plain text in non-strict mode"

    mutated_obj = copy.deepcopy(obj)
    mutator.walk_and_mutate(mutated_obj, False, "asdf")
    assert mutated_obj != obj, "dict should mutate"
    assert (
        plain_str not in mutated_obj["1"]
    ), "string mutation should apply for entire string if pattern is not matched in non-strict mode"
    assert (
        placeholder_str not in mutated_obj["1"]
    ), "string mutation should apply for entire string if pattern is not matched in non-strict mode"

    mutated_obj = copy.deepcopy(obj)
    mutator.walk_and_mutate(mutated_obj, True, None)
    assert mutated_obj == obj, "dict should not mutate if in strict mode but no pattern"


def test_mutate(mutator):
    state = mutator.state
    assert mutator.mutate(None) is None, "empty objects should not mutate"
    assert state == mutator.state, "mutator state should not change"

    obj = {"type": "asdfa{adsf}"}
    assert mutator.mutate(obj) != obj, "objects should mutate"
    assert state == mutator.state, "mutator state should not change"
    assert mutator.mutate(obj) == mutator.mutate(
        obj
    ), "output should be identical since state has not changed"

    obj = "/some/shoopy/uri"
    assert mutator.mutate(obj) != obj, "strings should mutate"
    assert state == mutator.state, "mutator state should not change"
    assert mutator.mutate(obj) == mutator.mutate(
        obj
    ), "output should be identical since state has not changed"


def test_mutate_strict(mutator, config):
    base = "asdf/"
    placeholder = "{test}"
    obj = {"string": base + placeholder}
    mutated = mutator.mutate(obj, True, config.default_placeholder_pattern)
    assert mutated != obj, "object should mutate if in strict mode and has pattern"

    mutated = mutator.mutate(obj, True)
    assert mutated == obj, "object shouldn't mutate if in strict mode and no pattern"

    mutated = mutator.mutate(obj, True, "ffff")
    assert (
        mutated == obj
    ), "object shouldn't mutate if pattern not found in field and in strict mode"

    mutated = mutator.mutate(obj, pattern="ffff")
    assert mutated != obj, "object should mutate if not in strict mode"

    obj = "/some/nuby/uri/" + placeholder
    mutated = mutator.mutate(obj, True, config.default_placeholder_pattern)
    assert mutated != obj, "string should mutate if in strict mode and has pattern"

    mutated = mutator.mutate(obj, True)
    assert mutated == obj, "string shouldn't mutate if in strict mode and no pattern"

    mutated = mutator.mutate(obj, True, "ffff")
    assert (
        mutated == obj
    ), "string shouldn't mutate if pattern not found in field and in strict mode"

    mutated = mutator.mutate(obj, pattern="ffff")
    assert mutated != obj, "object should mutate if not in strict mode"


def test_mutate_regex_str(mutator, config):
    uri = "/my/{sherby}/{uri}"
    mutatedObj = mutator.mutate_regex(uri, config.default_placeholder_pattern)
    assert uri != mutatedObj, "uri should mutate"
    assert (
        re.search(config.default_placeholder_pattern, uri) is not None
    ), "uri should not contain placeholders"

    myPlaceholder = "asdf"
    mutatedObj = mutator.mutate_regex(uri, myPlaceholder)
    assert uri == mutatedObj, "uri should not mutate"
    assert re.search(myPlaceholder, uri) is None, "uri should contain placeholders"


def test_mutate_regex_obj(mutator, config):
    uri = "/json"
    with open(config.model_file, "r") as model_file:
        model = json.loads(model_file.read(), object_pairs_hook=OrderedDict)

    obj = Fuzzer.get_endpoints(model["endpoints"], uri)[0]["input"]["body"]
    staticValue = "stuff "
    dynamicValue = "{placeholder}"
    assert (
        re.search(config.default_placeholder_pattern, obj["dynamicField"]) is not None
    ), "obj should contain placeholder"
    assert (
        staticValue + dynamicValue in obj["dynamicField"]
    ), "field should contain string"
    mutatedObj = mutator.mutate(obj, pattern=config.default_placeholder_pattern)
    assert obj != mutatedObj, "obj should mutate"
    assert (
        re.search(config.default_placeholder_pattern, mutatedObj["dynamicField"])
        is None
    ), "mutatedObj should not contain placeholder"
    assert (
        staticValue in mutatedObj["dynamicField"]
    ), "mutatedObj field should not fuzzerest the part of the string which is not a placeholder"


def test_change_state(mutator):
    mutator.change_state(0)
    assert mutator.state == 0, "should be state=0 after setting the state to 0"

    rand_state = mutator.own_rand.getstate()
    first = mutator.own_rand.randint(0, sys.maxsize)
    assert (
        rand_state != mutator.own_rand.getstate()
    ), "the internal random state should change"
    assert first != mutator.own_rand.randint(
        0, sys.maxsize
    ), "should change after initial seed"

    mutator.change_state(0)
    assert (
        rand_state == mutator.own_rand.getstate()
    ), "the internal random state should match the initial state"
    assert first == mutator.own_rand.randint(
        0, sys.maxsize
    ), "should be the same output if the seed is the same"


def test_safe_decode(mutator):
    emoji = "🙂"
    assert mutator.safe_decode(emoji.encode()) == emoji.encode().decode(
        mutator.byte_encoding
    ), f'should properly decode "{emoji}" using {mutator.byte_encoding} encoding'
    mutator.byte_encoding = "ascii"
    assert mutator.safe_decode(emoji.encode()) == str(
        emoji.encode()
    ), f'should stringify "{emoji}" bytes because it cannot decode using {mutator.byte_encoding} byte encoding'
