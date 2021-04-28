import copy
import os
import random
import re
from pathlib import Path
from subprocess import PIPE, STDOUT, Popen

from fuzzerest.config.config import Config


class Radamsa:
    def __init__(self, config: Config = Config()):
        self.config = config
        path = Path(os.environ.get("RADAMSA_BIN", self.config.radamsa_bin_path))
        self.ready = path.exists() and path.is_file()
        self.bin_path = str(path.resolve())
        if not self.ready:
            self.config.root_logger.error(
                "Unable to locate radamsa binary at %s", self.bin_path
            )

    def get(self, value: str, encoding: str, seed: int = -1) -> bytes:
        if not self.ready:
            self.config.root_logger.warning("Generating empty output")
            return b""

        if seed == -1:
            radamsa_process = Popen(
                [self.bin_path], stdout=PIPE, stdin=PIPE, stderr=STDOUT
            )
        else:
            radamsa_process = Popen(
                [self.bin_path, "-s", str(seed)],
                stdout=PIPE,
                stdin=PIPE,
                stderr=STDOUT,
            )

        return radamsa_process.communicate(input=value.encode(encoding))[0]


class Mutator:
    def __init__(
        self,
        fuzzdb_array: list = [],
        state=0,
        byte_encoding="unicode_escape",
        config: Config = Config(),
    ):
        self.config = config
        self.own_rand = random.Random()
        self.change_state(state)
        self.fuzzdb_array = fuzzdb_array if fuzzdb_array else config.fuzz_db_array
        self.byte_encoding = byte_encoding
        self.radamsa = Radamsa()

    def change_state(self, new_state):
        self.state = new_state
        self.own_rand.seed(self.state)

    def chance(self, probability):
        """Returns True x% of the time"""
        self.change_state(self.state)
        return self.own_rand.random() < probability

    def roll_dice(self, minimum, maximum):
        self.change_state(self.state)
        return self.own_rand.randint(minimum, maximum)

    def safe_decode(self, input_bytes):
        """
        Attempt to decode the input using byte_encoding. Return the value as a string if not possible.
        """
        try:
            output = input_bytes.decode(self.byte_encoding)
        except (UnicodeDecodeError, OverflowError):
            output = str(input_bytes)  # Leave it as it is

        return output

    def mutate_radamsa(self, value) -> str:
        """
        Mutate the value and encode the mutator output using byte_encoding.
        :param value: seed value for the mutator
        :param byte_encoding: name of the byte encoding method defined in the python encodings library
        :return:
        """
        return self.safe_decode(
            self.radamsa.get(str(value), self.byte_encoding, self.state)
        )

    def juggle_type(self, value):

        roll = self.roll_dice(1, 6)

        if roll == 1:  # String
            return str(value)

        if roll == 2:  # Boolean
            return self.chance(0.5)

        if roll == 3:  # Number
            try:
                return int(value)
            except ValueError:
                if self.chance(0.5):
                    return 1
                return 0

        if roll == 4:  # Array
            return [value]

        if roll == 5:  # Object
            return {str(value): value}

        if roll == 6:  # NoneType / null
            return None

    def pick_from_fuzzdb(self):
        roll = self.roll_dice(0, len(self.fuzzdb_array) - 1)

        return self.fuzzdb_array[roll]

    def mutate_val(self, value):
        roll = self.roll_dice(1, 3)

        if roll == 1:
            mutated_val = (
                self.mutate_radamsa(value)
                if self.radamsa.ready
                else self.pick_from_fuzzdb()
            )
        elif roll == 2:
            mutated_val = self.juggle_type(value)
        elif roll == 3:
            mutated_val = self.pick_from_fuzzdb()

        return mutated_val

    @staticmethod
    def list_obj_iterable(obj):
        if isinstance(obj, dict):
            return obj
        return range(len(obj))

    def mutate_regex(self, string, pattern):
        """
        Discards tokens matching the pattern and replaces them with mutations seeded by the preceding string value
        This works as long as the tokens in string are not sequential
        """
        tokens = re.split(pattern, string)
        mutated = ""
        for index, token in enumerate(tokens):
            mutated += token
            if index < len(tokens) - 1:
                mutated += str(self.mutate_val(token))
        return mutated

    def walk_and_mutate(self, obj, strict, pattern):
        for key in self.list_obj_iterable(obj):
            if isinstance(obj[key], (dict, list)):  # Not a single val, dig deeper
                self.walk_and_mutate(obj[key], strict, pattern)
            elif isinstance(obj[key], str) and pattern and re.search(pattern, obj[key]):
                obj[key] = self.mutate_regex(obj[key], pattern)
            elif not strict:
                obj[key] = self.mutate_val(obj[key])

    def mutate(self, obj, strict=False, pattern=None):
        """
        Main entry point
        :obj: Data structure to mutate, can be any type
        :strict: If true, values that are of type string will only be mutated where a substring matches the pattern
        :pattern: A string regex
        """

        if not obj:
            return obj
        elif isinstance(obj, str):
            if pattern and re.search(pattern, obj):
                obj = self.mutate_regex(obj, pattern)
            elif not strict:
                obj = self.mutate_val(obj)

            return obj
        else:
            obj_to_mutate = copy.deepcopy(obj)
            self.walk_and_mutate(obj_to_mutate, strict, pattern)
            return obj_to_mutate
