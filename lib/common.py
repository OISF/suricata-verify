"""Shared runner helpers for Suricata verify runners."""

import os
import platform
import shutil
import subprocess
import filecmp
import json
import re


class UnsatisfiedRequirementError(Exception):
    pass


class ImpossibleRequirementError(Exception):
    pass


def check_required_commands(requires, unsatisfied_error=UnsatisfiedRequirementError):
    """Validate host command requirements from a requires mapping."""
    if not isinstance(requires, dict):
        raise ValueError("requires must be a mapping")
    commands = requires.get("command", [])
    if commands is None:
        return
    if not isinstance(commands, list) or any(
        not isinstance(command, str) for command in commands
    ):
        raise ValueError("requires.command must be an array of strings")
    for command in commands:
        if shutil.which(command) is None:
            raise unsatisfied_error("requires command {}".format(command))


def check_requires(
    requires,
    suricata_config,
    is_version_compatible,
    test_dir=None,
    version_is_lt=None,
    eval_globals=None,
    unsatisfied_error=UnsatisfiedRequirementError,
    impossible_error=ImpossibleRequirementError,
    unknown_error=ValueError,
    unknown_message="unknown requires type: {key}",
    gt_message="for version greater than {version}",
    script_message="requires script returned false",
    include_script_error=False,
):
    """Validate a test requires mapping.

    Runner-specific version parsing is supplied by is_version_compatible so this
    helper can be shared by both the classic and live runners.
    """
    check_required_commands(requires, unsatisfied_error)

    if (
        version_is_lt is not None
        and "gt-version" in requires
        and "lt-version" in requires
        and not version_is_lt(requires["gt-version"], requires["lt-version"])
    ):
        raise impossible_error(
            "test has both lt-version {} and gt-version {}".format(
                requires["lt-version"], requires["gt-version"]
            )
        )

    suri_version = suricata_config.version
    for key in requires:
        if key == "min-version":
            min_version = requires["min-version"]
            if not is_version_compatible(min_version, suri_version, "gte"):
                raise unsatisfied_error(
                    "requires at least version {}".format(min_version)
                )
        elif key == "lt-version":
            lt_version = requires["lt-version"]
            if not is_version_compatible(lt_version, suri_version, "lt"):
                raise unsatisfied_error("for version less than {}".format(lt_version))
        elif key == "gt-version":
            gt_version = requires["gt-version"]
            if not is_version_compatible(gt_version, suri_version, "gt"):
                raise unsatisfied_error(gt_message.format(version=gt_version))
        elif key == "version":
            req_version = requires["version"]
            if not is_version_compatible(req_version, suri_version, "equal"):
                raise unsatisfied_error("only for version {}".format(req_version))
        elif key == "features":
            for feature in requires["features"]:
                if not suricata_config.has_feature(feature):
                    raise unsatisfied_error("requires feature {}".format(feature))
        elif key == "command":
            pass
        elif key == "env":
            for env in requires["env"]:
                if env not in os.environ:
                    raise unsatisfied_error("requires env var {}".format(env))
        elif key == "files":
            for filename in requires["files"]:
                if test_dir and not os.path.isabs(filename):
                    filename = os.path.join(test_dir, filename)
                if not os.path.exists(filename):
                    raise unsatisfied_error("requires file {}".format(filename))
        elif key == "script":
            for script in requires["script"]:
                try:
                    subprocess.check_call("{}".format(script), shell=True)
                except Exception as err:
                    if include_script_error:
                        raise unsatisfied_error(
                            "{}: {}".format(script_message, err)
                        ) from err
                    raise unsatisfied_error(script_message)
        elif key == "pcap":
            pass
        elif key == "lambda":
            if eval_globals is None:
                lambda_result = eval(requires["lambda"])
            else:
                lambda_result = eval(requires["lambda"], eval_globals)
            if not lambda_result:
                raise unsatisfied_error(requires["lambda"])
        elif key == "os":
            cur_platform = platform.system().lower()
            if not cur_platform.startswith(requires["os"].lower()):
                raise unsatisfied_error(requires["os"])
        elif key == "arch":
            cur_arch = platform.machine().lower()
            if not cur_arch.startswith(requires["arch"].lower()):
                raise unsatisfied_error(requires["arch"])
        else:
            raise unknown_error(unknown_message.format(key=key))

COMPARISON_OPERATORS = {
    "__gt": ">",
    "__gte": ">=",
    "__lt": "<",
    "__lte": "<=",
}

MATCH_OPERATORS = (
    "__contains",
    "__find",
    "__startswith",
    "__endswith",
)


class CheckResult:
    """Result returned by shared check implementations."""

    def __init__(self, failures=None, warnings=None):
        self.failures = list(failures or [])
        self.warnings = list(warnings or [])

    def ok(self):
        return not self.failures


def _comparison_operators(comparison_operators=None):
    return comparison_operators or COMPARISON_OPERATORS


def _operator_suffixes(comparison_operators=None):
    return set(MATCH_OPERATORS) | set(_comparison_operators(comparison_operators))


def _validate_keys(config, allowed, check_type):
    for key in config:
        if key not in allowed:
            raise ValueError("Unexpected key in {} check: {}".format(check_type, key))


def find_value(name, obj, comparison_operators=None):
    """Find the value in an object for a field specified by name.

    Example names:
      event_type
      alert.signature_id
      smtp.rcpt_to[0]
    """
    parts = name.split(".")
    operator_suffixes = _operator_suffixes(comparison_operators)
    for part in parts:
        if part == "__len":
            try:
                return len(obj)
            except Exception:
                return -1

        if part in operator_suffixes:
            break

        index = None
        m = re.match(r"^(.*)\[(\d+)\]$", part)
        if m:
            key = m.group(1)
            index = m.group(2)
        else:
            key = part

        if not isinstance(obj, dict) or key not in obj:
            return None
        obj = obj[key]

        if index is not None:
            try:
                obj = obj[int(index)]
            except Exception:
                return None

    return obj


def get_comparison_operator(key, comparison_operators=None):
    """Return the comparison operator suffix from a check key, if present."""
    suffix = key.rsplit(".", 1)[-1]
    if suffix in _comparison_operators(comparison_operators):
        return suffix
    return None


def compare_values(actual, expected, operator):
    """Compare two numeric values using a comparison operator suffix."""
    if isinstance(actual, bool) or isinstance(expected, bool):
        return False
    if not isinstance(actual, (int, float)) or not isinstance(expected, (int, float)):
        return False
    if operator == "__gt":
        return actual > expected
    if operator == "__gte":
        return actual >= expected
    if operator == "__lt":
        return actual < expected
    if operator == "__lte":
        return actual <= expected
    raise ValueError("unknown comparison operator: {}".format(operator))


def _as_list(value):
    if isinstance(value, list):
        return value
    return [value]


def _contains(value, expected):
    if value is None:
        return False
    try:
        return expected in value
    except TypeError:
        return False


def match_event(config, event, comparison_operators=None, type_mismatch_callback=None):
    for key, expected in config["match"].items():
        if key == "has-key":
            for item in _as_list(expected):
                if find_value(item, event, comparison_operators) is None:
                    return False
        elif key == "not-has-key":
            for item in _as_list(expected):
                if find_value(item, event, comparison_operators) is not None:
                    return False
        else:
            val = find_value(key, event, comparison_operators)
            if key.endswith("__find"):
                if val is None or str(val).find(str(expected)) < 0:
                    return False
            elif key.endswith("__contains"):
                if not _contains(val, expected):
                    return False
            elif key.endswith("__startswith"):
                if val is None or not str(val).startswith(str(expected)):
                    return False
            elif key.endswith("__endswith"):
                if val is None or not str(val).endswith(str(expected)):
                    return False
            else:
                operator = get_comparison_operator(key, comparison_operators)
                if operator is not None:
                    if not compare_values(val, expected, operator):
                        return False
                elif val != expected:
                    if (
                        type_mismatch_callback is not None
                        and str(val) == str(expected)
                    ):
                        type_mismatch_callback(val, expected)
                    return False
    return True


def check_requirements(
    requires,
    require_checker=None,
    suricata_config=None,
    test_dir=None,
    skip_as_warning=False,
    skip_message=None,
):
    if require_checker is None:
        return CheckResult()
    try:
        require_checker(requires, suricata_config, test_dir)
    except UnsatisfiedRequirementError as err:
        if skip_as_warning:
            if skip_message is None:
                skip_message = "SKIP: check skipped: {}"
            return CheckResult(warnings=[skip_message.format(err)])
        raise
    return CheckResult()


class StatsCheck:
    """Check values in the last stats event of eve.json."""

    def __init__(self, config, output_dir, comparison_operators=None):
        self.config = config
        self.output_dir = output_dir
        self.comparison_operators = comparison_operators

    def run(self):
        eve_json_path = os.path.join(self.output_dir, "eve.json")
        if not os.path.exists(eve_json_path):
            return CheckResult(failures=["eve.json not found: {}".format(eve_json_path)])

        stats = None
        with open(eve_json_path, "r", encoding="utf-8") as fileobj:
            for line in fileobj:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") == "stats":
                    stats = event["stats"]

        if stats is None:
            return CheckResult(failures=["no stats event found in eve.json"])

        failures = []
        for key, expected in self.config.items():
            val = find_value(key, stats, self.comparison_operators)
            operator = get_comparison_operator(key, self.comparison_operators)
            if operator is not None:
                if not compare_values(val, expected, operator):
                    symbol = _comparison_operators(self.comparison_operators)[operator]
                    failures.append(
                        "stats.{}: expected {} {}; got {}".format(
                            key, symbol, expected, val
                        )
                    )
            elif val != expected:
                failures.append(
                    "stats.{}: expected {}; got {}".format(key, expected, val)
                )
        return CheckResult(failures=failures)


class FileCompareCheck:
    def __init__(self, config, directory, output_dir, windows=False):
        _validate_keys(config, ["requires", "filename", "expected"], "file-compare")
        self.config = config
        self.directory = directory
        self.output_dir = output_dir
        self.windows = windows

    def run(self):
        if self.windows:
            raise UnsatisfiedRequirementError("shell check not supported on Windows")

        expected = os.path.join(self.directory, self.config["expected"])
        filename = self.config["filename"]
        if self.output_dir and not os.path.isabs(filename):
            filename = os.path.join(self.output_dir, filename)
        try:
            if filecmp.cmp(expected, filename):
                return CheckResult()
            return CheckResult(
                failures=[
                    "{} {} \nFAILED: verification failed".format(expected, filename)
                ]
            )
        except Exception as err:
            return CheckResult(
                failures=["file-compare check failed with exception: {}".format(err)]
            )


class ShellCheck:
    """Run a shell command in the test output directory."""

    def __init__(
        self,
        config,
        env,
        output_dir,
        suricata_config=None,
        test_dir=None,
        require_checker=None,
        skip_as_warning=False,
        use_bash=False,
        windows=False,
    ):
        _validate_keys(config, ["requires", "args", "expect"], "shell")
        self.config = config
        self.env = env
        self.output_dir = output_dir
        self.suricata_config = suricata_config
        self.test_dir = test_dir
        self.require_checker = require_checker
        self.skip_as_warning = skip_as_warning
        self.use_bash = use_bash
        self.windows = windows

    def run(self):
        if not self.config or "args" not in self.config:
            return CheckResult(failures=["shell check missing args"])

        requires = self.config.get("requires", {})
        result = check_requirements(
            requires,
            self.require_checker,
            self.suricata_config,
            self.test_dir,
            self.skip_as_warning,
            "SKIP: shell check skipped: {}",
        )
        if result.warnings:
            return result

        if self.windows:
            if self.skip_as_warning:
                return CheckResult(
                    warnings=["SKIP: shell check skipped: shell check not supported on Windows"]
                )
            raise UnsatisfiedRequirementError("shell check not supported on Windows")

        if self.use_bash:
            cmd = ["bash", "-c", self.config["args"]]
            run_kwargs = {"shell": False}
        else:
            cmd = self.config["args"]
            run_kwargs = {"shell": True}

        completed = subprocess.run(
            cmd,
            cwd=self.output_dir,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=False,
            **run_kwargs
        )
        if completed.returncode != 0:
            details = []
            if completed.stdout.strip():
                details.append("stdout={!r}".format(completed.stdout.strip()))
            if completed.stderr.strip():
                details.append("stderr={!r}".format(completed.stderr.strip()))
            suffix = " ({})".format(", ".join(details)) if details else ""
            return CheckResult(
                failures=[
                    "shell command failed with exit code {}: {!r}{}".format(
                        completed.returncode, self.config["args"], suffix
                    )
                ]
            )

        if "expect" in self.config:
            output = completed.stdout.strip()
            if str(self.config["expect"]) != output:
                return CheckResult(
                    failures=[
                        "shell check expected {!r}; got {!r}".format(
                            self.config["expect"], output
                        )
                    ]
                )

        return CheckResult()


class FilterCheck:
    """Filter JSON lines output and count matching events."""

    def __init__(
        self,
        config,
        output_dir,
        suricata_config=None,
        test_dir=None,
        require_checker=None,
        skip_as_warning=False,
        test_version=None,
        version_compat_checker=None,
        comparison_operators=None,
        type_mismatch_callback=None,
    ):
        _validate_keys(
            config, ["count", "match", "filename", "requires", "comment"], "filter"
        )
        self.config = config
        self.output_dir = output_dir
        self.suricata_config = suricata_config
        self.test_dir = test_dir
        self.require_checker = require_checker
        self.skip_as_warning = skip_as_warning
        self.test_version = test_version
        self.version_compat_checker = version_compat_checker
        self.comparison_operators = comparison_operators
        self.type_mismatch_callback = type_mismatch_callback

    def run(self):
        if "count" not in self.config:
            return CheckResult(failures=["filter check missing count"])
        if "match" not in self.config:
            return CheckResult(failures=["filter check missing match"])

        requires = self.config.get("requires", {})
        if self.version_compat_checker is not None:
            self.version_compat_checker(requires, self.test_version)
        result = check_requirements(
            requires,
            self.require_checker,
            self.suricata_config,
            self.test_dir,
            self.skip_as_warning,
            "SKIP: filter check skipped: {}",
        )
        if result.warnings:
            return result

        if "filename" in self.config:
            json_filename = self.config["filename"]
            if not os.path.isabs(json_filename):
                json_filename = os.path.join(self.output_dir, json_filename)
        else:
            json_filename = os.path.join(self.output_dir, "eve.json")
        if not os.path.exists(json_filename):
            return CheckResult(failures=["{} does not exist".format(json_filename)])

        count = 0
        try:
            with open(json_filename, "r", encoding="utf-8") as fileobj:
                for line in fileobj:
                    event = json.loads(line)
                    if self.match(event):
                        count += 1
        except Exception as err:
            return CheckResult(
                failures=["filter check failed for {}: {}".format(json_filename, err)]
            )

        if count == self.config["count"]:
            return CheckResult()
        if "comment" in self.config:
            return CheckResult(
                failures=[
                    "{}: expected {}, got {}".format(
                        self.config["comment"], self.config["count"], count
                    )
                ]
            )
        return CheckResult(
            failures=[
                "expected {} matches; got {} for filter {}".format(
                    self.config["count"], count, self.config
                )
            ]
        )

    def match(self, event):
        return match_event(
            self.config,
            event,
            self.comparison_operators,
            self.type_mismatch_callback,
        )
