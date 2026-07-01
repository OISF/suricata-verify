"""Shared requirement checks for Suricata verify runners."""

import os
import platform
import shutil
import subprocess


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
