# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import copy
import json
import os
from typing import Any, List, Dict
from azext_confcom.template_util import case_insensitive_dict_get
from azext_confcom import config
from azext_confcom.errors import eprint


_DEFAULT_MOUNTS = config.DEFAULT_MOUNTS_USER

_INJECTED_CUSTOMER_ENV_RULES = (
    config.OPENGCS_ENV_RULES
    + config.FABRIC_ENV_RULES
    + config.MANAGED_IDENTITY_ENV_RULES
    + config.ENABLE_RESTART_ENV_RULE
)


class ContainerImage:
    @classmethod
    def from_json(
        cls, container_json: Any, debug_mode: bool = False
    ) -> "ContainerImage":
        containerImage = case_insensitive_dict_get(
            container_json, config.ACI_FIELD_CONTAINERS_CONTAINERIMAGE
        )
        if not containerImage:
            eprint(
                f'Field ["{config.ACI_FIELD_CONTAINERS}"]'
                + f'["{config.ACI_FIELD_CONTAINERS_CONTAINERIMAGE}"] is empty or can not be found.'
            )

        id_val = case_insensitive_dict_get(container_json, config.ACI_FIELD_CONTAINERS_ID)

        environmentRules = []
        env_rules = case_insensitive_dict_get(
            container_json, config.ACI_FIELD_CONTAINERS_ENVS
        )
        if env_rules is None:  # empty(no envs) is acceptable
            eprint(
                f'Field ["{config.ACI_FIELD_CONTAINERS}"]'
                + f'["{config.ACI_FIELD_CONTAINERS_ENVS}"] is null or can not be found.'
            )

        # parse each environment variable pair and add it to list
        for rule in env_rules:
            name, value, strategy, required = (
                case_insensitive_dict_get(rule, config.ACI_FIELD_CONTAINERS_ENVS_NAME),
                case_insensitive_dict_get(rule, config.ACI_FIELD_CONTAINERS_ENVS_VALUE),
                case_insensitive_dict_get(
                    rule, config.ACI_FIELD_CONTAINERS_ENVS_STRATEGY
                ),
                case_insensitive_dict_get(
                    rule, config.ACI_FIELD_CONTAINERS_ENVS_REQUIRED
                ),
            )
            if name is None or value is None or strategy is None:
                eprint(
                    f'Field ["{config.ACI_FIELD_CONTAINERS}"]["{config.ACI_FIELD_CONTAINERS_ENVS}"] is incorrect.'
                )

            environmentRules.append(
                {
                    config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS_RULE: f"{name}={value}",
                    config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS_STRATEGY: strategy,
                    # default value for "required" is False
                    config.POLICY_FIELD_CONTAINERS_ELEMENTS_REQUIRED: required
                    if required is not None
                    else False,
                }
            )

        # parse command
        command = case_insensitive_dict_get(
            container_json, config.ACI_FIELD_CONTAINERS_COMMAND
        )
        if not isinstance(command, list):
            eprint(
                f'Field ["{config.ACI_FIELD_CONTAINERS}"]'
                + f'["{config.ACI_FIELD_CONTAINERS_COMMAND}"] must be list of Strings.'
            )

        # parse working directory
        workingDir = case_insensitive_dict_get(
            container_json, config.ACI_FIELD_CONTAINERS_WORKINGDIR
        )
        # check workingDir is an absolute path if user specified
        if workingDir:
            if not isinstance(workingDir, str):
                eprint(
                    f'Field ["{config.ACI_FIELD_CONTAINERS}"]'
                    + f'["{config.ACI_FIELD_CONTAINERS_WORKINGDIR}"] must be a String.'
                )
            if not os.path.isabs(workingDir):
                eprint(
                    f'Field ["{config.ACI_FIELD_CONTAINERS}"]'
                    + f'["{config.ACI_FIELD_CONTAINERS_WORKINGDIR}"] with value: {workingDir} is not absolute path.'
                )

        # parse mounts
        mounts = case_insensitive_dict_get(
            container_json, config.ACI_FIELD_CONTAINERS_MOUNTS
        )
        _mounts = []
        if mounts:
            if not isinstance(mounts, list):
                eprint(
                    f'Field ["{config.ACI_FIELD_CONTAINERS}"]'
                    + f'["{config.ACI_FIELD_CONTAINERS_MOUNTS}"] must be list of Mount configuration.'
                )

            for m in mounts:
                mount_type = case_insensitive_dict_get(
                    m, config.ACI_FIELD_CONTAINERS_MOUNTS_TYPE
                )
                if mount_type not in config.MOUNT_SOURCE_TABLE:
                    eprint(
                        f'Field ["{config.ACI_FIELD_CONTAINERS}"]'
                        + f'["{config.ACI_FIELD_CONTAINERS_MOUNTS}"]'
                        + f'["{config.ACI_FIELD_CONTAINERS_MOUNTS_TYPE}"]'
                        + "can only be following values:"
                        + f'{",".join(list(config.MOUNT_SOURCE_TABLE.keys()))} .'
                    )

                mount_path = case_insensitive_dict_get(
                    m, config.ACI_FIELD_CONTAINERS_MOUNTS_PATH
                )
                if not mount_path:
                    eprint(
                        f'Field ["{config.ACI_FIELD_CONTAINERS}"]'
                        + f'["{config.ACI_FIELD_CONTAINERS_MOUNTS}"]'
                        + f'["{config.ACI_FIELD_CONTAINERS_MOUNTS_PATH}"] is empty or can not be found.'
                    )

                mount_readonly = case_insensitive_dict_get(
                    m, config.ACI_FIELD_CONTAINERS_MOUNTS_READONLY
                )
                if mount_readonly is not None and not isinstance(mount_readonly, bool):
                    eprint(
                        f'Field ["{config.ACI_FIELD_CONTAINERS}"]'
                        + f'["{config.ACI_FIELD_CONTAINERS_MOUNTS}"]'
                        + f'["{config.ACI_FIELD_CONTAINERS_MOUNTS_READONLY}"] can only be boolean value.'
                    )

                # readonly default to False if not specified
                if mount_readonly is None:
                    mount_readonly = False

                _mounts.append(m)

        _allow_elevated = case_insensitive_dict_get(
            container_json, config.ACI_FIELD_CONTAINERS_ALLOW_ELEVATED
        )
        if _allow_elevated:
            if not isinstance(_allow_elevated, bool):
                eprint(
                    f'Field ["{config.ACI_FIELD_CONTAINERS}"]'
                    + f'["{config.ACI_FIELD_CONTAINERS_ALLOW_ELEVATED}"] can only be boolean value.'
                )
        else:
            # default is allow_elevated should be true
            _allow_elevated = True

        if ":" in containerImage:
            base = containerImage.split(":")[0]
        else:
            base = containerImage

        # get the exec_processes info used as a liveness probe
        exec_processes = case_insensitive_dict_get(
            container_json, config.ACI_FIELD_CONTAINERS_EXEC_PROCESSES
        )
        exec_processes_output = []
        if exec_processes:
            if not isinstance(exec_processes, list):
                eprint(
                    f'Field ["{config.ACI_FIELD_CONTAINERS}"]'
                    + f'["{config.ACI_FIELD_CONTAINERS_EXEC_PROCESSES}"] can only be a list.'
                )

            for exec_processes_item in exec_processes:

                exec_command = case_insensitive_dict_get(
                    exec_processes_item, config.ACI_FIELD_CONTAINERS_COMMAND
                )
                if not isinstance(exec_command, list) and all(
                    map(lambda x: isinstance(x, str), exec_command)
                ):
                    eprint(
                        f'Field ["{config.ACI_FIELD_CONTAINERS}"]'
                        + f'["{config.ACI_FIELD_CONTAINERS_EXEC_PROCESSES}"]'
                        + f'["{config.ACI_FIELD_CONTAINERS_COMMAND}"]'
                        + "can only be a list of strings."
                    )

                exec_signals = case_insensitive_dict_get(
                    exec_processes_item,
                    config.ACI_FIELD_CONTAINERS_SIGNAL_CONTAINER_PROCESSES,
                )
                if not isinstance(exec_signals, list) and all(
                    map(lambda x: isinstance(x, int), exec_signals)
                ):
                    eprint(
                        f'Field ["{config.ACI_FIELD_CONTAINERS}"]'
                        + f'["{config.ACI_FIELD_CONTAINERS_EXEC_PROCESSES}"]'
                        + f'["{config.ACI_FIELD_CONTAINERS_COMMAND}"]'
                        + "can only be a list of integers."
                    )

                # can either be bool or undefined so give it a default value of False if not a sidecar
                default_exec_stdio = (
                    True if base in config.BASELINE_SIDECAR_CONTAINERS else debug_mode
                )
                exec_stdio_value = case_insensitive_dict_get(
                    exec_processes_item, config.ACI_FIELD_CONTAINERS_ALLOW_STDIO_ACCESS
                )
                exec_stdio_access = (
                    exec_stdio_value
                    if exec_stdio_value is not None
                    else default_exec_stdio
                )

                if not isinstance(exec_stdio_access, bool):
                    eprint(
                        f'Field ["{config.ACI_FIELD_CONTAINERS}"]'
                        + f'["{config.ACI_FIELD_CONTAINERS_EXEC_PROCESSES}"]'
                        + f'["{config.ACI_FIELD_CONTAINERS_ALLOW_STDIO_ACCESS}"]'
                        + "can only be a boolean."
                    )

                exec_processes_output.append(
                    {
                        config.POLICY_FIELD_CONTAINERS_ELEMENTS_COMMANDS: exec_command,
                        config.POLICY_FIELD_CONTAINER_SIGNAL_CONTAINER_PROCESSES: exec_signals,
                        config.POLICY_FIELD_CONTAINERS_ALLOW_STDIO_ACCESS: exec_stdio_access,
                    }
                )

        # get the signals info used as a liveness probe
        signals = (
            case_insensitive_dict_get(
                container_json, config.ACI_FIELD_CONTAINERS_SIGNAL_CONTAINER_PROCESSES
            )
            or []
        )
        if signals:
            if not isinstance(signals, list):
                eprint(
                    f'Field ["{config.ACI_FIELD_CONTAINERS}"]'
                    + '["{config.ACI_FIELD_CONTAINERS_SIGNAL_CONTAINER_PROCESSES}"]'
                    + "can only be a list."
                )

            for signals_item in signals:
                if not isinstance(signals_item, int):
                    eprint(
                        f'Field ["{config.ACI_FIELD_CONTAINERS}"]'
                        + '["{config.ACI_FIELD_CONTAINERS_SIGNAL_CONTAINER_PROCESSES}"]'
                        + "can only be an integer."
                    )

        # get the field for Standard IO access, default to true
        allow_stdio_value = case_insensitive_dict_get(
            container_json, config.ACI_FIELD_CONTAINERS_ALLOW_STDIO_ACCESS
        )
        allow_stdio_access = (
            allow_stdio_value if allow_stdio_value is not None else True
        )

        return ContainerImage(
            containerImage=containerImage,
            environmentRules=environmentRules,
            command=command,
            workingDir=workingDir,
            mounts=_mounts,
            allow_elevated=_allow_elevated,
            extraEnvironmentRules=[],
            execProcesses=exec_processes_output,
            signals=signals,
            allowStdioAccess=allow_stdio_access,
            id_val=id_val,
        )

    def __init__(
        self,
        containerImage: str,
        environmentRules: Dict,
        command: List[str],
        workingDir: str,
        mounts: List,
        allow_elevated: bool,
        id_val: str,
        extraEnvironmentRules: Dict,
        allowStdioAccess: bool = False,
        execProcesses: List = None,
        signals: List = None,
    ) -> None:
        self.containerImage = containerImage
        if ":" in containerImage:
            self.base, self.tag = containerImage.split(":")
        else:
            self.base, self.tag = containerImage, "latest"
        self._environmentRules = environmentRules
        self._command = command
        self._workingDir = workingDir
        self._layers = []
        self._mounts = mounts
        self._allow_elevated = allow_elevated
        self._allow_stdio_access = allowStdioAccess
        self._policy_json = None
        self._policy_json_str = None
        self._policy_json_str_pp = None
        self._identifier = id_val
        self._exec_processes = execProcesses or []
        self._signals = signals or []
        self._extraEnvironmentRules = extraEnvironmentRules

    def get_policy_json(self) -> str:
        if not self._policy_json:
            self._policy_json_serialization()

        return self._policy_json

    def get_id(self) -> str:
        return self._identifier

    def get_working_dir(self) -> str:
        return self._workingDir

    def set_working_dir(self, workingDir: str) -> None:
        self._workingDir = workingDir

    def get_command(self) -> List[str]:
        return self._command

    def set_command(self, command: List[str]) -> None:
        self._command = command

    def get_environment_rules(self) -> Dict:
        return self._environmentRules

    def get_layers(self) -> List[str]:
        return self._layers

    def set_layers(self, layers: List[str]) -> None:
        self._layers = layers

    def get_mounts(self) -> List:
        return self._mounts

    def set_extra_environment_rules(self, rules: Dict) -> None:
        self._extraEnvironmentRules = rules

    def _get_environment_rules(self) -> List[Dict[str, Any]]:
        out_rules = copy.deepcopy(self._environmentRules)
        env_var_names = [
            var[config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS_RULE].split("=")[0]
            for var in out_rules
        ]
        for rule in self._extraEnvironmentRules:
            if rule[config.ACI_FIELD_CONTAINERS_ENVS_NAME] not in env_var_names:
                out_rules.append(
                    {
                        config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS_RULE:
                        f"{rule[config.ACI_FIELD_CONTAINERS_ENVS_NAME]}="
                        + f"{rule[config.ACI_FIELD_CONTAINERS_ENVS_VALUE]}",
                        config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS_STRATEGY: rule[
                            config.ACI_FIELD_CONTAINERS_ENVS_STRATEGY
                        ],
                        config.POLICY_FIELD_CONTAINERS_ELEMENTS_REQUIRED: rule[
                            config.ACI_FIELD_CONTAINERS_ENVS_REQUIRED
                        ],
                    }
                )

        return out_rules

    def _get_mounts_json(self) -> Dict[str, Any]:
        # if mount is empty, return None
        if not self._mounts:
            return None

        mounts = []

        for m in self._mounts:
            mount = copy.deepcopy(config.DEFAULT_MOUNT_POLICY)
            mount[
                config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS_SOURCE
            ] = config.MOUNT_SOURCE_TABLE[
                case_insensitive_dict_get(m, config.ACI_FIELD_TEMPLATE_MOUNTS_TYPE)
            ]
            mount[
                config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS_DESTINATION
            ] = case_insensitive_dict_get(m, config.ACI_FIELD_TEMPLATE_MOUNTS_PATH)
            if case_insensitive_dict_get(
                m, "readonly"
            ) is not None and case_insensitive_dict_get(m, "readonly"):
                mount[config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS_OPTIONS][2] = "ro"
            # specified options will overwrite default options in default mount policy
            if case_insensitive_dict_get(m, "options"):
                mount[
                    config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS_OPTIONS
                ] = case_insensitive_dict_get(m, "options")
            # TODO: figure out what type of mount it is for secretsSource. For now, assume it is a bind mount
            mount[
                config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS_TYPE
            ] = config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS_TYPE_BIND
            mounts.append(mount)

        return mounts

    def _populate_policy_json_elements(self) -> Dict[str, Any]:
        elements = {
            config.POLICY_FIELD_CONTAINERS_ID: self._identifier,
            config.POLICY_FIELD_CONTAINERS_ELEMENTS_LAYERS: self._layers,
            config.POLICY_FIELD_CONTAINERS_ELEMENTS_COMMANDS: self._command,
            config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS: self._get_environment_rules(),
            config.POLICY_FIELD_CONTAINERS_ELEMENTS_WORKINGDIR: self._workingDir,
            config.POLICY_FIELD_CONTAINERS_ELEMENTS_ALLOW_ELEVATED: self._allow_elevated,
            config.POLICY_FIELD_CONTAINER_EXEC_PROCESSES: self._exec_processes,
            config.POLICY_FIELD_CONTAINER_SIGNAL_CONTAINER_PROCESSES: self._signals,
            config.POLICY_FIELD_CONTAINERS_ALLOW_STDIO_ACCESS: self._allow_stdio_access,
        }
        mounts = self._get_mounts_json()
        # mounts are optional, if it is None, remove it from the policy
        if mounts:
            elements[config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS] = mounts

        self._policy_json = elements
        return self._policy_json

    def _policy_json_serialization(self):
        policy = self._populate_policy_json_elements()
        # serialize json policy to object, compact string and pretty print string
        self._policy_json_str, self._policy_json_str_pp = (
            json.dumps(policy, separators=(",", ":"), sort_keys=True),
            json.dumps(policy, indent=2, sort_keys=True),
        )


class UserContainerImage(ContainerImage):
    @classmethod
    def from_json(
        cls, container_json: Any, debug_mode: bool = False
    ) -> "UserContainerImage":
        image = super().from_json(container_json, debug_mode=debug_mode)
        image.__class__ = UserContainerImage
        # inject default mounts for user container
        if image.base not in config.BASELINE_SIDECAR_CONTAINERS:
            image.get_mounts().extend(_DEFAULT_MOUNTS)

        image.set_extra_environment_rules(_INJECTED_CUSTOMER_ENV_RULES)
        return image

    def __init__(
        self,
        containerImage: str,
        environmentRules: Dict,
        command: List[str],
        mounts: List[Dict],
        workingDir: str,
        allowElevated: bool,
        id_val: str,
        execProcesses: List = None,
        signals: List = None,
        extraEnvironmentRules: Dict = _INJECTED_CUSTOMER_ENV_RULES,
    ) -> None:
        super().__init__(
            containerImage=containerImage,
            environmentRules=environmentRules,
            command=command,
            mounts=mounts,
            workingDir=workingDir,
            allow_elevated=allowElevated,
            id_val=id_val,
            signals=signals or [],
            extraEnvironmentRules=extraEnvironmentRules,
            execProcesses=execProcesses or [],
        )

    def _populate_policy_json_elements(self) -> Dict[str, Any]:
        elements = super()._populate_policy_json_elements()
        self._policy_json = elements

        return self._policy_json
