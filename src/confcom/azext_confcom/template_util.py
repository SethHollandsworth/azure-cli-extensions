import re
import json
from typing import Any, Tuple, Dict, List
import deepdiff
import yaml
from azext_confcom.errors import (
    eprint,
)
from azext_confcom import os_util
from azext_confcom import config


def case_insensitive_dict_get(dictionary, search_key) -> Any:
    # if the cases happen to match, immediately return .get() result
    possible_match = dictionary.get(search_key)
    if possible_match:
        return possible_match
    # case insensitive get and return reference instead of just value
    for key in dictionary.keys():
        if key.lower() == search_key.lower():
            return dictionary[key]
    return None


def readable_diff(diff_dict) -> Dict[str, Any]:
    # need to rename fields in the deep diff to be more accessible to customers
    name_translation = {
        "values_changed": "values_changed",
        "iterable_item_removed": "values_removed",
        "iterable_item_added": "values_added",
    }

    human_readable_diff = {}
    # iterate through the possible types of changes i.e. "iterable_item_removed"
    for category in diff_dict:
        new_name = case_insensitive_dict_get(name_translation, category) or category
        if case_insensitive_dict_get(human_readable_diff, category) is None:
            human_readable_diff[new_name] = {}
        # sometimes the output will be an array, this next chunk doesn't work for that case in its current state
        if isinstance(diff_dict[category], dict):
            # search for the area of the ARM Template with the change i.e. "mounts" or "env_rules"
            for key in diff_dict[category]:
                key = str(key)
                key_name = re.search(r"'(.*?)'", key).group(1)
                human_readable_diff[new_name].setdefault(key_name, []).append(
                    diff_dict[category][key]
                )

    return change_key_names(human_readable_diff)


def compare_containers(container1, container2) -> Dict[str, Any]:
    """Utility method: see if the container in test_policy
    would be allowed to run under the rules of the 'self' policy"""

    diff = deepdiff.DeepDiff(
        container1,
        container2,
    )
    # cast to json using built-in function in deepdiff so there's safe translation
    # e.g. a type will successfully cast to string
    return readable_diff(json.loads(diff.to_json()))


def change_key_names(dictionary) -> Dict:
    """Recursive function to rename keys wherever they are in the output diff dictionary"""
    # need to rename fields in the deep diff to be more accessible to customers
    name_translation = {
        "old_value": "policy_value",
        "new_value": "tested_value",
    }

    if isinstance(dictionary, (str, int)):
        return None
    if isinstance(dictionary, list):
        for item in dictionary:
            change_key_names(item)
    if isinstance(dictionary, dict):
        keys = list(dictionary.keys())
        for key in keys:
            if key in name_translation:
                dictionary[name_translation[key]] = dictionary.pop(key)
                key = name_translation[key]
            # go through the rest of the keys in case the objects are nested
            change_key_names(dictionary[key])
    return dictionary


def find_value_in_params_and_vars(params: dict, vars_dict: dict, search: str) -> str:
    """Utility function: either returns the input search value,
    or replaces it with the defined value in either params or vars of the ARM template"""
    # this pattern might need to be updated for more naming options in the future
    # pattern = "(parameters|variables)\('([\w\-\_0-9]+)'\)"
    pattern = r"(?:parameters|variables)\(\s*'([^\.\/]+?)'\s*\)"
    param_name = re.findall(pattern, search)

    if not param_name:
        return search

    # this could be updated in the future if more than one variable/parameter is used in one value
    param_name = param_name[0]

    # figure out if we need to search in variables or parameters

    match = ""
    if config.ACI_FIELD_TEMPLATE_PARAMETERS in search:

        param_value = case_insensitive_dict_get(params, param_name)

        if not param_value:
            eprint(
                f"""Field ["{param_name}"] not found in ["{config.ACI_FIELD_TEMPLATE_PARAMETERS}"]
                 or ["{config.ACI_FIELD_TEMPLATE_VARIABLES}"]"""
            )
        # fallback to default value
        match = case_insensitive_dict_get(
            param_value, "value"
        ) or case_insensitive_dict_get(param_value, "defaultValue")
    else:
        match = case_insensitive_dict_get(vars_dict, param_name)

    if not match:
        eprint(
            f"""Field ["{param_name}"] not found in ["{config.ACI_FIELD_TEMPLATE_PARAMETERS}"]
             or ["{config.ACI_FIELD_TEMPLATE_VARIABLES}"]"""
        )

    return match


def parse_template(params: dict, vars_dict: dict, template) -> Any:
    """Utility function: replace all instances of variable and parameter references in an ARM template
    current limitations:
        - object values for parameters and variables
        - template functions
        - complex values for parameters and variables
        - parameter and variables names might not be recognized all the time
    """
    if isinstance(template, dict):
        for key, value in template.items():
            if isinstance(value, str):
                template[key] = find_value_in_params_and_vars(params, vars_dict, value)
            elif isinstance(value, dict):
                parse_template(params, vars_dict, value)
            elif isinstance(value, list):
                for i, _ in enumerate(value):
                    template[key][i] = parse_template(params, vars_dict, value[i])
    return template


def extract_containers_from_text(text, start) -> str:
    """Utility function: extract the container and fragment
    information from the string version of a rego file.
     The contained information is assumed to be an array between square brackets"""
    start_index = text.find(start)
    ending = text[start_index + len(start):]

    count = bracket_count = 0
    character = ending[count]
    flag = True
    # kind of an FSM to get everything between starting square bracket and end
    while bracket_count > 0 or flag:
        count += 1
        # make sure we're ending on the correct end bracket
        if character == "[":
            bracket_count += 1
            flag = False
        elif character == "]":
            bracket_count -= 1

        if count == len(ending):
            # throw error, invalid rego file
            break
        character = ending[count]
    # get everything between the square brackets
    return ending[:count]


def extract_confidential_properties(
    container_group_properties,
) -> Tuple[List[Dict], List[Dict]]:
    container_start = "containers := "
    fragment_start = "fragments := "
    # extract the existing cce policy if that's what was being asked
    confidential_compute_properties = case_insensitive_dict_get(
        container_group_properties, config.ACI_FIELD_TEMPLATE_CONFCOM_PROPERTIES
    )

    if confidential_compute_properties is None:
        eprint(
            f"""Field ["{config.ACI_FIELD_TEMPLATE_CONFCOM_PROPERTIES}"]
             not found in ["{config.ACI_FIELD_TEMPLATE_PROPERTIES}"]"""
        )

    cce_policy = case_insensitive_dict_get(
        confidential_compute_properties, config.ACI_FIELD_TEMPLATE_CCE_POLICY
    )
    # special case when "ccePolicy" field is blank, indicating the use of the "allow all" policy
    if not cce_policy:
        return ([], config.DEFAULT_REGO_FRAGMENTS)

    cce_policy = os_util.base64_to_str(cce_policy)
    # error check that the decoded policy existing in the template is not in JSON format
    try:
        json.loads(cce_policy)
        eprint(
            """The existing security policy within the ARM Template
             is not in the expected Rego format when decoded from base64"""
        )
    except json.decoder.JSONDecodeError:
        # this is expected, we do not want json
        pass

    try:
        container_text = extract_containers_from_text(cce_policy, container_start)
        # replace tabs with 4 spaces, YAML parser can take in JSON with trailing commas but not tabs
        # so we need to get rid of the tabs
        container_text = container_text.replace("\t", "    ")

        containers = yaml.load(container_text, Loader=yaml.FullLoader)

        fragment_text = extract_containers_from_text(
            cce_policy, fragment_start
        ).replace("\t", "    ")

        fragments = yaml.load(
            fragment_text,
            Loader=yaml.FullLoader,
        )
    except yaml.YAMLError:
        # reading the rego file failed, so we'll just return the default outputs
        containers = []
        fragments = []

    return (containers, fragments)


# making these lambda print functions looks cleaner than having "json.dumps" 6 times
def print_func(x: dict) -> str:
    print("x: ", x)

    return json.dumps(x, separators=(",", ":"), sort_keys=True)


def pretty_print_func(x: dict) -> str:
    return json.dumps(x, indent=2, sort_keys=True)


def is_sidecar(image_name: str) -> bool:
    return image_name.split(":")[0] in config.BASELINE_SIDECAR_CONTAINERS


def compare_env_vars(
    id_val, env_list1: List[Dict[str, Any]], env_list2: List[Dict[str, Any]]
) -> Dict[str, List[str]]:
    reason_list = {}
    policy_env_rules_regex = [
        case_insensitive_dict_get(i, config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS_RULE)
        for i in env_list1
        if case_insensitive_dict_get(
            i, config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS_STRATEGY
        )
        == "re2"
    ]

    policy_env_rules_str = [
        case_insensitive_dict_get(i, config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS_RULE)
        for i in env_list1
        if case_insensitive_dict_get(
            i, config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS_STRATEGY
        )
        == "string"
    ]

    # check that all env vars in the container match rules that are present in the policy
    for env_rule in env_list2:
        # case where rule with strategy string is not in the policy's list of string rules
        # we need to check if it fits one of the patterns in the regex list
        if (
            case_insensitive_dict_get(
                env_rule, config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS_STRATEGY
            )
            == "string"
            and case_insensitive_dict_get(
                env_rule, config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS_RULE
            )
            not in policy_env_rules_str
        ):
            # check if the env var matches any of the regex rules
            matching = False
            for pattern in policy_env_rules_regex:
                matching = matching or re.search(
                    pattern,
                    case_insensitive_dict_get(
                        env_rule, config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS_RULE
                    ),
                )
                if matching:
                    break

            if not matching:
                # create the env_rules entry in the diff output if it doesn't exist
                reason_list.setdefault(id_val, {})
                # add this to the list of rules violating policy
                reason_list[id_val].setdefault(
                    config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS, []
                ).append(
                    "environment variable with rule "
                    + f"'{case_insensitive_dict_get(env_rule, config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS_RULE)}' "
                    + "does not match strings or regex in policy rules"
                )
        # make sure all the regex patterns are included in the policy too
        elif (
            case_insensitive_dict_get(
                env_rule, config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS_STRATEGY
            )
            == "re2"
            and case_insensitive_dict_get(
                env_rule, config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS_RULE
            )
            not in policy_env_rules_regex
        ):
            # create the env_rules entry in the diff output if it doesn't exist
            reason_list.setdefault(id_val, {})
            # add this to the list of rules violating policy
            reason_list[id_val].setdefault(
                config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS, []
            ).append(
                "environment variable with rule "
                + f"'{case_insensitive_dict_get(env_rule, config.POLICY_FIELD_CONTAINERS_ELEMENTS_ENVS_RULE)}' "
                + "is not in the policy"
            )
    return reason_list


def inject_policy_into_template(
    arm_template_path: str, policy: str, count: int
) -> bool:
    write_flag = False
    input_arm_json = os_util.load_json_from_file(arm_template_path)

    # find the image names and extract them from the template
    arm_resources = case_insensitive_dict_get(
        input_arm_json, config.ACI_FIELD_RESOURCES
    )

    if not arm_resources:
        eprint(f"Field [{config.ACI_FIELD_RESOURCES}] is empty or cannot be found")

    aci_list = [
        item
        for item in arm_resources
        if item["type"] == config.ACI_FIELD_TEMPLATE_RESOURCE_LABEL
    ]

    if not aci_list:
        eprint(
            f'Field ["type"] must contain value of ["{config.ACI_FIELD_TEMPLATE_RESOURCE_LABEL}"]'
        )

    resource = aci_list[count]
    container_group_name = case_insensitive_dict_get(
        resource, config.ACI_FIELD_RESOURCES_NAME
    )
    container_group_properties = case_insensitive_dict_get(
        resource, config.ACI_FIELD_TEMPLATE_PROPERTIES
    )

    # extract the existing cce policy if that's what was being asked
    confidential_compute_properties = case_insensitive_dict_get(
        container_group_properties, config.ACI_FIELD_TEMPLATE_CONFCOM_PROPERTIES
    )

    if confidential_compute_properties is None:
        eprint(
            f"""Field ["{config.ACI_FIELD_TEMPLATE_CONFCOM_PROPERTIES}"]
            not found in ["{config.ACI_FIELD_TEMPLATE_PROPERTIES}"]"""
        )

    cce_policy = case_insensitive_dict_get(
        confidential_compute_properties, config.ACI_FIELD_TEMPLATE_CCE_POLICY
    )
    # special case when "ccePolicy" field is blank, indicating the use of the "allow all" policy
    if not cce_policy:
        confidential_compute_properties[config.ACI_FIELD_TEMPLATE_CCE_POLICY] = policy
        write_flag = True
    else:
        user_input = input(
            f"""Do you want to overwrite the CCE Policy currently in container group
             "{container_group_name}" in the ARM Template? (y/n) """
        )
        if user_input.lower() == "y":
            confidential_compute_properties[
                config.ACI_FIELD_TEMPLATE_CCE_POLICY
            ] = policy
            write_flag = True
    if write_flag:
        os_util.write_json_to_file(arm_template_path, input_arm_json)
        return True
    return False
