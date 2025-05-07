# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import yaml
import copy
from typing import List
from knack.log import get_logger
from azext_confcom import config
from azext_confcom import oras_proxy
from azext_confcom.template_util import (
    case_insensitive_dict_get,
    extract_containers_from_text,
    extract_svn_from_text,
)

logger = get_logger(__name__)


# input is the full rego file as a string
# output is all of the containers in the rego files as a list of dictionaries
def combine_fragments_with_policy(all_fragments):
    out_fragments = []
    for fragment in all_fragments:
        container_text = extract_containers_from_text(fragment, "containers := ")
        container_text = container_text.replace("\t", "    ")
        containers = yaml.load(container_text, Loader=yaml.FullLoader)
        out_fragments.extend(containers)
    return out_fragments


def get_all_fragment_contents(
    image_names: List[str],
    fragment_imports: List[dict],
) -> List[str]:
    # was getting errors with pass by reference so we need to copy it
    copied_fragment_imports = copy.deepcopy(fragment_imports)

    def remove_from_list_via_feed(fragment_import_list, feed):
        for i, fragment_import in enumerate(fragment_import_list):
            if fragment_import.get("feed") == feed:
                fragment_import_list.pop(i)

    all_fragments_contents = []
    remaining_fragments = copied_fragment_imports.copy()
    # get all the image attached fragments
    for image in image_names:
        # TODO: make sure this doesn't error out if the images aren't in a registry.
        # This will probably be in the discover function
        image_attached_fragments, feeds = oras_proxy.pull_all_image_attached_fragments(image)
        for fragment, feed in zip(image_attached_fragments, feeds):
            all_feeds = [
                case_insensitive_dict_get(fragment, config.POLICY_FIELD_CONTAINERS_ELEMENTS_REGO_FRAGMENTS_FEED)
                for fragment in remaining_fragments
            ]
            feed_idx = all_feeds.index(feed) if feed in all_feeds else -1

            if feed_idx != -1:
                import_statement = remaining_fragments[feed_idx]

                if (
                    int(
                        case_insensitive_dict_get(
                            import_statement, config.POLICY_FIELD_CONTAINERS_ELEMENTS_REGO_FRAGMENTS_MINIMUM_SVN
                        )
                    ) <= extract_svn_from_text(fragment)
                ):
                    remove_from_list_via_feed(remaining_fragments, feed)
                    all_fragments_contents.append(fragment)
            else:
                logger.warning("Fragment feed %s not in list of feeds to use. Skipping fragment.", feed)
    # grab the remaining fragments which should be standalone
    standalone_fragments, _ = oras_proxy.pull_all_standalone_fragments(remaining_fragments)
    all_fragments_contents.extend(standalone_fragments)

    return combine_fragments_with_policy(all_fragments_contents)
