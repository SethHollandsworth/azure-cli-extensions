# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import subprocess
import json
import platform
from azext_confcom.errors import eprint
from azext_confcom.config import ARTIFACT_TYPE
from azext_confcom.cose_proxy import CoseSignToolProxy

host_os = platform.system()
machine = platform.machine()


# discover if there are policy artifacts associated with the image
# return their digests in a list if there are some
def discover(
    image: str,
) -> bool:
    arg_list = ["oras", "discover", image, "-o", "json", "--artifact-type", ARTIFACT_TYPE]

    item = subprocess.run(
        arg_list,
        check=False,
        capture_output=True,
    )

    hashes = []

    if item.returncode == 0:
        json_output = json.loads(item.stdout.decode("utf-8"))
        manifests = json_output["manifests"]
        for manifest in manifests:
            hashes.append(manifest["digest"])
    # get the exit code from the subprocess
    else:
        if "401: Unauthorized" in item.stderr.decode("utf-8"):
            eprint(
                f"Error pulling the policy fragment from {image}.\n\n"
                + "Please log into the registry and try again.\n\n"
            )
        eprint(f"Error retrieving fragments from remote repo: {item.stderr.decode('utf-8')}", exit_code=item.returncode)
    return hashes


# pull the policy fragment from the remote repo and return its contents as a string
def pull(
    image: str,
    image_hash: str,
) -> str:
    if "@sha256:" in image:
        image = image.split("@")[0]
    arg_list = ["oras", "pull", f"{image}@{image_hash}"]

    item = subprocess.run(
        arg_list,
        check=False,
        capture_output=True,
    )

    # get the exit code from the subprocess
    if item.returncode != 0:
        if "401: Unauthorized" in item.stderr.decode("utf-8"):
            eprint(
                f"Error pulling the policy fragment: {image}@{image_hash}.\n\n"
                + "Please log into the registry and try again.\n\n"
            )
        eprint(f"Error while pulling fragment: {item.stderr.decode('utf-8')}", exit_code=item.returncode)

    # extract the file name from stdout
    lines = item.stdout.decode("utf-8").splitlines()
    for line in lines:
        if "Downloaded" in line:
            filename = line.split(" ")[-1]
            break

    return filename


def pull_all_image_attached_fragments(image):
    # TODO: be smart about if we're pulling a fragment directly or trying to discover them from an image tag
    # TODO: this will be for standalone fragments
    fragments = discover(image)
    fragment_contents = []
    proxy = CoseSignToolProxy()
    for fragment_digest in fragments:
        filename = pull(image, fragment_digest)
        text = proxy.extract_payload_from_path(filename)
        # containers = extract_containers_from_text(text, REGO_CONTAINER_START)
        # new_fragments = extract_containers_from_text(text, REGO_FRAGMENT_START)
        # if new_fragments:
        #     for new_fragment in new_fragments:
        #         feed = new_fragment.get("feed")
        #         # if we don't have the feed in the list of feeds we've already pulled, pull it
        #         if feed not in fragment_feeds:
        #             fragment_contents.extend(pull_all_image_attached_fragments(feed, fragment_feeds=fragment_feeds))
        fragment_contents.append(text)
    return fragment_contents


def check_oras_cli():
    item = subprocess.run(["oras", "version"], check=True, capture_output=True)

    if item.returncode != 0:
        eprint(
            "ORAS CLI not installed. Please install ORAS CLI: https://oras.land/docs/installation"
        )


def attach_fragment_to_image(image_name: str, filename: str):
    if ":" not in image_name:
        image_name += ":latest"
    # attach the fragment to the image
    item = subprocess.run(
        ["oras", "attach", "--artifact-type", ARTIFACT_TYPE, image_name, filename],
        check=False,
        capture_output=True,
    )
    if item.returncode != 0:
        eprint(f"Could not attach fragment to image: {image_name}. Failed with {item.stderr}")

    # extract digest from stdout
    digest = item.stdout.decode("utf8").strip("\n").split("\n")[-1]
    print(f"Fragment attached to image '{image_name}' with {digest}")
