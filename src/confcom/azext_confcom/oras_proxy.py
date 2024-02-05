# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import subprocess
import json
import sys
import platform
from azext_confcom.errors import eprint


host_os = platform.system()
machine = platform.machine()


# discover if there are policy artifacts associated with the image
# return their digests in a list if there are some
def discover(
    image: str,
) -> bool:
    arg_list = ["oras", "discover", image, "-o", "json", "--artifact-type", "policy/fragment"]

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
        eprint("Error retrieving fragments from remote repo: ", item.stderr)
        sys.exit(item.returncode)

    return hashes

# pull the policy fragment from the remote repo and return its contents as a string
def pull(
    image: str,
    image_hash: str,
) -> str:
    arg_list = ["oras", "pull", f"{image}@{image_hash}"]

    item = subprocess.run(
        arg_list,
        check=False,
        capture_output=True,
    )

    # get the exit code from the subprocess
    if item.returncode != 0:
        # TODO: fix this so eprint can take a custom exit code
        if "401: Unauthorized" in item.stderr.decode("utf-8"):
            eprint(
                f"Error pulling the policy fragment: {image}@{image_hash}.\n\n"
                + "Please log into the registry and try again.\n\n"
            )
        eprint(f"Error while pulling fragment: {item.stderr.decode('utf-8')}")
        sys.exit(item.returncode)

    # extract the file name from stdout
    lines = item.stdout.decode("utf-8").splitlines()
    for line in lines:
        if "Downloaded" in line:
            file_name = line.split(" ")[-1]
            break

    text = ""
    with open(file_name, "r") as f:
        text = f.read()

    return text

def pull_all_image_attached_fragments(image):
    fragments = discover(image)
    for fragment_digest in fragments:
        fragment_content = pull(image, fragment_digest)
        print("fragment: ", fragment_content)
