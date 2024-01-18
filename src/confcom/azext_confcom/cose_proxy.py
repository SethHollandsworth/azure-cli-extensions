# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import subprocess
from typing import List
import os
import stat
import sys
from pathlib import Path
import platform
from zipfile import ZipFile
import requests
import getpass
from azext_confcom.errors import eprint


host_os = platform.system()
machine = platform.machine()


class CoseSignToolProxy:  # pylint: disable=too-few-public-methods

    @staticmethod
    def download_binaries():
        dir_path = os.path.dirname(os.path.realpath(__file__))

        bin_folder = os.path.join(dir_path, "bin")
        if not os.path.exists(bin_folder):
            os.makedirs(bin_folder)

        # get the most recent release artifacts from github
        r = requests.get("https://api.github.com/repos/microsoft/CoseSignTool/releases")
        needed_assets = ["CoseSignTool-Windows-release.zip", "CoseSignTool-Linux-release.zip"]
        windows_flag = False
        linux_flag = False
        for release in r.json():
            # these should be newest to oldest
            for asset in release["assets"]:
                # download the file if it's what we want
                if asset["name"] in needed_assets:
                    if "Windows" in asset["name"]:
                        windows_flag = True
                    else:
                        linux_flag = True

                    last_dash = asset["name"].rfind("-")
                    save_name = asset["name"][:last_dash]

                    zip_url = asset["browser_download_url"]
                    r = requests.get(zip_url)
                    # save and unzip the file to the bin folder
                    with open(os.path.join(bin_folder, asset["name"]), "wb") as f:
                        f.write(r.content)
                    with ZipFile(os.path.join(bin_folder, asset["name"]), "r") as zip_ref:
                        zip_ref.extractall(os.path.join(bin_folder, save_name))
                    # remove the zip file
                    os.remove(os.path.join(bin_folder, asset["name"]))

            # stop early so we don't have to iterate through all releases
            if windows_flag and linux_flag:
                break


    def __init__(self):
        script_directory = os.path.dirname(os.path.realpath(__file__))
        DEFAULT_LIB = "./bin/CoseSignTool"

        if host_os == "Linux":
            DEFAULT_LIB += "-Linux/release/CoseSignTool"
        elif host_os == "Windows":
            DEFAULT_LIB += "-Windows/release/CoseSignTool.exe"
        elif host_os == "Darwin":
            eprint("The extension for MacOS has not been implemented.")
        else:
            eprint(
                "Unknown target platform. The extension only works with Windows and Linux"
            )

        self.policy_bin = Path(os.path.join(f"{script_directory}", f"{DEFAULT_LIB}"))

        # check if the extension binary exists
        if not os.path.exists(self.policy_bin):
            eprint("The extension binary file cannot be located.")
        if not os.access(self.policy_bin, os.X_OK):
            # add executable permissions for the current user if they don't exist
            st = os.stat(self.policy_bin)
            os.chmod(self.policy_bin, st.st_mode | stat.S_IXUSR)

    # Takes in a path to a fragment file and a path to a cert file
    # Writes a file called payload-file.csm to the current directory which is the payload COSE signed and wrapped
    # CoseSignTool has no expected stdout so we only print stderr if there is an error
    def cose_sign(
        self,
        payload_path: str,
        cert_path: str,
    ) -> bool:
        policy_bin_str = str(self.policy_bin)

        password = getpass.getpass("Enter password for certificate: ")
        # TODO: try this out with a password protected cert
        # TODO: figure out how to make it non-interactive for certs without a password
        arg_list = [policy_bin_str, "sign", "/Payload", payload_path, "/PfxCertificate", cert_path, "/Password", password, "/EmbedPayload", "/SignatureFile", "payload-file.csm"]

        item = subprocess.run(
            arg_list,
            stdout=sys.stdout,
            stderr=sys.stderr,
            check=False,
        )

        # get the exit code from the subprocess
        if item.returncode != 0:
            eprint("Error signing the policy fragment: ", item.stderr)
            sys.exit(item.returncode)

        return True
