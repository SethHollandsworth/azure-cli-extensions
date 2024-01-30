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
        DEFAULT_LIB = "./bin/sign1util"

        if host_os == "Linux":
            DEFAULT_LIB += ""
        elif host_os == "Windows":
            DEFAULT_LIB += ".exe"
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

    def cose_sign(
        self,
        payload_path: str,
        key_path: str,
        cert_path: str,
        feed: str,
        iss: str,
        out_path: str = "payload.rego.cose",
    ) -> bool:
        policy_bin_str = str(self.policy_bin)

        arg_list = [policy_bin_str, "create", "-algo", "ES384", "-chain", cert_path, "-claims", payload_path, "-key", key_path, "-out", out_path,]

        if feed:
            arg_list.extend(["-feed", feed])

        if iss:
            arg_list.extend(["-issuer", iss])

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

    def get_payload(
        self,
        signature_path: str,
    ) -> str:
        policy_bin_str = str(self.policy_bin)

        arg_list = [policy_bin_str, "get", "/SignatureFile", signature_path, "/Roots", "/RevocationMode", "none"]

        item = subprocess.run(
            arg_list,
            stdout=sys.stdout,
            stderr=sys.stderr,
            check=False,
        )

        # get the exit code from the subprocess
        if item.returncode != 0:
            eprint("Error getting the policy fragment: ", item.stderr)
            sys.exit(item.returncode)

        return item.stdout.decode("utf-8")

    def create_issuer(self, cert_path: str) -> str:
        policy_bin_str = str(self.policy_bin)

        arg_list = [policy_bin_str, "did-x509", "-chain", cert_path, "-policy", "CN"]

        print("arg_list: ", arg_list)

        item = subprocess.run(
            arg_list,
            stdout=sys.stdout,
            stderr=sys.stderr,
            check=False,
        )

        # get the exit code from the subprocess
        if item.returncode != 0:
            eprint("Error creating the issuer: ", item.stderr)
            sys.exit(item.returncode)

        return item.stdout.decode("utf-8")