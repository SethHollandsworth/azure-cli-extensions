# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------


import subprocess
from typing import List
import os
import sys
import stat
from pathlib import Path
import platform
import requests
from knack.log import get_logger
from azext_confcom.errors import eprint


host_os = platform.system()
machine = platform.machine()
logger = get_logger(__name__)


class VirtualKubeletProxy:  # pylint: disable=too-few-public-methods
    arm_template_path = ""
    @staticmethod
    # TODO: update this to pull from new repo
    def download_binaries():
        dir_path = os.path.dirname(os.path.realpath(__file__))

        bin_folder = os.path.join(dir_path, "bin")
        if not os.path.exists(bin_folder):
            os.makedirs(bin_folder)

        # get the most recent release artifacts from github
        r = requests.get("https://api.github.com/repos/microsoft/hcsshim/releases")
        bin_flag = False
        exe_flag = False
        # search for dmverity-vhd in the assets from hcsshim releases
        for release in r.json():
            # these should be newest to oldest
            for asset in release["assets"]:
                # download the file if it contains dmverity-vhd
                if "dmverity-vhd" in asset["name"]:
                    if "exe" in asset["name"]:
                        exe_flag = True
                    else:
                        bin_flag = True
                    # get the download url for the dmverity-vhd file
                    exe_url = asset["browser_download_url"]
                    # download the file
                    r = requests.get(exe_url)
                    # save the file to the bin folder
                    with open(os.path.join(bin_folder, asset["name"]), "wb") as f:
                        f.write(r.content)
            if bin_flag and exe_flag:
                break

    def __init__(self):
        script_directory = os.path.dirname(os.path.realpath(__file__))
        DEFAULT_LIB = "./bin/podspec-to-arm"

        if host_os == "Linux":
            pass
        elif host_os == "Windows":
            if machine.endswith("64"):
                DEFAULT_LIB += ".exe"
            else:
                eprint(
                    "32-bit Windows is not supported."
                )
        elif host_os == "Darwin":
            eprint("The extension for MacOS has not been implemented.")
        else:
            eprint(
                "Unknown target platform. The extension only works with Windows, Linux and MacOS"
            )

        self.policy_bin = Path(os.path.join(f"{script_directory}", f"{DEFAULT_LIB}"))

        # check if the extension binary exists
        if not os.path.exists(self.policy_bin):
            eprint("The extension binary file cannot be located.")
        if not os.access(self.policy_bin, os.X_OK):
            # add executable permissions for the current user if they don't exist
            st = os.stat(self.policy_bin)
            os.chmod(self.policy_bin, st.st_mode | stat.S_IXUSR)

    def get_arm_template_path(self) -> str:
        return VirtualKubeletProxy.arm_template_path

    def generate_arm_template(
        self,
        virtual_kubelet_yaml_path: str,
        configmaps: str = "",
        kubernetes_port: str = "",
        kubernetes_port_tcp: str = "",
        kubernetes_port_tcp_addr: str = "",
        kubernetes_port_tcp_proto: str = "",
        kubernetes_service_host: str = "",
        kubernetes_service_port: str = "",
        kubernetes_service_port_https: str = "",
        kubernetes_tcp_port: str = "",
        output_file_name: str = "",
        print_json: str = "",
        secrets: str = "",
    ) -> None:

        VirtualKubeletProxy.arm_template_path = output_file_name
        policy_bin_str = str(self.policy_bin)

        arg_list = [
            f"{policy_bin_str}", f"{virtual_kubelet_yaml_path}",
        ]

        if configmaps:
            arg_list += ["--configmaps", f"{configmaps}"]
        if kubernetes_port:
            arg_list += ["--kubernetes-port", f"{kubernetes_port}"]
        if kubernetes_port_tcp:
            arg_list += ["--kubernetes-port-tcp", f"{kubernetes_port_tcp}"]
        if kubernetes_port_tcp_addr:
            arg_list += ["--kubernetes-port-tcp-addr", f"{kubernetes_port_tcp_addr}"]
        if kubernetes_port_tcp_proto:
            arg_list += ["--kubernetes-port-tcp-proto", f"{kubernetes_port_tcp_proto}"]
        if kubernetes_service_host:
            arg_list += ["--kubernetes-service-host", f"{kubernetes_service_host}"]
        if kubernetes_service_port:
            arg_list += ["--kubernetes-service-port", f"{kubernetes_service_port}"]
        if kubernetes_service_port_https:
            arg_list += ["--kubernetes-service-port-https", f"{kubernetes_service_port_https}"]
        if kubernetes_tcp_port:
            arg_list += ["--kubernetes-tcp-port", f"{kubernetes_tcp_port}"]
        if output_file_name:
            arg_list += ["--output-file-name", f"{output_file_name}"]
        if print_json:
            arg_list += ["--print-json", f"{print_json}"]
        if secrets:
            arg_list += ["--secrets", f"{secrets}"]

        item = subprocess.run(
            arg_list,
            capture_output=True,
            check=False,
        )

        if item.returncode != 0:
            if item.stderr.decode("utf-8") != "" and item.stderr.decode("utf-8") is not None:
                logger.warning(item.stderr.decode("utf-8"))
            sys.exit(item.returncode)

        return
