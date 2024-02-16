# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import os
import unittest
import json
import subprocess

from azext_confcom.security_policy import (
    UserContainerImage,
    OutputType,
    load_policy_from_config_str
)

import azext_confcom.config as config
from azext_confcom.template_util import (
    case_insensitive_dict_get,
    extract_containers_and_fragments_from_text,
)
from azext_confcom.custom import acifragmentgen_confcom
import yaml
from azure.cli.testsdk import ScenarioTest

TEST_DIR = os.path.abspath(os.path.join(os.path.abspath(__file__), ".."))


class FragmentMountEnforcement(unittest.TestCase):
    custom_json = """
    {
        "version": "1.0",
        "containers": [
            {
                "name": "test-container",
                "image": "alpine:3.16",
                "environmentVariables": [
                    {
                        "name": "PATH",
                        "value": "/customized/path/value"
                    },
                    {
                        "name": "TEST_REGEXP_ENV",
                        "value": "test_regexp_env_[[:alpha:]]*",
                        "regex": true
                    }
                ],
                "command": ["rustc", "--help"],
                "volumeMounts": [
                    {
                        "name": "azurefile",
                        "mountPath": "/mount/azurefile",
                        "readonly": true
                    }
                ]
            }
        ]
    }
    """
    aci_policy = None

    @classmethod
    def setUpClass(cls):
        with load_policy_from_config_str(cls.custom_json) as aci_policy:
            aci_policy.populate_policy_content_for_all_images()
            cls.aci_policy = aci_policy

    def test_fragment_user_container_customized_mounts(self):
        # TODO: add another mount
        image = next(
            (
                img
                for img in self.aci_policy.get_images()
                if isinstance(img, UserContainerImage) and img.base == "alpine"
            ),
            None,
        )

        self.assertIsNotNone(image)
        data = image.get_policy_json()


        self.assertEqual(
            len(
                case_insensitive_dict_get(
                    data, config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS
                )
            ),
            1,
        )
        mount = case_insensitive_dict_get(
            data, config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS
        )[0]
        self.assertIsNotNone(mount)
        # self.assertEqual(
        #     case_insensitive_dict_get(mount, "source"),
        #     "sandbox:///tmp/atlas/azureFileVolume/.+",
        # )
        self.assertEqual(
            case_insensitive_dict_get(
                mount, config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS_DESTINATION
            ),
            "/etc/resolv.conf",
        )
        self.assertEqual(
            mount[config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS_OPTIONS][2], "rw"
        )

    def test_fragment_user_container_mount_injected_dns(self):
        image = next(
            (
                img
                for img in self.aci_policy.get_images()
                if isinstance(img, UserContainerImage) and img.base == "alpine"
            ),
            None,
        )

        self.assertIsNotNone(image)
        data = image.get_policy_json()
        self.assertEqual(
            len(
                case_insensitive_dict_get(
                    data, config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS
                )
            ),
            1,
        )
        mount = case_insensitive_dict_get(
            data, config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS
        )[0]
        self.assertIsNotNone(mount)
        self.assertEqual(
            case_insensitive_dict_get(
                mount, config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS_SOURCE
            ),
            "sandbox:///tmp/atlas/resolvconf/.+",
        )
        self.assertEqual(
            case_insensitive_dict_get(
                mount, config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS_DESTINATION
            ),
            "/etc/resolv.conf",
        )
        self.assertEqual(
            mount[config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS_OPTIONS][2], "rw"
        )


class FragmentGenerating(unittest.TestCase):
    custom_json = """
      {
        "version": "1.0",
        "containers": [
            {
                "name": "sidecar-container",
                "image": "mcr.microsoft.com/aci/msi-atlas-adapter:master_20201203.1",
                "environmentVariables": [
                {
                    "name": "IDENTITY_API_VERSION",
                    "value": ".+",
                    "regex": true
                },
                {
                    "name": "IDENTITY_HEADER",
                    "value": ".+",
                    "regex": true
                },
                {
                    "name": "IDENTITY_SERVER_THUMBPRINT",
                    "value": ".+",
                    "regex": true
                },
                {
                    "name": "ACI_MI_CLIENT_ID_.+",
                    "value": ".+",
                    "regex": true
                },
                {
                    "name": "ACI_MI_RES_ID_.+",
                    "value": ".+",
                    "regex": true
                },
                {
                    "name": "HOSTNAME",
                    "value": ".+",
                    "regex": true
                },
                {
                    "name": "TERM",
                    "value": "xterm",
                    "regex": false
                },
                {
                    "name": "PATH",
                    "value": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                },
                {
                    "name": "(?i)(FABRIC)_.+",
                    "value": ".+",
                    "regex": true
                },
                {
                    "name": "Fabric_Id+",
                    "value": ".+",
                    "regex": true
                },
                {
                    "name": "Fabric_ServiceName",
                    "value": ".+",
                    "regex": true
                },
                {
                    "name": "Fabric_ApplicationName",
                    "value": ".+",
                    "regex": true
                },
                {
                    "name": "Fabric_CodePackageName",
                    "value": ".+",
                    "regex": true
                },
                {
                    "name": "Fabric_ServiceDnsName",
                    "value": ".+",
                    "regex": true
                },
                {
                    "name": "ACI_MI_DEFAULT",
                    "value": ".+",
                    "regex": true
                },
                {
                    "name": "TokenProxyIpAddressEnvKeyName",
                    "value": "[ContainerToHostAddress|Fabric_NodelPOrFQDN]",
                    "regex": true
                },
                {
                    "name": "ContainerToHostAddress",
                    "value": "sidecar-container"
                },
                {
                    "name": "Fabric_NetworkingMode",
                    "value": ".+",
                    "regex": true
                },
                {
                    "name": "azurecontainerinstance_restarted_by",
                    "value": ".+",
                    "regex": true
                }
            ],
            "command": ["/bin/sh","-c","until ./msiAtlasAdapter; do echo $? restarting; done"],
            "mounts": null
            }
        ]
    }
    """
    aci_policy = None

    @classmethod
    def setUpClass(cls):
        with load_policy_from_config_str(cls.custom_json) as aci_policy:
            aci_policy.populate_policy_content_for_all_images()
            cls.aci_policy = aci_policy

    def test_fragment_injected_sidecar_container_msi(self):
        image = self.aci_policy.get_images()[0]
        env_vars = [
            {
                "name": "IDENTITY_API_VERSION",
                "value": ".+",
            },
            {
                "name": "IDENTITY_HEADER",
                "value": ".+",
            },
            {
                "name": "IDENTITY_SERVER_THUMBPRINT",
                "value": ".+",
            },
            {
                "name": "ACI_MI_CLIENT_ID_.+",
                "value": ".+",
            },
            {
                "name": "ACI_MI_RES_ID_.+",
                "value": ".+",
            },
            {
                "name": "HOSTNAME",
                "value": ".+",
            },
            {
                "name": "TERM",
                "value": "xterm",
            },
            {
                "name": "PATH",
                "value": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            },
            {
                "name": "(?i)(FABRIC)_.+",
                "value": ".+",
            },
            {
                "name": "Fabric_Id+",
                "value": ".+",
            },
            {
                "name": "Fabric_ServiceName",
                "value": ".+",
            },
            {
                "name": "Fabric_ApplicationName",
                "value": ".+",
            },
            {
                "name": "Fabric_CodePackageName",
                "value": ".+",
            },
            {
                "name": "Fabric_ServiceDnsName",
                "value": ".+",
            },
            {
                "name": "ACI_MI_DEFAULT",
                "value": ".+",
            },
            {
                "name": "TokenProxyIpAddressEnvKeyName",
                "value": "[ContainerToHostAddress|Fabric_NodelPOrFQDN]",
            },
            {
                "name": "ContainerToHostAddress",
                "value": "sidecar-container",
            },
            {
                "name": "Fabric_NetworkingMode",
                "value": ".+",
            },
            {
                "name": "azurecontainerinstance_restarted_by",
                "value": ".+",
            }
        ]
        command = ["/bin/sh", "-c", "until ./msiAtlasAdapter; do echo $? restarting; done"]
        self.assertEqual(image.base, "mcr.microsoft.com/aci/msi-atlas-adapter")
        self.assertIsNotNone(image)

        self.assertEqual(image._command, command)
        for env_var in env_vars:
            env_names = map(lambda x: x['pattern'], image._environmentRules + image._extraEnvironmentRules)
            self.assertIn(env_var['name'] + "=" + env_var['value'], env_names)

        expected_workingdir = "/root/"
        self.assertEqual(image._workingDir, expected_workingdir)

    # def test_sign_and_upload(self):
    #     # generate a key and certificate
    #     subprocess.run("openssl genrsa -out key.pem 2048", shell=True)
    #     subprocess.run("openssl req -new -key key.pem -out csr.pem -subj '/CN=example.com'", shell=True)
    #     subprocess.run("openssl x509 -req -in csr.pem -signkey key.pem -out cert.pem", shell=True)
    #     # sign the fragment
    #     acifragmentgen_confcom(image="mcr.microsoft.com/aci/msi-atlas-adapter:master_20201210.1", key="key.pem", chain="cert.pem", namespace="test", svn="1", output_filename="signed_fragment.rego", upload_fragment=True)

    #     self.assertTrue(os.path.exists("signed_fragment.rego"))
    #     self.assertTrue(os.path.exists("signed_fragment.rego.cose"))

    #     # see if the fragment is uploaded
    #     # TODO: figure out how to do an oras pull from the local registry



class FragmentPolicyGeneratingDebugMode(unittest.TestCase):
    custom_json = """
      {
        "version": "1.0",
        "containers": [
            {
            "name": "test-container",
                "image": "python:3.6.14-slim-buster",
            "environmentVariables": [

            ],
            "command": ["python3"]
            }
        ]
    }
    """
    aci_policy = None

    @classmethod
    def setUpClass(cls):
        with load_policy_from_config_str(cls.custom_json, debug_mode=True) as aci_policy:
            aci_policy.populate_policy_content_for_all_images()
            cls.aci_policy = aci_policy

    def test_debug_processes(self):
        policy = self.aci_policy.get_serialized_output(
            output_type=OutputType.RAW, rego_boilerplate=True
        )
        self.assertIsNotNone(policy)

        # see if debug mode is enabled
        containers, _ = extract_containers_and_fragments_from_text(policy)
        yaml.load(containers, Loader=yaml.FullLoader)
        self.assertTrue(containers[0]["allow_stdio_access"])
        self.assertTrue(containers[0]["exec_processes"][0]["command"] == ["/bin/sh"])


class FragmentSidecarValidation(unittest.TestCase):
    custom_json = """
      {
    "version": "1.0",
    "containers": [
        {
            "image": "mcr.microsoft.com/aci/msi-atlas-adapter:master_20201210.1",
            "environmentVariables": [
                {
                    "name": "PATH",
                    "value": ".+",
                    "regex": true
                }
            ],
            "command": [
                "/bin/sh",
                "-c",
                "until ./msiAtlasAdapter; do echo $? restarting; done"
            ],
            "workingDir": "/root/",
            "mounts": null
        }
    ]
}
    """
    custom_json2 = """
      {
    "version": "1.0",
    "containers": [
        {
            "image": "mcr.microsoft.com/aci/msi-atlas-adapter:master_20201210.1",
            "environmentVariables": [
               {"name": "PATH",
               "value":"/",
               "strategy":"string"}
            ],
            "command": [
                "/bin/sh",
                "-c",
                "until ./msiAtlasAdapter; do echo $? restarting; done"
            ],
            "workingDir": "/root/",
            "mounts": null
        }
    ]
}
    """

    aci_policy = None
    existing_policy = None

    @classmethod
    def setUpClass(cls):
        with load_policy_from_config_str(cls.custom_json) as aci_policy:
            aci_policy.populate_policy_content_for_all_images()
            cls.aci_policy = aci_policy
        with load_policy_from_config_str(cls.custom_json2) as aci_policy2:
            aci_policy2.populate_policy_content_for_all_images()
            cls.aci_policy2 = aci_policy2

    def test_fragment_sidecar(self):
        print("self.aci_policy: ", self.aci_policy)

        is_valid, diff = self.aci_policy.validate_sidecars()
        print("diff: ", diff)

        self.assertTrue(is_valid)
        self.assertTrue(not diff)

    def test_fragment_sidecar_stdio_access_default(self):
        self.assertTrue(
            json.loads(
                self.aci_policy.get_serialized_output(
                    output_type=OutputType.RAW, rego_boilerplate=False
                )
            )[0][config.POLICY_FIELD_CONTAINERS_ELEMENTS_ALLOW_STDIO_ACCESS]
        )

    def test_fragment_incorrect_sidecar(self):

        is_valid, diff = self.aci_policy2.validate_sidecars()

        self.assertFalse(is_valid)
        expected_diff = {
            "mcr.microsoft.com/aci/msi-atlas-adapter:master_20201210.1": {
                "env_rules": [
                    "environment variable with rule "
                    + "'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'"
                    + " does not match strings or regex in policy rules"
                ]
            }
        }

        self.assertEqual(diff, expected_diff)


# class GenerateImport(unittest.TestCase):
#     # set up for the test class
#     def setUp(self):
#         subprocess.run("docker run -d -p 5000:5000 --restart=always --name registry ghcr.io/project-zot/zot-linux-amd64:latest", shell=True)
#         # create a test image
#         subprocess.run("docker pull mcr.microsoft.com/aks/e2e/library-busybox:master.220314.1-linux-amd64", shell=True)
#         subprocess.run("docker tag mcr.microsoft.com/aks/e2e/library-busybox:master.220314.1-linux-amd64 localhost:5000/library-busybox:master.220314.1-linux-amd64", shell=True)
#         subprocess.run("docker push localhost:5000/library-busybox:master.220314.1-linux-amd64", shell=True)
#         # TODO: build and sign fragment, upload to local registry at localhost:5000

#     def test_generate_import_local(self):
#         pass

#     def test_generate_import_remote(self):
#         pass


class InitialFragmentErrors(ScenarioTest):
    def test_invalid_input(self):
        with self.assertRaises(SystemExit) as wrapped_exit:
            self.cmd("az confcom acifragmentgen -i mcr.microsoft.com/aci/msi-atlas-adapter:master_20201210.1 -c fakepath/parameters.json")
        self.assertEqual(wrapped_exit.exception.code, 1)

        with self.assertRaises(SystemExit) as wrapped_exit:
            self.cmd("az confcom acifragmentgen --generate-import")

        with self.assertRaises(SystemExit) as wrapped_exit:
            self.cmd("az confcom acifragmentgen -i mcr.microsoft.com/aci/msi-atlas-adapter:master_20201210.1 -k fakepath/key.pem")
        self.assertEqual(wrapped_exit.exception.code, 1)



