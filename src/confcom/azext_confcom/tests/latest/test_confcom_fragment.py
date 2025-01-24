# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import os
from tarfile import TarFile
import tempfile
import unittest
import json
import requests
import time
import subprocess
from knack.util import CLIError

from azext_confcom.security_policy import (
    UserContainerImage,
    OutputType,
    load_policy_from_json
)
from azext_confcom.errors import (
    AccContainerError,
)
from azext_confcom.cose_proxy import CoseSignToolProxy
import azext_confcom.config as config
from azext_confcom.template_util import (
    case_insensitive_dict_get,
    extract_containers_and_fragments_from_text,
    decompose_confidential_properties,
)
from azext_confcom.os_util import (
    write_str_to_file,
    load_json_from_file,
    load_str_from_file,
    load_json_from_str,
    delete_silently,
    write_str_to_file,
    force_delete_silently,
    str_to_base64,
)
from azext_confcom.oras_proxy import push_fragment_to_registry
from azext_confcom.custom import acifragmentgen_confcom
from azure.cli.testsdk import ScenarioTest

from azext_confcom.tests.latest.test_confcom_tar import create_tar_file

TEST_DIR = os.path.abspath(os.path.join(os.path.abspath(__file__), ".."))

class FragmentMountEnforcement(unittest.TestCase):
    custom_json = """
    {
        "version": "1.0",
        "containers": [
            {
                "name": "test-container",
                "properties": {
                    "image": "mcr.microsoft.com/azurelinux/distroless/base:3.0",
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
                            "mountType": "azureFile",
                            "readonly": true
                        }
                    ]
                }
            }
        ]
    }
    """
    custom_json2 = """
{
  "version": "1.0",
  "fragments": [],
  "scenario": "vn2",
  "containers": [
    {
      "name": "simple-container",
      "properties": {
        "image": "mcr.microsoft.com/azurelinux/base/python:3.12",
        "environmentVariables": [
          {
            "name": "PATH",
            "value": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
          }
        ],
        "command": [
          "python3"
        ],
        "securityContext": {
            "allowPrivilegeEscalation": true,
            "privileged": true
        },
        "volumeMounts": [
          {
            "name": "logs",
            "mountType": "emptyDir",
            "mountPath": "/aci/logs",
            "readonly": false
          },
          {
            "name": "secret",
            "mountType": "emptyDir",
            "mountPath": "/aci/secret",
            "readonly": true
          }
        ]
      }
    }
  ]
}
    """
    aci_policy = None

    @classmethod
    def setUpClass(cls):
        with load_policy_from_json(cls.custom_json) as aci_policy:
            aci_policy.populate_policy_content_for_all_images()
            cls.aci_policy = aci_policy

    def test_fragment_user_container_customized_mounts(self):
        image = next(
            (
                img
                for img in self.aci_policy.get_images()
                if isinstance(img, UserContainerImage) and img.base == "mcr.microsoft.com/azurelinux/distroless/base"
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
            2,
        )
        mount = case_insensitive_dict_get(
            data, config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS
        )[0]
        resolv_mount = case_insensitive_dict_get(
            data, config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS
        )[1]
        self.assertIsNotNone(resolv_mount)
        self.assertEqual(
            case_insensitive_dict_get(mount, "source"),
            "sandbox:///tmp/atlas/azureFileVolume/.+",
        )
        self.assertEqual(
            case_insensitive_dict_get(
                resolv_mount, config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS_DESTINATION
            ),
            "/etc/resolv.conf",
        )
        self.assertEqual(
            resolv_mount[config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS_OPTIONS][2], "rw"
        )

    def test_fragment_user_container_mount_injected_dns(self):
        image = next(
            (
                img
                for img in self.aci_policy.get_images()
                if isinstance(img, UserContainerImage) and img.base == "mcr.microsoft.com/azurelinux/distroless/base"
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
            2,
        )
        mount = case_insensitive_dict_get(
            data, config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS
        )[1]
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

    def test_virtual_node_policy_fragment_generation(self):
        try:
            fragment_filename = "policy_fragment_file.json"
            write_str_to_file(fragment_filename, self.custom_json2)
            rego_filename = "example_fragment_file"
            acifragmentgen_confcom(None, fragment_filename, None, rego_filename, "1", "test_feed_file", None, None, None)

            containers, _ = decompose_confidential_properties(str_to_base64(load_str_from_file(f"{rego_filename}.rego")))

            custom_container = containers[0]
            vn2_privileged_mounts = [x.get(config.ACI_FIELD_CONTAINERS_MOUNTS_PATH) for x in config.DEFAULT_MOUNTS_PRIVILEGED_VIRTUAL_NODE]
            vn2_mounts = [x.get(config.ACI_FIELD_CONTAINERS_MOUNTS_PATH) for x in config.DEFAULT_MOUNTS_VIRTUAL_NODE]

            vn2_mount_count = 0
            priv_mount_count = 0
            for mount in custom_container.get(config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS):
                mount_name = mount.get(config.POLICY_FIELD_CONTAINERS_ELEMENTS_MOUNTS_DESTINATION)

                if mount_name in vn2_privileged_mounts:
                    priv_mount_count += 1
                if mount_name in vn2_mounts:
                    vn2_mount_count += 1
            if priv_mount_count != len(vn2_privileged_mounts):
                self.fail("policy does not contain privileged vn2 mounts")
            if vn2_mount_count != len(vn2_mounts):
                self.fail("policy does not contain default vn2 mounts")
        finally:
            force_delete_silently(fragment_filename)
            force_delete_silently(f"{rego_filename}.rego")


class FragmentGenerating(unittest.TestCase):
    custom_json = """
      {
        "version": "1.0",
        "containers": [
            {
                "name": "sidecar-container",
                "properties": {
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
            }
        ]
    }
    """
    aci_policy = None

    @classmethod
    def setUpClass(cls):
        with load_policy_from_json(cls.custom_json) as aci_policy:
            aci_policy.populate_policy_content_for_all_images()
            cls.aci_policy = aci_policy


    def test_fragment_omit_id(self):
        output = self.aci_policy.get_serialized_output(
            output_type=OutputType.RAW, rego_boilerplate=False, omit_id=True
        )
        output_json = load_json_from_str(output)

        self.assertNotIn("id", output_json[0])

        # test again with omit_id=False
        output2 = self.aci_policy.get_serialized_output(
            output_type=OutputType.RAW, rego_boilerplate=False
        )
        output_json2 = load_json_from_str(output2)

        self.assertIn("id", output_json2[0])


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
        env_names = list(map(lambda x: x['pattern'], image._environmentRules + image._extraEnvironmentRules))
        for env_var in env_vars:
            self.assertIn(env_var['name'] + "=" + env_var['value'], env_names)

        expected_workingdir = "/root/"
        self.assertEqual(image._workingDir, expected_workingdir)


class FragmentPolicyGeneratingTarfile(unittest.TestCase):
    custom_json= """
    {
        "version" : "1.0",
        "containers": [
            {
                "name": "simple-container",
                "properties": {
                    "image": "mcr.microsoft.com/aks/e2e/library-busybox:master.220314.1-linux-amd64",
                    "environmentVariables": [
                    {
                        "name": "PORT",
                        "value": "8080"
                    }
                ],
                "command": ["/bin/bash","-c","while sleep 5; do cat /mnt/input/access.log; done"],
                "mounts": null
                }
            }
        ]
    }
    """
    aci_policy = None

    @classmethod
    def setUpClass(cls) -> None:
        path = os.path.dirname(__file__)
        cls.path = path

    def test_tar_file_fragment(self):
        try:
            with tempfile.TemporaryDirectory() as folder:
                filename = os.path.join(folder, "oci.tar")
                filename2 = os.path.join(self.path, "oci2.tar")

                tar_mapping_file = {"mcr.microsoft.com/aks/e2e/library-busybox:master.220314.1-linux-amd64": filename2}
                create_tar_file(filename)
                with TarFile(filename, "r") as tar:
                    tar.extractall(path=folder)

                with TarFile.open(filename2, mode="w") as out_tar:
                    out_tar.add(os.path.join(folder, "index.json"), "index.json")
                    out_tar.add(os.path.join(folder, "blobs"), "blobs", recursive=True)

                with load_policy_from_json(self.custom_json) as aci_policy:
                    aci_policy.populate_policy_content_for_all_images(
                        tar_mapping=tar_mapping_file
                    )

                    clean_room_fragment_text = aci_policy.generate_fragment("payload", "1", OutputType.RAW)
                    self.assertIsNotNone(clean_room_fragment_text)
        except Exception as e:
            raise AccContainerError("Could not get image from tar file") from e


class FragmentPolicyGeneratingDebugMode(unittest.TestCase):
    custom_json = """
      {
        "version": "1.0",
        "containers": [
            {
            "name": "test-container",
            "properties": {
                    "image": "mcr.microsoft.com/azurelinux/distroless/base:3.0",
                "environmentVariables": [

                ],
                "command": ["python3"]
            }
        }
        ]
    }
    """
    aci_policy = None

    @classmethod
    def setUpClass(cls):
        with load_policy_from_json(cls.custom_json, debug_mode=True) as aci_policy:
            aci_policy.populate_policy_content_for_all_images()
            cls.aci_policy = aci_policy

    def test_debug_processes(self):
        policy = self.aci_policy.get_serialized_output(
            output_type=OutputType.RAW, rego_boilerplate=True
        )
        self.assertIsNotNone(policy)

        # see if debug mode is enabled
        containers, _ = extract_containers_and_fragments_from_text(policy)

        self.assertTrue(containers[0]["allow_stdio_access"])
        self.assertTrue(containers[0]["exec_processes"][0]["command"] == ["/bin/sh"])


class FragmentSidecarValidation(unittest.TestCase):
    custom_json = """
      {
    "version": "1.0",
    "containers": [
        {
            "name": "test-container",
            "properties": {
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
        }
    ]
}
    """
    custom_json2 = """
      {
    "version": "1.0",
    "containers": [
        {
            "name": "test-container",
            "properties": {
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
        }
    ]
}
    """

    aci_policy = None
    existing_policy = None

    @classmethod
    def setUpClass(cls):
        with load_policy_from_json(cls.custom_json) as aci_policy:
            aci_policy.populate_policy_content_for_all_images()
            cls.aci_policy = aci_policy
        with load_policy_from_json(cls.custom_json2) as aci_policy2:
            aci_policy2.populate_policy_content_for_all_images()
            cls.aci_policy2 = aci_policy2

    def test_fragment_sidecar(self):
        is_valid, diff = self.aci_policy.validate_sidecars()
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


class FragmentPolicySigning(unittest.TestCase):
    custom_json = """
{
    "version": "1.0",
    "containers": [
        {
            "name": "my-image",
            "properties": {
                "image": "mcr.microsoft.com/acc/samples/aci/helloworld:2.9",
                "execProcesses": [
                    {
                        "command": [
                            "echo",
                            "Hello World"
                        ]
                    }
                ],
                "volumeMounts": [
                    {
                        "name": "azurefile",
                        "mountPath": "/mount/azurefile",
                        "mountType": "azureFile",
                        "readOnly": true
                    }
                ],
                "environmentVariables": [
                    {
                        "name": "PATH",
                        "value": "/customized/path/value"
                    },
                    {
                        "name": "TEST_REGEXP_ENV",
                        "value": "test_regexp_env(.*)",
                        "regex": true
                    }
                ]
            }
        }
    ]
}
    """
    custom_json2 = """
{
    "version": "1.0",
    "fragments": [
    ],
    "containers": [
        {
            "name": "my-image",
            "properties": {
                "image": "mcr.microsoft.com/cbl-mariner/busybox:1.35",
                "execProcesses": [
                    {
                        "command": [
                            "sleep",
                            "infinity"
                        ]
                    }
                ],
                "environmentVariables": [
                    {
                        "name": "PATH",
                        "value": "/another/customized/path/value"
                    },
                    {
                        "name": "TEST_REGEXP_ENV2",
                        "value": "test_regexp_env2(.*)",
                        "regex": true
                    }
                ]
            }
        },
        {
            "name": "my-image",
            "properties": {
                "image": "mcr.microsoft.com/acc/samples/aci/helloworld:2.9",
                "execProcesses": [
                    {
                        "command": [
                            "echo",
                            "Hello World"
                        ]
                    }
                ],
                "volumeMounts": [
                    {
                        "name": "azurefile",
                        "mountPath": "/mount/azurefile",
                        "mountType": "azureFile",
                        "readOnly": true
                    }
                ],
                "environmentVariables": [
                    {
                        "name": "PATH",
                        "value": "/customized/path/value"
                    },
                    {
                        "name": "TEST_REGEXP_ENV",
                        "value": "test_regexp_env(.*)",
                        "regex": true
                    }
                ]
            }
        }
    ]
}
    """
    @classmethod
    def setUpClass(cls):
        cls.key_dir_parent = os.path.join(TEST_DIR, '..', '..', '..', 'samples', 'certs')
        cls.key = os.path.join(cls.key_dir_parent, 'intermediateCA', 'private', 'ec_p384_private.pem')
        cls.chain = os.path.join(cls.key_dir_parent, 'intermediateCA', 'certs', 'www.contoso.com.chain.cert.pem')
        if not os.path.exists(cls.key) or not os.path.exists(cls.chain):
            script_path = os.path.join(cls.key_dir_parent, 'create_certchain.sh')

            arg_list = [
                script_path,
            ]
            os.chmod(script_path, 0o755)

            # NOTE: this will raise an exception if it's run on windows and the key/cert files don't exist
            item = subprocess.run(
                arg_list,
                check=False,
                shell=True,
                cwd=cls.key_dir_parent,
                env=os.environ.copy(),
            )

            if item.returncode != 0:
                raise Exception("Error creating certificate chain")

        with load_policy_from_json(cls.custom_json) as aci_policy:
            aci_policy.populate_policy_content_for_all_images()
            cls.aci_policy = aci_policy
        with load_policy_from_json(cls.custom_json2) as aci_policy2:
            aci_policy2.populate_policy_content_for_all_images()
            cls.aci_policy2 = aci_policy2

    def test_signing(self):
        filename = "payload.rego"
        feed = "test_feed"
        algo = "ES384"
        out_path = filename + ".cose"

        fragment_text = self.aci_policy.generate_fragment("payload", 1, OutputType.RAW)
        try:
            write_str_to_file(filename, fragment_text)

            cose_proxy = CoseSignToolProxy()
            iss = cose_proxy.create_issuer(self.chain)

            cose_proxy.cose_sign(filename, self.key, self.chain, feed, iss, algo, out_path)
            self.assertTrue(os.path.exists(filename))
            self.assertTrue(os.path.exists(out_path))
        except Exception as e:
            raise e
        finally:
            delete_silently(filename)
            delete_silently(out_path)

    def test_generate_import(self):
        filename = "payload4.rego"
        feed = "test_feed"
        algo = "ES384"
        out_path = filename + ".cose"

        fragment_text = self.aci_policy.generate_fragment("payload4", "1", OutputType.RAW)
        try:
            write_str_to_file(filename, fragment_text)

            cose_proxy = CoseSignToolProxy()
            iss = cose_proxy.create_issuer(self.chain)
            cose_proxy.cose_sign(filename, self.key, self.chain, feed, iss, algo, out_path)

            import_statement = cose_proxy.generate_import_from_path(out_path, "1")
            self.assertTrue(import_statement)
            self.assertEqual(
                import_statement.get(config.POLICY_FIELD_CONTAINERS_ELEMENTS_REGO_FRAGMENTS_ISSUER,""),iss
            )
            self.assertEqual(
                import_statement.get(config.POLICY_FIELD_CONTAINERS_ELEMENTS_REGO_FRAGMENTS_FEED,""),feed
            )
            self.assertEqual(
                import_statement.get(config.POLICY_FIELD_CONTAINERS_ELEMENTS_REGO_FRAGMENTS_MINIMUM_SVN,""), "1"
            )
            self.assertEqual(
                import_statement.get(config.POLICY_FIELD_CONTAINERS_ELEMENTS_REGO_FRAGMENTS_INCLUDES,[]),[config.POLICY_FIELD_CONTAINERS, config.POLICY_FIELD_CONTAINERS_ELEMENTS_REGO_FRAGMENTS]
            )

        except Exception as e:
            raise e
        finally:
            delete_silently(filename)
            delete_silently(out_path)

    def test_local_fragment_references(self):
        filename = "payload2.rego"
        filename2 = "payload3.rego"
        fragment_json = "fragment_local.json"
        feed = "test_feed"
        feed2 = "test_feed2"
        algo = "ES384"
        out_path = filename + ".cose"
        out_path2 = filename2 + ".cose"

        fragment_text = self.aci_policy.generate_fragment("payload2", "1", OutputType.RAW)

        try:
            write_str_to_file(filename, fragment_text)
            write_str_to_file(fragment_json, self.custom_json2)

            cose_proxy = CoseSignToolProxy()
            iss = cose_proxy.create_issuer(self.chain)
            cose_proxy.cose_sign(filename, self.key, self.chain, feed, iss, algo, out_path)

            # this will insert the import statement from the first fragment into the second one
            acifragmentgen_confcom(
                None, None, None, None, None, None, None, None, generate_import=True, minimum_svn="1", fragments_json=fragment_json, fragment_path=out_path
            )
            # put the "path" field into the import statement
            temp_json = load_json_from_file(fragment_json)
            temp_json["fragments"][0]["path"] = out_path

            write_str_to_file(fragment_json, json.dumps(temp_json))

            acifragmentgen_confcom(
                None, fragment_json, None, "payload3", "1", feed2, self.key, self.chain, None, output_filename=filename2
            )

            # make sure all of our output files exist
            self.assertTrue(os.path.exists(filename2))
            self.assertTrue(os.path.exists(out_path2))
            self.assertTrue(os.path.exists(fragment_json))
            # check the contents of the unsigned rego file
            rego_str = load_str_from_file(filename2)
            # see if the import statement is in the rego file
            self.assertTrue("test_feed" in rego_str)
            # make sure the image covered by the first fragment isn't in the second fragment
            self.assertFalse("mcr.microsoft.com/acc/samples/aci/helloworld:2.9" in rego_str)
        except Exception as e:
            raise e
        finally:
            delete_silently(filename)
            delete_silently(out_path)
            delete_silently(filename2)
            delete_silently(out_path2)
            delete_silently(fragment_json)


class FragmentVirtualNode(unittest.TestCase):
    custom_json = """
{
    "version": "1.0",
    "scenario": "vn2",
    "labels": {
        "azure.workload.identity/use": true
    },
    "containers": [
        {
            "name": "test-container",
            "properties": {
                "image": "mcr.microsoft.com/acc/samples/aci/helloworld:2.9",
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
                    "while true; do echo 'Hello World'; done"
                ],
                "securityContext": {
                    "privileged": true
                }
"""
    aci_policy = None

    @classmethod
    def setUpClass(cls):
        with load_policy_from_json(cls.custom_json) as aci_policy:
            aci_policy.populate_policy_content_for_all_images()
            cls.aci_policy = aci_policy

    def test_fragment_vn2_env_vars(self):
        image = self.aci_policy.get_images()[0]
        env_names = [i.get('pattern') for i in image._get_environment_rules()]
        env_rules = [f"{i.get('name')}={i.get('value')}" for i in config.VIRTUAL_NODE_ENV_RULES]
        for env_rule in env_rules:
            self.assertIn(env_rule, env_names)

    def test_fragment_vn2_workload_identity_env_vars(self):
        image = self.aci_policy.get_images()[0]
        env_names = [i.get('pattern') for i in image._get_environment_rules()]
        env_rules = [f"{i.get('name')}={i.get('value')}" for i in config.VIRTUAL_NODE_ENV_RULES_WORKLOAD_IDENTITY]
        for env_rule in env_rules:
            self.assertIn(env_rule, env_names)

    def test_fragment_vn2_user_mounts(self):
        image = self.aci_policy.get_images()[0]
        mount_destinations = [i.get('destination') for i in image._get_mounts_json()]
        default_mounts = [i.get('mountPath') for i in config.DEFAULT_MOUNTS_VIRTUAL_NODE + config.DEFAULT_MOUNTS_USER_VIRTUAL_NODE]
        for default_mount in default_mounts:
            self.assertIn(default_mount, mount_destinations)

    def test_fragment_vn2_privileged_mounts(self):
        image = self.aci_policy.get_images()[0]
        mount_destinations = [i.get('destination') for i in image._get_mounts_json()]
        default_mounts = [i.get('mountPath') for i in config.DEFAULT_MOUNTS_PRIVILEGED_VIRTUAL_NODE]
        for default_mount in default_mounts:
            self.assertIn(default_mount, mount_destinations)

    def test_fragment_vn2_workload_identity_mounts(self):
        image = self.aci_policy.get_images()[0]
        mount_destinations = [i.get('destination') for i in image._get_mounts_json()]
        default_mounts = [i.get('mountPath') for i in config.DEFAULT_MOUNTS_WORKLOAD_IDENTITY_VIRTUAL_NODE]
        for default_mount in default_mounts:
            self.assertIn(default_mount, mount_destinations)
class FragmentRegistryInteractions(unittest.TestCase):
    custom_json = """
{
    "version": "1.0",
    "fragments": [
    ],
    "containers": [
        {
            "name": "my-image2",
            "properties": {
                "image": "mcr.microsoft.com/acc/samples/aci/helloworld:2.8",
                "execProcesses": [
                    {
                        "command": [
                            "echo",
                            "Hello World"
                        ]
                    }
                ],
                "volumeMounts": [
                    {
                        "name": "azurefile",
                        "mountPath": "/mount/azurefile",
                        "mountType": "azureFile",
                        "readOnly": true
                    }
                ],
                "environmentVariables": [
                    {
                        "name": "PATH",
                        "value": "/customized/path/value"
                    },
                    {
                        "name": "TEST_REGEXP_ENV",
                        "value": "test_regexp_env(.*)",
                        "regex": true
                    }
                ]
            }
        }
    ]
}
    """


    custom_json2 = """
{
    "version": "1.0",
    "fragments": [
    ],
    "containers": [
        {
            "name": "my-image",
            "properties": {
                "image": "mcr.microsoft.com/cbl-mariner/busybox:1.35",
                "execProcesses": [
                    {
                        "command": [
                            "sleep",
                            "infinity"
                        ]
                    }
                ],
                "environmentVariables": [
                    {
                        "name": "PATH",
                        "value": "/another/customized/path/value"
                    },
                    {
                        "name": "TEST_REGEXP_ENV2",
                        "value": "test_regexp_env2(.*)",
                        "regex": true
                    }
                ]
            }
        },
        {
            "name": "my-image2",
            "properties": {
                "image": "mcr.microsoft.com/acc/samples/aci/helloworld:2.8",
                "execProcesses": [
                    {
                        "command": [
                            "echo",
                            "Hello World"
                        ]
                    }
                ],
                "volumeMounts": [
                    {
                        "name": "azurefile",
                        "mountPath": "/mount/azurefile",
                        "mountType": "azureFile",
                        "readOnly": true
                    }
                ],
                "environmentVariables": [
                    {
                        "name": "PATH",
                        "value": "/customized/path/value"
                    },
                    {
                        "name": "TEST_REGEXP_ENV",
                        "value": "test_regexp_env(.*)",
                        "regex": true
                    }
                ]
            }
        }
    ]
}
"""

    custom_json3 = """
    {
        "version": "1.0",
        "fragments": [
        ],
        "containers": [
            {
                "name": "my-image",
                "properties": {
                    "image": "localhost:5000/helloworld:2.8",
                    "execProcesses": [
                        {
                            "command": [
                                "echo",
                                "Hello World"
                            ]
                        }
                    ],
                    "volumeMounts": [
                        {
                            "name": "azurefile",
                            "mountPath": "/mount/azurefile",
                            "mountType": "azureFile",
                            "readOnly": true
                        }
                    ],
                    "environmentVariables": [
                        {
                            "name": "PATH",
                            "value": "/customized/path/value"
                        },
                        {
                            "name": "TEST_REGEXP_ENV",
                            "value": "test_regexp_env(.*)",
                            "regex": true
                        }
                    ]
                }
            }
        ]
    }
    """

    @classmethod
    def setUpClass(cls):
        # start the zot registry
        cls.zot_image = "ghcr.io/project-zot/zot-linux-amd64:v2.1.2"
        cls.registry = "localhost:5000"
        registry_name = "myregistry"
        subprocess.run(f"docker pull {cls.zot_image}")
        output = subprocess.run("docker ps -a", capture_output=True)

        if registry_name not in output.stdout.decode():
            subprocess.run(f"docker run --name {registry_name} -d -p 5000:5000 {cls.zot_image}")

        cls.key_dir_parent = os.path.join(TEST_DIR, '..', '..', '..', 'samples', 'certs')
        cls.key = os.path.join(cls.key_dir_parent, 'intermediateCA', 'private', 'ec_p384_private.pem')
        cls.chain = os.path.join(cls.key_dir_parent, 'intermediateCA', 'certs', 'www.contoso.com.chain.cert.pem')
        if not os.path.exists(cls.key) or not os.path.exists(cls.chain):
            script_path = os.path.join(cls.key_dir_parent, 'create_certchain.sh')

            arg_list = [
                script_path,
            ]
            os.chmod(script_path, 0o755)

            # NOTE: this will raise an exception if it's run on windows and the key/cert files don't exist
            item = subprocess.run(
                arg_list,
                check=False,
                shell=True,
                cwd=cls.key_dir_parent,
                env=os.environ.copy(),
            )

            if item.returncode != 0:
                raise Exception("Error creating certificate chain")

        with load_policy_from_config_str(cls.custom_json) as aci_policy:
            aci_policy.populate_policy_content_for_all_images()
            cls.aci_policy = aci_policy
        with load_policy_from_config_str(cls.custom_json2) as aci_policy2:
            aci_policy2.populate_policy_content_for_all_images()
            cls.aci_policy2 = aci_policy2

        # stall while we wait for the registry to start running
        logs = subprocess.run(f"docker logs {registry_name}", capture_output=True)
        counter = 0
        while logs.returncode != 0:
            time.sleep(1)
            logs = subprocess.run(f"docker logs {registry_name}", capture_output=True)
            counter += 1
            if counter == 10:
                raise Exception("Could not start local registry in time")


    def test_registry_is_running(self):
        result = requests.get(f"http://{self.registry}/v2/_catalog")
        self.assertTrue("repositories" in result.json())

    def test_generate_import_from_remote(self):
        filename = "payload5.rego"
        feed = f"{self.registry}/test_feed:test_tag"
        algo = "ES384"
        out_path = filename + ".cose"

        fragment_text = self.aci_policy.generate_fragment("payload4", 1, OutputType.RAW)
        temp_filename = "temp.json"
        try:
            write_str_to_file(filename, fragment_text)

            cose_proxy = CoseSignToolProxy()
            iss = cose_proxy.create_issuer(self.chain)
            cose_proxy.cose_sign(filename, self.key, self.chain, feed, iss, algo, out_path)
            push_fragment_to_registry(feed, out_path)

            # this should download and create the import statement
            acifragmentgen_confcom(None, None, None, None, None, None, None, None, 1, generate_import=True, fragment_path=feed, fragments_json=temp_filename)
            import_file = load_json_from_file(temp_filename)
            import_statement = import_file.get(config.ACI_FIELD_CONTAINERS_REGO_FRAGMENTS)[0]

            self.assertTrue(import_statement)
            self.assertEqual(
                import_statement.get(config.POLICY_FIELD_CONTAINERS_ELEMENTS_REGO_FRAGMENTS_ISSUER,""),iss
            )
            self.assertEqual(
                import_statement.get(config.POLICY_FIELD_CONTAINERS_ELEMENTS_REGO_FRAGMENTS_FEED,""),feed
            )
            self.assertEqual(
                import_statement.get(config.POLICY_FIELD_CONTAINERS_ELEMENTS_REGO_FRAGMENTS_MINIMUM_SVN,""),1
            )
            self.assertEqual(
                import_statement.get(config.POLICY_FIELD_CONTAINERS_ELEMENTS_REGO_FRAGMENTS_INCLUDES,[]),[config.POLICY_FIELD_CONTAINERS, config.POLICY_FIELD_CONTAINERS_ELEMENTS_REGO_FRAGMENTS]
            )

        except Exception as e:
            raise e
        finally:
            delete_silently(filename)
            delete_silently(out_path)
            delete_silently(temp_filename)

    def test_remote_fragment_references(self):
        filename = "payload6.rego"
        filename2 = "payload7.rego"
        first_fragment = "first_fragment.json"
        fragment_json = "fragment_remote.json"
        feed = f"{self.registry}/test_feed:v1"
        feed2 = f"{self.registry}/test_feed2:v2"
        out_path = filename + ".cose"
        out_path2 = filename2 + ".cose"

        # fragment_text = self.aci_policy.generate_fragment("payload6", 1, OutputType.RAW)

        try:
            write_str_to_file(first_fragment, self.custom_json)
            write_str_to_file(fragment_json, self.custom_json2)
            acifragmentgen_confcom(
                None, first_fragment, None, "payload7", 1, feed, self.key, self.chain, None, output_filename=filename
            )

            # this will insert the import statement from the first fragment into the second one
            acifragmentgen_confcom(
                None, None, None, None, None, None, None, None, generate_import=True, minimum_svn=1, fragments_json=fragment_json, fragment_path=out_path
            )

            push_fragment_to_registry(feed, out_path)

            acifragmentgen_confcom(
                None, fragment_json, None, "payload7", 1, feed2, self.key, self.chain, None, output_filename=filename2
            )

            # make sure all of our output files exist
            self.assertTrue(os.path.exists(filename2))
            self.assertTrue(os.path.exists(out_path2))
            self.assertTrue(os.path.exists(fragment_json))
            # check the contents of the unsigned rego file
            rego_str = load_str_from_file(filename2)
            # see if the import statement is in the rego file
            self.assertTrue(feed in rego_str)
            # make sure the image covered by the first fragment isn't in the second fragment
            self.assertFalse("mcr.microsoft.com/acc/samples/aci/helloworld:2.8" in rego_str)
        except Exception as e:
            raise e
        finally:
            delete_silently(filename)
            delete_silently(out_path)
            delete_silently(filename2)
            delete_silently(out_path2)
            delete_silently(fragment_json)
            delete_silently(first_fragment)

    def test_incorrect_minimum_svn(self):
        filename = "payload8.rego"
        filename2 = "payload9.rego"
        fragment_json = "fragment.json"
        feed = f"{self.registry}/test_feed:v3"
        feed2 = f"{self.registry}/test_feed2:v4"
        algo = "ES384"
        out_path = filename + ".cose"
        out_path2 = filename2 + ".cose"

        fragment_text = self.aci_policy.generate_fragment("payload8", 1, OutputType.RAW)

        try:
            write_str_to_file(filename, fragment_text)
            write_str_to_file(fragment_json, self.custom_json2)

            cose_proxy = CoseSignToolProxy()
            iss = cose_proxy.create_issuer(self.chain)
            cose_proxy.cose_sign(filename, self.key, self.chain, feed, iss, algo, out_path)


            # this will insert the import statement from the first fragment into the second one
            acifragmentgen_confcom(
                None, None, None, None, None, None, None, None, generate_import=True, minimum_svn=2, fragments_json=fragment_json, fragment_path=out_path
            )
            # put the "path" field into the import statement
            push_fragment_to_registry(feed, out_path)
            acifragmentgen_confcom(
                None, fragment_json, None, "payload9", 1, feed2, self.key, self.chain, None, output_filename=filename2
            )

            # make sure all of our output files exist
            self.assertTrue(os.path.exists(filename2))
            self.assertTrue(os.path.exists(out_path2))
            self.assertTrue(os.path.exists(fragment_json))
            # check the contents of the unsigned rego file
            rego_str = load_str_from_file(filename2)
            # see if the import statement is in the rego file
            self.assertTrue("test_feed" in rego_str)
            # make sure the image covered by the first fragment is in the second fragment because the svn prevents usage
            self.assertTrue("mcr.microsoft.com/acc/samples/aci/helloworld:2.8" in rego_str)
        except Exception as e:
            raise e
        finally:
            delete_silently(filename)
            delete_silently(out_path)
            delete_silently(filename2)
            delete_silently(out_path2)
            delete_silently(fragment_json)

    def test_image_attached_fragment_coverage(self):
        subprocess.run("docker tag mcr.microsoft.com/acc/samples/aci/helloworld:2.8 localhost:5000/helloworld:2.8")
        subprocess.run("docker push localhost:5000/helloworld:2.8", timeout=30)
        filename = "container_image_attached.json"
        rego_filename = "temp_namespace"
        try:
            write_str_to_file(filename, self.custom_json3)
            acifragmentgen_confcom(
                None,
                filename,
                None,
                rego_filename,
                1,
                "temp_feed",
                self.key,
                self.chain,
                1,
                "localhost:5000/helloworld:2.8",
                upload_fragment=True,
            )


            # this will insert the import statement into the original container.json
            acifragmentgen_confcom(
                "localhost:5000/helloworld:2.8", None, None, None, None, None, None, None, generate_import=True, minimum_svn=1, fragments_json=filename
            )

            # try to generate the policy again to make sure there are no containers in the resulting rego
            with self.assertRaises(SystemExit) as exc_info:
                acifragmentgen_confcom(
                    None,
                    filename,
                    None,
                    "temp_namespace2",
                    1,
                    "temp_feed2",
                    None,
                    None,
                    1,
                    "localhost:5000/helloworld:2.8",
                )
            self.assertEqual(exc_info.exception.code, 1)

        except Exception as e:
            raise e
        finally:
            delete_silently(filename)
            delete_silently(f"{rego_filename}.rego")
            delete_silently(f"{rego_filename}.rego.cose")

class InitialFragmentErrors(ScenarioTest):
    def test_invalid_input(self):
        with self.assertRaises(CLIError) as wrapped_exit:
            self.cmd("az confcom acifragmentgen --image mcr.microsoft.com/aci/msi-atlas-adapter:master_20201210.1 -i fakepath/parameters.json --namespace fake_namespace --svn 1")
        self.assertEqual(wrapped_exit.exception.args[0], "Must provide either an image name or an input file to generate a fragment")

        with self.assertRaises(CLIError) as wrapped_exit:
            self.cmd("az confcom acifragmentgen --generate-import --minimum-svn 1")
        self.assertEqual(wrapped_exit.exception.args[0], "Must provide either a fragment path or " +
            "an image name to generate an import statement")

        with self.assertRaises(CLIError) as wrapped_exit:
            self.cmd("az confcom acifragmentgen --image mcr.microsoft.com/aci/msi-atlas-adapter:master_20201210.1 -k fakepath/key.pem --namespace fake_namespace --svn 1")
        self.assertEqual(wrapped_exit.exception.args[0], "Must provide both --key and --chain to sign a fragment")

        with self.assertRaises(CLIError) as wrapped_exit:
            self.cmd("az confcom acifragmentgen --fragment-path ./fragment.json --image mcr.microsoft.com/aci/msi-atlas-adapter:master_20201210.1 --namespace fake_namespace --svn 1 --minimum-svn 1")
        self.assertEqual(wrapped_exit.exception.args[0], "Must provide --generate-import to specify a fragment path")

        with self.assertRaises(CLIError) as wrapped_exit:
            self.cmd("az confcom acifragmentgen --input ./input.json --namespace example --svn -1")
        self.assertEqual(wrapped_exit.exception.args[0], "--svn must be an integer")

        with self.assertRaises(CLIError) as wrapped_exit:
            self.cmd("az confcom acifragmentgen --input ./input.json --namespace policy --svn 1")
        self.assertEqual(wrapped_exit.exception.args[0], "Namespace 'policy' is reserved")

        with self.assertRaises(CLIError) as wrapped_exit:
            self.cmd("az confcom acifragmentgen --algo fake_algo --key ./key.pem --chain ./cert-chain.pem --namespace example --svn 1 -i ./input.json")
        self.assertEqual(wrapped_exit.exception.args[0], f"Algorithm 'fake_algo' is not supported. Supported algorithms are {config.SUPPORTED_ALGOS}")