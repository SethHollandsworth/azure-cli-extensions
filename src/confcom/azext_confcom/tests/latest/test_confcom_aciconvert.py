# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import os
import unittest
import json
from azext_confcom.custom import convert_to_json_confcom

TEST_DIR = os.path.abspath(os.path.join(os.path.abspath(__file__), ".."))


class AciconvertTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Example ARM template
        cls.arm_template_content = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {
                "containerGroupName": {
                    "type": "string",
                    "defaultValue": "my-container-group"
                },
                "containerName": {
                    "type": "string",
                    "defaultValue": "my-container"
                }
            },
            "variables": {
                "image": "mcr.microsoft.com/cbl-mariner/distroless/python:3.9-nonroot"
            },
            "resources": [
                {
                    "type": "Microsoft.ContainerInstance/containerGroups",
                    "apiVersion": "2023-05-01",
                    "name": "[parameters('containerGroupName')]",
                    "location": "[resourceGroup().location]",
                    "properties": {
                        "containers": [
                            {
                                "name": "[parameters('containerName')]",
                                "properties": {
                                    "image": "[variables('image')]",
                                    "command": [
                                        "python3"
                                    ],
                                    "resources": {
                                        "requests": {
                                            "cpu": 1.0,
                                            "memoryInGb": 1.5
                                        }
                                    },
                                    "volumeMounts": [
                                        {
                                            "name": "filesharevolume",
                                            "mountPath": "/aci/logs",
                                            "readOnly": False
                                        }
                                    ]
                                }
                            }
                        ],
                        "volumes": [
                            {
                                "name": "filesharevolume",
                                "azureFile": {
                                    "shareName": "my-share",
                                    "storageAccountName": "my-storage-acct",
                                    "storageAccountKey": "<secret>"
                                }
                            }
                        ],
                        "osType": "Linux",
                        "restartPolicy": "Always",
                        "confidentialComputeProperties": {
                            "IsolationType": "SevSnp"
                        }
                    }
                }
            ],
            "outputs": {}
        }
        cls.arm_template_file = os.path.join(TEST_DIR, "test_arm_template.json")
        with open(cls.arm_template_file, "w") as f:
            json.dump(cls.arm_template_content, f, indent=2)

        cls.arm_template_parameters_content = {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {
                "containerGroupName": {
                    "value": "my-parameterized-group"
                },
                "containerName": {
                    "value": "my-parameterized-container"
                }
            }
        }
        cls.arm_template_parameters_file = os.path.join(TEST_DIR, "test_arm_template.parameters.json")
        with open(cls.arm_template_parameters_file, "w") as f:
            json.dump(cls.arm_template_parameters_content, f, indent=2)


        # Example YAML file
        cls.yaml_content = """
apiVersion: v1
kind: Pod
metadata:
  labels:
    app: test-app
  name: test-pod
spec:
  containers:
    - name: container1
      image: mcr.microsoft.com/cbl-mariner/distroless/python:3.9-nonroot
      env:
        - name: ENV_VAR_1
          value: value1
        - name: CONFIG_VAR
          valueFrom:
            configMapKeyRef:
              key: config-key
              name: test-configmap
        - name: SECRET_VAR
          valueFrom:
            secretKeyRef:
              key: secret-key
              name: test-secret
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        - name: POD_IP
          valueFrom:
            fieldRef:
              fieldPath: status.podIP
        - name: CPU_LIMIT
          valueFrom:
            resourceFieldRef:
              containerName: container1
              resource: limits.cpu
        - name: MEMORY_REQUEST
          valueFrom:
            resourceFieldRef:
              containerName: container1
              resource: requests.memory
      livenessProbe:
        httpGet:
          path: /healthz
          port: 8080
        initialDelaySeconds: 10
        periodSeconds: 5
      readinessProbe:
        httpGet:
          path: /readiness
          port: 8080
        initialDelaySeconds: 5
        periodSeconds: 5
      resources:
        limits:
          cpu: 500m
          memory: 128Mi
        requests:
          cpu: 250m
          memory: 64Mi
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      volumeMounts:
        - mountPath: /etc/config
          name: config-volume
        - mountPath: /etc/secrets
          name: secret-volume
          readOnly: true
        - mountPath: /etc/projected
          name: projected-volume
        - mountPath: /data
          name: pvc-volume
    - name: container2
      image: mcr.microsoft.com/cbl-mariner/distroless/minimal:2.0
      command:
        - sleep
        - "3600"
      volumeMounts:
        - mountPath: /shared
          name: shared-volume
  restartPolicy: Always
  volumes:
    - name: config-volume
      configMap:
        name: test-configmap
    - name: secret-volume
      secret:
        secretName: test-secret
    - name: projected-volume
      projected:
        sources:
          - configMap:
              name: test-configmap
          - secret:
              name: test-secret
    - name: pvc-volume
      persistentVolumeClaim:
        claimName: test-pvc
    - name: shared-volume
      emptyDir: {}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-configmap
data:
  another-key: another-value
  config-key: config-value
---
apiVersion: v1
kind: Secret
metadata:
  name: test-secret
  type: Opaque
data:
  another-secret: YW5vdGhlci12YWx1ZQ==
  secret-key: c2VjcmV0LXZhbHVl
"""
        cls.yaml_file = os.path.join(TEST_DIR, "test_virtual_node.yaml")
        with open(cls.yaml_file, "w") as f:
            f.write(cls.yaml_content)

        # Example output file
        cls.output_file = os.path.join(TEST_DIR, "output.json")

    @classmethod
    def tearDownClass(cls):
        # Clean up test files
        for fpath in [
            cls.arm_template_file,
            cls.arm_template_parameters_file,
            cls.yaml_file,
            cls.output_file
        ]:
            if os.path.exists(fpath):
                os.remove(fpath)

    def test_convert_arm_template(self):
        """Test converting an ARM template to JSON."""
        convert_to_json_confcom(
            arm_template=self.arm_template_file,
            arm_template_parameters=None,
            image_name=None,
            virtual_node_yaml_path=None,
            output_filename=self.output_file,
            outraw_pretty_print=True
        )
        # Validate output
        self.assertTrue(os.path.exists(self.output_file))
        with open(self.output_file, "r") as f:
            data = json.load(f)

        # Instead of looking for 'resources',
        # now you should check for top-level 'containers'
        self.assertIn("containers", data, "Output JSON must have a 'containers' key.")
        self.assertGreater(len(data["containers"]), 0, "Expected at least one container in the policy.")

        container0 = data["containers"][0]
        self.assertIn("properties", container0)
        props = container0["properties"]

        # Validate container properties
        self.assertIn("image", props)
        self.assertEqual(
            props["image"],
            "mcr.microsoft.com/cbl-mariner/distroless/python:3.9-nonroot",
            "Expected ARM variable 'image' to match the policy output"
        )

        # Validate volume mounts
        self.assertIn("volumeMounts", props)
        mount_paths = [mount["mountPath"] for mount in props["volumeMounts"]]
        self.assertIn("/aci/logs", mount_paths, "Expected '/aci/logs' as a volume mount path.")

    def test_convert_arm_template_with_params(self):
        """
        Test converting an ARM template to JSON with an overridden parameter file.
        This should change the container name and image from the default values in the template.
        """
        convert_to_json_confcom(
            arm_template=self.arm_template_file,
            arm_template_parameters=self.arm_template_parameters_file,
            image_name=None,
            virtual_node_yaml_path=None,
            output_filename=self.output_file,
            outraw_pretty_print=True
        )

        self.assertTrue(os.path.exists(self.output_file))
        with open(self.output_file, "r") as f:
            data = json.load(f)

        # We expect top-level "containers"
        self.assertIn("containers", data, "Output JSON must have a 'containers' key.")
        self.assertGreater(len(data["containers"]), 0, "Expected at least one container in the policy.")

        container0 = data["containers"][0]
        self.assertIn("properties", container0)
        props = container0["properties"]

        # Check that the parameter file's container name is used
        self.assertEqual(container0["name"], "my-parameterized-container")

    def test_convert_virtual_node_yaml(self):
        """Test converting a Virtual Node YAML to JSON."""
        convert_to_json_confcom(
            arm_template=None,
            arm_template_parameters=None,
            image_name=None,
            virtual_node_yaml_path=self.yaml_file,
            output_filename=self.output_file,
            outraw_pretty_print=True
        )
        # Validate output
        self.assertTrue(os.path.exists(self.output_file))
        with open(self.output_file, "r") as f:
            data = json.load(f)
            self.assertIn("containers", data)
            self.assertEqual(len(data["containers"]), 2)
            
            # Validate first container
            container1 = data["containers"][0]
            self.assertEqual(container1["name"], "container1")
            self.assertEqual(container1["properties"]["image"], "mcr.microsoft.com/cbl-mariner/distroless/python:3.9-nonroot")
            
            # Validate environment variables
            env_vars = {var["name"]: var["value"] for var in container1["properties"]["environmentVariables"]}
            self.assertEqual(env_vars["ENV_VAR_1"], "value1")
            self.assertEqual(env_vars["CONFIG_VAR"], "config-value")
            self.assertEqual(env_vars["SECRET_VAR"], "secret-value")
            
            # Validate volume mounts
            volume_mounts = {mount["mountPath"]: mount for mount in container1["properties"]["volumeMounts"]}
            self.assertIn("/etc/config", volume_mounts)
            self.assertTrue(volume_mounts["/etc/config"]["readonly"])
            
            # Validate second container
            container2 = data["containers"][1]
            self.assertEqual(container2["name"], "container2")
            self.assertEqual(container2["properties"]["image"], "mcr.microsoft.com/cbl-mariner/distroless/minimal:2.0")

    def test_convert_image_name(self):
        """Test converting an image name to JSON with proper output validation."""
        from io import StringIO
        import sys

        # Redirect stdout
        old_stdout = sys.stdout
        sys.stdout = StringIO()

        try:
            convert_to_json_confcom(
                arm_template=None,
                arm_template_parameters=None,
                image_name="mcr.microsoft.com/cbl-mariner/distroless/python:3.9-nonroot",
                virtual_node_yaml_path=None,
                output_filename=None,
                outraw_pretty_print=False
            )
            # Capture the output
            output = sys.stdout.getvalue()
            self.assertTrue(len(output) > 0)

            # Parse and validate the JSON output
            data = json.loads(output)
            self.assertIn("containers", data)
            self.assertEqual(len(data["containers"]), 1)

            container = data["containers"][0]
            self.assertEqual(container["name"], "mcr.microsoft.com/cbl-mariner/distroless/python:3.9-nonroot")
            self.assertIn("properties", container)
            self.assertEqual(container["properties"]["image"], "mcr.microsoft.com/cbl-mariner/distroless/python:3.9-nonroot")

            # Validate volume mounts
            volume_mounts = container["properties"].get("volumeMounts", [])
            self.assertEqual(len(volume_mounts), 1)
            mount = volume_mounts[0]
            self.assertEqual(mount["mountPath"], "/etc/resolv.conf")
            self.assertEqual(mount["mountType"], "resolvconf")
            self.assertEqual(mount["name"], "dns_resolve")
            self.assertFalse(mount["readonly"])
        finally:
            # Restore stdout
            sys.stdout = old_stdout