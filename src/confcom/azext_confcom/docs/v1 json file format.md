# v1 `--input`, `-i` json file format

This document provides a comprehensive reference for the JSON configuration format used by the Azure Confidential Container Extension (`confcom`). This schema allows you to define container properties and fragment specifications to be used with `acipolicygen` and `acifragmentgen` including usage with `VN2`.

## Schema Overview

The configuration file uses a structured JSON format with the following main sections:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | Schema version identifier (currently "1.0") |
| `scenario` | string | No | Adds appropriate mounts and environment variables for different deployment scenarios. If deploying to `vn2`, this field is required |
| `fragments` | array | Yes (either `containers` or `fragments` must be defined) | Specifies policy fragments to include |
| `containers` | array | Yes (either `containers` or `fragments` must be defined) | Container configurations to deploy |

## Detailed Field Reference

### Top-Level Fields

#### `version`

- **Type**: String
- **Required**: Yes
- **Description**: Version identifier for the schema format
- **Allowed Values**: "1.0"
- **Example**: `"version": "1.0"`

#### `scenario`

- **Type**: String
- **Required**: No
- **Description**: Adds appropriate mounts and environment variables for different deployment scenarios. If deploying to `vn2`, this field is required. The default value is `aci`
- **Allowed Values**: "1.0"
- **Example**: `"scenario": "vn2"`

#### `fragments`

- **Type**: Array of objects
- **Required**: Yes (either `containers` or `fragments` must be defined)
- **Description**: Policy fragments that extend container behavior

#### `containers`

- **Type**: Array of objects
- **Required**: Yes (either `containers` or `fragments` must be defined)
- **Description**: Container specifications for deployment

### Fragment Objects

#### fragments

Type: array of objects
Required: Yes (can be empty)
Description: Defines reusable policy fragments.

| Field         | Type   | Required | Description                                             |
|---------------|--------|----------|---------------------------------------------------------|
| `issuer`      | string | Yes      | DID identifier of the fragment issuer                   |
| `feed`        | string | Yes      | Container registry URL hosting the fragment             |
| `minimum_svn` | string | Yes      | Minimum Security Version Number required                |
| `includes`    | array  | Yes      | Capabilities included in the fragment (e.g., "containers") |

Example:

```json
{
  "issuer": "did:x509:0:sha256:I__iuL25oXEVFdTP_aBLx_eT1RPHbCQ_ECBQfYZpt9s::eku:1.3.6.1.4.1.311.76.59.1.3",
  "feed": "contoso.azurecr.io/infra",
  "minimum_svn": "1",
  "includes": ["containers"]
}
```

#### containers

Type: array of objects
Required: Yes
Description: Defines container instances and their configurations.

Container Object Fields

| Field      | Type   | Required | Description                         |
|------------|--------|----------|-------------------------------------|
| name       | string | Yes      | Unique identifier for the container |
| properties | object | Yes      | Container-specific configuration    |

Container `properties` Fields

| Field                | Type   | Required | Description                                             |
|----------------------|--------|----------|---------------------------------------------------------|
| image                | string | Yes      | Container image URI                                     |
| execProcesses        | array  | No       | Commands executed within the container                  |
| command              | array  | No       | Container startup command (alternative to execProcesses)|
| volumeMounts         | array  | No       | Volumes mounted into the container                      |
| environmentVariables | array  | No       | Environment variables set within the container          |

`execProcesses` Object Fields

| Field   | Type  | Required | Description                    |
|---------|-------|----------|--------------------------------|
| command | array | Yes      | Command and arguments to execute|

Example:

```json
{
  "command": ["echo", "Hello World"]
}
```

`command` Field
Type: array of strings
Required: No
Description: Command executed at container startup.
Example:

```json
"command": ["python3"]
```

`volumeMounts` Object Fields

| Field      | Type    | Required | Description                                             |
|------------|---------|----------|---------------------------------------------------------|
| name       | string  | Yes      | Name of the volume                                      |
| mountPath  | string  | Yes      | Path inside the container where volume is mounted       |
| mountType  | string  | Yes      | Type of volume (`azureFile`, `secret`, `configMap`, `emptyDir`) |
| readOnly   | boolean | No       | Mount volume as read-only (default: false)              |

Example:

```json
{
  "name": "azurefile",
  "mountPath": "/aci/logs",
  "mountType": "azureFile",
  "readOnly": false
}
```

`environmentVariables` Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name  | string | Yes | Environment variable name |
| value | string | Yes | Environment variable value |
| regex | boolean | No | Indicates if the value is a regex pattern (default: false) |

```json
[
  {
    "name": "PATH",
    "value": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  },
  {
    "name": "NEW_VAR",
    "value": "value.*",
    "regex": true
  }
]
```

Example:

#### Usage Notes and Best Practices

- Use either command or execProcesses, but not both simultaneously.
- Clearly name containers to reflect their role or function.
- Limit environment variables to essential values; use regex sparingly.
- Mount volumes as read-only whenever possible for enhanced security.
- Keep fragments modular and scoped to specific capabilities.

#### Azure Best Practices

- Store container images securely in Azure Container Registry (ACR).
- Regularly update container images and fragments to patch vulnerabilities.
- Follow the principle of least privilege when defining container capabilities and permissions.
- Use Azure Managed Identities for secure access to Azure resources from containers.

#### Full Example

The most up to date example [can be found here](../../samples/config.json)
