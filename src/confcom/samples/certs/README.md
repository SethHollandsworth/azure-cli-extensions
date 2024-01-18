# Create a Key and Cert for Signing

## Prerequisites

- Must have OpenSSL installed
- Must have Azure CLI installed
- Must have the [`confcom` extension](../../README.md) installed
- Must have [ORAS CLI](https://oras.land/docs/installation/) installed

## Update Config

*This step sets up the configuration for creating certs to sign the fragment policy. This only needs to be done once.*

`create_certchain.sh` should have `<your-username>` specified at the top for `RootPath`

The image in `fragment_config.json` must be updated to the image you want to attach the fragment to. The default image is hosted on Microsoft Artifact Registry so it will not allow fragment uploads.

## Run the Script

*This step will create the necessary certs to sign the fragment policy. This also only needs to be done once.*

```bash
./create_certchain.sh
```

You will need to select (y) for four prompts to sign the certs needed to create a cert chain.

After completion, this will create the following files to be used in the confcom signing process:

- `intermediate/private/ec_p384_private.pem`
- `intermediateCA/certs/www.contoso.com.chain.cert.pem`

## Run confcom

*This step will generate the fragment policy, sign it with the certs created in the previous step, and upload the fragment to the container registry.*

You may need to change the path to the chain and key files in the following command:

```bash
az confcom acifragmentgen --chain ./samples/certs/intermediateCA/certs/www.contoso.com.chain.cert.pem --key ./samples/certs/intermediateCA/private/ec_p384_private.pem --svn 1 --namespace contoso --config ./samples/config.json --upload-fragment
```

After running the command, there will be the following files created:

- `contoso.rego`
- `contoso.rego.cose`

Where `contoso.rego` is the fragment policy and `contoso.rego.cose` is the signed policy in COSE format.

The `--upload-fragment` flag will attempt to attach the fragment to the container image in the ORAS-compliant registry.

## Generate Security Policy for an ARM Template

*This step will generate a security policy for an ARM template and include the fragment policy created in the previous step.*

To create an import statement for the newly created rego fragment, run the following command:

```bash
az confcom acifragmentgen --generate-import -p ./contoso.rego.cose --minimum-svn 1
```

Which will output the fragment's import in json format. **Place this import statement into a new `fragments.json` file.**

To generate a security policy for an ARM template, run the following command:

```bash
az confcom acipolicygen -a template.json --include-fragments --fragments-json fragments.json
```

This will insert the fragment policy into the ARM template and include the mentioned fragments in the `fragments.json` file.
