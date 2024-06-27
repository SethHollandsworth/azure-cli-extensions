# Create a Key and Cert for Signing

## Prerequisites

- Must have OpenSSL installed
- Must have Azure CLI installed
- Must have the `confcom` extension installed
- Must have ORAS CLI installed

## Update Config

Inside `openssl_intermediate.cnf` and `openssl_roof.cnf` update the following fields:

`dir` should have the path where you want to create the certs.
`create_certchain.sh` should have `<your-username>` specified at the top for `RootPath`

## Run the Script

```bash
./create_certchain.sh
```

You will need to select (y) for four prompts to sign the certs needed to create a cert chain.

After completion, this will create the following files to be used in the confcom signing process:

- `intermediate/private/ec_p384_private.pem`
- `intermediateCA/certs/www.contoso.com.chain.cert.pem`

## Run confcom

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

To create an import statement for the newly created rego fragment, run the following command:

```bash
az confcom acifragmentgen --generate-import -p ./contoso.rego.cose --minimum-svn 1
```

Which will output the fragment's import in json format. Place this import statement into a new `fragments.json` file.

To generate a security policy for an ARM template, run the following command:

```bash
az confcom acipolicygen -a "template.json" --include_fragments --fragments-json fragments.json
```

This will insert the fragment policy into the ARM template and include the mentioned fragments in the fragments.json file.
