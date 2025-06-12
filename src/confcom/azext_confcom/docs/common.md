# Common Documentation

- [Security Policy Information Sources](#security-policy-information-sources)

## Security Policy Information Sources

Each container in a security policy can get its information from two different sources:

1. The image manifest.
This can be explored using `docker image inspect`
2. The ARM Template used to generate the security policy.
This can be used for startup command, environment variables, etc.

The `confcom` tooling uses the image manifest for default values and then adds or overwrites those values using what is found in the ARM Template. The API Reference for defining values in the [ARM Template can be found here](https://learn.microsoft.com/en-us/azure/templates/microsoft.containerinstance/containergroups?pivots=deployment-language-arm-template)

## dmverity Layer Hashing

To ensure the container that is being deployed is the intended container, the `confcom` tooling uses [dmverity hashing](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html).
This is done by downloading the container locally with the Docker Daemon (or using a pre-downloaded tar file of the OCI image) and performing the dmverity hashing using the [dmverity-vhd tool](https://github.com/microsoft/hcsshim/tree/main/cmd/dmverity-vhd).
These layer hashes are placed into the Rego security policy in the "layers" field of their respective container.
Note that these dmverity layer hashes are different than the layer hashes reported by `docker image inspect`.

### Mixed-mode Policy Generation

An OCI image can be made available for policy generation in three ways:

1. The image is in the local Docker Daemon and can be found either with its image and tag names or its sha256 hash.
2. The image is in an accessible remote repository.
Usually this is either Docker Hub or Azure Container Registry.
Note that if the registry is private, you must log in prior to policy generation.
3. The image is locally saved as a tar file in the form specified by `docker save`.

Mixed-mode policy generation is available in the `confcom` tooling, meaning images within the same security policy can be in any of these three locations with no issues.
