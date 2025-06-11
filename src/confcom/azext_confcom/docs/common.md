# Common Documentation

- [Security Policy Information Sources](#security-policy-information-sources)

## Security Policy Information Sources

Each container in a security policy can get its information from two different sources:

1. The image manifest. This can be explored using `docker image inspect`
2. The ARM Template used to generate the security policy. This can be used for startup command, environment variables, etc.

The `confcom` tooling uses the image manifest for default values and then adds or overwrites those values using what is found in the ARM Template. The API Reference for defining values in the [ARM Template can be found here](https://learn.microsoft.com/en-us/azure/templates/microsoft.containerinstance/containergroups?pivots=deployment-language-arm-template)
