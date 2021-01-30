## lego webhook for cert-manager

This repo contains an go-acme (lego) webhook DNS01 provider for cert-manager. 
That means you can use any lego supported dns provider in cert-manager.

See [https://github.com/jetstack/cert-manager]() and [https://github.com/jetstack/cert-manager-webhook-example]()

### State of the project
This must be considered as an alpha project under testing.
It need an updated version of cert-manager (See [https://github.com/jetstack/cert-manager/pull/3614]()) to work !
Helm chart is not working, use deploy/manifests/

## Example configuration
See [deploy/manifests/sample-issuer.yaml]() for an example issuer configuration.
You need to provide the lego provider name and the required lego env var in k8s native format.

```yaml
provider: <lego-provider-name>
env:
- name: <env-var-name>
  value: <env-var-value>
- name: <env-var-name>
  valueFrom:
    secretKeyRef:
      name: <secret-name>
      key: <secret-key>
- name: INFOMANIAK_ENDPOINT
  valueFrom:
    configMapKeyRef:
      name: <configmap-name>
      key: <configmap-key>
```
## API Group and Name
GROUP_NAME in the deployment must match the APIService group name and be configured in the issuer manifest.
SOLVER_NAME (defaults to lego) can be changed and must match the name configured in the issuer and the APIservice.


## RBAC
The webhook deployment must have rights to fetch secret and config maps if needed.

## Cluster Issuer
The secrets and configmaps referenced in the config must be in the deployment namespace (to be verified).

## Tests

An Go test file has been provided in [main_test.go]().
You can run the test suite with:

```bash
$ TEST_ZONE_NAME=example.com go test .
```

## TODO
- Adapt and Enhance the test suite (using lego, we can only set _\_acme-challenge_ DNS key and the tests create random keys)
- Do extended test 
- Clarify the CNAME following policy
- Check is recreating the provider between Present and Cleanup is OK (probably not) and add a store system if needed.
- Update the helm chart