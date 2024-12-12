
# Sysdig Secure Inline Scan Action

> 🚧 **Warning**: To use the Legacy Scanning Engine Action, please use version v3.* and visit the [previous README](./README.v3.md).

This action performs analysis on a specific container image and posts the result to Sysdig Secure. For more information about Sysdig CLI Scanner, see [Sysdig Secure documentation](https://docs.sysdig.com/en/docs/installation/sysdig-secure/install-vulnerability-cli-scanner/running-in-vm-mode/).

## Inputs

| Input                        | Description                                                                                                                                                                                                                                                                                                              | Default                   |
|------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------|
| `cli-scanner-url`            | URL to `sysdig-cli-scanner` binary download. The action will detect the runner OS and architecture. For more info about the Sysdig CLI Scanner download visit [the official documentation](https://docs.sysdig.com/en/docs/installation/sysdig-secure/install-vulnerability-cli-scanner/).                               |                           |
| `mode`                       | Mode of operation. Can be "vm" or "iac".                                                                                                                                                                                                                                                                                 | `vm`                      |
| `cli-scanner-version`        | Custom sysdig-cli-scanner version to download. If using iac mode, minimum required version is 1.9.0. Please note that for VM mode the Action has only been tested with the current default version and it is not guaranteed that it will work as expected with other versions.                                           | `1.18.0`                  |
| `registry-user`              | Registry username to authenticate to while pulling the image to scan.                                                                                                                                                                                                                                                    |                           |
| `registry-password`          | Registry password to authenticate to while pulling the image to scan.                                                                                                                                                                                                                                                    |                           |
| `stop-on-failed-policy-eval` | Fail the job if the Policy Evaluation is Failed.                                                                                                                                                                                                                                                                         |                           |
| `stop-on-processing-error`   | Fail the job if the Scanner terminates execution with errors.                                                                                                                                                                                                                                                            |                           |
| `severity-at-least`          | Filtering option to only report vulnerabilities with at least the specified severity. Can take `critical`, `high`, `medium`, `low`, `negligible` or `any`. Default value "any" for no filtering. For example, if `severity-at-least` is set to `medium`, only Medium, High or Critical vulnerabilities will be reported. | `any`                     |
| `group-by-package`           | Enable grouping the vulnerabilities in the SARIF report by package. Useful if you want to manage security per package or condense the number of findings.                                                                                                                                                                |                           |
| `standalone`                 | Enable standalone mode. Do not depend on Sysdig backend for execution, avoiding the need of specifying 'sysdig-secure-token' and 'sysdig-secure-url'. Recommended when using runners with no access to the internet. May require to specify custom `cli-scanner-url` and `db-path`.                                      |                           |
| `db-path`                    | Specify the directory for the vulnerabilities database to use while scanning. Useful when running in standalone mode.                                                                                                                                                                                                    |                           |
| `skip-upload`                | Skip uploading scanning results to Sysdig Secure.                                                                                                                                                                                                                                                                        |                           |
| `skip-summary`               | Skip generating Summary.                                                                                                                                                                                                                                                                                                 |                           |
| `use-policies`               | Specify Sysdig Secure VM Policies to evaluate the image.                                                                                                                                                                                                                                                                 |                           |
| `override-pullstring`        | Custom PullString to give the image when scanning and uploading. Useful when building images in a pipeline with temporary names. The custom PullString will be used to identify the scanned image in Sysdig Secure.                                                                                                      |                           |
| `image-tag`                  | Tag of the image to analyse.                                                                                                                                                                                                                                                                                             |                           |
| `sysdig-secure-token`        | API token for Sysdig Scanning authentication. (Required if not in Standalone mode.)                                                                                                                                                                                                                                      |                           |
| `sysdig-secure-url`          | Sysdig Secure Endpoint URL. Defaults to `https://secure.sysdig.com`. Please, visit the [official documentation](https://docs.sysdig.com/en/docs/administration/saas-regions-and-ip-ranges/) for more details on endpoints and regions.                                                                                   | https://secure.sysdig.com |
| `sysdig-skip-tls`            | Skip TLS verification when calling Sysdig Secure endpoints.                                                                                                                                                                                                                                                              |                           |
| `extra-parameters`           | Additional parameters to be added to the CLI Scanner. Note that these may not be supported with the current Action.                                                                                                                                                                                                      |                           |
| `recursive`                  | Recursively scan all folders within the folder specified in the iacScanPath.                                                                                                                                                                                                                                             |                           |
| `minimum-severity`           | Minimum severity to fail when scanning in IaC mode.                                                                                                                                                                                                                                                                      |                           |
| `iac-scan-path`              | Path to the IaC files to scan.                                                                                                                                                                                                                                                                                           |                           |


## SARIF Report

The action generates a SARIF report that can be uploaded using the `codeql-action/upload-sarif` action.

You need to assign an ID to the Sysdig Scan Action step, like:

```yaml
    ...

    - name: Scan image
      id: scan
      uses: sysdiglabs/scan-action@v5
      with:
        ...
```

and then add another step for uploading the SARIF report, providing the path in the `sarif_file` parameter:

```yaml
    ...
      - name: Upload SARIF file
        if: success() || failure() 
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ github.workspace }}/sarif.json
```

The `if: success() || failure()` option makes sure the SARIF report is uploaded even if the scan fails and interrupts the workflow. (Q: Why not `always()`? A: That would allow for canceled jobs as well.)

## Example usages

### Build and scan image locally using Docker, and upload SARIF report

```yaml

    ...

    - name: Build the Docker image
      run: docker build . --file Dockerfile --tag sysdiglabs/dummy-vuln-app:latest

    - name: Scan image
      id: scan
      uses: sysdiglabs/scan-action@v5
      with:
          image-tag: sysdiglabs/dummy-vuln-app:latest
          sysdig-secure-token: ${{ secrets.SYSDIG_SECURE_TOKEN }}

      - name: Upload SARIF file
        if: success() || failure() 
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ github.workspace }}/sarif.json

```

### Pull and scan an image from a registry

```yaml
    ...

    - name: Scan image
      uses: sysdiglabs/scan-action@v5
      with:
        image-tag: "sysdiglabs/dummy-vuln-app:latest"
        sysdig-secure-token: ${{ secrets.SYSDIG_SECURE_TOKEN }}
```

### Scan infrastructure using IaC scan

```yaml
    ...

    - name: Scan infrastructure
      uses: sysdiglabs/scan-action@v5
      with:
        sysdig-secure-token: ${{ secrets.SYSDIG_SECURE_TOKEN }}
        cli-scanner-version: 1.9.0
        mode: iac
        iac-scan-path: ./terraform
```

### Fail pipeline when Policy Evaluation is failed or scanner fails to run


```yaml
    ...

    - name: Scan image
      uses: sysdiglabs/scan-action@v3
      with:
        image-tag: "sysdiglabs/dummy-vuln-app:latest"
        sysdig-secure-token: ${{ secrets.SYSDIG_SECURE_TOKEN }}
        stop-on-failed-policy-eval: true
        stop-on-processing-error: true
```
