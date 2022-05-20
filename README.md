
# Sysdig Secure Inline Scan Action

This action performs analysis on locally built container image and posts the result to Sysdig Secure. For more information about Secure Inline Scan, see [Sysdig Secure documentation](https://docs.sysdig.com/en/integrate-with-ci-cd-tools.html).

## Inputs

### `image-tag`

**Required** The tag of the local image to scan. Example: `"sysdiglabs/dummy-vuln-app:latest"`.

### `sysdig-secure-token`

**Required** API token for Sysdig Scanning auth. Example: `"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"`.

Directly specifying the API token in the action configuration is not recommended. A better approach is to [store it in GitHub secrets](https://help.github.com/en/actions/automating-your-workflow-with-github-actions/creating-and-using-encrypted-secrets), and reference `${{ secrets.MY_SECRET_NAME }}` instead.

### `sysdig-secure-url`

Sysdig Secure URL. Example: `https://secure-sysdig.svc.cluster.local`

If not specified, it will default to Sysdig Secure SaaS URL (https://secure.sysdig.com).

For SaaS, eee [SaaS Regions and IP Ranges](https://docs.sysdig.com/en/saas-regions-and-ip-ranges.html).

### `sysdig-skip-tls`

Skip TLS verification when calling secure endpoints.

### `dockerfile-path`

Path to Dockerfile. Example: `"./Dockerfile"`.

### `ignore-failed-scan`

Don't fail the execution of this action even if the scan result is FAILED.

### `input-type`

If specified, where should we scan the image from. Possible values:
* **pull**: Pull the image from the registry. Default if not specified.
* **docker-daemon**: Get the image from the Docker daemon. The Docker socket must be available at `/var/run/docker.sock`
* **cri-o**: Get the image from containers-storage (CRI-O and others). Images must be stored in `/var/lib/containers`
* docker-archive: Image is provided as a Docker .tar file (from Docker save). Specify the path to the tar file with `input-path` parameter.
* **oci-archive**: Image is provided as a OCI image tar file. Specify the path to the tar file with `input-path` parameter.
* **oci-dir**: Image is provided as a OCI image, untared. Specify the path to the directory file with `input-path` parameter.

### `input-path`

Path to the tar file or OCI layout directory, or the Docker daemon when using `input-type: docker-daemon`, in case the `docker.sock` file is not in the default path `/var/run/docker.sock`.

### `run-as-user`

Run the scan container with this username or UID.
It might be required when scanning from docker-daemon or cri-o to provide a user with permissions on the socket or storage.

### `extra-parameters`

Additional parameters added to the secure-inline-scan container execution.

### `extra-docker-parameters`

Additional parameters added to the `docker` command when executing the secure-inline-scan container execution.

### `severity`

Filter output annotations by severity. Default is "unknown".
Possible values:
- critical
- high
- medium
- negligible
- unknown

### `unique-report-by-package`

Only one annotation by package name/version will be displayed in the build output. 
The last highest (by severity) vulnerability will be displayed by package.
It increases the readability of the output, avoiding duplicates for the same package.
Default to false.


### `inline-scan-image`

The image `quay.io/sysdig/secure-inline-scan:2`, which points to the latest 2.x version of the Sysdig Secure inline scanner is used by default.
This parameter allows overriding the default image, to use a specific version or for air-gapped environments.

## SARIF Report

The action generates a SARIF report that can be uploaded using the `codeql-action/upload-sarif` action.

You need to assign an ID to the Sysdig Scan Action step, like:

```yaml
    ...

    - name: Scan image
      id: scan
      uses: sysdiglabs/scan-action@v3
      with:
        ...
```

and then add another step for uploading the SARIF report, providing the path in the `sarifReport` output:

```yaml
    ...
      - uses: github/codeql-action/upload-sarif@v1
        with:
          if: always()
          sarif_file: ${{ steps.scan.outputs.sarifReport }}
```

The `if: always()` option makes sure the SARIF report is uploaded even if the scan fails and interrupts the workflow.

## Example usages

### Build and scan image locally using Docker, and upload SARIF report

```yaml

    ...

    - name: Build the Docker image
      run: docker build . --file Dockerfile --tag sysdiglabs/dummy-vuln-app:latest

    - name: Scan image
      id: scan
      uses: sysdiglabs/scan-action@v3
      with:
        image-tag: "sysdiglabs/dummy-vuln-app:latest"
        sysdig-secure-token: ${{ secrets.SYSDIG_SECURE_TOKEN }}
        input-type: docker-daemon
        run-as-user: root

      - uses: github/codeql-action/upload-sarif@v1
        if: always()
        with:
          sarif_file: ${{ steps.scan.outputs.sarifReport }}

```

### Pull and scan an image from a registry

```yaml
    ...

    - name: Scan image
      uses: sysdiglabs/scan-action@v3
      with:
        image-tag: "sysdiglabs/dummy-vuln-app:latest"
        sysdig-secure-token: ${{ secrets.SYSDIG_SECURE_TOKEN }}
```

### Scan a Docker archive image


```yaml
    ...

    - name: Scan image
      uses: sysdiglabs/scan-action@v3
      with:
        image-tag: "sysdiglabs/dummy-vuln-app:latest"
        sysdig-secure-token: ${{ secrets.SYSDIG_SECURE_TOKEN }}
        input-type: docker-archive
        input-path: artifacts/my-image.tar
```
