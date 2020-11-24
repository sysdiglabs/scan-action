# Sysdig Secure Inline Scan Action

This action performs analysis on locally built container image and posts the result to Sysdig Secure. For more information about Secure Inline Scan, see https://github.com/sysdiglabs/secure-inline-scan and read [Sysdig Secure documentation](https://docs.sysdig.com/en/image-scanning.html).

## Inputs

### `image-tag`

**Required** The tag of the local image to scan. Example: `"sysdiglabs/dummy-vuln-app:latest"`.

### `sysdig-secure-token`

**Required** API token for Sysdig Scanning auth. Example: `"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"`.

Directly specifying the API token in the action configuration is not recommended. A better approach is to [store it in GitHub secrets](https://help.github.com/en/actions/automating-your-workflow-with-github-actions/creating-and-using-encrypted-secrets), and reference `${{ secrets.MY_SECRET_NAME }}` instead.

### `github-token`

**Required** Github App token to publish the checks. You can use secrets.GITHUB_TOKEN:

```yaml
    - name: Scan image
      uses: sysdiglabs/scan-action@v3
      ...
      with:
        ...
        github-token: ${{ secrets.GITHUB_TOKEN }}
```

See https://docs.github.com/en/free-pro-team@latest/actions/reference/authentication-in-a-workflow#about-the-github_token-secret

### `sysdig-secure-url`

Sysdig Secure URL. Example: "https://secure-sysdig.svc.cluster.local".

If not specified, it will default to Sysdig Secure SaaS URL (https://secure.sysdig.com/).

### `sysdig-skip-tls`

Skip TLS verification when calling secure endpoints.

### `dockerfile-path`

Path to Dockerfile. Example: `"./Dockerfile"`.

### `pull-from-registry`

Pull container image from registry instead of using a locally built image. It takes precedence over any 'input-type'.

### `ignore-failed-scan`

Don't fail the execution of this action even if the scan result is FAILED.

### `input-type`

Source of the image. Possible values:

* docker-daemon   Get the image from the Docker daemon.
                  The docker socket must be available at /var/run/docker.sock
* cri-o           Get the image from containers-storage (CRI-O and others).
                  Images must be stored in /var/lib/containers
* docker-archive  Image is provided as a Docker .tar file (from docker save).
                  Specify path to the tar file with 'input-path'
* oci-archive     Image is provided as a OCI image tar file.
                  Specify path to the tar file with 'input-path'
* oci-dir         Image is provided as a OCI image, untared.
                  Specify path to the directory file with 'input-path'
  
If not specified, it defaults to docker-daemon, unless 'pull-from-registry' is enabled.

### `input-path`

Path to the tar file or OCI layout directory.

### `run-as-user`

Run the scan container with this username or UID.
It might required if scanning from docker-daemon or cri-o to provide a user with permissions on the socket or storage.

### `extra-parameters`

Additional parameters added to the secure-inline-scan container execution.

### `extra-docker-parameters`

Additional parameters added to the docker command when executing the secure-inline-scan container execution.

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
        sarif_file: ${{ steps.scan.outputs.sarifReport }}
```

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
        run-as-user: root
        github-token: ${{ secrets.GITHUB_TOKEN }}

      - uses: github/codeql-action/upload-sarif@v1
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
        pull-from-registry: true
        github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Scan a docker archive image


```yaml
    ...

    - name: Scan image
      uses: sysdiglabs/scan-action@v3
      with:
        image-tag: "sysdiglabs/dummy-vuln-app:latest"
        sysdig-secure-token: ${{ secrets.SYSDIG_SECURE_TOKEN }}
        input-type: docker-archive
        input-path: artifacts/my-image.tar
        github-token: ${{ secrets.GITHUB_TOKEN }}
```