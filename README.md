# Sysdig Secure Inline Scan Action

This action performs analysis on locally built container image and posts the result to Sysdig Secure. For more information about Secure Inline Scan, see https://github.com/sysdiglabs/secure-inline-scan and read [Sysdig Secure documentation](https://docs.sysdig.com/en/image-scanning.html).

## Inputs

### `image-tag`

**Required** The tag of the local image to scan. Example: `"sysdiglabs/dummy-vuln-app:latest"`.

### `sysdig-secure-token`

**Required** API token for Sysdig Scanning auth. Example: `"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"`.

Directly specifying the API token in the action configuration is not recommended. A better approach is to [store it in GitHub secrets](https://help.github.com/en/actions/automating-your-workflow-with-github-actions/creating-and-using-encrypted-secrets), and reference `${{ secrets.MY_SECRET_NAME }}` instead.

### `sysdig-secure-url`

Sysdig Secure URL. Example: "https://secure-sysdig.svc.cluster.local".

If not specified, it will default to Sysdig Secure SaaS URL (https://secure.sysdig.com/).

### `dockerfile-path`

Path to Dockerfile. Example: `"./Dockerfile"`.

### `pull-from-registry`

Pull container image from registry instead of using the locally built image.

## Example usage

```yaml
    ...
    - name: Build the Docker image
      run: docker build . --file Dockerfile --tag sysdiglabs/dummy-vuln-app:latest

    - name: Scan image
      uses: sysdiglabs/secure-inline-scan-action@v1
      with:
        image-tag: "sysdiglabs/dummy-vuln-app:latest"
        sysdig-secure-token: ${{ secrets.SYSDIG_SECURE_TOKEN }}

```
