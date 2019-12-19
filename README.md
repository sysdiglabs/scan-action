# Sysdig Secure Inline Scan Action

This action performs image analysis on locally built container image and posts the result of the analysis to Sysdig Secure. For more information about Secure Inline Scan, see https://github.com/sysdiglabs/secure-inline-scan and read [Sysdig Secure documentation](https://docs.sysdig.com/en/image-scanning.html)

## Inputs

### `image-tag`

**Required** The tag of the image to scan. The image needs to be build on a previous step, as the scan is done locally. Example: `"sysdiglabs/dummy-vuln-app:latest"`

### `sysdig-secure-token`

**Required** API token for Sysdig Scanning auth. Example: `"924c7ddc-4c09-4d22-bd52-2f7db22f3066"`

It is not recommended to hardcode the API token in the action, but [store it in Github secrets](https://help.github.com/en/actions/automating-your-workflow-with-github-actions/creating-and-using-encrypted-secrets) instead and use `${{ secrets.MY_SECRET_NAME }}` instead.

### `sysdig-secure-url`

URL to Sysdig Secure URL (ex: "https://secure-sysdig.com").

If not specified, it will default to Sysdig Secure SaaS URL (https://secure.sysdig.com)

### `dockerfile-path`

Path to Dockerfile (ex: "./Dockerfile")

### `pull-from-registry`

Pull docker image from registry instead of using locally built image.

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
