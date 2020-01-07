const core = require('@actions/core');
const exec = require('@actions/exec');
const querystring = require("querystring");

(async () => {
  
  try {

    const image_tag = core.getInput('image-tag', {required: true});
    const sysdig_secure_token = core.getInput('sysdig-secure-token', {required: true});
    const sysdig_secure_url = core.getInput('sysdig-secure-url', {required: true});
    const dockerfile_path = core.getInput('dockerfile-path');
    const pull_from_registry = core.getInput('pull-from-registry') == 'true';
    
    let image_id = '';

    // Calculate SYSDIG_DIGEST as done in inline_scan.sh
    const options = {};
    options.silent = true;
    options.listeners = {
      stdout: (data) => {
        image_id += data.toString();
      }
    };

    try {
      await exec.exec(`docker inspect --format="{{index .RepoDigests 0}}" ${image_tag}`, [], options);
      image_id = "sha256:" + image_id.split(':')[1];
    } catch {
      // Calculate from the output of docker inspect
      image_id = '';
      await exec.exec(`bash -c "docker inspect ${image_tag} | sha256sum | awk '{ print $1 }' | tr -d \\"\\n\\""`, [], options);
      image_id = "sha256:" + image_id;
    }

    let cmd = `${__dirname}/inline_scan.sh analyze -s ${sysdig_secure_url} -k ${sysdig_secure_token}`;
    
    core.info('Analyzing image: ' + image_tag);
    core.info('Sysdig Secure URL: ' + sysdig_secure_url);
    if (dockerfile_path) {
      core.info('Dockerfile Path: ' + dockerfile_path);
      cmd = cmd + ` -f ${dockerfile_path}`;
    }
    if (pull_from_registry) {
      core.info('Pull from registry: ' + true);
      cmd += ' -P';
    }

    cmd += ` ${image_tag}`;

    try {
      await exec.exec(cmd);
      core.info(`Scan was SUCCESS. Check scan results at ${sysdig_secure_url}/#/scanning/scan-results/localbuild%2F${querystring.escape(image_tag)}/${image_id}`);
    } catch (error) {
      core.setFailed(`Scan FAILED. Check scan results at ${sysdig_secure_url}/#/scanning/scan-results/localbuild%2F${querystring.escape(image_tag)}/${image_id}`);
    }

  } catch (error) {
    core.setFailed(error.message);
  }
  
})();

