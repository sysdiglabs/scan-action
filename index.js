const core = require('@actions/core');
const exec = require('@actions/exec');

(async () => {
  try {
    const image_tag = core.getInput('image-tag', {required: true});
    const sysdig_secure_token = core.getInput('sysdig-secure-token', {required: true});
    const sysdig_secure_url = core.getInput('sysdig-secure-url', {required: true});
    const dockerfile_path = core.getInput('dockerfile-path');
    const pull_from_registry = core.getInput('pull-from-registry') == 'true';

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

    await exec.exec(cmd);

  } catch (error) {
    core.setFailed(error.message);
  }
})();
