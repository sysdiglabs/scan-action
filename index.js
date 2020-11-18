const core = require('@actions/core');
const exec = require('@actions/exec');
const path = require('path')
const querystring = require("querystring");

(async () => {
  
  try {

    const image_tag = core.getInput('image-tag', {required: true});
    const sysdig_secure_token = core.getInput('sysdig-secure-token', {required: true});
    const sysdig_secure_url = core.getInput('sysdig-secure-url');
    const sysdig_skip_tls = core.getInput('sysdig-skip-tls') == 'true';
    const dockerfile_path = core.getInput('dockerfile-path');
    const pull_from_registry = core.getInput('pull-from-registry') == 'true';
    const ignore_failed_scan = core.getInput('ignore-failed-scan') == 'true';
    let input_type = core.getInput('input-type');
    const input_path = core.getInput('input-path');
    const run_as_user = core.getInput('run-as-user')
    const extra_parameters = core.getInput('extra-parameters')
    const extra_docker_parameters = core.getInput('extra-docker-parameters')
    
    let docker_flags = "--rm"
    let run_flags = `--sysdig-token ${sysdig_secure_token}`
    let docker_socket_path = input_path || "/var/run/docker.sock"
    
    core.info('Analyzing image: ' + image_tag);
    
    if (sysdig_secure_url) {
      core.info('Sysdig Secure URL: ' + sysdig_secure_url);
      run_flags += `--sysdig-url ${sysdig_secure_url}`
    }

    if (pull_from_registry) {
      core.info('Input type: pull from registry');
    } else {
      input_type = input_type || "docker-daemon"
      core.info(`Input type: ${input_type}`);
      run_flags += ` --storage-type=${input_type}`
    }

    if (input_path) {
      core.info(`Input path: ${input_path}`);
      let file_name = path.basename(input_path)
      docker_flags += ` -v ${path.resolve(input_path)}:/tmp/${file_name}`
      run_flags += ` --storage-path=/tmp/${file_name}`
    }

    if (input_type == "docker-daemon") {
      docker_flags += ` -v ${docker_socket_path}:/var/run/docker.sock`
    }

    if (dockerfile_path) {
      core.info(`Dockerfile Path: ${dockerfile_path}`);
      docker_flags += ` -v ${path.resolve(dockerfile_path)}:/tmp/Dockerfile`
      run_flags += ` --dockerfile /tmp/Dockerfile`;
    }

    if (run_as_user) {
      core.info(`Running as user: ${run_as_user}`);
      docker_flags += ` -u ${run_as_user}`
    }

    if (sysdig_skip_tls) {
      core.info(`Sysdig skip TLS: true`);
      run_flags += `--sysdig-skip-tls`
    }

    if (extra_parameters) {
      run_flags += ` ${extra_parameters}`
    }

    if (extra_docker_parameters) {
      docker_flags += ` ${extra_docker_parameters}`
    }

    run_flags += ` ${image_tag}`;

    let cmd = `docker run ${docker_flags} sysdiglabs/secure-inline-scan:2 ${run_flags}`;

    try {
      let retCode = await exec.exec(cmd, null, {ignoreReturnCode: true});
      if (retCode == 0) {
        core.info(`Scan was SUCCESS.`);
      } else if (retCode == 1) {
        if (ignore_failed_scan) {
          core.info(`Scan was FAILED.`);
        } else {
          core.setFailed(`Scan was FAILED.`);
        }
      } else {
        core.setFailed(`Execution error`)
      }
    } catch (error) {
      core.setFailed(error.message);
    }

  } catch (error) {
    core.setFailed(error.message);
  }
  
})();

