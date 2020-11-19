const core = require('@actions/core');
const exec = require('@actions/exec');
const fs = require('fs')
const path = require('path');

const tool_version = "3.0.0"
const dotted_quad_tool_version = "3.0.0.0"
const secure_inline_scan_image = "airadier/secure-inline-scan:ci"

async function run() {
  
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
    let run_flags = `--sysdig-token ${sysdig_secure_token} --format=JSON`
    let docker_socket_path = input_path || "/var/run/docker.sock"
    
    core.info('Analyzing image: ' + image_tag);
    
    if (sysdig_secure_url) {
      core.info('Sysdig Secure URL: ' + sysdig_secure_url);
      run_flags += ` --sysdig-url ${sysdig_secure_url}`
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

    let cmd = `docker run ${docker_flags} ${secure_inline_scan_image} ${run_flags}`;

    try {
      let execOutput = '';

      const options = {
        silent: true,
        ignoreReturnCode: true,
        listeners:  {
          stdout: (data) => {
            execOutput += data.toString();
          }
        }
      };

      let retCode = await exec.exec(cmd, null, options);
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

      fs.writeFileSync("./report.json", execOutput);
      core.setOutput("scanReport", "./report.json")
      generateSARIFReport()
    } catch (error) {
      core.setFailed(error.message);
    }

  } catch (error) {
    core.setFailed(error.message);
  }
  
}

if (require.main === module) {
  run();
}

function vulnerabilities2SARIF(vulnerabilities) {

  const sarifOutput = {
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
          {
      "tool": {
          "driver": {
          "name": "Sysdig Inline Scanner V2",
          "fullName": "Sysdig Inline Scanner V2",
          "version": tool_version,
          "semanticVersion": tool_version,
          "dottedQuadFileVersion": dotted_quad_tool_version,
          "rules": renderRules(vulnerabilities)
          }
      },
      "logicalLocations": [
                  {
          "name": "container-image",
          "fullyQualifiedName": "container-image",
          "kind": "namespace"
                  }
      ],
      "results": renderResults(vulnerabilities),
      "columnKind": "utf16CodeUnits"
          }
  ]
  }

  return(sarifOutput)
}

function renderRules(vulnerabilities) {
  var ret = {}
  if (vulnerabilities) {
  ret = vulnerabilities.map(v =>
                {
                    return {
                    "id": "ANCHOREVULN_"+v.vuln+"_"+v.package_type+"_"+v.package,
                    "shortDescription": {
                        "text": v.vuln + " Severity=" + v.severity + " Package=" + v.package + " Type=" + v.package_type + " Fix=" + v.fix + " Url=" + v.url,
                    },
                    "fullDescription": {
                        "text": v.vuln + " Severity=" + v.severity + " Package=" + v.package + " Type=" + v.package_type + " Fix=" + v.fix + " Url=" + v.url,
                    },
                    "help": {
                        "text": "Vulnerability "+v.vuln+"\n"+
                        "Severity: "+v.severity+"\n"+
                        "Package: "+v.package_name+"\n"+
                        "Version: "+v.package_version+"\n"+
                        "Fix Version: "+v.fix+"\n"+
                        "Type: "+v.package_type+"\n"+
                        "Location: "+v.package_path+"\n"+
                        "Data Namespace: "+v.feed + ", "+v.feed_group+"\n"+
                        "Link: ["+v.vuln+"]("+v.url+")",
                        "markdown": "**Vulnerability "+v.vuln+"**\n"+
                        "| Severity | Package | Version | Fix Version | Type | Location | Data Namespace | Link |\n"+
                        "| --- | --- | --- | --- | --- | --- | --- | --- |\n"+
                        "|"+v.severity+"|"+v.package_name+"|"+v.package_version+"|"+v.fix+"|"+v.package_type+"|"+v.package_path+"|"+v.feed_group+"|["+v.vuln+"]("+v.url+")|\n"
                    }

                    }
                }
               );
  }
  return(ret);
}

function convertSeverityToSARIF(input_severity) {
  var ret = "error";
  // const severityLevels = {
  //   Unknown: 0,
  //   Negligible: 1,
  //   Low: 2,
  //   Medium: 3,
  //   High: 4,
  //   Critical: 5,
  // };

  return ret;
}



function renderResults(vulnerabilities) {
  var ret = {};

  if (vulnerabilities) {
    ret = vulnerabilities.map((v) => {
      return {
        ruleId:
          "ANCHOREVULN_" + v.vuln + "_" + v.package_type + "_" + v.package,
        ruleIndex: 0,
        level: convertSeverityToSARIF(v.severity),
        message: {
          text: v.vuln + " Severity=" + v.severity + "Package=" + v.package + " Type=" + v.package_type + " Fix=" + v.fix + " Url=" + v.url,
          id: "default",
        },
        analysisTarget: {
          uri: "Container image",
          index: 0,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: "Container image",
              },
              region: {
                startLine: 1,
                startColumn: 1,
                endLine: 1,
                endColumn: 1,
                byteOffset: 1,
                byteLength: 1,
              },
            },
            logicalLocations: [
              {
                fullyQualifiedName: "container-image",
              },
            ],
          },
        ],
        suppressions: [
          {
            kind: "external",
          },
        ],
        baselineState: "unchanged",
      };
    });
  }
  return ret;
}

function generateSARIFReport(){
  let reportData = fs.readFileSync("./report.json");
  let report = JSON.parse(reportData);
  let vulnerabilities = []
  if (report.vulnsReport) {
    vulnerabilities = report.vulnsReport.vulnerabilities
  }

  let sarifOutput = vulnerabilities2SARIF(vulnerabilities);
  fs.writeFileSync("./sarif.json", JSON.stringify(sarifOutput, null, 2));
  core.setOutput("sarifReport", "./sarif.json")
}
