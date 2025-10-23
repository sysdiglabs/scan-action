import * as core from '@actions/core';
import fs from 'fs';
import { IReportPresenter } from '../../application/ports/IReportPresenter';
import { FilterOptions, filterPackages } from '../../domain/services/filtering';
import { version } from '../../../package.json';
import { Package, ScanResult, Vulnerability } from '../../domain/scanresult';

const toolVersion = `${version}`;
const dottedQuadToolVersion = `${version}.0`;

interface SARIFResult {
  ruleId: string;
  level: string;
  message: {
    text: string;
  };
  locations: {
    physicalLocation: {
      artifactLocation: {
        uri: string;
        uriBaseId: string;
      };
    };
    message: {
      text: string;
    };
  }[];
}

interface SARIFRule {
  id: string;
  name: string;
  shortDescription: {
    text: string;
  };
  fullDescription: {
    text: string;
  };
  helpUri: string;
  help: {
    text: string;
    markdown: string;
  };
  properties: {
    precision: string;
    'security-severity': string;
    tags: string[];
  };
}

export class SarifReportPresenter implements IReportPresenter {
  generateReport(data: ScanResult, groupByPackage: boolean, filters?: FilterOptions) {
    let sarifOutput = this.vulnerabilities2SARIF(data, groupByPackage, filters);
    core.setOutput("sarifReport", "./sarif.json");
    fs.writeFileSync("./sarif.json", JSON.stringify(sarifOutput, null, 2));
  }

  private vulnerabilities2SARIF(
    data: ScanResult,
    groupByPackage: boolean,
    filters?: FilterOptions
  ) {


    let rules: SARIFRule[] = [];
    let results: SARIFResult[] = [];

    if (groupByPackage) {
      [rules, results] = this.vulnerabilities2SARIFResByPackage(data, filters)
    } else {
      [rules, results] = this.vulnerabilities2SARIFRes(data, filters)
    }

    const runs = [{
      tool: {
        driver: {
          name: "sysdig-cli-scanner",
          fullName: "Sysdig Vulnerability CLI Scanner",
          informationUri: "https://docs.sysdig.com/en/docs/installation/sysdig-secure/install-vulnerability-cli-scanner",
          version: toolVersion,
          semanticVersion: toolVersion,
          dottedQuadFileVersion: dottedQuadToolVersion,
          rules: rules
        }
      },
      logicalLocations: [
        {
          name: "container-image",
          fullyQualifiedName: "container-image",
          kind: "namespace"
        }
      ],
      results: results,
      columnKind: "utf16CodeUnits",
      properties: {
        pullString: data.metadata.pullString,
        digest: data.metadata.digest,
        imageId: data.metadata.imageId,
        architecture: data.metadata.architecture,
        baseOs: data.metadata.baseOs,
        os: data.metadata.baseOs,
        size: data.metadata.sizeInBytes.toString(),
        layersCount: data.getLayers().length,
        resultUrl: "",
        resultId: "",
      }
    }];


    const sarifOutput = {
      "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: runs
    };

    return (sarifOutput);
  }

  private vulnerabilities2SARIFResByPackage(data: ScanResult, filters?: FilterOptions): [SARIFRule[], SARIFResult[]] {
    let rules: SARIFRule[] = [];
    let results: SARIFResult[] = [];


    filterPackages(data.getPackages(), filters).forEach((pkg: Package) => {
      let fullDescription = "";
      let severityLevel = "";
      let maxCvssFound = 0;
      pkg.getVulnerabilities().forEach(vuln => {
        fullDescription += `${this.getSARIFVulnFullDescription(pkg, vuln)} \
\
\
`;

        if (vuln.cvssScore > maxCvssFound) {
          maxCvssFound = vuln.cvssScore;
        }

      });

      let rule: SARIFRule = {
        id: pkg.name,
        name: pkg.name,
        shortDescription: {
          text: `Vulnerable package: ${pkg.name}`
        },
        fullDescription: {
          text: fullDescription
        },
        helpUri: "",
        help: this.getSARIFPkgHelp(pkg),
        properties: {
          precision: "very-high",
          'security-severity': `${maxCvssFound}`,
          tags: [
            'vulnerability',
            'security',
            severityLevel
          ]
        }
      }
      rules.push(rule);

      let result: SARIFResult = {
        ruleId: pkg.name,
        level: this.check_level(severityLevel),
        message: {
          text: this.getSARIFReportMessageByPackage(pkg)
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: `file:///${this.sanitizeImageName(data.metadata.pullString)}`,
                uriBaseId: "ROOTPATH"
              }
            },
            message: {
              text: `${data.metadata.pullString} - ${pkg.name}@${pkg.version}`
            }
          }
        ]
      }
      results.push(result)
    });

    return [rules, results];
  }

  private sanitizeImageName(imageName: string) {
    // Replace / and : with -
    return imageName.replace(/[\/:]/g, '-');
  }

  private vulnerabilities2SARIFRes(data: ScanResult, filters?: FilterOptions): [SARIFRule[], SARIFResult[]] {
    let results: SARIFResult[] = [];
    let rules: SARIFRule[] = [];
    let ruleIds: string[] = [];

    filterPackages(data.getPackages(), filters).forEach(pkg => {
      pkg.getVulnerabilities().forEach(vuln => {
        if (!(vuln.cve in ruleIds)) {
          ruleIds.push(vuln.cve)
          let rule = {
            id: vuln.cve,
            name: pkg.packageType.toString(),
            shortDescription: {
              text: this.getSARIFVulnShortDescription(pkg, vuln)
            },
            fullDescription: {
              text: this.getSARIFVulnFullDescription(pkg, vuln)
            },
            helpUri: `https://nvd.nist.gov/vuln/detail/${vuln.cve}`,
            help: this.getSARIFVulnHelp(pkg, vuln),
            properties: {
              precision: "very-high",
              'security-severity': `${vuln.cvssScore}`,
              tags: [
                'vulnerability',
                'security',
                vuln.severity.toString()
              ]
            }
          }
          rules.push(rule)
        }

        let result = {
          ruleId: vuln.cve,
          level: this.check_level(vuln.severity.toString()),
          message: {
            text: this.getSARIFReportMessage(data, vuln, pkg)
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: `file:///${this.sanitizeImageName(data.metadata.pullString)}`,
                  uriBaseId: "ROOTPATH"
                }
              },
              message: {
                text: `${data.metadata.pullString} - ${pkg.name}@${pkg.version}`
              }
            }
          ]
        }
        results.push(result)
      });
    });

    return [rules, results];
  }
  private getSARIFVulnShortDescription(pkg: Package, vuln: Vulnerability) {
    return `${vuln.cve} Severity: ${vuln.severity} Package: ${pkg.name}`;
  }

  private getSARIFVulnFullDescription(pkg: Package, vuln: Vulnerability) {
    return `${vuln.cve}
  Severity: ${vuln.severity}
  Package: ${pkg.name}
  Type: ${pkg.packageType.toString()}
  Fix: ${vuln.fixVersion || "No fix available"}
  URL: https://nvd.nist.gov/vuln/detail/${vuln.cve}`;
  }

  private getSARIFPkgHelp(pkg: Package) {
    let text = "";
    pkg.getVulnerabilities().forEach(vuln => {
      text += `Vulnerability ${vuln.cve}
    Severity: ${vuln.severity}
    Package: ${pkg.name}
    CVSS Score: ${vuln.cvssScore}
    Version: ${pkg.version}
    Fix Version: ${vuln.fixVersion || "No fix available"}
    Exploitable: ${vuln.exploitable}
    Type: ${pkg.packageType.toString()}
    Location: ${pkg.path}
    URL: https://nvd.nist.gov/vuln/detail/${vuln.cve}\n\n\n`
    });

    let markdown = `| Vulnerability | Severity | CVSS Score | Exploitable |
    | -------- | ------- | ---------- |  ----------- |
`;

    pkg.getVulnerabilities().forEach(vuln => {
      markdown += `| ${vuln.cve} | ${vuln.severity} | ${vuln.cvssScore} | ${vuln.exploitable} |
`
    });

    return {
      text: text,
      markdown: markdown
    };
  }

  private getSARIFVulnHelp(pkg: Package, vuln: Vulnerability) {
    return {
      text: `Vulnerability ${vuln.cve}
  Severity: ${vuln.severity}
  Package: ${pkg.name}
  CVSS Score: ${vuln.cvssScore}
  Version: ${pkg.version}
  Fix Version: ${vuln.fixVersion || "No fix available"}
  Exploitable: ${vuln.exploitable}
  Type: ${pkg.packageType.toString()}
  Location: ${pkg.path}
  URL: https://nvd.nist.gov/vuln/detail/${vuln.cve}`,
      markdown: `
  **Vulnerability [${vuln.cve}](https://nvd.nist.gov/vuln/detail/${vuln.cve})**
  | Severity | Package | CVSS Score | Fixed Version | Exploitable |
  | -------- | ------- | ---------- | ------------- | ----------- |
  | ${vuln.severity} | ${pkg.name} | ${vuln.cvssScore} | ${vuln.fixVersion || "None"} | ${vuln.exploitable} |
`
    }
  }
  private getSARIFReportMessageByPackage(pkg: Package) {
    let message = "Full scan result:";

    message += `Package: ${pkg.name}
`;

    message += `Package type: ${pkg.packageType.toString()}
    Installed Version: ${pkg.version}
    Package path: ${pkg.path}
`;

    pkg.getVulnerabilities().forEach(vuln => {
      message += ".\n";

      message += `Vulnerability: ${vuln.cve}
`;

      message += `Severity: ${vuln.severity}
      CVSS Score: ${vuln.cvssScore}
      Fixed Version: ${(vuln.fixVersion || 'No fix available')}
      Exploitable: ${vuln.exploitable}
      Link to NVD: [${vuln.cve}](https://nvd.nist.gov/vuln/detail/${vuln.cve})
`;
    });



    return message;
  }

  private getSARIFReportMessage(data: ScanResult, vuln: Vulnerability, pkg: Package) {
    let message = `Full image scan results for ${data.metadata.pullString} scan result:
`;

      message += `Package: ${pkg.name}
`;

    message += `Package type: ${pkg.packageType.toString()}
    Installed Version: ${pkg.version}
    Package path: ${pkg.path}
`;

      message += `Vulnerability: ${vuln.cve}
`;
    message += `Severity: ${vuln.severity.toString()}
    CVSS Score: ${vuln.cvssScore}
    Fixed Version: ${(vuln.fixVersion || 'No fix available')}
    Exploitable: ${vuln.exploitable}
    Link to NVD: [${vuln.cve}](https://nvd.nist.gov/vuln/detail/${vuln.cve})`;

    return message;
  }

  // Sysdig to SARIF severity convertion
  private readonly LEVELS: any = {
    "error": ["High", "Critical"],
    "warning": ["Medium"],
    "note": ["Negligible", "Low"]
  }

  private check_level(sev_value: string) {
    let level = "note";

    for (let key in this.LEVELS) {
      if (sev_value in this.LEVELS[key]) {
        level = key
      }
    }

    return level
  }
}
