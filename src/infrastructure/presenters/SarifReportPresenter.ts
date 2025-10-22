import * as core from '@actions/core';
import fs from 'fs';
import { IReportPresenter } from '../../application/ports/IReportPresenter';
import { JsonScanResultV1, JsonPackage } from '../entities/JsonScanResultV1';
import { Vulnerability } from '../../domain/entities/vulnerability';
import { FilterOptions, filterPackages } from '../../domain/services/filtering';
import { SeverityNames } from '../../domain/value-objects/severity';
import { version } from '../../../package.json';

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
  generateReport(data: JsonScanResultV1, groupByPackage: boolean, filters?: FilterOptions) {
    let sarifOutput = this.vulnerabilities2SARIF(data, groupByPackage, filters);
    core.setOutput("sarifReport", "./sarif.json");
    fs.writeFileSync("./sarif.json", JSON.stringify(sarifOutput, null, 2));
  }

  private vulnerabilities2SARIF(
    data: JsonScanResultV1,
    groupByPackage: boolean,
    filters?: FilterOptions
  ) {

    const filteredPackages = filterPackages(data.result.packages, data.result.vulnerabilities, filters ?? {});
    const filteredData = { ...data, result: { ...data.result, packages: filteredPackages } };

    let rules: SARIFRule[] = [];
    let results: SARIFResult[] = [];

    if (groupByPackage) {
      [rules, results] = this.vulnerabilities2SARIFResByPackage(filteredData)
    } else {
      [rules, results] = this.vulnerabilities2SARIFRes(filteredData)
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
        pullString: data.result.metadata.pullString,
        digest: data.result.metadata.digest,
        imageId: data.result.metadata.imageId,
        architecture: data.result.metadata.architecture,
        baseOs: data.result.metadata.baseOs,
        os: data.result.metadata.os,
        size: data.result.metadata.size,
        layersCount: Object.values(data.result.layers).length,
        resultUrl: data.info.resultUrl || "",
        resultId: data.info.resultId || "",
      }
    }];


    const sarifOutput = {
      "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: runs
    };

    return (sarifOutput);
  }

  private numericPriorityForSeverity(severity: string): number {
    let sevNum = SeverityNames.indexOf(severity.toLowerCase() as any);
    sevNum = sevNum === -1 ? 5 : sevNum;
    return sevNum;
  }

  private vulnerabilities2SARIFResByPackage(data: JsonScanResultV1): [SARIFRule[], SARIFResult[]] {
    let rules: SARIFRule[] = [];
    let results: SARIFResult[] = [];
    let resultUrl = "";
    let baseUrl: string | undefined;

    if (data.info && data.result) {
      if (data.info.resultUrl) {
        resultUrl = data.info.resultUrl;
        baseUrl = resultUrl.slice(0, resultUrl.lastIndexOf('/'));
      }

      Object.values(data.result.packages).forEach((pkg: JsonPackage) => {
        let helpUri = "";
        let fullDescription = "";
        let severityLevel = "";
        let minSeverityNum = 5;
        let score = 0.0;
        if (pkg.vulnerabilitiesRefs) {
          pkg.vulnerabilitiesRefs.forEach(vulnRef => {
            const vuln = data.result.vulnerabilities[vulnRef];
            fullDescription += `${this.getSARIFVulnFullDescription(pkg, vuln)} \
\
\
`;

            const sevNum = this.numericPriorityForSeverity(vuln.severity);

            if (sevNum < minSeverityNum) {
              severityLevel = vuln.severity.toLowerCase();
              minSeverityNum = sevNum;
            }

            if (vuln.cvssScore.score > score) {
              score = vuln.cvssScore.score;
            }
          });
        }
        if (baseUrl) helpUri = `${baseUrl}/content?filter=freeText+in+("${pkg.name}")`;


        let rule: SARIFRule = {
          id: pkg.name,
          name: pkg.name,
          shortDescription: {
            text: `Vulnerable package: ${pkg.name}`
          },
          fullDescription: {
            text: fullDescription
          },
          helpUri: helpUri,
          help: this.getSARIFPkgHelp(pkg, data.result.vulnerabilities),
          properties: {
            precision: "very-high",
            'security-severity': `${score}`,
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
            text: this.getSARIFReportMessageByPackage(data, pkg, baseUrl)
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: `file:///${this.sanitizeImageName(data.result.metadata.pullString)}`,
                  uriBaseId: "ROOTPATH"
                }
              },
              message: {
                text: `${data.result.metadata.pullString} - ${pkg.name}@${pkg.version}`
              }
            }
          ]
        }
        results.push(result)
      });
    }

    return [rules, results];
  }

  private sanitizeImageName(imageName: string) {
    // Replace / and : with -
    return imageName.replace(/[\/:]/g, '-');
  }

  private vulnerabilities2SARIFRes(data: JsonScanResultV1): [SARIFRule[], SARIFResult[]] {
    let results: SARIFResult[] = [];
    let rules: SARIFRule[] = [];
    let ruleIds: string[] = [];
    let resultUrl = "";
    let baseUrl: string | undefined;

    if (data.info && data.result) {
      if (data.info.resultUrl) {
        resultUrl = data.info.resultUrl;
        baseUrl = resultUrl.slice(0, resultUrl.lastIndexOf('/'));
      }

      Object.values(data.result.packages).forEach(pkg => {
        if (pkg.vulnerabilitiesRefs) {
          pkg.vulnerabilitiesRefs.forEach(vulnRef => {
            const vuln = data.result.vulnerabilities[vulnRef];
            if (!(vuln.name in ruleIds)) {
              ruleIds.push(vuln.name)
              let rule = {
                id: vuln.name,
                name: pkg.type,
                shortDescription: {
                  text: this.getSARIFVulnShortDescription(pkg, vuln)
                },
                fullDescription: {
                  text: this.getSARIFVulnFullDescription(pkg, vuln)
                },
                helpUri: `https://nvd.nist.gov/vuln/detail/${vuln.name}`,
                help: this.getSARIFVulnHelp(pkg, vuln),
                properties: {
                  precision: "very-high",
                  'security-severity': `${vuln.cvssScore.score}`,
                  tags: [
                    'vulnerability',
                    'security',
                    vuln.severity
                  ]
                }
              }
              rules.push(rule)
            }

            let result = {
              ruleId: vuln.name,
              level: this.check_level(vuln.severity),
              message: {
                text: this.getSARIFReportMessage(data, vuln, pkg, baseUrl)
              },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: {
                      uri: `file:///${this.sanitizeImageName(data.result.metadata.pullString)}`,
                      uriBaseId: "ROOTPATH"
                    }
                  },
                  message: {
                    text: `${data.result.metadata.pullString} - ${pkg.name}@${pkg.version}`
                  }
                }
              ]
            }
            results.push(result)
          });
        }
      });
    }

    return [rules, results];
  }
  private getSARIFVulnShortDescription(pkg: JsonPackage, vuln: Vulnerability) {
    return `${vuln.name} Severity: ${vuln.severity} Package: ${pkg.name}`;
  }

  private getSARIFVulnFullDescription(pkg: JsonPackage, vuln: Vulnerability) {
    return `${vuln.name}
  Severity: ${vuln.severity}
  Package: ${pkg.name}
  Type: ${pkg.type}
  Fix: ${pkg.suggestedFix || "No fix available"}
  URL: https://nvd.nist.gov/vuln/detail/${vuln.name}`;
  }

  private getSARIFPkgHelp(pkg: JsonPackage, vulns: { [key: string]: Vulnerability}) {
    let text = "";
    if (pkg.vulnerabilitiesRefs) {
      pkg.vulnerabilitiesRefs.forEach(vulnRef => {
        const vuln = vulns[vulnRef];
        text += `Vulnerability ${vuln.name}
    Severity: ${vuln.severity}
    Package: ${pkg.name}
    CVSS Score: ${vuln.cvssScore.score}
    CVSS Version: ${vuln.cvssScore.version}
    CVSS Vector: ${vuln.cvssScore.vector}
    Version: ${pkg.version}
    Fix Version: ${pkg.suggestedFix || "No fix available"}
    Exploitable: ${vuln.exploitable}
    Type: ${pkg.type}
    Location: ${pkg.path}
    URL: https://nvd.nist.gov/vuln/detail/${vuln.name}\n\n\n`
      });
    }

    let markdown = `| Vulnerability | Severity | CVSS Score | CVSS Version | CVSS Vector | Exploitable |
    | -------- | ------- | ---------- | ------------ | -----------  | ----------- |
`;

    if (pkg.vulnerabilitiesRefs) {
      pkg.vulnerabilitiesRefs.forEach(vulnRef => {
        const vuln = vulns[vulnRef];
        markdown += `| ${vuln.name} | ${vuln.severity} | ${vuln.cvssScore.score} | ${vuln.cvssScore.version} | ${vuln.cvssScore.vector} | ${vuln.exploitable} |
`
      });
    }

    return {
      text: text,
      markdown: markdown
    };
  }

  private getSARIFVulnHelp(pkg: JsonPackage, vuln: Vulnerability) {
    return {
      text: `Vulnerability ${vuln.name}
  Severity: ${vuln.severity}
  Package: ${pkg.name}
  CVSS Score: ${vuln.cvssScore.score}
  CVSS Version: ${vuln.cvssScore.version}
  CVSS Vector: ${vuln.cvssScore.vector}
  Version: ${pkg.version}
  Fix Version: ${pkg.suggestedFix || "No fix available"}
  Exploitable: ${vuln.exploitable}
  Type: ${pkg.type}
  Location: ${pkg.path}
  URL: https://nvd.nist.gov/vuln/detail/${vuln.name}`,
      markdown: `
  **Vulnerability [${vuln.name}](https://nvd.nist.gov/vuln/detail/${vuln.name})**
  | Severity | Package | CVSS Score | CVSS Version | CVSS Vector | Fixed Version | Exploitable |
  | -------- | ------- | ---------- | ------------ | ----------- | ------------- | ----------- |
  | ${vuln.severity} | ${pkg.name} | ${vuln.cvssScore.score} | ${vuln.cvssScore.version} | ${vuln.cvssScore.vector} | ${pkg.suggestedFix || "None"} | ${vuln.exploitable} |
`
    }
  }
  private getSARIFReportMessageByPackage(data: JsonScanResultV1, pkg: JsonPackage, baseUrl?: string) {
    let message = `Full image scan results in Sysdig UI: [${data.result.metadata.pullString} scan result](${data.info.resultUrl})
`;

    if (baseUrl) {
      message += `Package: [${pkg.name}](${baseUrl}/content?filter=freeText+in+("${pkg.name}"))
`;
    } else {
      message += `Package: ${pkg.name}
`;
    }

    message += `Package type: ${pkg.type}
    Installed Version: ${pkg.version}
    Package path: ${pkg.path}
`;

    if (pkg.vulnerabilitiesRefs) {
      pkg.vulnerabilitiesRefs.forEach(vulnRef => {
        const vuln = data.result.vulnerabilities[vulnRef];
        message += ".\n";

        if (baseUrl) {
          message += `Vulnerability: [${vuln.name}](${baseUrl}/vulnerabilities?filter=freeText+in+("${vuln.name}"))
`;
        } else {
          message += `Vulnerability: ${vuln.name}
`;
        }

        message += `Severity: ${vuln.severity}
      CVSS Score: ${vuln.cvssScore.score}
      CVSS Version: ${vuln.cvssScore.version}
      CVSS Vector: ${vuln.cvssScore.vector}
      Fixed Version: ${(vuln.fixVersion || 'No fix available')}
      Exploitable: ${vuln.exploitable}
      Link to NVD: [${vuln.name}](https://nvd.nist.gov/vuln/detail/${vuln.name})
`;
      });
    }


    return message;
  }

  private getSARIFReportMessage(data: JsonScanResultV1, vuln: Vulnerability, pkg: JsonPackage, baseUrl: string | undefined) {
    let message = `Full image scan results in Sysdig UI: [${data.result.metadata.pullString} scan result](${data.info.resultUrl})
`;

    if (baseUrl) {
      message += `Package: [${pkg.name}](${baseUrl}/content?filter=freeText+in+("${pkg.name}"))
`;
    } else {
      message += `Package: ${pkg.name}
`;
    }

    message += `Package type: ${pkg.type}
    Installed Version: ${pkg.version}
    Package path: ${pkg.path}
`;

    if (baseUrl) {
      message += `Vulnerability: [${vuln.name}](${baseUrl}/vulnerabilities?filter=freeText+in+("${vuln.name}"))
`;
    } else {
      message += `Vulnerability: ${vuln.name}
`;
    }
    message += `Severity: ${vuln.severity}
    CVSS Score: ${vuln.cvssScore.score}
    CVSS Version: ${vuln.cvssScore.version}
    CVSS Vector: ${vuln.cvssScore.vector}
    Fixed Version: ${(vuln.fixVersion || 'No fix available')}
    Exploitable: ${vuln.exploitable}
    Link to NVD: [${vuln.name}](https://nvd.nist.gov/vuln/detail/${vuln.name})`;

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
