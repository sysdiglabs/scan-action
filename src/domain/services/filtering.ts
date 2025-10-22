import { Package } from "../../infrastructure/entities/JsonScanResultV1";
import { Vulnerability } from "../entities/vulnerability";
import { isSeverityGte, Severity } from "../value-objects/severity";

export interface FilterOptions {
  minSeverity?: Severity;
  packageTypes?: string[];
  notPackageTypes?: string[];
  excludeAccepted?: boolean;
}

export function filterPackages(pkgs: {[key:string]: Package}, vulns: {[key:string]: Vulnerability}, filters: FilterOptions): {[key:string]: Package} {
  const filteredPackages = Object.entries(pkgs)
    .filter(([key, pkg]) => {
      const pkgType = pkg.type?.toLowerCase();
      if (filters.packageTypes && filters.packageTypes.length > 0 &&
        !filters.packageTypes.map(t => t.toLowerCase()).includes(pkgType)) return false;
      if (filters.notPackageTypes && filters.notPackageTypes.length > 0 &&
        filters.notPackageTypes.map(t => t.toLowerCase()).includes(pkgType)) return false;
      return true;
    })

    return Object.fromEntries(filteredPackages
      .map(([key, pkg]) => {
        let vulnRefs = pkg.vulnerabilitiesRefs?.filter((vulnRef: string) => {
          const vuln = vulns[vulnRef];
          if (filters.minSeverity && vuln && !isSeverityGte(vuln.severity, filters.minSeverity)) {
            return false;
          }
          if (filters.excludeAccepted && vuln && Array.isArray(vuln.riskAcceptRefs) && vuln.riskAcceptRefs.length > 0) return false;
          return true;
        });
        const filteredPackage = { ...pkg, vulnerabilitiesRefs: vulnRefs}
        return [ key, filteredPackage] as [string, Package];
      })
      .filter(([key, pkg]) => pkg.vulnerabilitiesRefs && pkg.vulnerabilitiesRefs.length > 0));
}
