import { Package, Severity } from "../scanresult";

export interface FilterOptions {
  minSeverity?: Severity;
  packageTypes?: string[];
  notPackageTypes?: string[];
  excludeAccepted?: boolean;
}

export type PackageFilterOption = (pkgs: Package[]) => Package[];

export function withPackageTypes(packageTypes: string[]): PackageFilterOption {
  return (pkgs: Package[]) =>
    pkgs.filter((pkg) =>
      packageTypes.includes(pkg.packageType.toString().toLowerCase())
    );
}

export function withoutPackageTypes(
  packageTypes: string[]
): PackageFilterOption {
  return (pkgs: Package[]) =>
    pkgs.filter(
      (pkg) => !packageTypes.includes(pkg.packageType.toString().toLowerCase())
    );
}

export function withMinSeverity(minSeverity: Severity): PackageFilterOption {
  return (pkgs: Package[]) =>
    pkgs.filter((pkg) =>
      pkg
        .getVulnerabilities()
        .some((vuln) => vuln.severity.isMoreSevereThanOrEqualTo(minSeverity))
    );
}

export function withoutAcceptedRisks(): PackageFilterOption {
  return (pkgs: Package[]) =>
    pkgs.filter((pkg) => pkg.getAcceptedRisks().length === 0);
}

export function filterPackages(
  pkgs: Package[],
  filters?: FilterOptions
): Package[] {
  const filterOptions: PackageFilterOption[] = [];

  if (filters) {
    if (filters.packageTypes && filters.packageTypes.length > 0) {
      filterOptions.push(withPackageTypes(filters.packageTypes));
    }

    if (filters.notPackageTypes && filters.notPackageTypes.length > 0) {
      filterOptions.push(withoutPackageTypes(filters.notPackageTypes));
    }

    if (filters.minSeverity) {
      filterOptions.push(withMinSeverity(filters.minSeverity));
    }

    if (filters.excludeAccepted) {
      filterOptions.push(withoutAcceptedRisks());
    }
  }

  return filterOptions.reduce((acc, filter) => filter(acc), pkgs);
}
