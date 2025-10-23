export class Version {
  constructor(readonly value: string) {
    if (!value) {
      throw new Error('Version string cannot be empty');
    }
  }

  toString(): string {
    return this.value;
  }

  equals(other: Version): boolean {
    return this.compareTo(other) === 0;
  }

  greaterThan(other: Version): boolean {
    return this.compareTo(other) > 0;
  }

  lessThan(other: Version): boolean {
    return this.compareTo(other) < 0;
  }

  /**
   * Compares this version with another.
   * @returns 0 if equal, 1 if greater, -1 if less.
   */
  private compareTo(other: Version): number {
    const thisParts = Version.parse(this.value);
    const otherParts = Version.parse(other.value);

    // Compare core version parts
    for (let i = 0; i < 3; i++) {
      if (thisParts.core[i] > otherParts.core[i]) return 1;
      if (thisParts.core[i] < otherParts.core[i]) return -1;
    }

    // Core versions are same, check pre-release
    const thisPre = thisParts.preRelease;
    const otherPre = otherParts.preRelease;

    if (thisPre && !otherPre) return -1; // 1.0.0-alpha < 1.0.0
    if (!thisPre && otherPre) return 1;  // 1.0.0 > 1.0.0-alpha
    if (!thisPre && !otherPre) return 0; // 1.0.0 == 1.0.0
    if (!thisPre || !otherPre) return 0; // Should not happen because of previous checks, but makes typescript happy

    // Both have pre-release tags, compare them identifier by identifier
    const preLen = Math.max(thisPre.length, otherPre.length);
    for (let i = 0; i < preLen; i++) {
      if (thisPre[i] === undefined) return -1; // this is shorter, so smaller
      if (otherPre[i] === undefined) return 1;

      const thisIdent = thisPre[i];
      const otherIdent = otherPre[i];

      if (thisIdent === otherIdent) continue;

      const thisIsNum = typeof thisIdent === 'number';
      const otherIsNum = typeof otherIdent === 'number';

      if (thisIsNum && !otherIsNum) return -1; // numeric is smaller than string
      if (!thisIsNum && otherIsNum) return 1;

      if (thisIdent > otherIdent) return 1;
      if (thisIdent < otherIdent) return -1;
    }

    return 0; // pre-releases are identical
  }

  private static parse(versionString: string): { core: number[], preRelease: (string|number)[] | null } {
    const value = versionString.replace(/^v/, '');
    const preReleaseIndex = value.indexOf('-');
    const buildIndex = value.indexOf('+');

    let corePart: string;
    let preReleasePart: string | null = null;

    if (preReleaseIndex > -1) {
      corePart = value.substring(0, preReleaseIndex);
      const endOfPreRelease = buildIndex > -1 && buildIndex > preReleaseIndex ? buildIndex : value.length;
      preReleasePart = value.substring(preReleaseIndex + 1, endOfPreRelease);
    } else if (buildIndex > -1) {
      corePart = value.substring(0, buildIndex);
    } else {
      corePart = value;
    }

    const core = corePart.split('.').map(p => parseInt(p, 10) || 0);
    // Pad with zeros to ensure it has at least 3 parts (major, minor, patch)
    while (core.length < 3) {
      core.push(0);
    }

    if (preReleasePart) {
      const preRelease = preReleasePart.split('.').map(ident => {
        const num = parseInt(ident, 10);
        return isNaN(num) || String(num) !== ident ? ident : num;
      });
      return { core, preRelease };
    }

    return { core, preRelease: null };
  }
}
