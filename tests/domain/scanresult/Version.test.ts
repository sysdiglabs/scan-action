import { Version } from '../../../src/domain/scanresult/Version';

describe('Version', () => {
  describe('constructor', () => {
    it('should throw an error for an empty version string', () => {
      expect(() => new Version('')).toThrow('Version string cannot be empty');
    });

    it('should not throw for a valid version string', () => {
      expect(() => new Version('1.0.0')).not.toThrow();
    });
  });

  describe('toString', () => {
    it('should return the original version string', () => {
      const version = new Version('1.2.3-alpha+build456');
      expect(version.toString()).toBe('1.2.3-alpha+build456');
    });
  });

  describe('equals', () => {
    it.each([
      ['1.0.0', '1.0.0'],
      ['v1.2.3', '1.2.3'],
      ['2.3.4', 'v2.3.4'],
      ['1.0.0-alpha', '1.0.0-alpha'],
      ['1.0.0+build1', '1.0.0+build2'], // Build metadata is ignored for equality
      ['1.0.0-alpha+build1', '1.0.0-alpha+build2'],
      ['1.0', '1.0.0'],
      ['1', '1.0.0'],
    ])('should consider version %s and %s to be equal', (v1, v2) => {
      const version1 = new Version(v1);
      const version2 = new Version(v2);
      expect(version1.equals(version2)).toBe(true);
      expect(version2.equals(version1)).toBe(true);
    });

    it.each([
      ['1.0.1', '1.0.0'],
      ['1.0.0', '1.0.0-alpha'],
      ['1.0.0-beta', '1.0.0-alpha'],
    ])('should consider version %s and %s to be not equal', (v1, v2) => {
      const version1 = new Version(v1);
      const version2 = new Version(v2);
      expect(version1.equals(version2)).toBe(false);
      expect(version2.equals(version1)).toBe(false);
    });
  });

  describe('greaterThan', () => {
    it.each([
      ['2.0.0', '1.0.0'],
      ['1.1.0', '1.0.0'],
      ['1.0.1', '1.0.0'],
      ['1.0.0', '1.0.0-alpha'],
      ['1.0.0-alpha.2', '1.0.0-alpha.1'],
      ['1.0.0-alpha.beta', '1.0.0-alpha.1'],
      ['1.0.0-beta', '1.0.0-alpha.beta'],
      ['1.0.0-beta.2', '1.0.0-beta.1'],
      ['1.0.0-beta.11', '1.0.0-beta.2'],
      ['1.0.0-rc.1', '1.0.0-beta.11'],
    ])('%s should be greater than %s', (v1, v2) => {
      const version1 = new Version(v1);
      const version2 = new Version(v2);
      expect(version1.greaterThan(version2)).toBe(true);
      expect(version2.lessThan(version1)).toBe(true);
    });

    it('1.0.0+build2 should have same precedence as 1.0.0+build1', () => {
      const version1 = new Version('1.0.0+build2');
      const version2 = new Version('1.0.0+build1');
      expect(version1.greaterThan(version2)).toBe(false);
      expect(version1.lessThan(version2)).toBe(false);
      expect(version1.equals(version2)).toBe(true);
    });
  });

  describe('lessThan', () => {
    it.each([
      ['1.0.0', '2.0.0'],
      ['1.0.0', '1.1.0'],
      ['1.0.0', '1.0.1'],
      ['1.0.0-alpha', '1.0.0'],
      ['1.0.0-alpha.1', '1.0.0-alpha.2'],
      ['1.0.0-alpha.1', '1.0.0-alpha.beta'],
      ['1.0.0-alpha.beta', '1.0.0-beta'],
      ['1.0.0-beta.1', '1.0.0-beta.2'],
      ['1.0.0-beta.2', '1.0.0-beta.11'],
      ['1.0.0-beta.11', '1.0.0-rc.1'],
    ])('%s should be less than %s', (v1, v2) => {
      const version1 = new Version(v1);
      const version2 = new Version(v2);
      expect(version1.lessThan(version2)).toBe(true);
      expect(version2.greaterThan(version1)).toBe(true);
    });
  });

  describe('complex semver comparisons', () => {
    const versions = [
      '1.0.0-alpha',
      '1.0.0-alpha.1',
      '1.0.0-alpha.beta',
      '1.0.0-beta',
      '1.0.0-beta.2',
      '1.0.0-beta.11',
      '1.0.0-rc.1',
      '1.0.0',
      '1.0.1',
      '1.2.0',
      '2.0.0',
    ];

    it('should correctly sort a list of versions', () => {
      const shuffled = [...versions].sort(() => Math.random() - 0.5);
      const sorted = shuffled.map(v => new Version(v)).sort((a, b) => {
        if (a.greaterThan(b)) return 1;
        if (a.lessThan(b)) return -1;
        return 0;
      }).map(v => v.toString());

      expect(sorted).toEqual(versions);
    });
  });
});
