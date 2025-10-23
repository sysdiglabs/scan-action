import { PackageType } from '../../../src/domain/scanresult/PackageType';

describe('PackageType', () => {
  it.each([
    [PackageType.Unknown, 'Unknown'],
    [PackageType.Os, 'Os'],
    [PackageType.Python, 'Python'],
    [PackageType.Java, 'Java'],
    [PackageType.Javascript, 'Javascript'],
    [PackageType.Golang, 'Golang'],
    [PackageType.Rust, 'Rust'],
    [PackageType.Ruby, 'Ruby'],
    [PackageType.Php, 'Php'],
    [PackageType.CSharp, 'CSharp'],
  ])('should convert %s to %s', (pacakgeType, expected) => {
    expect(pacakgeType.toString()).toBe(expected);
  });
});
