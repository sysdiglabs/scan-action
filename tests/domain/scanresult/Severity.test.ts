import { Severity } from '../../../src/domain/scanresult/Severity';

describe('Severity', () => {
  describe('fromString', () => {
    it('should return Severity for valid string', () => {
      expect(Severity.fromString('critical')).toBe(Severity.Critical);
      expect(Severity.fromString('Critical')).toBe(Severity.Critical);
      expect(Severity.fromString('HIGH')).toBe(Severity.High);
      expect(Severity.fromString('Medium')).toBe(Severity.Medium);
      expect(Severity.fromString('Low')).toBe(Severity.Low);
      expect(Severity.fromString('Negligible')).toBe(Severity.Negligible);
    });

    it('should return Unknown for invalid string', () => {
      expect(Severity.fromString('invalid')).toBe(Severity.Unknown);
    });
  });

  describe('fromValue', () => {
    it('should return Severity for valid value', () => {
      expect(Severity.fromValue(0)).toBe(Severity.Critical);
      expect(Severity.fromValue(1)).toBe(Severity.High);
      expect(Severity.fromValue(2)).toBe(Severity.Medium);
      expect(Severity.fromValue(3)).toBe(Severity.Low);
      expect(Severity.fromValue(4)).toBe(Severity.Negligible);
      expect(Severity.fromValue(5)).toBe(Severity.Unknown);
    });

    it('should return Unknown for invalid value', () => {
      expect(Severity.fromValue(99)).toBe(Severity.Unknown);
    });
  });

  describe('comparison methods', () => {
    const { Critical, High, Medium, Low, Negligible } = Severity;

    describe('isEqualTo', () => {
      it('should return true for equal severities', () => {
        expect(Critical.isEqualTo(Severity.fromValue(0))).toBe(true);
        expect(High.isEqualTo(High)).toBe(true);
      });
      it('should return false for unequal severities', () => {
        expect(Critical.isEqualTo(High)).toBe(false);
      });
    });

    describe('isMoreSevereThan', () => {
      it('should correctly identify more severe', () => {
        expect(Critical.isMoreSevereThan(High)).toBe(true);
        expect(High.isMoreSevereThan(Medium)).toBe(true);
        expect(Medium.isMoreSevereThan(Low)).toBe(true);
        expect(Low.isMoreSevereThan(Negligible)).toBe(true);
      });
      it('should return false for less severe or equal', () => {
        expect(High.isMoreSevereThan(Critical)).toBe(false);
        expect(High.isMoreSevereThan(High)).toBe(false);
      });
    });

    describe('isMoreSevereThanOrEqualTo', () => {
      it('should correctly identify more severe or equal', () => {
        expect(Critical.isMoreSevereThanOrEqualTo(High)).toBe(true);
        expect(High.isMoreSevereThanOrEqualTo(High)).toBe(true);
      });
      it('should return false for less severe', () => {
        expect(Medium.isMoreSevereThanOrEqualTo(High)).toBe(false);
      });
    });

    describe('isLessSevereThan', () => {
      it('should correctly identify less severe', () => {
        expect(Negligible.isLessSevereThan(Low)).toBe(true);
        expect(Low.isLessSevereThan(Medium)).toBe(true);
        expect(Medium.isLessSevereThan(High)).toBe(true);
        expect(High.isLessSevereThan(Critical)).toBe(true);
      });
      it('should return false for more severe or equal', () => {
        expect(Critical.isLessSevereThan(High)).toBe(false);
        expect(Low.isLessSevereThan(Low)).toBe(false);
      });
    });

    describe('isLessSevereThanOrEqualTo', () => {
      it('should correctly identify less severe or equal', () => {
        expect(Negligible.isLessSevereThanOrEqualTo(Low)).toBe(true);
        expect(Low.isLessSevereThanOrEqualTo(Low)).toBe(true);
      });
      it('should return false for more severe', () => {
        expect(Critical.isLessSevereThanOrEqualTo(High)).toBe(false);
      });
    });
  });
});
