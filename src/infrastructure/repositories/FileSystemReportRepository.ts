import * as core from '@actions/core';
import fs from 'fs';
import { IReportRepository } from '../../application/ports/IReportRepository';

export class FileSystemReportRepository implements IReportRepository {
  writeReport(reportData: string): void {
    fs.writeFileSync("./report.json", reportData);
    core.setOutput("scanReport", "./report.json");
  }
}
