export interface ISummary {
    addHeading(text: string, level?: number): ISummary;
    addTable(rows: any[]): ISummary;
    addCodeBlock(code: string, lang?: string): ISummary;
    addList(items: string[], ordered?: boolean): ISummary;
    addRaw(text: string, addEOL?: boolean): ISummary;
}
