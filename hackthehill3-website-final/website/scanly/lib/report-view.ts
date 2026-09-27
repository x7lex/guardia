import { riskZone } from "./risk.ts"
import type { Report } from '../components/report-marker'
export type RiskFilter = 'all' | 'safe' | 'review' | 'unsafe'
export function reportMatches(path: string, report: Report, query: string, risk: RiskFilter, unsignedOnly: boolean) {
    const zone = riskZone(report.risk_assessment.risk.verdict ?? report.risk_assessment.risk.level)
    return (risk === 'all' || risk === zone) && (!unsignedOnly || !report.analysis.signature.signed) &&
        `${path} ${report.analysis.file.file_name}`.toLowerCase().includes(query.trim().toLowerCase())
}
