import type { Report } from '../components/report-marker'
export type RiskFilter = 'all' | 'safe' | 'review' | 'unsafe'
export function reportMatches(path: string, report: Report, query: string, risk: RiskFilter, unsignedOnly: boolean) {
    const level = report.risk_assessment.risk.level.trim().toLowerCase()
    const zone = ['safe', 'low'].includes(level) ? 'safe' : ['unsafe', 'high', 'critical'].includes(level) ? 'unsafe' : 'review'
    return (risk === 'all' || risk === zone) && (!unsignedOnly || !report.analysis.signature.signed) &&
        `${path} ${report.analysis.file.file_name}`.toLowerCase().includes(query.trim().toLowerCase())
}
