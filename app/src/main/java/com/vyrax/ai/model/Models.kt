package com.vyrax.ai.model

enum class RiskLevel(val label: String, val emoji: String) {
    SEGURO("Seguro", "✅"),
    BAIXO("Risco baixo", "🟢"),
    MEDIO("Risco médio", "🟡"),
    ALTO("Risco alto", "🟠"),
    CRITICO("Risco crítico", "🔴")
}

data class Finding(
    val line: Int,
    val title: String,
    val detail: String,
    val risk: RiskLevel,
    val recommendation: String
)

data class ScanResult(
    val title: String,
    val target: String,
    val risk: RiskLevel,
    val score: Int, // 0 a 100. 100 = mais seguro.
    val summary: String,
    val findings: List<Finding>,
    val timestamp: Long = System.currentTimeMillis()
) {
    fun toReportText(): String {
        val sb = StringBuilder()
        sb.appendLine("VYRAX AI - RELATORIO DE ANALISE")
        sb.appendLine("Titulo: $title")
        sb.appendLine("Alvo: $target")
        sb.appendLine("Risco: ${risk.label}")
        sb.appendLine("Pontuacao de seguranca: $score/100")
        sb.appendLine("Resumo: $summary")
        sb.appendLine("")
        if (findings.isEmpty()) {
            sb.appendLine("Nenhum achado suspeito encontrado pela analise offline.")
        } else {
            sb.appendLine("Achados (${findings.size}):")
            findings.forEachIndexed { i, f ->
                sb.appendLine("")
                sb.appendLine("${i + 1}. [${f.risk.label}] ${f.title} (linha ${f.line})")
                sb.appendLine("   ${f.detail}")
                sb.appendLine("   Recomendacao: ${f.recommendation}")
            }
        }
        sb.appendLine("")
        sb.appendLine("Aviso: analise heuristica OFFLINE. Nao garante que um arquivo seja seguro ou malicioso. Nao substitui um antivirus com banco de dados atualizado.")
        return sb.toString()
    }
}

data class HistoryItem(
    val timestamp: Long,
    val title: String,
    val riskLabel: String,
    val score: Int
)

enum class AppScreen {
    HOME, ANALYZE, APK, SEARCH, URL, HISTORY
}
