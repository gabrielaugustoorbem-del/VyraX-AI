package com.vyrax.ai.storage

import android.content.Context
import com.vyrax.ai.model.HistoryItem
import com.vyrax.ai.model.ScanResult
import java.io.File

// Historico simples, salvo em arquivo interno do app.
// Formato por linha: timestamp|titulo|risco|pontuacao
// Sem banco de dados externo, sem nuvem, sem envio para servidor.
object HistoryStore {
    private fun file(context: Context): File {
        return File(context.filesDir, "vyrax_history.txt")
    }

    fun add(context: Context, result: ScanResult) {
        try {
            val f = file(context)
            val cleanTitle = result.title.replace("|", "/").replace("\n", " ")
            val line = "${result.timestamp}|$cleanTitle|${result.risk.label}|${result.score}\n"
            f.appendText(line)
            // Mantem no maximo as 100 ultimas linhas.
            val lines = f.readLines()
            if (lines.size > 100) {
                f.writeText(lines.takeLast(100).joinToString("\n") + "\n")
            }
        } catch (_: Exception) {
            // Historico e opcional: falhar aqui nao pode travar a analise.
        }
    }

    fun load(context: Context): List<HistoryItem> {
        return try {
            val f = file(context)
            if (!f.exists()) return emptyList()
            f.readLines().mapNotNull { line ->
                val parts = line.split("|")
                if (parts.size < 4) return@mapNotNull null
                val ts = parts[0].toLongOrNull() ?: return@mapNotNull null
                val score = parts[3].toIntOrNull() ?: 0
                HistoryItem(ts, parts[1], parts[2], score)
            }.reversed()
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun clear(context: Context) {
        try {
            file(context).delete()
        } catch (_: Exception) {
        }
    }
}
