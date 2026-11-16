package com.vyrax.ai.analysis

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.vyrax.ai.model.Finding
import com.vyrax.ai.model.RiskLevel
import com.vyrax.ai.model.ScanResult
import java.io.File
import java.security.DigestInputStream
import java.security.MessageDigest
import java.util.zip.ZipFile

object ApkAnalyzer {

    // Hashes de exemplo. Lista vazia na v1.0: nenhum hash conhecido esta
    // embutido. Em versoes futuras o usuario pode alimentar essa lista.
    private val knownBadHashes = emptySet<String>()

    // Acima disso o aparelho pode ficar sem memoria ou sem espaco no cache.
    private const val MAX_BYTES = 300L * 1024 * 1024

    private val permRegex = Regex("android\\.permission\\.[A-Z_]+")

    fun analyze(context: Context, uri: Uri, fileName: String): ScanResult {
        val findings = mutableListOf<Finding>()
        var score = 100
        var sizeBytes = 0L
        var dexCount = 0
        var soCount = 0
        var entryCount = 0
        var hasManifest = false
        var hasDex = false
        val permissions = mutableSetOf<String>()
        var sha256 = ""

        // Tamanho declarado pelo seletor, para recusar arquivos gigantes
        // antes de copiar qualquer coisa para o cache.
        try {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { c ->
                if (c.moveToFirst() && !c.isNull(0)) {
                    val declared = c.getLong(0)
                    if (declared > MAX_BYTES) {
                        return ScanResult(
                            "Analise de APK", fileName, RiskLevel.MEDIO, 50,
                            "Arquivo muito grande (${declared} bytes) para analisar com seguranca no aparelho.",
                            emptyList()
                        )
                    }
                }
            }
        } catch (_: Exception) {
            // Se o provedor nao informa o tamanho, seguimos e conferimos depois.
        }

        var temp: File? = null
        try {
            // 1) Copia para um arquivo temporario no cache do app.
            //    O codigo antigo fazia readBytes() do APK inteiro: estourava a memoria.
            val copy = File.createTempFile("vyraxscan", ".apk", context.cacheDir)
            temp = copy
            val digest = MessageDigest.getInstance("SHA-256")
            context.contentResolver.openInputStream(uri)?.use { raw ->
                DigestInputStream(raw, digest).use { stream ->
                    copy.outputStream().use { out -> stream.copyTo(out) }
                }
            } ?: return ScanResult(
                "Analise de APK", fileName, RiskLevel.MEDIO, 50,
                "Nao foi possivel abrir o arquivo.", emptyList()
            )

            sizeBytes = copy.length()
            sha256 = digest.digest().joinToString("") { "%02x".format(it) }

            if (sizeBytes > MAX_BYTES) {
                copy.delete()
                return ScanResult(
                    "Analise de APK", fileName, RiskLevel.MEDIO, 50,
                    "Arquivo muito grande (${sizeBytes} bytes) para analisar com seguranca no aparelho.",
                    emptyList()
                )
            }

            // 2) Le o APK como ZIP, sem instalar nada.
            ZipFile(copy).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    entryCount++
                    val name = entry.name

                    if (name == "AndroidManifest.xml") {
                        hasManifest = true
                        // O manifesto dentro do APK esta comprimido: descompacta antes
                        // de procurar permissoes em texto. O codigo antigo varria os
                        // bytes crus do ZIP e quase nunca encontrava nada.
                        collectPermissions(zip.getInputStream(entry).readBytes(), permissions)
                    }
                    if (name.endsWith(".dex")) {
                        dexCount++
                        hasDex = true
                    }
                    if (name.endsWith(".so")) soCount++
                    if (name.endsWith(".exe") || name.endsWith(".bat") || name.endsWith(".sh")) {
                        findings.add(
                            Finding(
                                0,
                                "Arquivo executavel dentro do APK",
                                "Entrada $name nao e comum dentro de um APK normal.",
                                RiskLevel.ALTO,
                                "Nao instale. Apague o arquivo."
                            )
                        )
                        score -= 25
                    }
                    if (name.contains("..")) {
                        findings.add(
                            Finding(
                                0,
                                "Caminho suspeito no ZIP",
                                "Entrada $name contem ..",
                                RiskLevel.MEDIO,
                                "Nao extraia manualmente."
                            )
                        )
                        score -= 10
                    }
                }
            }
        } catch (e: Exception) {
            return ScanResult(
                "Analise de APK", fileName, RiskLevel.MEDIO, 50,
                "Erro ao ler o APK: ${e.message}", emptyList()
            )
        } finally {
            // O cache nunca deve guardar o APK do usuario.
            temp?.let { file -> runCatching { file.delete() } }
        }

        if (!hasManifest) {
            findings.add(
                Finding(0, "Manifesto nao encontrado", "O arquivo nao tem AndroidManifest.xml. Pode nao ser um APK valido.", RiskLevel.ALTO, "Nao instale este arquivo.")
            )
            score -= 30
        }
        if (!hasDex) {
            findings.add(
                Finding(0, "Sem codigo DEX", "Nenhum arquivo .dex encontrado.", RiskLevel.MEDIO, "Confira se o arquivo e mesmo um APK.")
            )
            score -= 15
        }
        if (soCount > 10) {
            findings.add(
                Finding(0, "Muitas bibliotecas nativas", "O APK tem $soCount arquivos .so. Pode ser normal em jogos, mas aumenta a superficie de risco.", RiskLevel.BAIXO, "So instale de fonte confiavel.")
            )
            score -= 5
        }
        if (sha256 in knownBadHashes) {
            findings.add(Finding(0, "Hash na lista de bloqueio", "O SHA-256 deste arquivo esta na lista local de bloqueio.", RiskLevel.CRITICO, "Nao instale. Apague o arquivo."))
            score = 0
        }
        if (permissions.contains("android.permission.SEND_SMS") || permissions.contains("android.permission.READ_SMS")) {
            findings.add(
                Finding(0, "Permissao de SMS detectada", "O manifesto menciona permissao de SMS. App de jogo raramente precisa disso.", RiskLevel.MEDIO, "Confira as permissoes antes de instalar.")
            )
            score -= 10
        }

        if (score < 0) score = 0
        val risk = when {
            findings.any { it.risk == RiskLevel.CRITICO } -> RiskLevel.CRITICO
            score < 40 -> RiskLevel.ALTO
            score < 70 -> RiskLevel.MEDIO
            score < 90 -> RiskLevel.BAIXO
            else -> RiskLevel.SEGURO
        }
        val sizeMb = sizeBytes / (1024 * 1024)
        val summary = buildString {
            append("Arquivo: $fileName | Tamanho: ${sizeBytes} bytes (~${sizeMb} MB) | Entradas: $entryCount | DEX: $dexCount | .so: $soCount")
            append(" | SHA-256: $sha256")
            if (permissions.isNotEmpty()) append(" | Permissoes detectadas (parcial): ${permissions.joinToString(", ")}")
            append(". Analise parcial e offline: permissoes do manifesto binario podem nao aparecer todas.")
        }
        return ScanResult(
            title = "Analise de APK",
            target = fileName,
            risk = risk,
            score = score,
            summary = summary,
            findings = findings
        )
    }

    private fun collectPermissions(manifestBytes: ByteArray, into: MutableSet<String>) {
        // O manifesto binario guarda a string pool em UTF-8 ou UTF-16.
        into += permRegex.findAll(String(manifestBytes, Charsets.UTF_8)).map { it.value }
        into += permRegex.findAll(String(manifestBytes, Charsets.UTF_16LE)).map { it.value }
    }
}
