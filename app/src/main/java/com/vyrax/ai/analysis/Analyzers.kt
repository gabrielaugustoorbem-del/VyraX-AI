package com.vyrax.ai.analysis

import com.vyrax.ai.model.Finding
import com.vyrax.ai.model.RiskLevel
import com.vyrax.ai.model.ScanResult

// ---------------------------------------------------------------------------
// Analise OFFLINE, por padroes (heuristica). Nao usa internet, nao usa API
// paga e nao envia o conteudo para nenhum servidor.
// IMPORTANTE: isso detecta padroes suspeitos conhecidos, mas NAO prova que
// um codigo e seguro ou que e malware. E um primeiro filtro, nao um veredito.
// ---------------------------------------------------------------------------

data class PatternRule(
    val regex: Regex,
    val title: String,
    val detail: String,
    val risk: RiskLevel,
    val recommendation: String,
    val penalty: Int
)

object CodeAnalyzer {

    private val rules = listOf(
        PatternRule(
            Regex("eval\\s*\\("),
            "Uso de eval()",
            "eval() executa texto como codigo. E uma porta comum para injecao de codigo.",
            RiskLevel.ALTO, "Evite eval(). Use uma alternativa segura e valide a entrada.", 25
        ),
        PatternRule(
            Regex("exec\\s*\\("),
            "Uso de exec()",
            "exec() executa texto como codigo, parecido com eval().",
            RiskLevel.ALTO, "Evite exec() com dados de fora do app.", 20
        ),
        PatternRule(
            Regex("os\\.system\\s*\\(|subprocess\\.|Runtime\\.getRuntime\\(\\)\\.exec|ProcessBuilder"),
            "Execucao de comando do sistema",
            "O codigo executa comandos do sistema operacional. Pode ser legitimo, mas tambem e usado por malware.",
            RiskLevel.MEDIO, "Confirme a origem do comando e nao passe dados do usuario sem validar.", 15
        ),
        PatternRule(
            Regex("curl\\s+.*\\|\\s*(sh|bash)|wget\\s+.*\\|\\s*(sh|bash)"),
            "Baixar e executar da internet",
            "Baixa um script da internet e executa na hora. Padrao classico de instalacao de malware.",
            RiskLevel.CRITICO, "Nao execute scripts baixados sem verificar o conteudo e a origem.", 35
        ),
        PatternRule(
            Regex("rm\\s+-rf\\s+(/|\\\$HOME|~)"),
            "Remocao destrutiva (rm -rf)",
            "Comando apaga pastas inteiras sem confirmacao.",
            RiskLevel.ALTO, "Nunca rode rm -rf em / ou na pasta do usuario sem saber o que faz.", 25
        ),
        PatternRule(
            Regex("base64\\s*-d|base64\\.b64decode|atob\\s*\\("),
            "Decodificacao Base64",
            "Base64 e usado para esconder texto, URLs e comandos. Sozinho nao e malware, mas e tecnica de ofuscacao.",
            RiskLevel.MEDIO, "Decodifique e leia o conteudo antes de executar.", 10
        ),
        PatternRule(
            Regex("[A-Za-z0-9+/]{80,}={0,2}"),
            "Texto longo codificado/ofuscado",
            "Trecho muito longo e sem espacos, parecido com codigo ofuscado ou dados codificados.",
            RiskLevel.MEDIO, "Verifique o que esse trecho contem antes de confiar.", 10
        ),
        PatternRule(
            Regex("(?i)(api[_-]?key|password|senha|secret|token)\\s*[:=]\\s*['\"][^'\"]{6,}['\"]"),
            "Possivel segredo fixo no codigo",
            "Senha, token ou chave de API escrita direto no codigo. Se vazar, qualquer um pode usar.",
            RiskLevel.ALTO, "Remova do codigo e use variavel de ambiente ou cofre de segredos.", 20
        ),
        PatternRule(
            Regex("http://[^\\s'\"}]+"),
            "Link HTTP sem criptografia",
            "O codigo usa http:// em vez de https://. Os dados podem ser lidos no caminho.",
            RiskLevel.BAIXO, "Troque por https:// quando possivel.", 5
        ),
        PatternRule(
            Regex("(?i)(socket|requests\\.post|fetch\\s*\\()"),
            "Envio de dados pela rede",
            "O codigo envia dados pela rede. Verifique para onde e o que esta sendo enviado.",
            RiskLevel.BAIXO, "Confira o destino e nao envie dados sensiveis sem necessidade.", 5
        ),
        PatternRule(
            Regex("(?i)(miner|cryptominer|xmrig|monero)"),
            "Termo ligado a mineracao",
            "Palavras ligadas a mineracao de criptomoeda. Pode ser legitimo, mas minerador escondido e comum em malware.",
            RiskLevel.ALTO, "Confirme se a mineracao foi autorizada por voce.", 20
        ),
        PatternRule(
            Regex("chmod\\s+\\+x|chmod\\s+777"),
            "Permissao de execucao ampla",
            "Da permissao de execucao, as vezes para todos os usuarios.",
            RiskLevel.BAIXO, "Use a menor permissao necessaria.", 5
        ),
        PatternRule(
            Regex("adb\\s+shell|su\\s*$|setprop\\s+"),
            "Comando de sistema / root",
            "Comandos de ADB, shell ou root. Em script de jogo pode ser normal, em app desconhecido e suspeito.",
            RiskLevel.MEDIO, "So execute se voce confiar na origem do script.", 10
        )
    )

    fun detectLanguage(code: String): String {
        return when {
            code.contains("#!/system/bin/sh") || code.contains("#!/bin/sh") || code.contains("adb ") -> "Shell / ADB"
            code.contains("def ") && code.contains("import ") -> "Python"
            // Parenteses explicitos: sem eles o "&&" vale so para o segundo teste.
            code.contains("fun ") || (code.contains("class ") && code.contains("val ")) -> "Kotlin"
            code.contains("public class") || code.contains("System.out") -> "Java"
            code.contains("function ") || code.contains("const ") || code.contains("console.log") -> "JavaScript / TypeScript"
            code.contains("<?php") -> "PHP"
            code.contains("#include") -> "C / C++"
            else -> "Texto / Codigo generico"
        }
    }

    fun analyze(code: String): ScanResult {
        val language = detectLanguage(code)
        val lines = code.lines()
        val findings = mutableListOf<Finding>()
        var score = 100

        lines.forEachIndexed { index, line ->
            for (rule in rules) {
                if (rule.regex.containsMatchIn(line)) {
                    findings.add(
                        Finding(
                            line = index + 1,
                            title = rule.title,
                            detail = rule.detail,
                            risk = rule.risk,
                            recommendation = rule.recommendation
                        )
                    )
                    score -= rule.penalty
                }
            }
        }

        if (score < 0) score = 0
        val risk = when {
            findings.any { it.risk == RiskLevel.CRITICO } -> RiskLevel.CRITICO
            score < 40 -> RiskLevel.ALTO
            score < 70 -> RiskLevel.MEDIO
            score < 90 -> RiskLevel.BAIXO
            else -> RiskLevel.SEGURO
        }
        val summary = if (findings.isEmpty()) {
            "Nenhum padrao suspeito conhecido foi encontrado neste conteudo. Isso nao garante seguranca total."
        } else {
            "Encontrados ${findings.size} padrao(oes) suspeito(s) em linguagem detectada: $language. Revise cada achado antes de executar."
        }
        return ScanResult(
            title = "Analise de codigo / script",
            target = "Linguagem detectada: $language | ${lines.size} linhas",
            risk = risk,
            score = score,
            summary = summary,
            findings = findings
        )
    }
}

object TextAnalyzer {

    // Regex compilado uma unica vez. O codigo antigo criava 5 Regex por linha:
    // num texto grande isso travava a tela (main thread).
    private val cpfRegex = Regex("\\b\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}\\b")
    private val emailRegex = Regex("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")
    private val cardRegex = Regex("\\b(?:\\d[ -]?){13,16}\\b")
    private val passwordRegex = Regex("(?i)(senha|password)\\s*[:=]")
    private val urlRegex = Regex("https?://[^\\s]+")
    private val spaceRegex = Regex("\\s+")

    fun analyze(text: String): ScanResult {
        val findings = mutableListOf<Finding>()
        var score = 100
        val lines = text.lines()

        fun add(line: Int, title: String, detail: String, risk: RiskLevel, rec: String, penalty: Int) {
            findings.add(Finding(line, title, detail, risk, rec))
            score -= penalty
        }

        lines.forEachIndexed { index, line ->
            if (cpfRegex.containsMatchIn(line)) {
                add(index + 1, "Possivel CPF", "O texto contem um numero no formato de CPF.", RiskLevel.MEDIO, "Nao compartilhe CPF em texto ou print.", 15)
            }
            if (emailRegex.containsMatchIn(line)) {
                add(index + 1, "Endereco de e-mail", "O texto contem um e-mail.", RiskLevel.BAIXO, "Evite expor e-mails em conteudo publico.", 5)
            }
            if (cardRegex.containsMatchIn(line)) {
                add(index + 1, "Possivel numero de cartao", "Sequencia longa de digitos, parecida com cartao.", RiskLevel.ALTO, "Nunca compartilhe numero de cartao.", 20)
            }
            if (passwordRegex.containsMatchIn(line)) {
                add(index + 1, "Possivel senha em texto", "O texto menciona senha junto com valor.", RiskLevel.ALTO, "Troque a senha e nao guarde senha em texto puro.", 20)
            }
            if (urlRegex.containsMatchIn(line)) {
                add(index + 1, "Link no texto", "O texto contem um link. Verifique o destino antes de abrir.", RiskLevel.BAIXO, "Confira o dominio antes de clicar.", 5)
            }
        }

        if (score < 0) score = 0
        val words = text.split(spaceRegex).filter { it.isNotBlank() }.size
        val risk = when {
            score < 50 -> RiskLevel.ALTO
            score < 80 -> RiskLevel.MEDIO
            score < 95 -> RiskLevel.BAIXO
            else -> RiskLevel.SEGURO
        }
        return ScanResult(
            title = "Analise de texto",
            target = "${text.length} caracteres | $words palavras | ${lines.size} linhas",
            risk = risk,
            score = score,
            summary = if (findings.isEmpty()) "Nenhum dado sensivel obvio foi encontrado." else "Encontrados ${findings.size} item(ns) que podem expor dados sensiveis.",
            findings = findings
        )
    }
}

object UrlChecker {
    // Lista LOCAL de exemplos bloqueados. Nao e um banco de dados de malware.
    // O usuario pode ampliar essa lista em versoes futuras.
    private val blockedDomains = listOf(
        "malware-exemplo.com",
        "free-gems-ff.com",
        "robux-gratis.xyz",
        "diamante-gratis.top",
        "phishing-exemplo.net"
    )
    private val suspiciousTlds = listOf(".xyz", ".top", ".click", ".buzz", ".work")
    private val shorteners = listOf("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd")

    fun check(rawUrl: String): ScanResult {
        val url = rawUrl.trim()
        val findings = mutableListOf<Finding>()
        var score = 100

        fun add(title: String, detail: String, risk: RiskLevel, rec: String, penalty: Int) {
            findings.add(Finding(0, title, detail, risk, rec))
            score -= penalty
        }

        if (url.isEmpty()) {
            return ScanResult("Verificacao de link", "URL vazia", RiskLevel.MEDIO, 50, "Digite um link para verificar.", emptyList())
        }
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            add("Link sem http/https", "O link nao comeca com http:// ou https://.", RiskLevel.MEDIO, "Cole o link completo.", 15)
        }
        if (url.startsWith("http://")) {
            add("Site sem HTTPS", "O site usa http://, sem criptografia.", RiskLevel.ALTO, "Prefira sites https://, principalmente para login e pagamento.", 25)
        }
        val lower = url.lowercase()
        for (domain in blockedDomains) {
            if (lower.contains(domain)) {
                add("Dominio na lista local de bloqueio", "Dominio $domain esta na lista local de exemplos bloqueados.", RiskLevel.CRITICO, "Nao abra. Feche a pagina e apague o link.", 40)
            }
        }
        for (tld in suspiciousTlds) {
            if (lower.contains(tld)) {
                add("Dominio com final suspeito", "Final $tld e muito usado em golpes, mas tambem existe site legitimo.", RiskLevel.MEDIO, "Confira a reputacao do site antes de continuar.", 10)
            }
        }
        for (s in shorteners) {
            if (lower.contains(s)) {
                add("Link encurtado", "Link encurtado esconde o destino real.", RiskLevel.MEDIO, "Expanda o link ou desconfie antes de clicar.", 10)
            }
        }
        if (Regex("(?i)(diamante.*gratis|robux.*gratis|gem.*gratis|hack|dinheiro.*gratis)").containsMatchIn(url)) {
            add("Isca comum de golpe", "O link usa promessa de item gratis, isca comum em golpes de Free Fire e Roblox.", RiskLevel.ALTO, "Nao informe login ou senha. Item gratis de jogo quase sempre e golpe.", 25)
        }
        if (lower.contains("@") || Regex("https?://\\d+\\.\\d+\\.\\d+\\.\\d+").containsMatchIn(lower)) {
            add("Link com IP ou @", "Link com endereco IP ou @ pode esconder o destino real.", RiskLevel.ALTO, "Nao abra sem verificar.", 20)
        }

        if (score < 0) score = 0
        val risk = when {
            findings.any { it.risk == RiskLevel.CRITICO } -> RiskLevel.CRITICO
            score < 40 -> RiskLevel.ALTO
            score < 70 -> RiskLevel.MEDIO
            score < 90 -> RiskLevel.BAIXO
            else -> RiskLevel.SEGURO
        }
        return ScanResult(
            title = "Verificacao de link",
            target = url,
            risk = risk,
            score = score,
            summary = if (findings.isEmpty()) "Nenhum sinal suspeito obvio. Continue com atencao: a lista local nao cobre todos os golpes." else "Encontrados ${findings.size} sinal(is) de risco neste link.",
            findings = findings
        )
    }

    fun buildSafeSearchUrl(query: String): String {
        val encoded = java.net.URLEncoder.encode(query.trim(), "UTF-8")
        // DuckDuckGo com SafeSearch ativado (kp=1). Abre no WebView do app.
        return "https://duckduckgo.com/?q=$encoded&kp=1&k1=-1"
    }
}
