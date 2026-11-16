package com.vyrax.ai.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import com.vyrax.ai.analysis.ApkAnalyzer
import com.vyrax.ai.analysis.CodeAnalyzer
import com.vyrax.ai.analysis.TextAnalyzer
import com.vyrax.ai.analysis.UrlChecker
import com.vyrax.ai.model.AppScreen
import com.vyrax.ai.model.HistoryItem
import com.vyrax.ai.model.RiskLevel
import com.vyrax.ai.model.ScanResult
import com.vyrax.ai.security.PinManager
import com.vyrax.ai.storage.HistoryStore
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// Limite de leitura de arquivos abertos pelo seletor: evita OOM em arquivo gigante.
private const val MAX_FILE_CHARS = 2_000_000

@Composable
fun VyraXApp() {
    val context = LocalContext.current
    var screen by remember { mutableStateOf(AppScreen.HOME) }
    var unlocked by remember { mutableStateOf(!PinManager.isPinSet(context)) }
    var lastResult by remember { mutableStateOf<ScanResult?>(null) }
    var history by remember { mutableStateOf(HistoryStore.load(context)) }

    fun saveResult(result: ScanResult) {
        lastResult = result
        HistoryStore.add(context, result)
        history = HistoryStore.load(context)
    }

    if (!unlocked) {
        PinLockScreen(
            onUnlocked = { unlocked = true },
            onSkip = { unlocked = true }
        )
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp)
    ) {
        Text("🛡️ VyraX AI", fontSize = 26.sp, fontWeight = FontWeight.Bold)
        Text("Análise offline • Pesquisa segura • Verificação heurística", fontSize = 13.sp)
        Text(
            "Sem conta e sem enviar seus dados. A análise é heurística e não garante 100% de segurança.",
            fontSize = 12.sp
        )
        Spacer(modifier = Modifier.height(12.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { screen = AppScreen.HOME }) { Text("Início") }
            Button(onClick = { screen = AppScreen.ANALYZE }) { Text("Código") }
            Button(onClick = { screen = AppScreen.APK }) { Text("APK") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { screen = AppScreen.SEARCH }) { Text("Pesquisa") }
            Button(onClick = { screen = AppScreen.URL }) { Text("Link") }
            Button(onClick = { screen = AppScreen.HISTORY }) { Text("Histórico") }
        }
        Spacer(modifier = Modifier.height(12.dp))

        when (screen) {
            AppScreen.HOME -> HomeScreen(
                history = history,
                onGoAnalyze = { screen = AppScreen.ANALYZE },
                onGoApk = { screen = AppScreen.APK },
                onGoSearch = { screen = AppScreen.SEARCH }
            )
            AppScreen.ANALYZE -> AnalyzeScreen(onResult = { saveResult(it) })
            AppScreen.APK -> ApkScreen(onResult = { saveResult(it) })
            AppScreen.SEARCH -> SafeSearchScreen()
            AppScreen.URL -> UrlScreen(onResult = { saveResult(it) })
            AppScreen.HISTORY -> HistoryScreen(
                history = history,
                onClear = {
                    HistoryStore.clear(context)
                    history = emptyList()
                    lastResult = null
                }
            )
        }

        lastResult?.let { result ->
            Spacer(modifier = Modifier.height(16.dp))
            ResultCard(result = result)
            Spacer(modifier = Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { shareReport(context, result.toReportText()) }) {
                    Text("Compartilhar")
                }
                OutlinedButton(onClick = { copyToClipboard(context, "Relatório VyraX AI", result.toReportText()) }) {
                    Text("Copiar")
                }
                OutlinedButton(onClick = { lastResult = null }) { Text("Limpar") }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
        Text("Dica: analise um APK ou script antes de instalar/executar.", fontSize = 12.sp)
        Text("VyraX AI v1.1 • Offline no seu aparelho", fontSize = 12.sp)
    }
}

@Composable
fun PinLockScreen(onUnlocked: () -> Unit, onSkip: () -> Unit) {
    val context = LocalContext.current
    var pin by remember { mutableStateOf("") }
    var pin2 by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    val isSet = PinManager.isPinSet(context)

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Text("🔒 Chave de segurança", fontSize = 24.sp, fontWeight = FontWeight.Bold)
        Text(
            if (isSet) "Digite seu PIN para abrir o VyraX AI."
            else "Crie um PIN de 4 a 8 dígitos para proteger o app. Você pode pular por agora.",
            fontSize = 14.sp
        )
        Spacer(modifier = Modifier.height(16.dp))
        OutlinedTextField(
            value = pin,
            onValueChange = { if (it.length <= 8) pin = it.filter { c -> c.isDigit() } },
            label = { Text("PIN") },
            modifier = Modifier.fillMaxWidth(),
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
            singleLine = true
        )
        if (!isSet) {
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = pin2,
                onValueChange = { if (it.length <= 8) pin2 = it.filter { c -> c.isDigit() } },
                label = { Text("Confirmar PIN") },
                modifier = Modifier.fillMaxWidth(),
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                singleLine = true
            )
        }
        if (message.isNotEmpty()) {
            Spacer(modifier = Modifier.height(8.dp))
            Text(message)
        }
        Spacer(modifier = Modifier.height(16.dp))
        Button(
            onClick = {
                if (isSet) {
                    if (PinManager.verifyPin(context, pin)) onUnlocked()
                    else message = "PIN incorreto. Tente de novo."
                } else {
                    if (pin.length < 4) message = "O PIN precisa ter pelo menos 4 dígitos."
                    else if (pin != pin2) message = "Os PINs não conferem."
                    else {
                        PinManager.savePin(context, pin)
                        Toast.makeText(context, "PIN criado!", Toast.LENGTH_SHORT).show()
                        onUnlocked()
                    }
                }
            },
            modifier = Modifier.fillMaxWidth()
        ) { Text(if (isSet) "Desbloquear" else "Criar PIN e entrar") }
        // Com PIN já criado não existe opção de pular: o bloqueio seria inútil.
        if (!isSet) {
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedButton(onClick = onSkip, modifier = Modifier.fillMaxWidth()) { Text("Pular por agora") }
        }
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            if (isSet) "O PIN fica só no aparelho (hash PBKDF2 com salt). Se esquecer, limpe os dados do app para resetar."
            else "O PIN fica só no aparelho, salvo como hash PBKDF2 com salt, nunca em texto puro.",
            fontSize = 12.sp
        )
    }
}

@Composable
fun HomeScreen(history: List<HistoryItem>, onGoAnalyze: () -> Unit, onGoApk: () -> Unit, onGoSearch: () -> Unit) {
    Text("O que você quer fazer hoje?", fontSize = 18.sp, fontWeight = FontWeight.Bold)
    Spacer(modifier = Modifier.height(8.dp))
    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text("🔍 Analisar código / script / texto", fontWeight = FontWeight.Bold)
            Text("Cole Python, Kotlin, Java, JS, Shell, ADB ou qualquer texto. O app procura eval, exec, rm -rf, base64, senha fixa, link HTTP e outros padrões.")
            Button(onClick = onGoAnalyze) { Text("Analisar código") }
        }
    }
    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text("📦 Analisar APK", fontWeight = FontWeight.Bold)
            Text("Escolha um arquivo .apk. O app calcula o SHA-256, lista DEX, .so e permissões detectadas, sem instalar nada.")
            Button(onClick = onGoApk) { Text("Analisar APK") }
        }
    }
    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text("🌐 Pesquisa segura", fontWeight = FontWeight.Bold)
            Text("Pesquisa com SafeSearch ativado no WebView com Safe Browsing do Android.")
            Button(onClick = onGoSearch) { Text("Pesquisar com segurança") }
        }
    }
    Spacer(modifier = Modifier.height(8.dp))
    Text("Últimas análises: ${history.size}", fontWeight = FontWeight.Bold)
    if (history.isEmpty()) {
        Text("Nenhuma análise ainda. Faça a primeira acima.")
    } else {
        history.take(3).forEach { item ->
            Text("• ${item.title} — ${item.riskLabel} (${item.score}/100)")
        }
    }
}

@Composable
fun AnalyzeScreen(onResult: (ScanResult) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var input by remember { mutableStateOf("") }
    var mode by remember { mutableStateOf("codigo") }
    var analyzing by remember { mutableStateOf(false) }

    Text("Analisar código / texto", fontSize = 20.sp, fontWeight = FontWeight.Bold)
    Text("Tudo offline. Cole o conteúdo abaixo ou abra um arquivo.")
    Spacer(modifier = Modifier.height(8.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = { mode = "codigo" }) { Text("Código") }
        Button(onClick = { mode = "texto" }) { Text("Texto") }
    }
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) {
            try {
                // Leitura limitada para evitar travar/estourar memória em arquivos gigantes.
                val text = context.contentResolver.openInputStream(uri)?.use { stream ->
                    stream.bufferedReader().use { reader ->
                        val buf = CharArray(8192)
                        val sb = StringBuilder()
                        var read = reader.read(buf)
                        while (read >= 0 && sb.length < MAX_FILE_CHARS) {
                            sb.append(buf, 0, minOf(read, MAX_FILE_CHARS - sb.length))
                            if (sb.length >= MAX_FILE_CHARS) break
                            read = reader.read(buf)
                        }
                        sb.toString()
                    }
                } ?: ""
                input = text
                val cut = text.length >= MAX_FILE_CHARS
                Toast.makeText(
                    context,
                    if (cut) "Arquivo carregado (limitado a $MAX_FILE_CHARS caracteres)"
                    else "Arquivo carregado: ${text.length} caracteres",
                    Toast.LENGTH_SHORT
                ).show()
            } catch (e: Exception) {
                Toast.makeText(context, "Erro ao ler arquivo: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }
    Spacer(modifier = Modifier.height(8.dp))
    OutlinedTextField(
        value = input,
        onValueChange = { input = it },
        label = { Text(if (mode == "codigo") "Cole o código / script aqui" else "Cole o texto aqui") },
        modifier = Modifier.fillMaxWidth().height(220.dp)
    )
    Spacer(modifier = Modifier.height(8.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(
            onClick = {
                if (input.isBlank()) {
                    Toast.makeText(context, "Cole algo primeiro.", Toast.LENGTH_SHORT).show()
                } else {
                    analyzing = true
                    scope.launch {
                        val result = try {
                            withContext(Dispatchers.Default) {
                                if (mode == "codigo") CodeAnalyzer.analyze(input) else TextAnalyzer.analyze(input)
                            }
                        } finally {
                            analyzing = false
                        }
                        onResult(result)
                    }
                }
            },
            enabled = !analyzing
        ) { Text(if (analyzing) "Analisando..." else "Analisar agora") }
        OutlinedButton(onClick = { filePicker.launch(arrayOf("*/*")) }) { Text("Abrir arquivo") }
        OutlinedButton(onClick = { input = "" }) { Text("Limpar") }
    }
    Spacer(modifier = Modifier.height(8.dp))
    Text("Exemplo para testar: cole um script com curl | sh ou eval() e veja o alerta.", fontSize = 12.sp)
}

@Composable
fun ApkScreen(onResult: (ScanResult) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var fileName by remember { mutableStateOf("Nenhum APK escolhido") }
    var loading by remember { mutableStateOf(false) }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) {
            loading = true
            val name = uri.lastPathSegment ?: "arquivo.apk"
            fileName = name
            scope.launch {
                val result = try {
                    withContext(Dispatchers.IO) { ApkAnalyzer.analyze(context, uri, name) }
                } catch (e: Exception) {
                    ScanResult(
                        "Análise de APK", name, RiskLevel.MEDIO, 50,
                        "Não foi possível analisar o arquivo: ${e.message}", emptyList()
                    )
                } finally {
                    loading = false
                }
                onResult(result)
            }
        }
    }

    Text("Analisar APK", fontSize = 20.sp, fontWeight = FontWeight.Bold)
    Text("O app NÃO instala o APK. Ele lê o arquivo como ZIP, calcula o hash e procura sinais suspeitos.")
    Spacer(modifier = Modifier.height(8.dp))
    Text("Arquivo: $fileName")
    if (loading) Text("Analisando... aguarde.")
    Spacer(modifier = Modifier.height(8.dp))
    Button(onClick = { picker.launch(arrayOf("application/vnd.android.package-archive", "*/*")) }) { Text("Escolher APK") }
    Spacer(modifier = Modifier.height(8.dp))
    Text(
        "Aviso: a leitura de permissões é parcial (manifesto binário). Um resultado SEGURO não garante que o APK seja confiável.",
        fontSize = 12.sp
    )
}

@Composable
fun SafeSearchScreen() {
    val context = LocalContext.current
    var query by remember { mutableStateOf("") }
    var url by remember { mutableStateOf<String?>(null) }

    Text("Pesquisa segura", fontSize = 20.sp, fontWeight = FontWeight.Bold)
    Text("SafeSearch ativado. O WebView usa Safe Browsing do Android quando disponível.")
    Spacer(modifier = Modifier.height(8.dp))
    OutlinedTextField(
        value = query,
        onValueChange = { query = it },
        label = { Text("O que você quer pesquisar?") },
        modifier = Modifier.fillMaxWidth()
    )
    Spacer(modifier = Modifier.height(8.dp))
    Button(onClick = {
        if (query.isBlank()) {
            Toast.makeText(context, "Digite algo para pesquisar.", Toast.LENGTH_SHORT).show()
        } else {
            url = UrlChecker.buildSafeSearchUrl(query)
        }
    }) { Text("Pesquisar") }
    Spacer(modifier = Modifier.height(8.dp))
    Text(
        "Dica: desconfie de promessas como 'diamante grátis', 'robux grátis' e 'hack'. Nunca digite senha em site vindo de link estranho.",
        fontSize = 12.sp
    )
    url?.let { safeUrl ->
        Spacer(modifier = Modifier.height(8.dp))
        Text("Resultado (DuckDuckGo, SafeSearch):", fontWeight = FontWeight.Bold)
        AndroidView(
            factory = { ctx ->
                WebView(ctx).apply {
                    settings.javaScriptEnabled = true
                    settings.domStorageEnabled = true
                    @Suppress("SetJavaScriptEnabled")
                    settings.safeBrowsingEnabled = true
                    webViewClient = WebViewClient()
                    loadUrl(safeUrl)
                }
            },
            update = { web ->
                if (web.url != safeUrl) web.loadUrl(safeUrl)
            },
            modifier = Modifier.fillMaxWidth().height(420.dp)
        )
    }
}

@Composable
fun UrlScreen(onResult: (ScanResult) -> Unit) {
    val context = LocalContext.current
    var url by remember { mutableStateOf("") }
    var lastChecked by remember { mutableStateOf<String?>(null) }

    Text("Verificar link", fontSize = 20.sp, fontWeight = FontWeight.Bold)
    Text("Cole um link antes de abrir. O app verifica HTTPS, domínio bloqueado, encurtador, IP e iscas comuns de golpe.")
    Spacer(modifier = Modifier.height(8.dp))
    OutlinedTextField(
        value = url,
        onValueChange = { url = it },
        label = { Text("Cole o link aqui") },
        modifier = Modifier.fillMaxWidth(),
        singleLine = true
    )
    Spacer(modifier = Modifier.height(8.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = {
            if (url.isBlank()) {
                Toast.makeText(context, "Cole um link primeiro.", Toast.LENGTH_SHORT).show()
            } else {
                lastChecked = url.trim()
                onResult(UrlChecker.check(url))
            }
        }) { Text("Verificar link") }
        OutlinedButton(onClick = { url = "" }) { Text("Limpar") }
    }
    lastChecked?.let { checked ->
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedButton(onClick = { openInBrowser(context, checked) }) {
            Text("Abrir último link no navegador")
        }
        Text("Abra apenas se você confiar no destino.", fontSize = 12.sp)
    }
}

@Composable
fun HistoryScreen(history: List<HistoryItem>, onClear: () -> Unit) {
    Text("Histórico", fontSize = 20.sp, fontWeight = FontWeight.Bold)
    Text("Fica só no seu aparelho. Máximo de 100 registros.")
    Spacer(modifier = Modifier.height(8.dp))
    if (history.isEmpty()) {
        Text("Histórico vazio.")
    } else {
        history.forEach { item ->
            val date = SimpleDateFormat("dd/MM HH:mm", Locale.getDefault()).format(Date(item.timestamp))
            Card(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(item.title, fontWeight = FontWeight.Bold)
                    Text("$date • ${item.riskLabel} • ${item.score}/100")
                }
            }
        }
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedButton(onClick = onClear) { Text("Limpar histórico") }
    }
}

@Composable
fun ResultCard(result: ScanResult) {
    val tint = riskColor(result.risk)
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = tint.copy(alpha = 0.12f))
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text("${result.risk.emoji} ${result.title}", fontSize = 18.sp, fontWeight = FontWeight.Bold, color = tint)
            Text("Risco: ${result.risk.label} • Pontuação: ${result.score}/100", fontWeight = FontWeight.SemiBold)
            Text("Alvo: ${result.target}")
            Spacer(modifier = Modifier.height(8.dp))
            Text(result.summary)
            if (result.findings.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                Text("Achados:", fontWeight = FontWeight.Bold)
                result.findings.forEachIndexed { i, f ->
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        if (f.line > 0) "${i + 1}. [${f.risk.label}] ${f.title} (linha ${f.line})"
                        else "${i + 1}. [${f.risk.label}] ${f.title}",
                        fontWeight = FontWeight.Bold
                    )
                    Text(f.detail)
                    Text("Recomendação: ${f.recommendation}")
                }
            } else {
                Spacer(modifier = Modifier.height(8.dp))
                Text("Nenhum achado suspeito. Isso não garante segurança total.")
            }
        }
    }
}

private fun riskColor(risk: RiskLevel): Color = when (risk) {
    RiskLevel.SEGURO -> Color(0xFF4CAF50)
    RiskLevel.BAIXO -> Color(0xFF8BC34A)
    RiskLevel.MEDIO -> Color(0xFFFFC107)
    RiskLevel.ALTO -> Color(0xFFFF9800)
    RiskLevel.CRITICO -> Color(0xFFF44336)
}

private fun shareReport(context: Context, text: String) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
        putExtra(Intent.EXTRA_SUBJECT, "Relatório VyraX AI")
    }
    try {
        context.startActivity(Intent.createChooser(intent, "Compartilhar relatório"))
    } catch (_: Exception) {
        Toast.makeText(context, "Nenhum app de compartilhamento encontrado.", Toast.LENGTH_LONG).show()
    }
}

private fun copyToClipboard(context: Context, label: String, text: String) {
    try {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText(label, text))
        Toast.makeText(context, "Relatório copiado.", Toast.LENGTH_SHORT).show()
    } catch (_: Exception) {
        Toast.makeText(context, "Não foi possível copiar.", Toast.LENGTH_LONG).show()
    }
}

private fun openInBrowser(context: Context, rawUrl: String) {
    val candidate = rawUrl.trim()
    val uri = try {
        val parsed = Uri.parse(candidate)
        if (parsed.scheme.isNullOrBlank()) Uri.parse("https://$candidate") else parsed
    } catch (_: Exception) {
        null
    }
    if (uri == null) {
        Toast.makeText(context, "Link inválido.", Toast.LENGTH_LONG).show()
        return
    }
    try {
        context.startActivity(Intent(Intent.ACTION_VIEW, uri))
    } catch (_: Exception) {
        Toast.makeText(context, "Nenhum navegador encontrado.", Toast.LENGTH_LONG).show()
    }
}
