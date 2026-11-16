# 🛡️ VyraX AI v1.1

**Nome:** VyraX AI (evolução do NoxShield AI).  
**Pacote:** `com.vyrax.ai`  
**Perfil:** análise / pesquisa de dados e segurança, **offline-first**, sem chatbot.

> Android nativo, Min SDK 26, target/compile 34, Kotlin + Jetpack Compose + Material 3.

## O que o app faz

1. **Analisar código / script / texto**
   - Cola Python, Kotlin, Java, JavaScript, PHP, C/C++, Shell / ADB ou texto.
   - Detecta padrões: `eval()`, `exec()`, `os.system`, `curl | sh`, `rm -rf /`, Base64/ofuscação, senha/token fixo no código, `http://`, minerador, comando root/ADB.
   - Mostra linguagem detectada, linha, risco, explicação e recomendação.
   - Abre arquivo de código/texto pelo seletor do Android (leitura limitada para evitar travas).

2. **Analisar APK (sem instalar)**
   - Escolhe um `.apk` pelo seletor.
   - Calcula SHA-256, tamanho, entradas ZIP, DEX e `.so`.
   - Procura executáveis/artefatos suspeitos dentro do APK e permissões detectadas no manifesto (extração parcial).
   - **Não instala nada.**

3. **Pesquisa segura**
   - Pesquisa no DuckDuckGo com SafeSearch ativado, dentro de WebView com Safe Browsing do Android (quando disponível).

4. **Verificar link**
   - Verifica HTTPS, domínio em lista local de bloqueio, TLD suspeito (`.xyz`, `.top`...), link encurtado, IP, `@` e iscas comuns de golpe.
   - Permite abrir o último link verificado no navegador (com aviso).

5. **Chave de segurança (PIN)**
   - PIN de 4 a 8 dígitos, salvo localmente como hash **PBKDF2WithHmacSHA1** com salt aleatório (nunca em texto puro).
   - Entrada de PIN mascarada.
   - Se esquecer o PIN, limpe os dados do app para resetar.

6. **Histórico e relatório**
   - Últimas 100 análises salvas só no aparelho.
   - Relatório em texto pode ser **compartilhado** ou **copiado**.

## Novidades v1.1
- Renomeado para **VyraX AI** (`com.vyrax.ai`).
- Correções/UX: captura correta do nome do APK analisado, PIN mascarado, botão de copiar relatório, indicador visual de risco no resultado, abrir link verificado no navegador, limpeza de campos.
- Ajustes de consistência em textos e metadados de build.

## O que o app NÃO faz (honesto)
- Não é um antivírus com banco de dados atualizado. A análise é **heurística offline**.
- Não tem proteção em tempo real, não escaneia o celular inteiro sozinho e não remove vírus.
- A lista de domínios bloqueados é **local e de exemplo**; não cobre todos os golpes.
- A extração de permissões do APK é **parcial** (manifesto binário).
- Pesquisa segura precisa de internet para carregar resultados; a análise em si é offline.

## Como compilar

### Neste ambiente (Gradle)
```sh
cd VyraXAI
./gradlew :app:assembleDebug --no-daemon --stacktrace
# APK: app/build/outputs/apk/debug/app-debug.apk
```

### GitHub Actions
O workflow em `.github/workflows/android.yml` compila o APK debug e publica o artefato `VyraXAI-debug-apk`.

### Android Studio
Abra a pasta do projeto, sincronize o Gradle e use **Build > Build Bundle(s) / APK(s) > Build APK(s)**.

## Estrutura
```
VyraXAI/
  app/src/main/java/com/vyrax/ai/
    MainActivity.kt
    model/Models.kt
    analysis/{Analyzers.kt, ApkAnalyzer.kt}
    security/PinManager.kt
    storage/HistoryStore.kt
    ui/Screens.kt
  app/src/main/res/...
  .github/workflows/android.yml
```

## Versão
- **v1.1** — 2026-04-16 — Renomeação para VyraX AI, correções de bugs e melhorias de UX.
- **v1.0** — 2026-11-14 — Primeira versão offline (NoxShield AI).
