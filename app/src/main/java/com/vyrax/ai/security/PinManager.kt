package com.vyrax.ai.security

import android.content.Context
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

// Chave de seguranca do app: um PIN de 4 a 8 digitos.
// O PIN nunca e salvo em texto puro: guardamos um salt aleatorio e o hash
// PBKDF2 (120 mil iteracoes). Isso protege o app se alguem pegar o celular
// desbloqueado, mas nao e seguranca de nivel bancario: se a pessoa tiver
// acesso root e souber onde procurar, pode apagar os dados do app e resetar o PIN.
object PinManager {
    private const val PREFS = "vyrax_pin"
    private const val KEY_HASH = "pin_hash"
    private const val KEY_SALT = "pin_salt"
    private const val ITERATIONS = 120_000
    private const val KEY_BITS = 256
    private const val SALT_BYTES = 16

    private val random = SecureRandom()

    private fun newSalt(): ByteArray {
        val salt = ByteArray(SALT_BYTES)
        random.nextBytes(salt)
        return salt
    }

    private fun toHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    private fun fromHex(hex: String): ByteArray? {
        if (hex.length % 2 != 0) return null
        return try {
            ByteArray(hex.length / 2) { i ->
                hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        } catch (_: Exception) {
            null
        }
    }

    fun hashPin(pin: String, salt: ByteArray): String {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val spec = PBEKeySpec(pin.toCharArray(), salt, ITERATIONS, KEY_BITS)
        val out = factory.generateSecret(spec).encoded
        spec.clearPassword()
        return toHex(out)
    }

    fun isPinSet(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return prefs.contains(KEY_HASH) && prefs.contains(KEY_SALT)
    }

    fun savePin(context: Context, pin: String) {
        val salt = newSalt()
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.edit()
            .putString(KEY_SALT, toHex(salt))
            .putString(KEY_HASH, hashPin(pin, salt))
            .apply()
    }

    fun verifyPin(context: Context, pin: String): Boolean {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val saved = prefs.getString(KEY_HASH, null) ?: return false
        val salt = fromHex(prefs.getString(KEY_SALT, null) ?: return false) ?: return false
        val candidate = hashPin(pin, salt)
        // Comparacao em tempo constante: nao vaza por tempo de resposta.
        if (candidate.length != saved.length) return false
        var diff = 0
        for (i in candidate.indices) {
            diff = diff or (candidate[i].code xor saved[i].code)
        }
        return diff == 0
    }

    fun clearPin(context: Context) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        prefs.edit().remove(KEY_HASH).remove(KEY_SALT).apply()
    }
}
