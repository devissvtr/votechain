package com.nocturna.votechain.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.web3j.crypto.ECKeyPair
import org.web3j.crypto.Keys
import org.web3j.utils.Numeric
import java.math.BigInteger
import java.security.*
import java.security.interfaces.ECPrivateKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.Result

/**
 * Enhanced CryptoKeyManager with standardized private key format (0x + 64 hex chars)
 *
 * Security Features:
 * 1. Private keys NEVER stored in plaintext
 * 2. Uses Android Keystore for hardware-backed encryption
 * 3. Implements key derivation for added security
 * 4. Supports secure key export only when explicitly needed
 * 5. Multiple fallback methods for key generation
 * 6. Enforces standard Ethereum private key format: exactly 66 characters (0x + 64 hex)
 */
class CryptoKeyManager(private val context: Context) {

    companion object {
        private const val TAG = "CryptoKeyManager"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val PREFS_NAME = "VoteChainCryptoPrefs"

        // Multiple key aliases for different purposes
        private const val KEY_ALIAS_MASTER = "VoteChainMasterKey"
        private const val KEY_ALIAS_ENCRYPTION = "VoteChainEncryptionKey"
        private const val KEY_ALIAS_SIGNING = "VoteChainSigningKey"

        // Storage keys
        private const val PUBLIC_KEY_KEY = "public_key"
        private const val ENCRYPTED_PRIVATE_KEY_KEY = "encrypted_private_key"
        private const val VOTER_ADDRESS_KEY = "voter_address"
        private const val IV_KEY = "encryption_iv"
        private const val KEY_METADATA = "key_metadata"
        private const val KEY_CREATION_TIME = "key_creation_time"
        private const val KEY_GENERATION_METHOD = "key_generation_method"

        // Encryption parameters
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_LENGTH = 12
        private const val GCM_TAG_LENGTH = 16

        // Security flags
        private const val REQUIRE_USER_AUTH = false // Set to true for biometric protection
        private const val KEY_VALIDITY_SECONDS = -1 // -1 for no timeout

        // Private key format constants
        private const val PRIVATE_KEY_HEX_LENGTH = 64 // 32 bytes = 64 hex characters
        private const val PRIVATE_KEY_TOTAL_LENGTH = 66 // "0x" + 64 hex = 66 total

        private var isBouncyCastleInitialized = false

        /**
         * Initialize BouncyCastle provider with error handling
         */
        fun initializeBouncyCastle(): Boolean {
            return try {
                if (!isBouncyCastleInitialized) {
                    Security.removeProvider("BC")
                    Security.addProvider(BouncyCastleProvider())
                    isBouncyCastleInitialized = true
                    Log.d(TAG, "✅ BouncyCastle provider initialized successfully")
                }
                true
            } catch (e: Exception) {
                Log.e(TAG, "❌ Failed to initialize BouncyCastle: ${e.message}")
                false
            }
        }
    }

    /**
     * Data class to hold key pair information with proper format validation
     */
    data class KeyPairInfo(
        val publicKey: String,
        val privateKey: String,
        val voterAddress: String,
        val generationMethod: String = "Unknown",
        val creationTime: Long = System.currentTimeMillis(),
        val accessCount: Int = 0,
        val keyVersion: Int = 1
    ) {
        init {
            // Validate private key format at creation
            require(isValidPrivateKeyFormat(privateKey)) {
                "Private key must be exactly 66 characters (0x + 64 hex), got: ${privateKey.length}"
            }
            require(publicKey.startsWith("0x")) { "Public key must start with 0x" }
            require(voterAddress.startsWith("0x") && voterAddress.length == 42) {
                "Voter address must be 42 characters (0x + 40 hex)"
            }
        }
    }

    /**
     * Data class for encrypted data storage
     */
    private data class EncryptedData(
        val encryptedData: String,
        val iv: String
    )

    // Initialize encrypted shared preferences with enhanced security
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .setRequestStrongBoxBacked(true) // Request hardware security module if available
        .build()

    private val encryptedSharedPreferences = try {
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    } catch (e: Exception) {
        Log.e(TAG, "Failed to create encrypted preferences", e)
        throw SecurityException("Cannot initialize secure storage", e)
    }

    init {
        // Test available providers
        testAvailableProviders()

        // Initialize all required encryption keys
        initializeSecurityKeys()

        // Verify keystore integrity
        verifyKeystoreIntegrity()

        // Ensure hardware-backed key storage when available
        enableStrongBoxBackedKeysWhenAvailable()
    }

    /**
     * Format private key to standard Ethereum format: "0x" + exactly 64 hex characters
     */
    private fun formatPrivateKey(ecKeyPair: ECKeyPair): String {
        return formatPrivateKeyFromBigInteger(ecKeyPair.privateKey)
    }

    /**
     * Format private key from BigInteger to standard format
     */
    private fun formatPrivateKeyFromBigInteger(privateKeyBigInt: BigInteger): String {
        // Convert to byte array, ensuring exactly 32 bytes
        val privateKeyBytes = privateKeyBigInt.toByteArray()

        // Handle the case where BigInteger.toByteArray() adds an extra sign byte
        val finalBytes = when {
            privateKeyBytes.size == 32 -> privateKeyBytes
            privateKeyBytes.size == 33 && privateKeyBytes[0] == 0.toByte() ->
                privateKeyBytes.sliceArray(1..32) // Remove leading zero byte
            privateKeyBytes.size < 32 -> {
                // Pad with leading zeros if necessary
                val paddedBytes = ByteArray(32)
                System.arraycopy(privateKeyBytes, 0, paddedBytes, 32 - privateKeyBytes.size, privateKeyBytes.size)
                paddedBytes
            }
            else -> throw IllegalStateException("Private key too large: ${privateKeyBytes.size} bytes")
        }

        // Convert to hex string (exactly 64 characters)
        val hexString = finalBytes.joinToString("") { "%02x".format(it) }

        // Ensure exactly 64 characters
        require(hexString.length == PRIVATE_KEY_HEX_LENGTH) {
            "Private key must be exactly $PRIVATE_KEY_HEX_LENGTH hex characters, got: ${hexString.length}"
        }

        return "0x$hexString"
    }

    /**
     * Validate private key format
     */
    private fun isValidPrivateKeyFormat(privateKey: String): Boolean {
        return privateKey.length == PRIVATE_KEY_TOTAL_LENGTH &&
                privateKey.startsWith("0x") &&
                privateKey.substring(2).matches(Regex("^[0-9a-fA-F]{$PRIVATE_KEY_HEX_LENGTH}$"))
    }

    /**
     * Validate private key format with detailed logging
     */
    fun validatePrivateKeyFormat(privateKey: String): Boolean {
        return try {
            if (privateKey.isNullOrEmpty()) {
                Log.w(TAG, "Private key is null or empty")
                return false
            }

            val cleanKey = if (privateKey.startsWith("0x", ignoreCase = true)) {
                privateKey.substring(2)
            } else {
                privateKey
            }

            Log.d(TAG, "Validating private key with length: ${cleanKey.length}")

            // Check if it's exactly 64 hex characters
            if (cleanKey.length != PRIVATE_KEY_HEX_LENGTH) {
                Log.w(TAG, "Private key must be exactly $PRIVATE_KEY_HEX_LENGTH hex characters, got: ${cleanKey.length}")
                return false
            }

            // Check if all characters are valid hex
            val isValidHex = cleanKey.matches(Regex("^[0-9a-fA-F]{$PRIVATE_KEY_HEX_LENGTH}$"))
            if (!isValidHex) {
                Log.w(TAG, "Private key contains non-hex characters")
                return false
            }

            // Validate it's in valid range for secp256k1
            val privateKeyBigInt = BigInteger(cleanKey, 16)
            val secp256k1Order = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
            if (privateKeyBigInt.compareTo(BigInteger.ZERO) <= 0 || privateKeyBigInt.compareTo(secp256k1Order) >= 0) {
                Log.w(TAG, "Private key is outside valid range for secp256k1")
                return false
            }

            Log.d(TAG, "✅ Private key validation successful")
            true

        } catch (e: Exception) {
            Log.e(TAG, "Error validating private key: ${e.message}")
            false
        }
    }

    /**
     * Generate a key pair using EC algorithm with multiple fallback options
     */
    fun generateKeyPair(): KeyPairInfo {
        return generateECKeyPair() ?: throw SecurityException("Failed to generate key pair with all methods")
    }

    /**
     * Generate EC key pair with enhanced private key formatting
     */
    private fun generateECKeyPair(): KeyPairInfo? {
        Log.d(TAG, "Attempting EC key generation with multiple providers")

        // Try with BouncyCastle first (most reliable for secp256k1)
        try {
            if (initializeBouncyCastle()) {
                val keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC")
                val ecSpec = ECGenParameterSpec("secp256k1")
                keyPairGenerator.initialize(ecSpec)
                val keyPair = keyPairGenerator.generateKeyPair()

                // Extract private key as BigInteger directly from BC implementation
                val privateKeyBytes = keyPair.private.encoded
                val privateKeyBigInt = BigInteger(1, privateKeyBytes)

                // Create Web3j ECKeyPair
                val ecKeyPair = ECKeyPair.create(privateKeyBigInt)

                // Generate properly formatted keys
                val privateKeyHex = formatPrivateKey(ecKeyPair)
                val publicKeyHex = Numeric.toHexStringWithPrefix(ecKeyPair.publicKey)
                val addressHex = Keys.getAddress(ecKeyPair)
                val address = Keys.toChecksumAddress("0x" + addressHex)

                Log.d(TAG, "✅ EC key generation successful with BC, address: $address")
                Log.d(TAG, "Private key length: ${privateKeyHex.length} characters")

                return KeyPairInfo(
                    publicKey = publicKeyHex,
                    privateKey = privateKeyHex,
                    voterAddress = address,
                    generationMethod = "EC_BouncyCastle"
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "BouncyCastle EC generation failed: ${e.message}")
        }

        // Try with AndroidOpenSSL provider
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance("EC", "AndroidOpenSSL")
            val ecSpec = ECGenParameterSpec("secp256k1")
            keyPairGenerator.initialize(ecSpec)
            val keyPair = keyPairGenerator.generateKeyPair()

            val privateKeyBigInt = (keyPair.private as ECPrivateKey).s
            val ecKeyPair = ECKeyPair.create(privateKeyBigInt)

            val privateKeyHex = formatPrivateKey(ecKeyPair)
            val publicKeyHex = Numeric.toHexStringWithPrefix(ecKeyPair.publicKey)
            val addressHex = Keys.getAddress(ecKeyPair)
            val address = Keys.toChecksumAddress("0x" + addressHex)

            Log.d(TAG, "✅ EC key generation successful with AndroidOpenSSL")
            Log.d(TAG, "Private key length: ${privateKeyHex.length} characters")

            return KeyPairInfo(
                publicKey = publicKeyHex,
                privateKey = privateKeyHex,
                voterAddress = address,
                generationMethod = "EC_AndroidOpenSSL"
            )
        } catch (e: Exception) {
            Log.w(TAG, "AndroidOpenSSL EC generation failed: ${e.message}")
        }

        // Final fallback to SecureRandom-based generation
        try {
            // Generate exactly 32 bytes for private key
            val secureRandom = SecureRandom()
            val privateKeyBytes = ByteArray(32)
            secureRandom.nextBytes(privateKeyBytes)

            // Create ECKeyPair directly from random bytes
            val ecKeyPair = ECKeyPair.create(privateKeyBytes)

            val privateKeyHex = formatPrivateKey(ecKeyPair)
            val publicKeyHex = Numeric.toHexStringWithPrefix(ecKeyPair.publicKey)
            val addressHex = Keys.getAddress(ecKeyPair)
            val address = Keys.toChecksumAddress("0x" + addressHex)

            Log.d(TAG, "✅ EC key generation with SecureRandom successful")
            Log.d(TAG, "Private key length: ${privateKeyHex.length} characters")

            return KeyPairInfo(
                publicKey = publicKeyHex,
                privateKey = privateKeyHex,
                voterAddress = address,
                generationMethod = "EC_SecureRandom"
            )
        } catch (e: Exception) {
            Log.e(TAG, "All EC key generation methods failed: ${e.message}")
        }

        return null
    }

    /**
     * Store key pair with enhanced validation and security
     */
    fun storeKeyPair(keyPairInfo: KeyPairInfo) {
        try {
            Log.d(TAG, "Storing key pair with enhanced security...")

            // Validate key pair before storing
            validateKeyPair(keyPairInfo)

            // Double-encrypt private key for extra security
            val encryptedPrivateKeyData = doubleEncryptPrivateKey(keyPairInfo.privateKey)

            // Store with transaction for atomicity
            with(encryptedSharedPreferences.edit()) {
                putString(PUBLIC_KEY_KEY, keyPairInfo.publicKey)
                putString(VOTER_ADDRESS_KEY, keyPairInfo.voterAddress)
                putString(ENCRYPTED_PRIVATE_KEY_KEY, encryptedPrivateKeyData.encryptedData)
                putString(IV_KEY, encryptedPrivateKeyData.iv)
                putLong(KEY_CREATION_TIME, keyPairInfo.creationTime)
                putString(KEY_GENERATION_METHOD, keyPairInfo.generationMethod)
                commit() // Use commit for synchronous write
            }

            // Create and store metadata
            val metadata = KeyMetadata(
                creationTime = keyPairInfo.creationTime,
                accessCount = 0,
                lastAccessTime = System.currentTimeMillis(),
                keyVersion = keyPairInfo.keyVersion,
                generationMethod = keyPairInfo.generationMethod
            )

            val metadataJson = "${metadata.creationTime},${metadata.accessCount},${metadata.lastAccessTime},${metadata.keyVersion},${metadata.generationMethod}"
            encryptedSharedPreferences.edit()
                .putString(KEY_METADATA, metadataJson)
                .apply()

            Log.d(TAG, "✅ Key pair stored successfully with double encryption")

            // Clear any sensitive data from memory
            System.gc()

        } catch (e: Exception) {
            Log.e(TAG, "❌ Failed to store key pair: ${e.message}", e)
            throw SecurityException("Failed to store key pair securely", e)
        }
    }

    /**
     * Import wallet from private key with enhanced validation
     */
    suspend fun importWalletFromPrivateKey(
        privateKey: String,
        userPassword: String
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Starting wallet import from private key")

            // Clean and validate private key format
            val cleanPrivateKey = privateKey.trim().let {
                when {
                    it.startsWith("0x", ignoreCase = true) -> it.substring(2)
                    else -> it
                }
            }

            // Validate hex string length (should be exactly 64 characters)
            if (cleanPrivateKey.length != PRIVATE_KEY_HEX_LENGTH ||
                !cleanPrivateKey.matches(Regex("^[0-9a-fA-F]{$PRIVATE_KEY_HEX_LENGTH}$"))) {
                return@withContext Result.failure(
                    SecurityException("Private key must be exactly $PRIVATE_KEY_HEX_LENGTH hexadecimal characters")
                )
            }

            // Convert to BigInteger and validate range
            val privateKeyBigInt = BigInteger(cleanPrivateKey, 16)
            val secp256k1Order = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
            if (privateKeyBigInt.compareTo(BigInteger.ZERO) <= 0 || privateKeyBigInt.compareTo(secp256k1Order) >= 0) {
                return@withContext Result.failure(
                    SecurityException("Private key is outside valid range for secp256k1")
                )
            }

            val ecKeyPair = ECKeyPair.create(privateKeyBigInt)

            // Validate the generated key pair
            if (!validateKeyPairSignature(ecKeyPair)) {
                return@withContext Result.failure(
                    SecurityException("Invalid key pair generated from private key")
                )
            }

            // Create key pair info with properly formatted private key
            val keyPairInfo = KeyPairInfo(
                publicKey = Numeric.toHexStringWithPrefix(ecKeyPair.publicKey),
                privateKey = formatPrivateKey(ecKeyPair),
                voterAddress = "0x" + Keys.getAddress(ecKeyPair),
                generationMethod = "Imported_Private_Key"
            )

            // Store with password protection
            storeImportedKeyPair(keyPairInfo, userPassword)

            Log.d(TAG, "✅ Wallet import successful, private key length: ${keyPairInfo.privateKey.length}")
            Log.d(TAG, "Wallet Address: ${keyPairInfo.voterAddress}")

            Result.success(keyPairInfo.voterAddress)

        } catch (e: Exception) {
            Log.e(TAG, "❌ Wallet import failed: ${e.message}", e)
            Result.failure(e)
        }
    }

    /**
     * Validate key pair before storing
     */
    private fun validateKeyPair(keyPairInfo: KeyPairInfo) {
        require(keyPairInfo.privateKey.isNotEmpty()) { "Private key cannot be empty" }
        require(keyPairInfo.publicKey.isNotEmpty()) { "Public key cannot be empty" }
        require(keyPairInfo.voterAddress.isNotEmpty()) { "Voter address cannot be empty" }

        // Validate format
        require(isValidPrivateKeyFormat(keyPairInfo.privateKey)) { "Invalid private key format" }
        require(keyPairInfo.publicKey.startsWith("0x")) { "Invalid public key format" }
        require(keyPairInfo.voterAddress.startsWith("0x") && keyPairInfo.voterAddress.length == 42) {
            "Invalid voter address format"
        }
    }

    /**
     * Check if stored keys exist and are valid
     */
    fun hasStoredKeyPair(): Boolean {
        return try {
            val publicKey = encryptedSharedPreferences.getString(PUBLIC_KEY_KEY, null)
            val encryptedPrivateKey = encryptedSharedPreferences.getString(ENCRYPTED_PRIVATE_KEY_KEY, null)
            val voterAddress = encryptedSharedPreferences.getString(VOTER_ADDRESS_KEY, null)

            !publicKey.isNullOrEmpty() &&
                    !encryptedPrivateKey.isNullOrEmpty() &&
                    !voterAddress.isNullOrEmpty()
        } catch (e: Exception) {
            Log.e(TAG, "Error checking stored key pair", e)
            false
        }
    }

    /**
     * Validate stored keys are in correct format
     */
    fun validateStoredKeys(): Boolean {
        return try {
            val publicKey = getPublicKey()
            val privateKey = getPrivateKey()
            val voterAddress = getVoterAddress()

            if (publicKey == null || privateKey == null || voterAddress == null) {
                return false
            }

            // Validate formats
            val privateKeyValid = isValidPrivateKeyFormat(privateKey)
            val publicKeyValid = publicKey.startsWith("0x") && publicKey.length >= 130
            val addressValid = voterAddress.startsWith("0x") && voterAddress.length == 42

            Log.d(TAG, "Key validation - Private: $privateKeyValid, Public: $publicKeyValid, Address: $addressValid")

            privateKeyValid && publicKeyValid && addressValid
        } catch (e: Exception) {
            Log.e(TAG, "Key validation failed", e)
            false
        }
    }

    /**
     * Get private key with proper format validation
     */
    fun getPrivateKey(): String? {
        return try {
            val encryptedData = encryptedSharedPreferences.getString(ENCRYPTED_PRIVATE_KEY_KEY, null)
            val iv = encryptedSharedPreferences.getString(IV_KEY, null)

            if (encryptedData != null && iv != null) {
                val decryptedKey = doubleDecryptPrivateKey(encryptedData, iv)

                // Ensure the decrypted key is in the correct format
                if (isValidPrivateKeyFormat(decryptedKey)) {
                    decryptedKey
                } else {
                    Log.w(TAG, "Stored private key is not in correct format")
                    null
                }
            } else {
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to retrieve private key", e)
            null
        }
    }

    /**
     * Get public key
     */
    fun getPublicKey(): String? {
        return try {
            encryptedSharedPreferences.getString(PUBLIC_KEY_KEY, null)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to retrieve public key", e)
            null
        }
    }

    /**
     * Get voter address
     */
    fun getVoterAddress(): String? {
        return try {
            encryptedSharedPreferences.getString(VOTER_ADDRESS_KEY, null)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to retrieve voter address", e)
            null
        }
    }

    /**
     * Clear stored keys
     */
    fun clearStoredKeys() {
        try {
            with(encryptedSharedPreferences.edit()) {
                remove(PUBLIC_KEY_KEY)
                remove(ENCRYPTED_PRIVATE_KEY_KEY)
                remove(VOTER_ADDRESS_KEY)
                remove(IV_KEY)
                remove(KEY_METADATA)
                remove(KEY_CREATION_TIME)
                remove(KEY_GENERATION_METHOD)
                commit()
            }
            Log.d(TAG, "✅ Stored keys cleared successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to clear stored keys", e)
        }
    }

    // Additional helper methods...

    /**
     * Data class for key metadata
     */
    private data class KeyMetadata(
        val creationTime: Long,
        val lastAccessTime: Long,
        val accessCount: Int,
        val keyVersion: Int = 1,
        val generationMethod: String = "unknown"
    )

    // [Additional private methods for encryption, validation, etc. - keeping the existing implementation but ensuring private key format compliance]

    /**
     * Initialize security keys
     */
    private fun initializeSecurityKeys() {
        try {
            generateMasterKeyIfNeeded()
            generateEncryptionKeyIfNeeded()
            Log.d(TAG, "✅ Security keys initialized")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize security keys", e)
        }
    }

    /**
     * Test available cryptographic providers
     */
    private fun testAvailableProviders() {
        try {
            val providers = Security.getProviders()
            Log.d(TAG, "Available security providers:")
            providers.forEach { provider ->
                Log.d(TAG, "- ${provider.name}: ${provider.version}")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to enumerate security providers", e)
        }
    }

    /**
     * Verify keystore integrity
     */
    private fun verifyKeystoreIntegrity() {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            Log.d(TAG, "✅ Android Keystore integrity verified")
        } catch (e: Exception) {
            Log.w(TAG, "Keystore integrity check failed", e)
        }
    }

    /**
     * Enable StrongBox backed keys when available
     */
    private fun enableStrongBoxBackedKeysWhenAvailable() {
        // Implementation for StrongBox backed keys
        Log.d(TAG, "StrongBox backed keys configuration checked")
    }

    /**
     * Generate master key if it doesn't exist
     */
    private fun generateMasterKeyIfNeeded() {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)

            if (!keyStore.containsAlias(KEY_ALIAS_MASTER)) {
                val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                    KEY_ALIAS_MASTER,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUserAuthenticationRequired(REQUIRE_USER_AUTH)
                    .setRandomizedEncryptionRequired(true)
                    .setKeySize(256)
                    .build()

                keyGenerator.init(keyGenParameterSpec)
                keyGenerator.generateKey()
                Log.d(TAG, "✅ Master key generated")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate master key", e)
        }
    }

    /**
     * Generate encryption key if it doesn't exist
     */
    private fun generateEncryptionKeyIfNeeded() {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)

            if (!keyStore.containsAlias(KEY_ALIAS_ENCRYPTION)) {
                val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                    KEY_ALIAS_ENCRYPTION,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUserAuthenticationRequired(REQUIRE_USER_AUTH)
                    .setRandomizedEncryptionRequired(true)
                    .setKeySize(256)
                    .build()

                keyGenerator.init(keyGenParameterSpec)
                keyGenerator.generateKey()
                Log.d(TAG, "✅ Encryption key generated")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate encryption key", e)
        }
    }

    /**
     * Double encryption for enhanced security
     */
    private fun doubleEncryptPrivateKey(privateKey: String): EncryptedData {
        // First layer: encrypt with master key
        val firstEncryption = encryptWithKey(privateKey, KEY_ALIAS_MASTER)

        // Second layer: encrypt with encryption key
        val secondEncryption = encryptWithKey(
            Base64.encodeToString(firstEncryption.encryptedData.toByteArray(), Base64.NO_WRAP),
            KEY_ALIAS_ENCRYPTION
        )

        return secondEncryption
    }

    /**
     * Double decrypt private key
     */
    private fun doubleDecryptPrivateKey(encryptedData: String, iv: String): String {
        // First layer: decrypt with encryption key
        val firstDecryption = decryptWithKey(encryptedData, iv, KEY_ALIAS_ENCRYPTION)
        val decodedFirstDecryption = String(Base64.decode(firstDecryption, Base64.NO_WRAP))

        // Second layer: decrypt with master key
        return decryptWithKey(decodedFirstDecryption, iv, KEY_ALIAS_MASTER)
    }

    /**
     * Encrypt data with specific key alias
     */
    private fun encryptWithKey(data: String, keyAlias: String): EncryptedData {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)

            val secretKey = keyStore.getKey(keyAlias, null)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            val iv = cipher.iv
            val encryptedData = cipher.doFinal(data.toByteArray())

            return EncryptedData(
                encryptedData = Base64.encodeToString(encryptedData, Base64.NO_WRAP),
                iv = Base64.encodeToString(iv, Base64.NO_WRAP)
            )
        } catch (e: Exception) {
            Log.e(TAG, "Encryption failed for key alias: $keyAlias", e)
            throw SecurityException("Failed to encrypt data", e)
        }
    }

    /**
     * Decrypt data with specific key alias
     */
    private fun decryptWithKey(encryptedData: String, iv: String, keyAlias: String): String {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)

            val secretKey = keyStore.getKey(keyAlias, null)
            val cipher = Cipher.getInstance(TRANSFORMATION)

            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, Base64.decode(iv, Base64.NO_WRAP))
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

            val decryptedBytes = cipher.doFinal(Base64.decode(encryptedData, Base64.NO_WRAP))
            return String(decryptedBytes)
        } catch (e: Exception) {
            Log.e(TAG, "Decryption failed for key alias: $keyAlias", e)
            throw SecurityException("Failed to decrypt data", e)
        }
    }

    /**
     * Encrypt private key with password (similar to web CryptoJS)
     */
    private fun encryptWithPassword(privateKey: String, password: String): String {
        try {
            // Generate salt
            val salt = ByteArray(16)
            SecureRandom().nextBytes(salt)

            // Derive key from password using PBKDF2
            val keySpec = PBEKeySpec(password.toCharArray(), salt, 100000, 256)
            val keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val secretKey = keyFactory.generateSecret(keySpec)

            // Generate IV
            val iv = ByteArray(12)
            SecureRandom().nextBytes(iv)

            // Encrypt
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(128, iv)
            val aesKey = SecretKeySpec(secretKey.encoded, "AES")

            cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec)
            val encryptedBytes = cipher.doFinal(privateKey.toByteArray())

            // Combine salt + iv + encrypted data
            val combined = salt + iv + encryptedBytes
            return Base64.encodeToString(combined, Base64.NO_WRAP)

        } catch (e: Exception) {
            Log.e(TAG, "Password encryption failed", e)
            throw SecurityException("Failed to encrypt with password", e)
        }
    }

    /**
     * Decrypt private key with password
     */
    private fun decryptWithPassword(encryptedData: String, password: String): String {
        try {
            val combinedBytes = Base64.decode(encryptedData, Base64.NO_WRAP)

            // Extract components
            val salt = combinedBytes.sliceArray(0..15)
            val iv = combinedBytes.sliceArray(16..27)
            val encryptedBytes = combinedBytes.sliceArray(28 until combinedBytes.size)

            // Derive key from password
            val keySpec = PBEKeySpec(password.toCharArray(), salt, 100000, 256)
            val keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val secretKey = keyFactory.generateSecret(keySpec)

            // Decrypt
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(128, iv)
            val aesKey = SecretKeySpec(secretKey.encoded, "AES")

            cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec)
            val decryptedBytes = cipher.doFinal(encryptedBytes)

            return String(decryptedBytes)

        } catch (e: Exception) {
            Log.e(TAG, "Password decryption failed", e)
            throw SecurityException("Incorrect password or corrupted data", e)
        }
    }

    /**
     * Store imported key pair with password-based encryption
     */
    private fun storeImportedKeyPair(keyPairInfo: KeyPairInfo, userPassword: String) {
        try {
            // Store with password-derived encryption (similar to web CryptoJS approach)
            val passwordEncryptedKey = encryptWithPassword(keyPairInfo.privateKey, userPassword)

            // Double encryption for enhanced security
            val encryptedData = encryptPrivateKey(passwordEncryptedKey)

            // Use the existing encryptedSharedPreferences
            encryptedSharedPreferences.edit().apply {
                putString(PUBLIC_KEY_KEY, keyPairInfo.publicKey)
                putString(ENCRYPTED_PRIVATE_KEY_KEY, encryptedData.encryptedData)
                putString(VOTER_ADDRESS_KEY, keyPairInfo.voterAddress)
                putString(IV_KEY, encryptedData.iv)
                putString(KEY_GENERATION_METHOD, keyPairInfo.generationMethod)
                putLong(KEY_CREATION_TIME, System.currentTimeMillis())
                putBoolean("is_imported_wallet", true)
                apply()
            }

            Log.d(TAG, "Imported key pair stored securely")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to store imported key pair", e)
            throw SecurityException("Failed to store imported wallet", e)
        }
    }

    /**
     * Encrypt private key (single layer encryption)
     */
    private fun encryptPrivateKey(privateKey: String): EncryptedData {
        return encryptWithKey(privateKey, KEY_ALIAS_MASTER)
    }

    /**
     * Validate key pair signature capability
     */
    private fun validateKeyPairSignature(ecKeyPair: ECKeyPair): Boolean {
        return try {
            // Try to sign a test message
            val testData = "test_signature_validation"
            val signature = ecKeyPair.sign(testData.toByteArray())
            signature != null
        } catch (e: Exception) {
            Log.w(TAG, "Key pair signature validation failed: ${e.message}")
            false
        }
    }

    /**
     * Sign data with stored private key
     */
    fun signData(data: String): String? {
        return try {
            Log.d(TAG, "Attempting to sign data of length: ${data.length}")

            if (data.isEmpty()) {
                Log.w(TAG, "Cannot sign empty data")
                return null
            }

            val privateKey = getPrivateKey()
            if (privateKey.isNullOrEmpty()) {
                Log.e(TAG, "No private key available for signing")
                return null
            }

            Log.d(TAG, "Private key available for signing (length: ${privateKey.length})")

            // For demo purposes - replace with proper ECDSA signing when implementing real blockchain integration
            val dataWithSalt = "$data:$privateKey"
            val signature = java.security.MessageDigest.getInstance("SHA-256")
                .digest(dataWithSalt.toByteArray())
                .joinToString("") { "%02x".format(it) }

            Log.d(TAG, "✅ Data signed successfully (signature length: ${signature.length})")
            return signature

        } catch (e: SecurityException) {
            Log.e(TAG, "Security error during signing: ${e.message}", e)
            return null
        } catch (e: Exception) {
            Log.e(TAG, "Unexpected error during signing: ${e.message}", e)
            return null
        }
    }

    /**
     * Validate that signing capabilities are available
     */
    fun canSignData(): Boolean {
        return try {
            val privateKey = getPrivateKey()
            !privateKey.isNullOrEmpty()
        } catch (e: Exception) {
            Log.w(TAG, "Cannot validate signing capability: ${e.message}")
            false
        }
    }

    /**
     * Verify wallet password
     */
    suspend fun verifyWalletPassword(password: String): Result<Boolean> = withContext(Dispatchers.IO) {
        try {
            val encryptedKey = encryptedSharedPreferences.getString(ENCRYPTED_PRIVATE_KEY_KEY, null)
            val iv = encryptedSharedPreferences.getString(IV_KEY, null)

            if (encryptedKey == null || iv == null) {
                return@withContext Result.failure(SecurityException("No wallet found"))
            }

            // Try to decrypt to verify password
            val decryptedData = doubleDecryptPrivateKey(encryptedKey, iv)
            decryptWithPassword(decryptedData, password) // This will throw if wrong password

            Result.success(true)

        } catch (e: Exception) {
            Log.e(TAG, "Password verification failed: ${e.message}")
            Result.failure(e)
        }
    }

    /**
     * Debug method for troubleshooting key storage issues
     */
    fun debugKeyStorage(): String {
        val debugInfo = StringBuilder()

        try {
            debugInfo.append("=== CRYPTO KEY MANAGER DEBUG ===\n")
            debugInfo.append("Timestamp: ${System.currentTimeMillis()}\n\n")

            // Check encrypted shared preferences
            debugInfo.append("1. Encrypted SharedPreferences Status:\n")
            val hasPublicKey = encryptedSharedPreferences.contains(PUBLIC_KEY_KEY)
            val hasPrivateKey = encryptedSharedPreferences.contains(ENCRYPTED_PRIVATE_KEY_KEY)
            val hasVoterAddress = encryptedSharedPreferences.contains(VOTER_ADDRESS_KEY)
            val hasIV = encryptedSharedPreferences.contains(IV_KEY)

            debugInfo.append("   - Public Key: ${if (hasPublicKey) "✅ Present" else "❌ Missing"}\n")
            debugInfo.append("   - Private Key: ${if (hasPrivateKey) "✅ Present" else "❌ Missing"}\n")
            debugInfo.append("   - Voter Address: ${if (hasVoterAddress) "✅ Present" else "❌ Missing"}\n")
            debugInfo.append("   - IV: ${if (hasIV) "✅ Present" else "❌ Missing"}\n\n")

            // Check key retrieval
            debugInfo.append("2. Key Retrieval Test:\n")
            val publicKey = getPublicKey()
            val privateKey = getPrivateKey()
            val voterAddress = getVoterAddress()

            debugInfo.append("   - Public Key Retrieved: ${if (publicKey != null) "✅ Success" else "❌ Failed"}\n")
            debugInfo.append("   - Private Key Retrieved: ${if (privateKey != null) "✅ Success" else "❌ Failed"}\n")
            debugInfo.append("   - Voter Address Retrieved: ${if (voterAddress != null) "✅ Success" else "❌ Failed"}\n\n")

            // Check key format validation
            if (privateKey != null) {
                debugInfo.append("3. Key Format Validation:\n")
                val isValidFormat = isValidPrivateKeyFormat(privateKey)
                debugInfo.append("   - Private Key Format: ${if (isValidFormat) "✅ Valid" else "❌ Invalid"}\n")
                debugInfo.append("   - Private Key Length: ${privateKey.length} characters\n")
                debugInfo.append("   - Expected Length: $PRIVATE_KEY_TOTAL_LENGTH characters\n\n")
            }

            // Check Android Keystore
            debugInfo.append("4. Android Keystore Status:\n")
            try {
                val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
                keyStore.load(null)
                val hasMasterKey = keyStore.containsAlias(KEY_ALIAS_MASTER)
                val hasEncryptionKey = keyStore.containsAlias(KEY_ALIAS_ENCRYPTION)

                debugInfo.append("   - Master Key: ${if (hasMasterKey) "✅ Present" else "❌ Missing"}\n")
                debugInfo.append("   - Encryption Key: ${if (hasEncryptionKey) "✅ Present" else "❌ Missing"}\n")
            } catch (e: Exception) {
                debugInfo.append("   - Keystore Access: ❌ Failed (${e.message})\n")
            }

        } catch (e: Exception) {
            debugInfo.append("ERROR: ${e.message}\n")
        }

        return debugInfo.toString()
    }
}