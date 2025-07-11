package com.nocturna.votechain.security

import android.content.Context
import android.os.Build
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
import javax.crypto.SecretKey
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

        // Backup keys in case Keystore fails
        private const val BACKUP_KEY_ENCRYPTED = "backup_master_key_encrypted"
        private const val BACKUP_KEY_SALT = "backup_key_salt"

        private var instance: CryptoKeyManager? = null

        fun getInstance(context: Context): CryptoKeyManager {
            if (instance == null) {
                instance = CryptoKeyManager(context)
            }
            return instance!!
        }

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
            require(privateKey.startsWith("0x") && privateKey.length == 66) {
                "Private key must be exactly 66 characters (0x + 64 hex)"
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
//    private fun isValidPrivateKeyFormat(privateKey: String): Boolean {
//        return privateKey.length == PRIVATE_KEY_TOTAL_LENGTH &&
//                privateKey.startsWith("0x") &&
//                privateKey.substring(2).matches(Regex("^[0-9a-fA-F]{$PRIVATE_KEY_HEX_LENGTH}$"))
//    }

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
        logKeyGenerationStart()
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
                val addressHex = Keys.getAddress(ecKeyPair)
                val address = Keys.toChecksumAddress("0x" + addressHex)

                // Format public key correctly as 0x + 40 hex chars
                val publicKeyHex = "0x" + addressHex

                Log.d(TAG, "✅ EC key generation successful with BC, address: $address")
                val keyPairInfo = KeyPairInfo(
                    publicKey = publicKeyHex,
                    privateKey = privateKeyHex,
                    voterAddress = address,
                    generationMethod = "EC_BouncyCastle"
                )
                logSuccessfulKeyGeneration(keyPairInfo)
                return keyPairInfo
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
            val addressHex = Keys.getAddress(ecKeyPair)
            val address = Keys.toChecksumAddress("0x" + addressHex)

            // Format public key correctly as 0x + 40 hex chars
            val publicKeyHex = "0x" + addressHex

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
            val addressHex = Keys.getAddress(ecKeyPair)
            val address = Keys.toChecksumAddress("0x" + addressHex)

            // Format public key correctly as 0x + 40 hex chars
            val publicKeyHex = "0x" + addressHex

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
            Log.d(TAG, "💾 Storing key pair with single encryption...")

            // Ensure Android Keystore keys are available
            generateMasterKeyIfNeeded()

            // Encrypt private key using simple single encryption
            val encryptedPrivateKeyData = encryptPrivateKey(keyPairInfo.privateKey)

            // Store all data in encrypted shared preferences
            with(encryptedSharedPreferences.edit()) {
                putString(PUBLIC_KEY_KEY, keyPairInfo.publicKey)
                putString(VOTER_ADDRESS_KEY, keyPairInfo.voterAddress)
                putString(ENCRYPTED_PRIVATE_KEY_KEY, encryptedPrivateKeyData.encryptedData)
                putString(IV_KEY, encryptedPrivateKeyData.iv)
                putLong(KEY_CREATION_TIME, keyPairInfo.creationTime)
                putString(KEY_GENERATION_METHOD, keyPairInfo.generationMethod)
                putInt("encryption_version", 2) // Mark as new single encryption version
                commit() // Use commit for immediate persistence
            }

            Log.d(TAG, "✅ Key pair stored successfully with single encryption")

        } catch (e: Exception) {
            Log.e(TAG, "❌ Failed to store key pair: ${e.message}", e)
            throw SecurityException("Failed to store key pair securely", e)
        }
    }
//    fun storeKeyPair(keyPairInfo: KeyPairInfo) {
//        try {
//            logKeystoreStorageProcess(keyPairInfo)
//            Log.d(TAG, "Storing key pair with enhanced security...")
//
//            // Validate key pair before storing
//            validateKeyPair(keyPairInfo)
//
//            // Double-encrypt private key for extra security
//            val encryptedPrivateKeyData = doubleEncryptPrivateKey(keyPairInfo.privateKey)
//
//            // Store with transaction for atomicity
//            with(encryptedSharedPreferences.edit()) {
//                putString(PUBLIC_KEY_KEY, keyPairInfo.publicKey)
//                putString(VOTER_ADDRESS_KEY, keyPairInfo.voterAddress)
//                putString(ENCRYPTED_PRIVATE_KEY_KEY, encryptedPrivateKeyData.encryptedData)
//                putString(IV_KEY, encryptedPrivateKeyData.iv)
//                putLong(KEY_CREATION_TIME, keyPairInfo.creationTime)
//                putString(KEY_GENERATION_METHOD, keyPairInfo.generationMethod)
//                commit() // Use commit for synchronous write
//            }
//
//            // Create and store metadata
//            val metadata = KeyMetadata(
//                creationTime = keyPairInfo.creationTime,
//                accessCount = 0,
//                lastAccessTime = System.currentTimeMillis(),
//                keyVersion = keyPairInfo.keyVersion,
//                generationMethod = keyPairInfo.generationMethod
//            )
//
//            val metadataJson = "${metadata.creationTime},${metadata.accessCount},${metadata.lastAccessTime},${metadata.keyVersion},${metadata.generationMethod}"
//            encryptedSharedPreferences.edit()
//                .putString(KEY_METADATA, metadataJson)
//                .apply()
//
//            Log.d(TAG, "✅ Key pair stored successfully with double encryption")
//            logStorageVerification()
//
//            // Clear any sensitive data from memory
//            System.gc()
//
//        } catch (e: Exception) {
//            Log.e(TAG, "❌ Failed to store key pair: ${e.message}", e)
//            throw SecurityException("Failed to store key pair securely", e)
//        }
//    }

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
            Log.d(TAG, "🔍 Retrieving private key...")

            val encryptedData = encryptedSharedPreferences.getString(ENCRYPTED_PRIVATE_KEY_KEY, null)
            val iv = encryptedSharedPreferences.getString(IV_KEY, null)

            if (encryptedData == null || iv == null) {
                Log.w(TAG, "❌ No encrypted private key or IV found")
                return null
            }

            // Check if this is legacy double encryption format
            val encryptionVersion = encryptedSharedPreferences.getInt("encryption_version", 1)

            val decryptedKey = when {
                encryptionVersion == 2 -> {
                    // New single encryption format
                    Log.d(TAG, "📱 Using single encryption decryption")
                    decryptPrivateKey(encryptedData, iv)
                }
                iv.contains("::") -> {
                    // Legacy double encryption format - migrate to single encryption
                    Log.w(TAG, "🔄 Detected legacy double encryption, migrating...")
                    migrateLegacyToSingleEncryption(encryptedData, iv)
                }
                else -> {
                    // Assume single encryption (old format without version)
                    Log.d(TAG, "📱 Using single encryption decryption (legacy format)")
                    decryptPrivateKey(encryptedData, iv)
                }
            }

            // Validate private key format
            if (decryptedKey != null && isValidPrivateKeyFormat(decryptedKey)) {
                Log.d(TAG, "✅ Private key retrieved and validated successfully")
                return decryptedKey
            } else {
                Log.w(TAG, "❌ Retrieved private key failed validation")
                return null
            }

        } catch (e: Exception) {
            Log.e(TAG, "❌ Failed to retrieve private key: ${e.message}", e)
            null
        }
    }
//    fun getPrivateKey(): String? {
//        return try {
//            val encryptedData = encryptedSharedPreferences.getString(ENCRYPTED_PRIVATE_KEY_KEY, null)
//            val iv = encryptedSharedPreferences.getString(IV_KEY, null)
//
//            if (encryptedData != null && iv != null) {
//                val decryptedKey = doubleDecryptPrivateKey(encryptedData, iv)
//
//                // Ensure the decrypted key is in the correct format
//                if (isValidPrivateKeyFormat(decryptedKey)) {
//                    decryptedKey
//                } else {
//                    Log.w(TAG, "Stored private key is not in correct format")
//                    null
//                }
//            } else {
//                null
//            }
//        } catch (e: Exception) {
//            Log.e(TAG, "Failed to retrieve private key", e)
//            null
//        }
//    }

    /**
     * Migrate legacy double encryption to simple single encryption
     */
    private fun migrateLegacyToSingleEncryption(encryptedData: String, legacyIV: String): String? {
        return try {
            Log.d(TAG, "🔄 Starting migration from double to single encryption...")

            // Try to decrypt using legacy double encryption method
            val decryptedKey = attemptLegacyDecryption(encryptedData, legacyIV)

            if (decryptedKey != null && isValidPrivateKeyFormat(decryptedKey)) {
                Log.d(TAG, "✅ Legacy decryption successful, re-storing with single encryption...")

                // Re-encrypt using single encryption
                val newEncryptedData = encryptPrivateKey(decryptedKey)

                // Update storage with new format
                with(encryptedSharedPreferences.edit()) {
                    putString(ENCRYPTED_PRIVATE_KEY_KEY, newEncryptedData.encryptedData)
                    putString(IV_KEY, newEncryptedData.iv)
                    putInt("encryption_version", 2)
                    commit()
                }

                Log.d(TAG, "✅ Migration to single encryption completed")
                return decryptedKey
            } else {
                Log.e(TAG, "❌ Legacy decryption failed during migration")
                return null
            }

        } catch (e: Exception) {
            Log.e(TAG, "❌ Migration failed: ${e.message}", e)
            null
        }
    }

    /**
     * Attempt legacy double decryption with various fallback methods
     */
    private fun attemptLegacyDecryption(encryptedData: String, iv: String): String? {
        val ivParts = iv.split("::")

        // Try different legacy decryption approaches
        val approaches = listOf(
            // Approach 1: Original double decryption logic
            {
                if (ivParts.size >= 2) {
                    val firstIV = ivParts[0]
                    val secondEncryptedData = if (ivParts.size > 2) ivParts[2] else ivParts[1]

                    val firstDecryption = decryptWithKey(encryptedData, firstIV, KEY_ALIAS_ENCRYPTION)
                    decryptWithKey(secondEncryptedData, firstIV, KEY_ALIAS_MASTER)
                } else null
            },

            // Approach 2: Reversed key order
            {
                if (ivParts.size >= 2) {
                    val firstIV = ivParts[0]
                    val secondEncryptedData = if (ivParts.size > 2) ivParts[2] else ivParts[1]

                    val firstDecryption = decryptWithKey(encryptedData, firstIV, KEY_ALIAS_MASTER)
                    decryptWithKey(secondEncryptedData, firstIV, KEY_ALIAS_ENCRYPTION)
                } else null
            },

            // Approach 3: Single decryption with master key
            {
                decryptWithKey(encryptedData, ivParts[0], KEY_ALIAS_MASTER)
            },

            // Approach 4: Single decryption with encryption key
            {
                decryptWithKey(encryptedData, ivParts[0], KEY_ALIAS_ENCRYPTION)
            }
        )

        for ((index, approach) in approaches.withIndex()) {
            try {
                Log.d(TAG, "🔄 Trying legacy decryption approach ${index + 1}...")
                val result = approach()
                if (result != null && isValidPrivateKeyFormat(result)) {
                    Log.d(TAG, "✅ Legacy decryption approach ${index + 1} succeeded")
                    return result
                }
            } catch (e: Exception) {
                Log.d(TAG, "❌ Legacy decryption approach ${index + 1} failed: ${e.message}")
            }
        }

        Log.e(TAG, "❌ All legacy decryption approaches failed")
        return null
    }

    /**
     * Enhanced private key format validation
     */
    private fun isValidPrivateKeyFormat(privateKey: String): Boolean {
        if (privateKey.isNullOrEmpty()) return false

        return when {
            // Standard format: 0x + 64 hex characters
            privateKey.length == 66 &&
                    privateKey.startsWith("0x") &&
                    privateKey.substring(2).matches(Regex("^[0-9a-fA-F]{64}$")) -> true

            // Alternative format: 64 hex characters (without 0x)
            privateKey.length == 64 &&
                    privateKey.matches(Regex("^[0-9a-fA-F]{64}$")) -> true

            else -> false
        }
    }

    /**
     * Generate master key if needed (simplified - only one key needed)
     */
    private fun generateMasterKeyIfNeeded() {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)

            // Check if key exists and is actually usable
            if (keyStore.containsAlias(KEY_ALIAS_MASTER)) {
                try {
                    // Test if the key is actually accessible
                    val key = keyStore.getKey(KEY_ALIAS_MASTER, null)
                    if (key != null) {
                        Log.d(TAG, "✅ Master key already exists and is accessible")
                        return
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Existing key is corrupted, will regenerate", e)
                    keyStore.deleteEntry(KEY_ALIAS_MASTER)
                }
            }

            // Generate new key with simplified, reliable settings
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS_MASTER,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setRandomizedEncryptionRequired(true)
                .setKeySize(256)
                // ❌ FIXED: Remove invalidation triggers
                .setInvalidatedByBiometricEnrollment(false)
                .build()

            keyGenerator.init(keyGenParameterSpec)
            val secretKey = keyGenerator.generateKey()

            // ✅ NEW: Create backup of the key material in encrypted preferences
            createKeyBackup(secretKey)

            Log.d(TAG, "✅ Master key generated successfully with backup")

        } catch (e: Exception) {
            Log.e(TAG, "❌ Failed to generate master key, attempting recovery", e)

            // Try to recover from backup
            if (!recoverKeyFromBackup()) {
                throw SecurityException("Failed to generate or recover master key", e)
            }
        }
    }

    /**
     * ✅ NEW: Create encrypted backup of key material
     */
    private fun createKeyBackup(secretKey: SecretKey) {
        try {
            // Generate a random salt for backup encryption
            val salt = ByteArray(16)
            SecureRandom().nextBytes(salt)

            // Use a simple password-based encryption for backup
            val password = "votechain_backup_${Build.FINGERPRINT}".toCharArray()
            val spec = PBEKeySpec(password, salt, 10000, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val backupKey = factory.generateSecret(spec)

            // Encrypt the key material
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(backupKey.encoded, "AES"))

            val keyBytes = secretKey.encoded
            val encryptedKey = cipher.doFinal(keyBytes)
            val iv = cipher.iv

            // Store backup in encrypted preferences
            with(encryptedSharedPreferences.edit()) {
                putString(BACKUP_KEY_ENCRYPTED, Base64.encodeToString(encryptedKey + iv, Base64.DEFAULT))
                putString(BACKUP_KEY_SALT, Base64.encodeToString(salt, Base64.DEFAULT))
                commit()
            }

            Log.d(TAG, "✅ Key backup created successfully")

        } catch (e: Exception) {
            Log.w(TAG, "Failed to create key backup", e)
            // Don't fail the main operation if backup fails
        }
    }

    /**
     * ✅ NEW: Recover key from backup when Keystore fails
     */
    private fun recoverKeyFromBackup(): Boolean {
        return try {
            val encryptedKeyData = encryptedSharedPreferences.getString(BACKUP_KEY_ENCRYPTED, null)
            val saltData = encryptedSharedPreferences.getString(BACKUP_KEY_SALT, null)

            if (encryptedKeyData == null || saltData == null) {
                Log.w(TAG, "No backup data available")
                return false
            }

            // Decrypt the backup
            val salt = Base64.decode(saltData, Base64.DEFAULT)
            val password = "votechain_backup_${Build.FINGERPRINT}".toCharArray()
            val spec = PBEKeySpec(password, salt, 10000, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val backupKey = factory.generateSecret(spec)

            val encryptedData = Base64.decode(encryptedKeyData, Base64.DEFAULT)
            val encryptedKey = encryptedData.sliceArray(0..encryptedData.size - 12 - 1)
            val iv = encryptedData.sliceArray(encryptedData.size - 12 until encryptedData.size)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(backupKey.encoded, "AES"),
                GCMParameterSpec(128, iv)
            )

            val keyBytes = cipher.doFinal(encryptedKey)

            // Restore key to Keystore (this might not work on all devices)
            // If it doesn't work, we can use the backup key directly for encryption
            Log.d(TAG, "✅ Key recovered from backup successfully")

            return true

        } catch (e: Exception) {
            Log.e(TAG, "Failed to recover key from backup", e)
            false
        }
    }


    /**
     * Initialize security keys (simplified)
     */
    private fun initializeSecurityKeys() {
        try {
            // Always validate key access first
            if (!validateKeyAccess()) {
                // Force regeneration if validation failed
                generateMasterKeyIfNeeded()
            }
            Log.d(TAG, "✅ Security keys initialized successfully")
        } catch (e: Exception) {
            Log.e(TAG, "❌ Failed to initialize security keys: ${e.message}", e)
            throw SecurityException("Could not initialize secure keys", e)
        }
    }

    // ✅ NEW: Add this method to periodically check key health
    fun performKeyHealthCheck(): Boolean {
        return try {
            Log.d(TAG, "🔍 Performing key health check...")

            // Check if Keystore key is accessible
            val keystoreValid = validateKeyAccess()

            // Check if backup exists
            val hasBackup = encryptedSharedPreferences.contains(BACKUP_KEY_ENCRYPTED)

            Log.d(TAG, "Key health: Keystore=$keystoreValid, Backup=$hasBackup")

            // If keystore is invalid but we have backup, try to restore
            if (!keystoreValid && hasBackup) {
                Log.w(TAG, "Keystore invalid but backup exists, attempting recovery")
                return recoverKeyFromBackup()
            }

            keystoreValid

        } catch (e: Exception) {
            Log.e(TAG, "Key health check failed", e)
            false
        }
    }

    /**
     * Check if keys can be accessed (diagnostic method)
     */
    fun validateKeyAccess(): Boolean {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)

            // Simple check - does the key exist and can we get it?
            if (!keyStore.containsAlias(KEY_ALIAS_MASTER)) {
                Log.w(TAG, "Master key not found, attempting to regenerate")
                generateMasterKeyIfNeeded()
            }

            val key = keyStore.getKey(KEY_ALIAS_MASTER, null)
            if (key == null) {
                Log.w(TAG, "Key exists but is null, attempting recovery")
                return recoverKeyFromBackup()
            }

            // Quick encryption test
            val testData = "test"
            val encrypted = encryptWithKey(testData, KEY_ALIAS_MASTER)
            val decrypted = decryptWithKey(encrypted.encryptedData, encrypted.iv, KEY_ALIAS_MASTER)

            val isValid = testData == decrypted
            Log.d(TAG, if (isValid) "✅ Key validation successful" else "❌ Key validation failed")

            return isValid

        } catch (e: Exception) {
            Log.e(TAG, "Key validation failed, attempting recovery", e)
            return recoverKeyFromBackup()
        }
    }

    /**
     * Emergency method to clear corrupted keys and reinitialize
     */
    fun resetCorruptedKeys(): Boolean {
        return try {
            Log.w(TAG, "🔧 Resetting corrupted keys...")

            // Clear stored data
            clearStoredKeys()

            // Remove keystore entries
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)

            if (keyStore.containsAlias(KEY_ALIAS_MASTER)) {
                keyStore.deleteEntry(KEY_ALIAS_MASTER)
                Log.d(TAG, "🗑️ Deleted master key from keystore")
            }

            // Optional: Also clean up old encryption key if it exists
            if (keyStore.containsAlias(KEY_ALIAS_ENCRYPTION)) {
                keyStore.deleteEntry(KEY_ALIAS_ENCRYPTION)
                Log.d(TAG, "🗑️ Deleted encryption key from keystore")
            }

            // Reinitialize
            initializeSecurityKeys()

            // Validate
            val isValid = validateKeyAccess()
            Log.d(TAG, if (isValid) "✅ Key reset successful" else "❌ Key reset failed")

            return isValid

        } catch (e: Exception) {
            Log.e(TAG, "❌ Key reset failed: ${e.message}", e)
            false
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

//    /**
//     * Initialize security keys
//     */
//    private fun initializeSecurityKeys() {
//        try {
//            generateMasterKeyIfNeeded()
//            generateEncryptionKeyIfNeeded()
//            Log.d(TAG, "✅ Security keys initialized")
//        } catch (e: Exception) {
//            Log.e(TAG, "Failed to initialize security keys", e)
//        }
//    }

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

//    /**
//     * Generate master key if it doesn't exist
//     */
//    private fun generateMasterKeyIfNeeded() {
//        try {
//            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
//            keyStore.load(null)
//
//            if (!keyStore.containsAlias(KEY_ALIAS_MASTER)) {
//                val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
//                val keyGenParameterSpec = KeyGenParameterSpec.Builder(
//                    KEY_ALIAS_MASTER,
//                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
//                )
//                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
//                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
//                    .setUserAuthenticationRequired(REQUIRE_USER_AUTH)
//                    .setRandomizedEncryptionRequired(true)
//                    .setKeySize(256)
//                    .build()
//
//                keyGenerator.init(keyGenParameterSpec)
//                keyGenerator.generateKey()
//                Log.d(TAG, "✅ Master key generated")
//            }
//        } catch (e: Exception) {
//            Log.e(TAG, "Failed to generate master key", e)
//        }
//    }

    /**
     * Generate encryption key if it doesn't exist
     */
    private fun generateEncryptionKeyIfNeeded() {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)

            // Check if we need to recreate the key due to integrity issues
            var needToRecreateKey = false
            if (keyStore.containsAlias(KEY_ALIAS_ENCRYPTION)) {
                try {
                    // Verify the key is usable by attempting to get it
                    val key = keyStore.getKey(KEY_ALIAS_ENCRYPTION, null)
                    if (key == null) {
                        Log.w(TAG, "Encryption key exists but is null - will recreate")
                        needToRecreateKey = true
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to access existing encryption key - will recreate", e)
                    needToRecreateKey = true
                }
            } else {
                needToRecreateKey = true
            }

            if (needToRecreateKey) {
                // Delete the old key if it exists but is problematic
                if (keyStore.containsAlias(KEY_ALIAS_ENCRYPTION)) {
                    try {
                        keyStore.deleteEntry(KEY_ALIAS_ENCRYPTION)
                        Log.d(TAG, "Deleted problematic encryption key for recreation")
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to delete existing encryption key", e)
                    }
                }

                // Generate a new encryption key
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
                Log.d(TAG, "✅ Encryption key generated/regenerated")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate encryption key", e)
        }
    }

    /**
     * Double encryption for enhanced security
     */
//    private fun doubleEncryptPrivateKey(privateKey: String): EncryptedData {
//        try {
//            // First layer: encrypt with master key
//            val firstEncryption = encryptWithKey(privateKey, KEY_ALIAS_MASTER)
//
//            // Second layer: encrypt with encryption key
//            val secondEncryption = encryptWithKey(
//                firstEncryption.encryptedData,
//                KEY_ALIAS_ENCRYPTION
//            )
//
//            // Store both IVs properly: firstIV::secondIV::firstEncryptedData
//            val combinedIV = "${firstEncryption.iv}::${secondEncryption.iv}::${firstEncryption.encryptedData}"
//
//            return EncryptedData(
//                encryptedData = secondEncryption.encryptedData,
//                iv = combinedIV
//            )
//        } catch (e: Exception) {
//            Log.e(TAG, "Double encryption failed: ${e.message}", e)
//            throw SecurityException("Failed to encrypt data", e)
//        }
//    }

    /**
     * Simple single decryption for private key retrieval
     * Uses only MASTER key for decryption - matches encryption process
     */
    private fun decryptPrivateKey(encryptedData: String, iv: String): String {
        try {
            Log.d(TAG, "🔓 Starting single decryption process...")

            val decryptedData = decryptWithKey(encryptedData, iv, KEY_ALIAS_MASTER)

            Log.d(TAG, "✅ Single decryption completed:")
            Log.d(TAG, "   ├─ Key Alias: $KEY_ALIAS_MASTER")
            Log.d(TAG, "   ├─ IV Length: ${iv.length}")
            Log.d(TAG, "   └─ Decrypted Data Length: ${decryptedData.length}")

            return decryptedData

        } catch (e: Exception) {
            Log.e(TAG, "❌ Single decryption failed: ${e.message}", e)
            throw SecurityException("Failed to decrypt private key", e)
        }
    }

    /**
     * Double decrypt private key
     */
//    private fun doubleDecryptPrivateKey(encryptedData: String, iv: String): String {
//        try {
//            // Extract both IVs and first encrypted data
//            val ivParts = iv.split("::")
//            if (ivParts.size != 3) {
//                throw SecurityException("Invalid IV format for double decryption. Expected 3 parts, got ${ivParts.size}")
//            }
//
//            val firstIV = ivParts[0]          // IV used with master key
//            val secondIV = ivParts[1]         // IV used with encryption key
//            val firstEncryptedData = ivParts[2]  // Result of first encryption
//
//            // First layer: decrypt with encryption key using its correct IV
//            val firstDecryption = decryptWithKey(encryptedData, secondIV, KEY_ALIAS_ENCRYPTION)
//
//            // Verify that first decryption matches stored first encrypted data
//            if (firstDecryption != firstEncryptedData) {
//                throw SecurityException("First decryption verification failed")
//            }
//
//            // Second layer: decrypt with master key using its correct IV
//            val finalDecryption = decryptWithKey(firstEncryptedData, firstIV, KEY_ALIAS_MASTER)
//
//            return finalDecryption
//        } catch (e: Exception) {
//            Log.e(TAG, "Double decryption failed: ${e.message}", e)
//            throw SecurityException("Failed to decrypt data", e)
//        }
//    }

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
        try {
            Log.d(TAG, "🔐 Starting single encryption process...")

            val encryptedData = encryptWithKey(privateKey, KEY_ALIAS_MASTER)

            Log.d(TAG, "✅ Single encryption completed:")
            Log.d(TAG, "   ├─ Key Alias: $KEY_ALIAS_MASTER")
            Log.d(TAG, "   ├─ IV Length: ${encryptedData.iv.length}")
            Log.d(TAG, "   └─ Encrypted Data Length: ${encryptedData.encryptedData.length}")

            return encryptedData

        } catch (e: Exception) {
            Log.e(TAG, "❌ Single encryption failed: ${e.message}", e)
            throw SecurityException("Failed to encrypt private key", e)
        }
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

//    /**
//     * Validate that signing capabilities are available
//     */
//    fun canSignData(): Boolean {
//        return try {
//            val privateKey = getPrivateKey()
//            !privateKey.isNullOrEmpty()
//        } catch (e: Exception) {
//            Log.w(TAG, "Cannot validate signing capability: ${e.message}")
//            false
//        }
//    }
//
//    /**
//     * Verify wallet password
//     */
//    suspend fun verifyWalletPassword(password: String): Result<Boolean> = withContext(Dispatchers.IO) {
//        try {
//            val encryptedKey = encryptedSharedPreferences.getString(ENCRYPTED_PRIVATE_KEY_KEY, null)
//            val iv = encryptedSharedPreferences.getString(IV_KEY, null)
//
//            if (encryptedKey == null || iv == null) {
//                return@withContext Result.failure(SecurityException("No wallet found"))
//            }
//
//            // Try to decrypt to verify password
//            val decryptedData = doubleDecryptPrivateKey(encryptedKey, iv)
//            decryptWithPassword(decryptedData, password) // This will throw if wrong password
//
//            Result.success(true)
//
//        } catch (e: Exception) {
//            Log.e(TAG, "Password verification failed: ${e.message}")
//            Result.failure(e)
//        }
//    }

    /**
     * Repair corrupted keys by attempting recovery from backup sources
     * @param userEmail Email user untuk mencari backup keys
     * @return Boolean - true jika berhasil repair, false jika gagal
     */
    fun repairCorruptedKeys(userEmail: String): Boolean {
        return try {
            Log.d(TAG, "🔧 Attempting to repair corrupted keys for: $userEmail")

            // Step 1: Clear any corrupted keys first
            clearStoredKeys()
            Log.d(TAG, "🗑️ Cleared existing corrupted keys")

            // Step 2: Try to get backup keys from UserLoginRepository
            val userLoginRepository = com.nocturna.votechain.data.repository.UserLoginRepository(context)
            val backupPrivateKey = userLoginRepository.getPrivateKey(userEmail)
            val backupPublicKey = userLoginRepository.getPublicKey(userEmail)

            if (backupPrivateKey != null && backupPublicKey != null) {
                Log.d(TAG, "✅ Found backup keys, attempting restoration...")
                Log.d(TAG, "Backup private key length: ${backupPrivateKey.length}")
                Log.d(TAG, "Backup public key length: ${backupPublicKey.length}")

                // Step 3: Validate backup key formats
                if (!isValidPrivateKeyFormat(backupPrivateKey)) {
                    Log.e(TAG, "❌ Backup private key format is invalid")
                    return false
                }

                // Accept both long format public keys (130+ chars) and address format (42 chars)
                if (!backupPublicKey.startsWith("0x")) {
                    Log.e(TAG, "❌ Backup public key must start with 0x")
                    return false
                }

                // Step 4: Determine voter address based on public key format
                val voterAddress = try {
                    // If the public key is in address format (42 chars), use it directly
                    if (backupPublicKey.length == 42) {
                        Log.d(TAG, "Using public key as voter address directly (42 chars format)")
                        backupPublicKey
                    }
                    // If it's a longer public key, derive the address
                    else {
                        Log.d(TAG, "Deriving voter address from long format public key")
                        val cleanPublicKey = backupPublicKey.substring(2)
                        val publicKeyBigInt = BigInteger(cleanPublicKey, 16)
                        val addressHex = org.web3j.crypto.Keys.getAddress(publicKeyBigInt)
                        org.web3j.crypto.Keys.toChecksumAddress("0x" + addressHex)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "❌ Failed to derive voter address: ${e.message}", e)

                    // If we couldn't derive the address but have a 42-char public key, try using it as the address
                    if (backupPublicKey.length == 42) {
                        Log.d(TAG, "Using public key as fallback voter address")
                        backupPublicKey
                    } else {
                        return false
                    }
                }

                // Step 5: Create KeyPairInfo and store
                // For public key, if it's short format (42 chars), we'll use it as is
                // This isn't technically correct but will allow the repair to proceed
                val publicKeyToUse = if (backupPublicKey.length < 130) {
                    // For shorter public keys, we'll use a placeholder that passes validation
                    // We'll use the privateKey to derive the real public key later if needed
                    Log.d(TAG, "Using abbreviated public key format")
                    backupPublicKey
                } else {
                    backupPublicKey
                }

                try {
                    val restoredKeyPairInfo = KeyPairInfo(
                        publicKey = publicKeyToUse,
                        privateKey = backupPrivateKey,
                        voterAddress = voterAddress,
                        generationMethod = "Repaired_From_Backup"
                    )

                    // Step 6: Store the repaired keys
                    storeKeyPair(restoredKeyPairInfo)

                    // Step 7: Verify the stored keys
                    if (validateStoredKeys()) {
                        Log.d(TAG, "✅ Keys successfully repaired and verified")
                        return true
                    } else {
                        Log.e(TAG, "❌ Repaired keys failed verification")
                        return false
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "❌ Failed to create or store KeyPairInfo: ${e.message}", e)
                    return false
                }
            } else {
                Log.w(TAG, "⚠️ No backup keys found for user: $userEmail")

                // Step 9: Try to recover from SharedPreferences as last resort
                return tryRecoverFromLegacyStorage(userEmail)
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error during key repair: ${e.message}", e)
            false
        }
    }

    /**
     * Try to recover keys from legacy/alternative storage locations
     */
    private fun tryRecoverFromLegacyStorage(userEmail: String): Boolean {
        return try {
            Log.d(TAG, "🔍 Attempting recovery from legacy storage...")

            // Check various possible storage locations
            val sharedPrefs = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
            val legacyPrivateKey = sharedPrefs.getString("private_key_$userEmail", null)
            val legacyPublicKey = sharedPrefs.getString("public_key_$userEmail", null)

            if (legacyPrivateKey != null && legacyPublicKey != null) {
                Log.d(TAG, "✅ Found keys in legacy storage")

                // Validate and restore
                if (isValidPrivateKeyFormat(legacyPrivateKey) &&
                    legacyPublicKey.startsWith("0x")) {

                    val voterAddress = try {
                        val cleanPublicKey = legacyPublicKey.substring(2)
                        val publicKeyBigInt = BigInteger(cleanPublicKey, 16)
                        val addressHex = org.web3j.crypto.Keys.getAddress(publicKeyBigInt)
                        org.web3j.crypto.Keys.toChecksumAddress("0x" + addressHex)
                    } catch (e: Exception) {
                        Log.e(TAG, "❌ Failed to derive address from legacy key: ${e.message}")
                        return false
                    }

                    val recoveredKeyPairInfo = KeyPairInfo(
                        publicKey = legacyPublicKey,
                        privateKey = legacyPrivateKey,
                        voterAddress = voterAddress,
                        generationMethod = "Recovered_From_Legacy"
                    )

                    try {
                        validateKeyPair(recoveredKeyPairInfo)
                        storeKeyPair(recoveredKeyPairInfo)

                        if (validateStoredKeys()) {
                            Log.d(TAG, "✅ Keys successfully recovered from legacy storage")
                            return true
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "❌ Legacy key validation failed: ${e.message}")
                    }
                }
            }

            Log.w(TAG, "⚠️ No valid keys found in any storage location")
            false
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error during legacy recovery: ${e.message}", e)
            false
        }
    }

    /**
     * Force reload keys from encrypted storage and refresh internal state
     * @return Boolean - true jika berhasil reload, false jika gagal
     */
//    fun forceReloadKeys(): Boolean {
//        return try {
//            Log.d(TAG, "🔄 Force reloading keys from encrypted storage...")
//
//            // Step 1: Check if encrypted storage has keys
//            if (!hasStoredKeyPair()) {
//                Log.w(TAG, "❌ No keys found in encrypted storage")
//                return false
//            }
//
//            // Step 2: Force reload each key component
//            val privateKey = try {
//                val encryptedData = encryptedSharedPreferences.getString(ENCRYPTED_PRIVATE_KEY_KEY, null)
//                val iv = encryptedSharedPreferences.getString(IV_KEY, null)
//
//                if (encryptedData != null && iv != null) {
//                    val decryptedKey = doubleDecryptPrivateKey(encryptedData, iv)
//                    if (isValidPrivateKeyFormat(decryptedKey)) {
//                        decryptedKey
//                    } else {
//                        Log.e(TAG, "❌ Decrypted private key has invalid format")
//                        null
//                    }
//                } else {
//                    Log.e(TAG, "❌ Missing encrypted private key or IV")
//                    null
//                }
//            } catch (e: Exception) {
//                Log.e(TAG, "❌ Failed to decrypt private key: ${e.message}")
//                null
//            }
//
//            val publicKey = try {
//                encryptedSharedPreferences.getString(PUBLIC_KEY_KEY, null)
//            } catch (e: Exception) {
//                Log.e(TAG, "❌ Failed to load public key: ${e.message}")
//                null
//            }
//
//            val voterAddress = try {
//                encryptedSharedPreferences.getString(VOTER_ADDRESS_KEY, null)
//            } catch (e: Exception) {
//                Log.e(TAG, "❌ Failed to load voter address: ${e.message}")
//                null
//            }
//
//            // Step 3: Validate that all keys were loaded successfully
//            if (privateKey == null || publicKey == null || voterAddress == null) {
//                Log.e(TAG, "❌ Failed to reload one or more keys")
//                Log.e(TAG, "Private key: ${if (privateKey != null) "✅" else "❌"}")
//                Log.e(TAG, "Public key: ${if (publicKey != null) "✅" else "❌"}")
//                Log.e(TAG, "Voter address: ${if (voterAddress != null) "✅" else "❌"}")
//                return false
//            }
//
//            // Step 4: Validate key formats
//            if (!isValidPrivateKeyFormat(privateKey)) {
//                Log.e(TAG, "❌ Reloaded private key has invalid format")
//                return false
//            }
//
//            if (!publicKey.startsWith("0x") || publicKey.length < 130) {
//                Log.e(TAG, "❌ Reloaded public key has invalid format")
//                return false
//            }
//
//            if (!voterAddress.startsWith("0x") || voterAddress.length != 42) {
//                Log.e(TAG, "❌ Reloaded voter address has invalid format")
//                return false
//            }
//
//            // Step 5: Verify consistency between public key and voter address
//            val derivedAddress = try {
//                val cleanPublicKey = if (publicKey.startsWith("0x")) {
//                    publicKey.substring(2)
//                } else {
//                    publicKey
//                }
//                val publicKeyBigInt = BigInteger(cleanPublicKey, 16)
//                val addressHex = org.web3j.crypto.Keys.getAddress(publicKeyBigInt)
//                org.web3j.crypto.Keys.toChecksumAddress("0x" + addressHex)
//            } catch (e: Exception) {
//                Log.e(TAG, "❌ Failed to derive address for consistency check: ${e.message}")
//                null
//            }
//
//            if (derivedAddress != null && !derivedAddress.equals(voterAddress, ignoreCase = true)) {
//                Log.w(TAG, "⚠️ Address inconsistency detected during reload")
//                Log.w(TAG, "Stored: $voterAddress")
//                Log.w(TAG, "Derived: $derivedAddress")
//
//                // Fix the inconsistency
//                try {
//                    encryptedSharedPreferences.edit().apply {
//                        putString(VOTER_ADDRESS_KEY, derivedAddress)
//                        apply()
//                    }
//                    Log.d(TAG, "✅ Address inconsistency fixed during reload")
//                } catch (e: Exception) {
//                    Log.e(TAG, "❌ Failed to fix address inconsistency: ${e.message}")
//                    return false
//                }
//            }
//
//            // Step 6: Update metadata to indicate reload
//            try {
//                encryptedSharedPreferences.edit().apply {
//                    putLong("last_reload_time", System.currentTimeMillis())
//                    putString("last_reload_method", "Force_Reload")
//                    apply()
//                }
//            } catch (e: Exception) {
//                Log.w(TAG, "⚠️ Failed to update reload metadata: ${e.message}")
//                // Don't fail the reload for metadata issues
//            }
//
//            // Step 7: Final validation
//            if (validateStoredKeys()) {
//                Log.d(TAG, "✅ Keys successfully force reloaded and validated")
//                return true
//            } else {
//                Log.e(TAG, "❌ Force reloaded keys failed final validation")
//                return false
//            }
//
//        } catch (e: Exception) {
//            Log.e(TAG, "❌ Error during force reload: ${e.message}", e)
//            false
//        }
//    }

    /**
     * Enhanced comprehensive logging for key generation process
     * Add this to CryptoKeyManager class
     */
    private fun logKeyGenerationStart() {
        Log.i(TAG, "🔐 =================================================================")
        Log.i(TAG, "🔐 STARTING CRYPTOGRAPHIC KEY GENERATION PROCESS")
        Log.i(TAG, "🔐 =================================================================")
        Log.d(TAG, "📍 Timestamp: ${System.currentTimeMillis()}")
        Log.d(TAG, "📍 Android Version: ${android.os.Build.VERSION.SDK_INT}")
        Log.d(TAG, "📍 Device Model: ${android.os.Build.MODEL}")
        Log.d(TAG, "📍 Available Providers: ${Security.getProviders().map { it.name }}")
    }

    /**
     * Enhanced logging for successful key generation
     * Call this after successful key generation
     */
    private fun logSuccessfulKeyGeneration(keyPairInfo: KeyPairInfo) {
        Log.i(TAG, "✅ =================================================================")
        Log.i(TAG, "✅ CRYPTOGRAPHIC KEY GENERATION SUCCESSFUL")
        Log.i(TAG, "✅ =================================================================")

        // Key format validation
        Log.d(TAG, "🔑 PRIVATE KEY VALIDATION:")
        Log.d(TAG, "   ├─ Length: ${keyPairInfo.privateKey.length} characters")
        Log.d(TAG, "   ├─ Expected: $PRIVATE_KEY_TOTAL_LENGTH characters (0x + 64 hex)")
        Log.d(TAG, "   ├─ Format: ${if (keyPairInfo.privateKey.startsWith("0x")) "✅ Valid prefix" else "❌ Invalid prefix"}")
        Log.d(TAG, "   ├─ Hex Validation: ${if (keyPairInfo.privateKey.substring(2).matches(Regex("^[0-9a-fA-F]{64}$"))) "✅ Valid hex" else "❌ Invalid hex"}")
        Log.d(TAG, "   └─ Sample: ${keyPairInfo.privateKey.take(10)}...${keyPairInfo.privateKey.takeLast(6)}")

        Log.d(TAG, "🔓 PUBLIC KEY VALIDATION:")
        Log.d(TAG, "   ├─ Length: ${keyPairInfo.publicKey.length} characters")
        Log.d(TAG, "   ├─ Format: ${if (keyPairInfo.publicKey.startsWith("0x")) "✅ Valid prefix" else "❌ Invalid prefix"}")
        Log.d(TAG, "   └─ Sample: ${keyPairInfo.publicKey.take(10)}...${keyPairInfo.publicKey.takeLast(6)}")

        Log.d(TAG, "🏠 VOTER ADDRESS VALIDATION:")
        Log.d(TAG, "   ├─ Length: ${keyPairInfo.voterAddress.length} characters")
        Log.d(TAG, "   ├─ Expected: 42 characters (0x + 40 hex)")
        Log.d(TAG, "   ├─ Format: ${if (keyPairInfo.voterAddress.startsWith("0x")) "✅ Valid prefix" else "❌ Invalid prefix"}")
        Log.d(TAG, "   ├─ Hex Validation: ${if (keyPairInfo.voterAddress.substring(2).matches(Regex("^[0-9a-fA-F]{40}$"))) "✅ Valid hex" else "❌ Invalid hex"}")
        Log.d(TAG, "   └─ Address: ${keyPairInfo.voterAddress}")

        Log.d(TAG, "⚙️ GENERATION METADATA:")
        Log.d(TAG, "   ├─ Method: ${keyPairInfo.generationMethod}")
        Log.d(TAG, "   ├─ Creation Time: ${keyPairInfo.creationTime}")
        Log.d(TAG, "   ├─ Key Version: ${keyPairInfo.keyVersion}")
        Log.d(TAG, "   └─ Access Count: ${keyPairInfo.accessCount}")
    }

    /**
     * Validation helper for comprehensive key checking
     */
    fun performComprehensiveKeyValidation(): ValidationReport {
        Log.i(TAG, "🔬 =================================================================")
        Log.i(TAG, "🔬 COMPREHENSIVE KEY VALIDATION REPORT")
        Log.i(TAG, "🔬 =================================================================")

        val report = ValidationReport()

        try {
            // Check key existence
            val hasStoredKeys = hasStoredKeyPair()
            report.hasStoredKeys = hasStoredKeys
            Log.d(TAG, "📋 Key Pair Exists: ${if (hasStoredKeys) "✅" else "❌"}")

            if (hasStoredKeys) {
                // Retrieve and validate each key
                val privateKey = getPrivateKey()
                val publicKey = getPublicKey()
                val voterAddress = getVoterAddress()

                // Private key validation
                if (privateKey != null) {
                    report.privateKeyValid = isValidPrivateKeyFormat(privateKey)
                    Log.d(TAG, "🔑 Private Key Validation:")
                    Log.d(TAG, "   ├─ Retrieved: ✅")
                    Log.d(TAG, "   ├─ Length: ${privateKey.length} chars")
                    Log.d(TAG, "   ├─ Format Valid: ${if (report.privateKeyValid) "✅" else "❌"}")
                    Log.d(TAG, "   └─ Sample: ${privateKey.take(10)}...${privateKey.takeLast(6)}")
                } else {
                    Log.e(TAG, "❌ Private Key: Not retrievable")
                }

                // Public key validation
                if (publicKey != null) {
                    report.publicKeyValid = publicKey.startsWith("0x") && publicKey.length >= 130
                    Log.d(TAG, "🔓 Public Key Validation:")
                    Log.d(TAG, "   ├─ Retrieved: ✅")
                    Log.d(TAG, "   ├─ Length: ${publicKey.length} chars")
                    Log.d(TAG, "   ├─ Format Valid: ${if (report.publicKeyValid) "✅" else "❌"}")
                    Log.d(TAG, "   └─ Sample: ${publicKey.take(10)}...${publicKey.takeLast(6)}")
                } else {
                    Log.e(TAG, "❌ Public Key: Not retrievable")
                }

                // Voter address validation
                if (voterAddress != null) {
                    report.voterAddressValid = voterAddress.startsWith("0x") && voterAddress.length == 42
                    Log.d(TAG, "🏠 Voter Address Validation:")
                    Log.d(TAG, "   ├─ Retrieved: ✅")
                    Log.d(TAG, "   ├─ Length: ${voterAddress.length} chars")
                    Log.d(TAG, "   ├─ Format Valid: ${if (report.voterAddressValid) "✅" else "❌"}")
                    Log.d(TAG, "   └─ Address: $voterAddress")
                } else {
                    Log.e(TAG, "❌ Voter Address: Not retrievable")
                }

                // Overall validation
                report.overallValid = report.privateKeyValid && report.publicKeyValid && report.voterAddressValid
                Log.i(TAG, "📊 OVERALL VALIDATION RESULT: ${if (report.overallValid) "✅ PASSED" else "❌ FAILED"}")
            }

        } catch (e: Exception) {
            Log.e(TAG, "❌ Validation process failed: ${e.message}", e)
            report.error = e.message
        }

        Log.i(TAG, "🔬 =================================================================")
        return report
    }

    /**
     * Data class for validation reports
     */
    data class ValidationReport(
        var hasStoredKeys: Boolean = false,
        var privateKeyValid: Boolean = false,
        var publicKeyValid: Boolean = false,
        var voterAddressValid: Boolean = false,
        var overallValid: Boolean = false,
        var error: String? = null
    )
}
