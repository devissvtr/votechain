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
import javax.crypto.spec.GCMParameterSpec
import kotlin.Result

/**
 * Enhanced CryptoKeyManager with standardized private key format (0x + 64 hex chars)
 * Optimized for VoteChain blockchain integration
 */
class CryptoKeyManager(private val context: Context) {

    companion object {
        private const val TAG = "CryptoKeyManager"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val PREFS_NAME = "VoteChainCryptoPrefs"

        // Key aliases for different purposes
        private const val KEY_ALIAS_MASTER = "VoteChainMasterKey"
        private const val KEY_ALIAS_ENCRYPTION = "VoteChainEncryptionKey"

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

        // Private key format constants - CRITICAL FOR BLOCKCHAIN COMPATIBILITY
        private const val PRIVATE_KEY_HEX_LENGTH = 64 // 32 bytes = 64 hex characters
        private const val PRIVATE_KEY_TOTAL_LENGTH = 66 // "0x" + 64 hex = 66 total

        private var isBouncyCastleInitialized = false

        /**
         * Initialize BouncyCastle provider for secp256k1 support
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
            // Validate private key format at creation - CRITICAL FOR BLOCKCHAIN
            require(privateKey.startsWith("0x") && privateKey.length == PRIVATE_KEY_TOTAL_LENGTH) {
                "Private key must be exactly $PRIVATE_KEY_TOTAL_LENGTH characters (0x + 64 hex)"
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
        // Initialize security infrastructure
        initializeSecurityKeys()
        Log.d(TAG, "CryptoKeyManager initialized with blockchain compatibility")
    }

    /**
     * Generate a key pair using secp256k1 curve for Ethereum compatibility
     */
    fun generateKeyPair(): KeyPairInfo {
        Log.d(TAG, "🔑 Starting key generation for blockchain compatibility")

        return generateSecp256k1KeyPair()
            ?: throw SecurityException("Failed to generate key pair with all methods")
    }

    /**
     * Generate secp256k1 key pair with multiple fallback methods
     */
    private fun generateSecp256k1KeyPair(): KeyPairInfo? {
        Log.d(TAG, "Attempting secp256k1 key generation with multiple providers")

        // Method 1: Try with BouncyCastle (most reliable for secp256k1)
        try {
            if (initializeBouncyCastle()) {
                val keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC")
                val ecSpec = ECGenParameterSpec("secp256k1")
                keyPairGenerator.initialize(ecSpec)
                val keyPair = keyPairGenerator.generateKeyPair()

                // Extract private key and create ECKeyPair
                val privateKeyBigInt = (keyPair.private as ECPrivateKey).s
                val ecKeyPair = ECKeyPair.create(privateKeyBigInt)

                // Generate properly formatted keys
                val privateKeyHex = formatPrivateKeyToStandard(ecKeyPair.privateKey)
                val publicKeyHex = Numeric.toHexStringWithPrefix(ecKeyPair.publicKey)
                val addressHex = Keys.getAddress(ecKeyPair)
                val address = Keys.toChecksumAddress("0x" + addressHex)

                Log.d(TAG, "✅ secp256k1 key generation successful with BouncyCastle")
                Log.d(TAG, "Private key length: ${privateKeyHex.length} characters")
                Log.d(TAG, "Address: $address")

                val keyPairInfo = KeyPairInfo(
                    publicKey = publicKeyHex,
                    privateKey = privateKeyHex,
                    voterAddress = address,
                    generationMethod = "secp256k1_BouncyCastle"
                )

                validateGeneratedKeyPair(keyPairInfo)
                return keyPairInfo
            }
        } catch (e: Exception) {
            Log.w(TAG, "BouncyCastle secp256k1 generation failed: ${e.message}")
        }

        // Method 2: Try with AndroidOpenSSL provider
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance("EC", "AndroidOpenSSL")
            val ecSpec = ECGenParameterSpec("secp256k1")
            keyPairGenerator.initialize(ecSpec)
            val keyPair = keyPairGenerator.generateKeyPair()

            val privateKeyBigInt = (keyPair.private as ECPrivateKey).s
            val ecKeyPair = ECKeyPair.create(privateKeyBigInt)

            val privateKeyHex = formatPrivateKeyToStandard(ecKeyPair.privateKey)
            val publicKeyHex = Numeric.toHexStringWithPrefix(ecKeyPair.publicKey)
            val addressHex = Keys.getAddress(ecKeyPair)
            val address = Keys.toChecksumAddress("0x" + addressHex)

            Log.d(TAG, "✅ secp256k1 key generation successful with AndroidOpenSSL")

            val keyPairInfo = KeyPairInfo(
                publicKey = publicKeyHex,
                privateKey = privateKeyHex,
                voterAddress = address,
                generationMethod = "secp256k1_AndroidOpenSSL"
            )

            validateGeneratedKeyPair(keyPairInfo)
            return keyPairInfo
        } catch (e: Exception) {
            Log.w(TAG, "AndroidOpenSSL secp256k1 generation failed: ${e.message}")
        }

        // Method 3: Final fallback using SecureRandom with Web3j
        try {
            Log.d(TAG, "Using SecureRandom fallback for key generation")

            // Generate exactly 32 bytes for private key
            val secureRandom = SecureRandom()
            val privateKeyBytes = ByteArray(32)
            secureRandom.nextBytes(privateKeyBytes)

            // Create ECKeyPair directly from random bytes
            val ecKeyPair = ECKeyPair.create(privateKeyBytes)

            val privateKeyHex = formatPrivateKeyToStandard(ecKeyPair.privateKey)
            val publicKeyHex = Numeric.toHexStringWithPrefix(ecKeyPair.publicKey)
            val addressHex = Keys.getAddress(ecKeyPair)
            val address = Keys.toChecksumAddress("0x" + addressHex)

            Log.d(TAG, "✅ secp256k1 key generation with SecureRandom successful")

            val keyPairInfo = KeyPairInfo(
                publicKey = publicKeyHex,
                privateKey = privateKeyHex,
                voterAddress = address,
                generationMethod = "secp256k1_SecureRandom"
            )

            validateGeneratedKeyPair(keyPairInfo)
            return keyPairInfo
        } catch (e: Exception) {
            Log.e(TAG, "All secp256k1 key generation methods failed: ${e.message}")
        }

        return null
    }

    /**
     * Format private key to standard Ethereum format: "0x" + exactly 64 hex characters
     */
    private fun formatPrivateKeyToStandard(privateKeyBigInt: BigInteger): String {
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
     * Validate generated key pair for blockchain compatibility
     */
    private fun validateGeneratedKeyPair(keyPairInfo: KeyPairInfo) {
        // Validate private key format
        require(keyPairInfo.privateKey.length == PRIVATE_KEY_TOTAL_LENGTH) {
            "Private key must be exactly $PRIVATE_KEY_TOTAL_LENGTH characters"
        }

        require(keyPairInfo.privateKey.startsWith("0x")) {
            "Private key must start with 0x"
        }

        val privateKeyHex = keyPairInfo.privateKey.substring(2)
        require(privateKeyHex.matches(Regex("^[0-9a-fA-F]{$PRIVATE_KEY_HEX_LENGTH}$"))) {
            "Private key must contain exactly $PRIVATE_KEY_HEX_LENGTH hex characters"
        }

        // Validate secp256k1 range
        val privateKeyBigInt = BigInteger(privateKeyHex, 16)
        val secp256k1Order = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
        require(privateKeyBigInt.compareTo(BigInteger.ZERO) > 0 && privateKeyBigInt.compareTo(secp256k1Order) < 0) {
            "Private key is outside valid range for secp256k1"
        }

        // Validate address format
        require(keyPairInfo.voterAddress.length == 42) {
            "Voter address must be exactly 42 characters"
        }

        require(keyPairInfo.voterAddress.startsWith("0x")) {
            "Voter address must start with 0x"
        }

        Log.d(TAG, "✅ Key pair validation successful")
    }

    /**
     * Store key pair with enhanced validation and security
     */
    fun storeKeyPair(keyPairInfo: KeyPairInfo) {
        try {
            Log.d(TAG, "💾 Storing key pair with enhanced security...")

            // Validate key pair before storing
            validateGeneratedKeyPair(keyPairInfo)

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

            Log.d(TAG, "✅ Key pair stored successfully with double encryption")
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
            Log.d(TAG, "📥 Starting wallet import from private key")

            // Clean and validate private key format
            val normalizedPrivateKey = normalizePrivateKeyFormat(privateKey.trim())

            // Validate the normalized private key
            if (!isValidPrivateKeyFormat(normalizedPrivateKey)) {
                return@withContext Result.failure(
                    SecurityException("Invalid private key format. Must be exactly 64 hexadecimal characters (with or without 0x prefix)")
                )
            }

            // Create ECKeyPair from the private key
            val cleanHex = normalizedPrivateKey.substring(2) // Remove 0x
            val privateKeyBigInt = BigInteger(cleanHex, 16)
            val ecKeyPair = ECKeyPair.create(privateKeyBigInt)

            // Generate wallet info
            val publicKeyHex = Numeric.toHexStringWithPrefix(ecKeyPair.publicKey)
            val addressHex = Keys.getAddress(ecKeyPair)
            val address = Keys.toChecksumAddress("0x" + addressHex)

            // Create key pair info
            val keyPairInfo = KeyPairInfo(
                publicKey = publicKeyHex,
                privateKey = normalizedPrivateKey,
                voterAddress = address,
                generationMethod = "Imported_Private_Key"
            )

            // Store the imported key pair
            storeKeyPair(keyPairInfo)

            Log.d(TAG, "✅ Wallet import successful, address: $address")
            Result.success(address)

        } catch (e: Exception) {
            Log.e(TAG, "❌ Wallet import failed: ${e.message}", e)
            Result.failure(e)
        }
    }

    /**
     * Normalize private key format to standard
     */
    private fun normalizePrivateKeyFormat(privateKey: String): String {
        val cleanKey = if (privateKey.startsWith("0x", ignoreCase = true)) {
            privateKey.substring(2)
        } else {
            privateKey
        }

        // Ensure exactly 64 characters, pad with leading zeros if necessary
        val paddedKey = cleanKey.lowercase().padStart(PRIVATE_KEY_HEX_LENGTH, '0')

        return "0x$paddedKey"
    }

    /**
     * Enhanced private key format validation
     */
    fun isValidPrivateKeyFormat(privateKey: String): Boolean {
        if (privateKey.isEmpty()) return false

        val cleanKey = if (privateKey.startsWith("0x", ignoreCase = true)) {
            privateKey.substring(2)
        } else {
            privateKey
        }

        // Must be exactly 64 hex characters
        if (cleanKey.length != PRIVATE_KEY_HEX_LENGTH) return false

        // Must contain only valid hex characters
        if (!cleanKey.matches(Regex("^[0-9a-fA-F]{$PRIVATE_KEY_HEX_LENGTH}$"))) return false

        // Must be in valid secp256k1 range
        return try {
            val privateKeyBigInt = BigInteger(cleanKey, 16)
            val secp256k1Order = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
            privateKeyBigInt.compareTo(BigInteger.ZERO) > 0 && privateKeyBigInt.compareTo(secp256k1Order) < 0
        } catch (e: Exception) {
            false
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
     * Validate stored keys format
     */
    fun validateStoredKeys(): Boolean {
        return try {
            val privateKey = getPrivateKey()
            val publicKey = getPublicKey()
            val voterAddress = getVoterAddress()

            if (privateKey == null || publicKey == null || voterAddress == null) {
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
                    Log.w(TAG, "❌ Stored private key is not in correct format")
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

    /**
     * Sign data with stored private key (for blockchain transactions)
     */
    fun signData(data: String): String? {
        try {
            Log.d(TAG, "🔐 Signing data with stored private key")

            if (data.isEmpty()) {
                Log.w(TAG, "Cannot sign empty data")
                return null
            }

            val privateKey = getPrivateKey()
            if (privateKey.isNullOrEmpty()) {
                Log.e(TAG, "No private key available for signing")
                return null
            }

            // For blockchain compatibility, use proper ECDSA signing
            val cleanPrivateKey = privateKey.substring(2) // Remove 0x prefix
            val privateKeyBigInt = BigInteger(cleanPrivateKey, 16)
            val ecKeyPair = ECKeyPair.create(privateKeyBigInt)

            // Sign the data hash
            val dataBytes = data.toByteArray()
            val signature = ecKeyPair.sign(dataBytes)

            // Return signature in hex format
            val signatureHex = Numeric.toHexString(signature.encodedSignature)

            Log.d(TAG, "✅ Data signed successfully")
            return signatureHex

        } catch (e: Exception) {
            Log.e(TAG, "❌ Error signing data: ${e.message}", e)
            return null
        }
    }

    /**
     * Validate that signing capabilities are available
     */
    fun canSignData(): Boolean {
        return try {
            val privateKey = getPrivateKey()
            !privateKey.isNullOrEmpty() && isValidPrivateKeyFormat(privateKey)
        } catch (e: Exception) {
            Log.w(TAG, "Cannot validate signing capability: ${e.message}")
            false
        }
    }

    // Private helper methods for encryption/decryption
    private fun initializeSecurityKeys() {
        try {
            generateMasterKeyIfNeeded()
            generateEncryptionKeyIfNeeded()
            Log.d(TAG, "✅ Security keys initialized")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize security keys", e)
        }
    }

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
                    .setUserAuthenticationRequired(false)
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
                    .setUserAuthenticationRequired(false)
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

    private fun doubleEncryptPrivateKey(privateKey: String): EncryptedData {
        // First layer encryption
        val firstEncryption = encryptWithKey(privateKey, KEY_ALIAS_MASTER)

        // Second layer encryption
        val secondEncryption = encryptWithKey(firstEncryption.encryptedData, KEY_ALIAS_ENCRYPTION)

        // Combine IVs for proper decryption
        val combinedIV = "${firstEncryption.iv}::${secondEncryption.iv}"

        return EncryptedData(
            encryptedData = secondEncryption.encryptedData,
            iv = combinedIV
        )
    }

    private fun doubleDecryptPrivateKey(encryptedData: String, combinedIV: String): String {
        val ivParts = combinedIV.split("::")
        require(ivParts.size == 2) { "Invalid IV format for double decryption" }

        val firstIV = ivParts[0]
        val secondIV = ivParts[1]

        // First decryption
        val firstDecrypted = decryptWithKey(encryptedData, secondIV, KEY_ALIAS_ENCRYPTION)

        // Second decryption
        val finalDecrypted = decryptWithKey(firstDecrypted, firstIV, KEY_ALIAS_MASTER)

        return finalDecrypted
    }

    private fun encryptWithKey(data: String, keyAlias: String): EncryptedData {
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
    }

    private fun decryptWithKey(encryptedData: String, iv: String, keyAlias: String): String {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        val secretKey = keyStore.getKey(keyAlias, null)
        val cipher = Cipher.getInstance(TRANSFORMATION)

        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH * 8, Base64.decode(iv, Base64.NO_WRAP))
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

        val decryptedBytes = cipher.doFinal(Base64.decode(encryptedData, Base64.NO_WRAP))
        return String(decryptedBytes)
    }

    /**
     * Debug method for troubleshooting
     */
    fun debugKeyStorage(): String {
        val debugInfo = StringBuilder()
        debugInfo.append("=== CRYPTO KEY MANAGER DEBUG ===\n")
        debugInfo.append("Timestamp: ${System.currentTimeMillis()}\n\n")

        try {
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

        } catch (e: Exception) {
            debugInfo.append("ERROR: ${e.message}\n")
        }

        return debugInfo.toString()
    }
}