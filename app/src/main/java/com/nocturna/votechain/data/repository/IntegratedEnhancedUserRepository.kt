package com.nocturna.votechain.data.repository

import android.content.Context
import android.net.Uri
import android.util.Log
import com.nocturna.votechain.blockchain.BlockchainManager
import com.nocturna.votechain.data.model.ApiResponse
import com.nocturna.votechain.data.model.CompleteUserData
import com.nocturna.votechain.data.model.UserProfile
import com.nocturna.votechain.data.model.UserRegistrationData
import com.nocturna.votechain.data.model.WalletInfo
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Enhanced UserRepository yang mengintegrasikan:
 * 1. Secure local key generation (CryptoKeyManager)
 * 2. Blockchain integration (BlockchainManager)
 * 3. Server registration (UserRepository)
 * 4. Complete user data management
 */
class IntegratedEnhancedUserRepository(private val context: Context) {
    private val userRepository = UserRepository(context)
    private val cryptoKeyManager = CryptoKeyManager(context)
    private val voterRepository = VoterRepository(context)
    private val userProfileRepository = UserProfileRepository(context)
    private val userLoginRepository = UserLoginRepository(context)
    private val TAG = "IntegratedEnhancedUserRepository"

    /**
     * Register user dengan secure key generation + optional blockchain integration
     */
    suspend fun registerWithFullIntegration(
        email: String,
        password: String,
        nik: String,
        fullName: String,
        gender: String,
        birthPlace: String,
        birthDate: String,
        residentialAddress: String,
        region: String,
        role: String = "voter",
        telephone: String,
        ktpFileUri: Uri? = null
    ): Result<RegistrationResult> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Starting full integration registration for: $email")

            // Step 1: Generate secure key pair locally with enhanced validation
            val keyPairInfo = generateValidatedKeyPair()
            Log.d(TAG, "✅ Generated secure key pair locally")
            Log.d(TAG, "   Voter Address: ${keyPairInfo.voterAddress}")
            Log.d(TAG, "   Private Key Length: ${keyPairInfo.privateKey.length} characters")

            // Step 2: Validate generated keys meet strict format requirements
            validateKeyPairFormat(keyPairInfo)
            Log.d(TAG, "✅ Key pair format validation passed")

            // Step 3: Store keys securely in Android Keystore
            cryptoKeyManager.storeKeyPair(keyPairInfo)
            Log.d(TAG, "✅ Keys stored securely in Android Keystore")

            // Step 4: Verify storage was successful and keys are retrievable
            verifyKeyStorage(keyPairInfo)
            Log.d(TAG, "✅ Key storage verification passed")

            // Step 5: Optional blockchain integration (non-blocking)
            val blockchainResult = tryBlockchainIntegration(keyPairInfo.voterAddress)

            // Step 6: Register user on server with generated voter address
            val registrationResult = userRepository.registerUser(
                email = email,
                password = password,
                nik = nik,
                fullName = fullName,
                gender = gender,
                birthPlace = birthPlace,
                birthDate = birthDate,
                residentialAddress = residentialAddress,
                region = region,
                role = role,
                voterAddress = keyPairInfo.voterAddress,
                ktpFileUri = ktpFileUri,
                telephone = telephone
            )

            registrationResult.fold(
                onSuccess = { response ->
                    // Step 7: Store voter data locally with validated keys
                    storeVoterKeysLocally(nik, fullName, keyPairInfo)

                    // Step 8: Initialize wallet with balance
                    val initialWalletInfo = initializeUserWallet(keyPairInfo.voterAddress)

                    val result = RegistrationResult(
                        serverResponse = response,
                        keyPairInfo = keyPairInfo,
                        blockchainIntegration = blockchainResult,
                        walletInfo = initialWalletInfo,
                        isSuccess = true
                    )

                    Log.d(TAG, "✅ Registration completed successfully with validated key format")
                    Result.success(result)
                },
                onFailure = { error ->
                    Log.e(TAG, "❌ Server registration failed: ${error.message}")

                    // Cleanup on server registration failure
                    cryptoKeyManager.clearStoredKeys()

                    Result.failure(error)
                }
            )

        } catch (e: Exception) {
            Log.e(TAG, "❌ Registration failed: ${e.message}", e)

            // Cleanup on any failure
            try {
                cryptoKeyManager.clearStoredKeys()
            } catch (cleanupError: Exception) {
                Log.w(TAG, "Failed to cleanup keys after registration failure", cleanupError)
            }

            Result.failure(e)
        }
    }

    /**
     * Generate key pair with enhanced validation
     */
    private fun generateValidatedKeyPair(): CryptoKeyManager.KeyPairInfo {
        try {
            Log.d(TAG, "Generating validated key pair...")

            val keyPairInfo = cryptoKeyManager.generateKeyPair()

            // Log generated key information for debugging
            Log.d(TAG, "Key pair generated:")
            Log.d(TAG, "- Private key length: ${keyPairInfo.privateKey.length}")
            Log.d(TAG, "- Public key length: ${keyPairInfo.publicKey.length}")
            Log.d(TAG, "- Voter address length: ${keyPairInfo.voterAddress.length}")
            Log.d(TAG, "- Generation method: ${keyPairInfo.generationMethod}")

            return keyPairInfo
        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate validated key pair", e)
            throw SecurityException("Key pair generation failed: ${e.message}", e)
        }
    }

    /**
     * Validate key pair format meets strict requirements
     */
    private fun validateKeyPairFormat(keyPairInfo: CryptoKeyManager.KeyPairInfo) {
        Log.d(TAG, "Validating key pair format...")

        // Validate private key format - exactly 66 characters (0x + 64 hex)
        if (keyPairInfo.privateKey.length != 66 ||
            !keyPairInfo.privateKey.startsWith("0x") ||
            !keyPairInfo.privateKey.substring(2).matches(Regex("^[0-9a-fA-F]{64}$"))) {
            throw IllegalStateException(
                "Private key format validation failed. Expected: 66 characters (0x + 64 hex), " +
                        "Got: ${keyPairInfo.privateKey.length} characters"
            )
        }

        // Validate public key format
        if (!keyPairInfo.publicKey.startsWith("0x") || keyPairInfo.publicKey.length < 130) {
            throw IllegalStateException(
                "Public key format validation failed. Expected: 0x + 128+ hex characters, " +
                        "Got: ${keyPairInfo.publicKey.length} characters"
            )
        }

        // Validate voter address format - exactly 42 characters (0x + 40 hex)
        if (keyPairInfo.voterAddress.length != 42 ||
            !keyPairInfo.voterAddress.startsWith("0x") ||
            !keyPairInfo.voterAddress.substring(2).matches(Regex("^[0-9a-fA-F]{40}$"))) {
            throw IllegalStateException(
                "Voter address format validation failed. Expected: 42 characters (0x + 40 hex), " +
                        "Got: ${keyPairInfo.voterAddress.length} characters"
            )
        }

        Log.d(TAG, "✅ Key pair format validation passed")
    }

    /**
     * Verify key storage and retrieval
     */
    private fun verifyKeyStorage(originalKeyPairInfo: CryptoKeyManager.KeyPairInfo) {
        Log.d(TAG, "Verifying key storage...")

        // Check if keys were stored
        if (!cryptoKeyManager.hasStoredKeyPair()) {
            throw SecurityException("Key storage verification failed: No keys found after storage")
        }

        // Retrieve and validate stored keys
        val storedPrivateKey = cryptoKeyManager.getPrivateKey()
        val storedPublicKey = cryptoKeyManager.getPublicKey()
        val storedVoterAddress = cryptoKeyManager.getVoterAddress()

        // Validate retrieved keys match original
        if (storedPrivateKey != originalKeyPairInfo.privateKey) {
            throw SecurityException("Key storage verification failed: Private key mismatch")
        }

        if (storedPublicKey != originalKeyPairInfo.publicKey) {
            throw SecurityException("Key storage verification failed: Public key mismatch")
        }

        if (storedVoterAddress != originalKeyPairInfo.voterAddress) {
            throw SecurityException("Key storage verification failed: Voter address mismatch")
        }

        // Validate stored keys format
        if (!cryptoKeyManager.validateStoredKeys()) {
            throw SecurityException("Key storage verification failed: Stored keys format validation failed")
        }

        Log.d(TAG, "✅ Key storage verification passed")
    }

    /**
     * Store voter keys locally with enhanced validation
     */
    private fun storeVoterKeysLocally(
        nik: String,
        fullName: String,
        keyPairInfo: CryptoKeyManager.KeyPairInfo
    ) {
        try {
            Log.d(TAG, "Storing voter keys locally with validation...")

            // Validate key formats before storing
            validateKeyPairFormat(keyPairInfo)

            // Store in VoterRepository with validated keys
            voterRepository.saveVoterDataLocally(
                fullName = fullName,
                nik = nik,
                publicKey = keyPairInfo.publicKey,
                privateKey = keyPairInfo.privateKey,
                voterAddress = keyPairInfo.voterAddress,
                hasVoted = false
            )

            Log.d(TAG, "✅ Voter keys stored locally successfully")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to store voter keys locally", e)
            throw SecurityException("Local voter key storage failed: ${e.message}", e)
        }
    }

    /**
     * Initialize user wallet with validated address
     */
    private suspend fun initializeUserWallet(voterAddress: String): WalletInfo = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Initializing user wallet for address: $voterAddress")

            // Validate voter address format
            if (voterAddress.length != 42 || !voterAddress.startsWith("0x")) {
                throw IllegalArgumentException("Invalid voter address format for wallet initialization")
            }

            // Get initial wallet information
            val walletInfo = voterRepository.getCompleteWalletInfo()

            Log.d(TAG, "✅ User wallet initialized successfully")
            Log.d(TAG, "- Address: ${walletInfo.voterAddress}")
            Log.d(TAG, "- Balance: ${walletInfo.balance} ETH")
            Log.d(TAG, "- Has error: ${walletInfo.hasError}")

            walletInfo

        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize user wallet", e)
            WalletInfo(
                hasError = true,
                errorMessage = "Wallet initialization failed: ${e.message}"
            )
        }
    }

    /**
     * Import wallet with enhanced validation
     */
    suspend fun importWalletWithValidation(
        privateKey: String,
        userPassword: String,
        email: String
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Starting wallet import with enhanced validation")

            // Pre-validate private key format
            val cleanPrivateKey = privateKey.trim().let {
                if (it.startsWith("0x", ignoreCase = true)) it.substring(2) else it
            }

            if (cleanPrivateKey.length != 64 || !cleanPrivateKey.matches(Regex("^[0-9a-fA-F]{64}$"))) {
                return@withContext Result.failure(
                    IllegalArgumentException("Private key must be exactly 64 hexadecimal characters")
                )
            }

            // Use CryptoKeyManager for import with validation
            val importResult = cryptoKeyManager.importWalletFromPrivateKey(
                privateKey = "0x$cleanPrivateKey",
                userPassword = userPassword
            )

            importResult.fold(
                onSuccess = { walletAddress ->
                    // Verify the imported keys are in correct format
                    if (!cryptoKeyManager.validateStoredKeys()) {
                        Log.e(TAG, "❌ Imported keys failed format validation")
                        cryptoKeyManager.clearStoredKeys()
                        return@withContext Result.failure(
                            SecurityException("Imported keys do not meet format requirements")
                        )
                    }

                    Log.d(TAG, "✅ Wallet import successful with validated format")
                    Log.d(TAG, "Wallet Address: $walletAddress")

                    // Store user login information
                    userLoginRepository.loginUser(email, userPassword)

                    Result.success(walletAddress)
                },
                onFailure = { error ->
                    Log.e(TAG, "❌ Wallet import failed: ${error.message}")
                    Result.failure(error)
                }
            )

        } catch (e: Exception) {
            Log.e(TAG, "❌ Wallet import exception: ${e.message}", e)
            Result.failure(e)
        }
    }

    /**
     * Validate existing user keys and repair if needed
     */
    suspend fun validateAndRepairUserKeys(email: String): Result<Boolean> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Validating and repairing user keys for: $email")

            if (!cryptoKeyManager.hasStoredKeyPair()) {
                Log.w(TAG, "No stored key pair found")
                return@withContext Result.failure(SecurityException("No keys found"))
            }

            val isValid = cryptoKeyManager.validateStoredKeys()

            if (isValid) {
                Log.d(TAG, "✅ Existing keys are valid")
                return@withContext Result.success(true)
            }

            Log.w(TAG, "❌ Existing keys are invalid, attempting repair...")

            // Try to repair keys if possible
            // This could involve:
            // 1. Reformatting existing keys to correct format
            // 2. Regenerating keys if format is completely wrong
            // 3. Recovering from backup if available

            // For now, clear invalid keys and indicate repair is needed
            cryptoKeyManager.clearStoredKeys()

            Log.d(TAG, "Invalid keys cleared, regeneration required")
            Result.success(false) // Indicates repair was needed

        } catch (e: Exception) {
            Log.e(TAG, "❌ Key validation and repair failed: ${e.message}", e)
            Result.failure(e)
        }
    }

    /**
     * Get user wallet information with format validation
     */
    suspend fun getValidatedUserWalletInfo(email: String): Result<WalletInfo> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Getting validated wallet info for: $email")

            // First validate stored keys
            if (!cryptoKeyManager.hasStoredKeyPair()) {
                return@withContext Result.failure(SecurityException("No wallet found"))
            }

            if (!cryptoKeyManager.validateStoredKeys()) {
                return@withContext Result.failure(SecurityException("Wallet keys are in invalid format"))
            }

            // Get wallet information
            val walletInfo = voterRepository.getCompleteWalletInfo()

            if (walletInfo.hasError) {
                return@withContext Result.failure(Exception(walletInfo.errorMessage ?: "Unknown wallet error"))
            }

            Log.d(TAG, "✅ Validated wallet info retrieved successfully")
            Result.success(walletInfo)

        } catch (e: Exception) {
            Log.e(TAG, "❌ Failed to get validated wallet info: ${e.message}", e)
            Result.failure(e)
        }
    }

    /**
     * Data class for registration results
     */
    data class RegistrationResult(
        val serverResponse: ApiResponse<UserRegistrationData>,
        val keyPairInfo: CryptoKeyManager.KeyPairInfo,
        val blockchainIntegration: BlockchainIntegrationResult,
        val walletInfo: WalletInfo,
        val isSuccess: Boolean
    )

    /**
     * Data class for blockchain integration results
     */
    data class BlockchainIntegrationResult(
        val success: Boolean,
        val message: String,
        val transactionHash: String? = null
    )

    /**
     * Optional blockchain integration - tidak akan block registration jika gagal
     */
    private suspend fun tryBlockchainIntegration(voterAddress: String): BlockchainIntegrationResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Attempting blockchain integration for: $voterAddress")

            // This is optional and non-blocking
            // If blockchain is not available, registration should still succeed

            // TODO: Implement actual blockchain integration
            // For now, return a successful mock result

            BlockchainIntegrationResult(
                success = true,
                message = "Blockchain integration ready (mock)"
            )

        } catch (e: Exception) {
            Log.w(TAG, "Blockchain integration failed (non-critical): ${e.message}")
            BlockchainIntegrationResult(
                success = false,
                message = "Blockchain integration failed: ${e.message}"
            )
        }
    }

    /**
     * Try to fund the voter address dengan ETH untuk transaction fees
     */
    private suspend fun tryFundingAddress(voterAddress: String): String {
        return try {
            val txHash = withContext(Dispatchers.IO) {
                BlockchainManager.fundVoterAddress(voterAddress)
            }

            if (txHash.isNotEmpty()) {
                Log.d(TAG, "✅ Address funded successfully: $txHash")
            } else {
                Log.w(TAG, "⚠️ Address funding returned empty hash")
            }

            txHash
        } catch (e: Exception) {
            Log.e(TAG, "❌ Address funding failed: ${e.message}")
            ""
        }
    }

    /**
     * Try to register address on blockchain smart contract (optional)
     */
    private suspend fun tryRegisterOnBlockchain(voterAddress: String): String {
        return try {
            // Implementasi spesifik untuk registrasi di smart contract
            // Ini tergantung pada smart contract yang digunakan

            Log.d(TAG, "🔗 Registering address on blockchain: $voterAddress")

            // Placeholder - implementasi actual tergantung smart contract
            // val txHash = BlockchainManager.registerVoterOnContract(voterAddress)
            val txHash = "" // Untuk sementara kosong

            if (txHash.isNotEmpty()) {
                Log.d(TAG, "✅ Address registered on blockchain: $txHash")
            }

            txHash
        } catch (e: Exception) {
            Log.e(TAG, "❌ Blockchain registration failed: ${e.message}")
            ""
        }
    }

    /**
     * Enhanced login with complete user data loading
     */
    suspend fun enhancedLogin(email: String, password: String): Result<CompleteUserData> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Starting enhanced login for: $email")

            // Step 1: Authenticate with server
            val loginResult = userLoginRepository.loginUser(email, password)

            loginResult.fold(
                onSuccess = { loginResponse ->
                    // Step 2: Get complete user data
                    val completeUserData = getCompleteUserData()

                    Log.d(TAG, "✅ Enhanced login completed successfully")
                    Result.success(completeUserData)
                },
                onFailure = { error ->
                    Log.e(TAG, "❌ Login failed: ${error.message}")
                    Result.failure(error)
                }
            )
        } catch (e: Exception) {
            Log.e(TAG, "❌ Enhanced login failed with exception", e)
            Result.failure(e)
        }
    }

    /**
     * Get complete user data for session management
     */
    suspend fun getCompleteUserData(): CompleteUserData = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Loading complete user data")

            // Get user profile (with fallback)
            val userProfile = try {
                userProfileRepository.fetchCompleteUserProfile().getOrNull()
                    ?.let { it.userProfile } // Access userProfile property correctly
            } catch (e: Exception) {
                Log.w(TAG, "Failed to fetch fresh profile, using saved: ${e.message}")
                userProfileRepository.getSavedCompleteProfile()
                    ?.let { it.userProfile } // Access userProfile property correctly
            }

            // Get voter data (with fallback)
            val voterData = try {
                voterRepository.getVoterData()
            } catch (e: Exception) {
                Log.w(TAG, "Failed to get voter data: ${e.message}")
                null
            }

            // Get wallet info with real-time balance
            val walletInfo = try {
                voterRepository.getCompleteWalletInfo()
            } catch (e: Exception) {
                Log.w(TAG, "Failed to get wallet info: ${e.message}")
                WalletInfo(
                    hasError = true,
                    errorMessage = e.message ?: "Unknown wallet error"
                )
            }

            val completeData = CompleteUserData(
                userProfile = userProfile as UserProfile?,
                voterData = voterData,
                walletInfo = walletInfo
            )

            Log.d(TAG, "✅ Complete user data loaded successfully")
            return@withContext completeData

        } catch (e: Exception) {
            Log.e(TAG, "Error loading complete user data", e)
            return@withContext CompleteUserData(
                walletInfo = WalletInfo(
                    hasError = true,
                    errorMessage = e.message ?: "Failed to load user data"
                )
            )
        }
    }

    /**
     * Refresh complete user data
     */
    suspend fun refreshCompleteUserData(): Result<CompleteUserData> = withContext(Dispatchers.IO) {
        try {
            // Refresh user profile from server
            userProfileRepository.fetchCompleteUserProfile()

            // Get updated complete data
            val completeData = getCompleteUserData()

            Result.success(completeData)
        } catch (e: Exception) {
            Log.e(TAG, "Error refreshing complete user data", e)
            Result.failure(e)
        }
    }

    /**
     * Store blockchain transaction for audit trail
     */
    private fun storeBlockchainTransaction(voterAddress: String, txHash: String, type: String) {
        try {
            val sharedPreferences = context.getSharedPreferences("BlockchainTransactions", Context.MODE_PRIVATE)
            with(sharedPreferences.edit()) {
                putString("${voterAddress}_${type}_tx", txHash)
                putLong("${voterAddress}_${type}_timestamp", System.currentTimeMillis())
                apply()
            }
            Log.d(TAG, "Blockchain transaction stored: $type - $txHash")
        } catch (e: Exception) {
            Log.e(TAG, "Error storing blockchain transaction", e)
        }
    }

    /**
     * Check blockchain connection status
     */
    suspend fun checkBlockchainConnection(): Boolean {
        return try {
            withContext(Dispatchers.IO) {
                BlockchainManager.isConnected()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error checking blockchain connection", e)
            false
        }
    }

    /**
     * Manual blockchain integration untuk user yang sudah terdaftar
     */
    suspend fun retryBlockchainIntegration(): Result<BlockchainIntegrationResult> {
        return try {
            val voterAddress = cryptoKeyManager.getVoterAddress()
            if (voterAddress.isNullOrEmpty()) {
                return Result.failure(Exception("No voter address found"))
            }

            val result = tryBlockchainIntegration(voterAddress)
            Result.success(result)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Clear all user data (for logout)
     */
    suspend fun clearAllUserData() {
        try {
            cryptoKeyManager.clearStoredKeys()
            voterRepository.clearVoterData()
            userLoginRepository.logoutUser()
            userProfileRepository.clearProfileData()

            // Clear blockchain transactions
            val sharedPreferences = context.getSharedPreferences("BlockchainTransactions", Context.MODE_PRIVATE)
            sharedPreferences.edit().clear().apply()

            Log.d(TAG, "✅ All user data cleared")
        } catch (e: Exception) {
            Log.e(TAG, "Error clearing user data", e)
        }
    }

    /**
     * Registration summary untuk UI
     */
    data class RegistrationSummary(
        val voterAddress: String,
        val publicKey: String,
        val hasPrivateKey: Boolean,
        val isKeysValid: Boolean
    )

    // ===== Delegation Methods =====

    /**
     * Delegate methods ke CryptoKeyManager dan VoterRepository
     */
    fun getPrivateKey(): String? = cryptoKeyManager.getPrivateKey()
    fun getPublicKey(): String? = cryptoKeyManager.getPublicKey()
    fun getVoterAddress(): String? = cryptoKeyManager.getVoterAddress()
    fun hasStoredKeys(): Boolean = cryptoKeyManager.hasStoredKeyPair()
    fun validateStoredKeys(): Boolean = voterRepository.validateStoredData()

    suspend fun getWalletInfo(): WalletInfo = voterRepository.getCompleteWalletInfo()
    suspend fun getWalletInfoWithPrivateKey(): WalletInfo = voterRepository.getCompleteWalletInfo()
}