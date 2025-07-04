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

            val keyGenSuccess = cryptoKeyManager.generateAndStoreKeyPair()
            if (!keyGenSuccess) {
                throw Exception("Failed to generate key pair")
            }

            // Kemudian ambil data key pair setelah berhasil di-generate
            val keyPairInfo = CryptoKeyManager.KeyPairInfo(
                publicKey = cryptoKeyManager.getPublicKey() ?: "",
                privateKey = cryptoKeyManager.getPrivateKey() ?: "",
                voterAddress = cryptoKeyManager.getVoterAddress() ?: "",
                creationTime = System.currentTimeMillis(),
//                keyVersion = 1,
                generationMethod = "EC-secp256k1"
            )

//            // Step 1: Generate secure key pair locally (independent dari blockchain)
//            val keyPairInfo = cryptoKeyManager.generateKeyPair()
//            Log.d(TAG, "✅ Generated secure key pair locally")
//            Log.d(TAG, "   Voter Address: ${keyPairInfo.voterAddress}")
//
//            // Step 2: Store keys securely di Android Keystore
//            cryptoKeyManager.storeKeyPair(keyPairInfo)
//            Log.d(TAG, "✅ Keys stored securely in Android Keystore")

            // Step 3: Optional blockchain integration (non-blocking)
            val blockchainResult = tryBlockchainIntegration(keyPairInfo.voterAddress)

            // Step 4: Register user di server dengan generated voter address
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
                    // Step 5: Store voter data locally
                    storeVoterKeysLocally(nik, fullName, keyPairInfo)

                    // Step 6: Initialize wallet with balance
                    val initialWalletInfo = initializeUserWallet(keyPairInfo.voterAddress)

                    val result = RegistrationResult(
                        serverResponse = response,
                        keyPairInfo = keyPairInfo,
                        blockchainIntegration = blockchainResult,
                        walletInfo = initialWalletInfo,
                        isSuccess = true
                    )

                    Log.d(TAG, "✅ Registration completed successfully")
                    Result.success(result)
                },
                onFailure = { exception ->
                    Log.e(TAG, "❌ Server registration failed: ${exception.message}")

                    // Cleanup generated keys jika server registration gagal
                    cryptoKeyManager.clearStoredKeys()

                    Result.failure(exception)
                }
            )

        } catch (e: Exception) {
            Log.e(TAG, "❌ Registration failed with exception", e)

            // Clean up on any failure
            try {
                cryptoKeyManager.clearStoredKeys()
            } catch (cleanupError: Exception) {
                Log.e(TAG, "Error during cleanup", cleanupError)
            }

            Result.failure(e)
        }
    }

    /**
     * Optional blockchain integration - tidak akan block registration jika gagal
     */
    private suspend fun tryBlockchainIntegration(voterAddress: String): BlockchainIntegrationResult {
        return try {
            Log.d(TAG, "🔗 Attempting blockchain integration...")

            // Check blockchain connection
            val isConnected = withContext(Dispatchers.IO) {
                BlockchainManager.isConnected()
            }

            if (isConnected) {
                Log.d(TAG, "✅ Blockchain connected")

                // Try to fund the address
                val fundingResult = tryFundingAddress(voterAddress)

                // Try to register address on blockchain (jika ada method tersebut)
                val registrationTxHash = tryRegisterOnBlockchain(voterAddress)

                BlockchainIntegrationResult(
                    isConnected = true,
                    fundingTxHash = fundingResult,
                    registrationTxHash = registrationTxHash,
                    isSuccess = fundingResult.isNotEmpty() || registrationTxHash.isNotEmpty()
                )
            } else {
                Log.w(TAG, "⚠️ Blockchain not connected, skipping integration")
                BlockchainIntegrationResult(
                    isConnected = false,
                    fundingTxHash = "",
                    registrationTxHash = "",
                    isSuccess = false
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "⚠️ Blockchain integration failed (non-critical): ${e.message}")
            BlockchainIntegrationResult(
                isConnected = false,
                fundingTxHash = "",
                registrationTxHash = "",
                isSuccess = false,
                error = e.message
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
                voterRepository.getVoterDataLocally()
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
     * Initialize user wallet with balance checking
     */
    suspend fun initializeUserWallet(voterAddress: String): WalletInfo = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Initializing wallet for address: $voterAddress")

            // Get initial balance
            val balance = try {
                BlockchainManager.getAccountBalance(voterAddress)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to get initial balance: ${e.message}")
                "0.00000000"
            }

            val walletInfo = WalletInfo(
                balance = balance,
                privateKey = cryptoKeyManager.getPrivateKey() ?: "",
                publicKey = cryptoKeyManager.getPublicKey() ?: "",
                voterAddress = voterAddress,
                lastUpdated = System.currentTimeMillis(),
                isLoading = false,
                hasError = false
            )

            Log.d(TAG, "✅ Wallet initialized with balance: $balance ETH")
            return@withContext walletInfo

        } catch (e: Exception) {
            Log.e(TAG, "Error initializing wallet", e)
            return@withContext WalletInfo(
                voterAddress = voterAddress,
                hasError = true,
                errorMessage = e.message ?: "Failed to initialize wallet"
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
     * Store voter data securely with crypto reference
     */
    private fun storeVoterKeysLocally(
        nik: String,
        fullName: String,
        keyPairInfo: CryptoKeyManager.KeyPairInfo
    ) {
        try {
            val sharedPreferences =
                context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
            with(sharedPreferences.edit()) {
                putString("voter_nik", nik)
                putString("voter_full_name", fullName)
                putString("voter_address", keyPairInfo.voterAddress)
                putString("voter_public_key", keyPairInfo.publicKey)
                putLong("key_generation_timestamp", System.currentTimeMillis())
                apply()
            }
            Log.d(TAG, "✅ Voter data stored locally")
        } catch (e: Exception) {
            Log.e(TAG, "Error storing voter data locally", e)
        }
    }

    /**
     * Get registration summary for UI
     */
    fun getRegistrationSummary(): RegistrationSummary? {
        return try {
            if (!cryptoKeyManager.hasStoredKeyPair()) {
                return null
            }

            RegistrationSummary(
                voterAddress = cryptoKeyManager.getVoterAddress() ?: "",
                publicKey = cryptoKeyManager.getPublicKey() ?: "",
                hasPrivateKey = cryptoKeyManager.getPrivateKey() != null,
                isKeysValid = voterRepository.validateStoredData()
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error getting registration summary", e)
            null
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

    // ===== Data Classes untuk Result =====

    /**
     * Comprehensive registration result
     */
    data class RegistrationResult(
        val serverResponse: ApiResponse<UserRegistrationData>,
        val keyPairInfo: CryptoKeyManager.KeyPairInfo,
        val blockchainIntegration: BlockchainIntegrationResult,
        val walletInfo: WalletInfo,
        val isSuccess: Boolean
    )

    /**
     * Blockchain integration result
     */
    data class BlockchainIntegrationResult(
        val isConnected: Boolean,
        val fundingTxHash: String,
        val registrationTxHash: String,
        val isSuccess: Boolean,
        val error: String? = null
    )

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