package com.nocturna.votechain.data.repository

import android.content.Context
import android.util.Log
import com.nocturna.votechain.blockchain.BlockchainManager
import com.nocturna.votechain.data.model.VoterData
import com.nocturna.votechain.data.model.WalletInfo
import com.nocturna.votechain.data.network.NetworkClient
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Updated VoterRepository with integrated cryptographic key management
 */
class VoterRepository(private val context: Context) {
    private val TAG = "VoterRepository"
    private val PREFS_NAME = "VoteChainPrefs"
    private val KEY_VOTER_FULL_NAME = "voter_full_name"
    private val KEY_VOTER_NIK = "voter_nik"
    private val KEY_VOTER_PUBLIC_KEY = "voter_public_key"
    private val KEY_VOTER_ADDRESS = "voter_address"
    private val KEY_VOTER_HAS_VOTED = "voter_has_voted"
    private val KEY_USER_ID = "user_id"
    private val KEY_LAST_BALANCE_UPDATE = "last_balance_update"
    private val KEY_CACHED_BALANCE = "cached_balance"

    // API service and crypto manager
    private val apiService = NetworkClient.apiService
    private val cryptoKeyManager = CryptoKeyManager(context)

    /**
     * Fetch voter data from API and merge with locally stored cryptographic keys
     */
    suspend fun fetchVoterData(userToken: String): Result<VoterData> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Fetching voter data with token")

            val formattedToken = if (userToken.startsWith("Bearer ")) {
                userToken
            } else {
                "Bearer $userToken"
            }

            val response = apiService.getVoterDataWithToken(formattedToken)

            if (response.isSuccessful) {
                response.body()?.let { voterResponse ->
                    if (voterResponse.data.isNotEmpty()) {
                        val userId = getUserIdFromResponse(response.headers()["x-user-id"])
                        Log.d(TAG, "Looking for voter data with user_id: $userId")

                        val voterData = if (!userId.isNullOrEmpty()) {
                            voterResponse.data.find { it.user_id == userId }
                                ?: voterResponse.data.first()
                        } else {
                            voterResponse.data.first()
                        }

                        // Save user ID for future reference
                        saveUserId(userId ?: voterData.user_id)

                        // Get and validate locally stored cryptographic data
                        val localVoterAddress = cryptoKeyManager.getVoterAddress()

                        // Merge with locally stored cryptographic data
                        val enhancedVoterData = voterData.copy(
                            voter_address = localVoterAddress ?: voterData.voter_address
                        )

                        Log.d(TAG, "✅ Voter data fetched and enhanced successfully")
                        Log.d(TAG, "- Server voter address: ${voterData.voter_address}")
                        Log.d(TAG, "- Local voter address: $localVoterAddress")
                        Log.d(TAG, "- Final voter address: ${enhancedVoterData.voter_address}")

                        return@withContext Result.success(enhancedVoterData)
                    } else {
                        Log.w(TAG, "No voter data found in response")
                        return@withContext Result.failure(Exception("No voter data found"))
                    }
                } ?: run {
                    Log.e(TAG, "Response body is null")
                    return@withContext Result.failure(Exception("Empty response from server"))
                }
            } else {
                Log.e(TAG, "API request failed: ${response.code()} - ${response.message()}")
                return@withContext Result.failure(Exception("Failed to fetch voter data: ${response.message()}"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception during voter data fetch: ${e.message}", e)
            return@withContext Result.failure(e)
        }
    }

    /**
     * Extract user_id from response header
     */
    private fun getUserIdFromResponse(headerValue: String?): String? {
        return headerValue?.takeIf { it.isNotEmpty() }?.also {
            Log.d(TAG, "Found user_id in header: $it")
        }
    }

    /**
     * Save user_id to SharedPreferences
     */
    private fun saveUserId(userId: String?) {
        if (userId != null) {
            val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            with(sharedPreferences.edit()) {
                putString(KEY_USER_ID, userId)
                apply()
            }
            Log.d(TAG, "User ID saved: $userId")
        }
    }

    /**
     * Save voter data to SharedPreferences (without private key for security)
     */
    fun saveVoterDataLocally(voterData: VoterData) {
        val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        with(sharedPreferences.edit()) {
            putString(KEY_VOTER_FULL_NAME, voterData.full_name)
            putString(KEY_VOTER_NIK, voterData.nik)
            putString(KEY_VOTER_PUBLIC_KEY, cryptoKeyManager.getPublicKey() ?: "")
            putString(KEY_VOTER_ADDRESS, voterData.voter_address)
            putBoolean(KEY_VOTER_HAS_VOTED, voterData.has_voted)
            apply()
        }
        Log.d(TAG, "Voter data saved to SharedPreferences")
    }

    /**
     * Get voter data from local storage with cryptographic key integration
     */
    suspend fun getVoterData(): VoterData? = withContext(Dispatchers.IO) {
        try {
            val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val fullName = sharedPreferences.getString(KEY_VOTER_FULL_NAME, "") ?: ""
            val nik = sharedPreferences.getString(KEY_VOTER_NIK, "") ?: ""
            val storedVoterAddress = sharedPreferences.getString(KEY_VOTER_ADDRESS, "") ?: ""
            val hasVoted = sharedPreferences.getBoolean(KEY_VOTER_HAS_VOTED, false)

            // Try to get voter address from crypto manager if not in regular storage
            val voterAddress = if (storedVoterAddress.isNotEmpty()) {
                storedVoterAddress
            } else {
                cryptoKeyManager.getVoterAddress() ?: ""
            }

            // Validate cryptographic keys if available
            if (cryptoKeyManager.hasStoredKeyPair()) {
                val isValidKeys = cryptoKeyManager.validateStoredKeys()
                if (!isValidKeys) {
                    Log.w(TAG, "Stored cryptographic keys are invalid format")
                    // Could trigger key regeneration or repair here if needed
                } else {
                    Log.d(TAG, "✅ Cryptographic keys validated successfully")
                }
            }

            return@withContext if (fullName.isNotEmpty()) {
                VoterData(
                    id = "",
                    user_id = "",
                    nik = nik,
                    full_name = fullName,
                    gender = "",
                    birth_place = "",
                    birth_date = "",
                    residential_address = "",
                    telephone = "",
                    voter_address = voterAddress,
                    region = "",
                    is_registered = true,
                    has_voted = hasVoted
                )
            } else {
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting voter data: ${e.message}", e)
            null
        }
    }

    /**
     * Get complete wallet information with real-time balance fetching
     */
    suspend fun getCompleteWalletInfo(): WalletInfo = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Fetching complete wallet information")

            val voterAddress = cryptoKeyManager.getVoterAddress()
            val publicKey = cryptoKeyManager.getPublicKey()
            val privateKey = cryptoKeyManager.getPrivateKey()

            if (voterAddress.isNullOrEmpty()) {
                Log.w(TAG, "No voter address found")
                return@withContext WalletInfo(
                    hasError = true,
                    errorMessage = "No voter address found"
                )
            }

            // Try to get fresh balance from blockchain
            val currentBalance = try {
                Log.d(TAG, "Fetching balance for address: $voterAddress")
                val balance = BlockchainManager.getAccountBalance(voterAddress)

                // Cache the balance with timestamp
                cacheBalance(balance)

                Log.d(TAG, "Balance fetched successfully: $balance ETH")
                balance
            } catch (e: Exception) {
                Log.w(TAG, "Failed to fetch live balance, using cached: ${e.message}")
                getCachedBalance()
            }

            return@withContext WalletInfo(
                balance = currentBalance,
                privateKey = privateKey ?: "",
                publicKey = publicKey ?: "",
                voterAddress = voterAddress,
                lastUpdated = System.currentTimeMillis(),
                isLoading = false,
                hasError = false
            )

        } catch (e: Exception) {
            Log.e(TAG, "Error getting complete wallet info", e)
            return@withContext WalletInfo(
                balance = getCachedBalance(),
                hasError = true,
                errorMessage = e.message ?: "Unknown error"
            )
        }
    }

    /**
     * Refresh balance from blockchain
     */
    suspend fun refreshBalance(): String = withContext(Dispatchers.IO) {
        try {
            val voterAddress = cryptoKeyManager.getVoterAddress()
            if (voterAddress.isNullOrEmpty()) {
                return@withContext "0.00000000"
            }

            val balance = BlockchainManager.getAccountBalance(voterAddress)
            cacheBalance(balance)
            return@withContext balance
        } catch (e: Exception) {
            Log.e(TAG, "Error refreshing balance", e)
            return@withContext getCachedBalance()
        }
    }

    /**
     * Cache balance with timestamp
     */
    private fun cacheBalance(balance: String) {
        try {
            val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            with(sharedPreferences.edit()) {
                putString(KEY_CACHED_BALANCE, balance)
                putLong(KEY_LAST_BALANCE_UPDATE, System.currentTimeMillis())
                apply()
            }
            Log.d(TAG, "Balance cached: $balance ETH")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to cache balance", e)
        }
    }

    /**
     * Get cached balance
     */
    private fun getCachedBalance(): String {
        return try {
            val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val cachedBalance = sharedPreferences.getString(KEY_CACHED_BALANCE, "0.0") ?: "0.0"
            val lastUpdate = sharedPreferences.getLong(KEY_LAST_BALANCE_UPDATE, 0)

            // Check if cache is still valid (less than 5 minutes old)
            val cacheAge = System.currentTimeMillis() - lastUpdate
            val maxCacheAge = 5 * 60 * 1000 // 5 minutes

            if (cacheAge < maxCacheAge) {
                Log.d(TAG, "Using cached balance: $cachedBalance ETH (age: ${cacheAge / 1000}s)")
                cachedBalance
            } else {
                Log.d(TAG, "Cached balance expired, returning default")
                "0.0"
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get cached balance", e)
            "0.0"
        }
    }


    /**
     * Get wallet information with secure private key access
     */
    fun getWalletInfo(): WalletInfo {
        return WalletInfo()
    }

    /**
     * Get only the private key (securely decrypted from Android Keystore)
     */
    fun getPrivateKey(): String? {
        return try {
            val privateKey = cryptoKeyManager.getPrivateKey()
            if (privateKey != null) {
                Log.d(TAG, "Private key retrieved successfully")
            } else {
                Log.w(TAG, "Private key not found")
            }
            privateKey
        } catch (e: Exception) {
            Log.e(TAG, "Error retrieving private key", e)
            null
        }
    }

    /**
     * Clear voter data from local storage and secure keystore
     */
    fun clearVoterData() {
        val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        with(sharedPreferences.edit()) {
            remove(KEY_VOTER_FULL_NAME)
            remove(KEY_VOTER_NIK)
            remove(KEY_VOTER_PUBLIC_KEY)
            remove(KEY_VOTER_ADDRESS)
            remove(KEY_VOTER_HAS_VOTED)
            remove(KEY_USER_ID)
            remove(KEY_CACHED_BALANCE)
            remove(KEY_LAST_BALANCE_UPDATE)
            apply()
        }

        // Also clear cryptographic keys from secure storage
        cryptoKeyManager.clearStoredKeys()

        Log.d(TAG, "Voter data and cryptographic keys cleared from all storage")
    }
}