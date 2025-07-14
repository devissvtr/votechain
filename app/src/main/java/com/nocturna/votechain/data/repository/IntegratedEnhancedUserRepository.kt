package com.nocturna.votechain.data.repository

import android.content.Context
import android.util.Log
import com.nocturna.votechain.blockchain.BlockchainManager
import com.nocturna.votechain.data.model.CompleteUserData
import com.nocturna.votechain.data.model.UserProfile
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
    private val cryptoKeyManager = CryptoKeyManager(context)
    private val voterRepository = VoterRepository(context)
    private val userProfileRepository = UserProfileRepository(context)
    private val userLoginRepository = UserLoginRepository(context)
    private val TAG = "IntegratedEnhancedUserRepository"

    /**
     * Get complete user data for session management
     */
    suspend fun getCompleteUserData(): CompleteUserData = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Loading complete user data")

            // Get user profile (with fallback)
            val userProfile = try {
                userProfileRepository.fetchCompleteUserProfile().getOrNull()?.userProfile // Access userProfile property correctly
            } catch (e: Exception) {
                Log.w(TAG, "Failed to fetch fresh profile, using saved: ${e.message}")
                userProfileRepository.getSavedCompleteProfile()?.userProfile // Access userProfile property correctly
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
     * Delegate methods ke CryptoKeyManager dan VoterRepository
     */
    fun getPrivateKey(): String? = cryptoKeyManager.getPrivateKey()
    fun hasStoredKeys(): Boolean = cryptoKeyManager.hasStoredKeyPair()
}