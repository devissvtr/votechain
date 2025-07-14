package com.nocturna.votechain.data.repository

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.nocturna.votechain.data.model.VoteCastRequest
import com.nocturna.votechain.data.model.VoteCastResponse
import com.nocturna.votechain.data.model.VotingCategory
import com.nocturna.votechain.data.network.NetworkClient
import com.nocturna.votechain.security.CryptoKeyManager
import com.nocturna.votechain.utils.SignedTransactionGenerator
import com.nocturna.votechain.viewmodel.vote.VotingViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn

/**
 * Enhanced Voting Repository with integrated OTP verification flow
 */
class VotingRepository(
    private val context: Context,
    private val cryptoKeyManager: CryptoKeyManager
) {
    private val TAG = "VotingRepository"
    private val PREFS_NAME = "VoteChainPrefs"
    private val KEY_HAS_VOTED = "has_voted"

    private val voteApiService = NetworkClient.voteApiService
    private val otpRepository = OTPRepository(context)
    private val signedTransactionGenerator = SignedTransactionGenerator(cryptoKeyManager)

    /**
     * Simplified user key validation for single encryption system
     */
    private fun validateUserKeys(): Boolean {
        return try {
            Log.d(TAG, "🔍 Validating user keys (single encryption mode)...")

            // Step 1: Perform health check (this will auto-recover if needed)
            if (!cryptoKeyManager.performKeyHealthCheck()) {
                Log.e(TAG, "❌ Key health check failed")
                return false
            }

            // Step 2: Check if keys are stored
            if (!cryptoKeyManager.hasStoredKeyPair()) {
                Log.e(TAG, "❌ No key pair stored")
                return false
            }

            // Step 3: Try to retrieve private key
            val privateKey = cryptoKeyManager.getPrivateKey()
            if (privateKey.isNullOrEmpty()) {
                Log.e(TAG, "❌ Private key not accessible")
                return false
            }

            // Step 4: Test signing capability
            val testData = "validation_test_${System.currentTimeMillis()}"
            val signature = cryptoKeyManager.signData(testData)

            if (signature.isNullOrEmpty()) {
                Log.e(TAG, "❌ Signing capability test failed")
                return false
            }

            Log.d(TAG, "✅ User keys validation successful")
            return true

        } catch (e: Exception) {
            Log.e(TAG, "❌ Key validation failed: ${e.message}", e)
            return false
        }
    }

    /**
     * Cast a vote with enhanced signed transaction validation
     * @param electionPairId The ID of the selected candidate pair
     * @param region The voter's region
     * @return Flow with the result of the vote casting operation
     */
    fun castVoteWithSignedTransaction(
        electionPairId: String,
        region: String,
        otpToken: String? = null
    ): Flow<Result<VoteCastResponse>> = flow {
        try {
            Log.d(TAG, "🗳️ Starting vote casting (single encryption mode)...")
            Log.d(TAG, "  - Election Pair ID: $electionPairId")
            Log.d(TAG, "  - Region: ${region ?: "null (will fetch from VoterData)"}")
            Log.d(TAG, "  - OTP Token provided: ${!otpToken.isNullOrEmpty()}")

            // Step 1: Validate all prerequisites
            val validationResult = validateVotePrerequisites(electionPairId, region)
            if (!validationResult.isValid) {
                Log.e(TAG, "❌ Vote prerequisites validation failed: ${validationResult.errorMessage}")
                emit(Result.failure(Exception(validationResult.errorMessage)))
                return@flow
            }
            Log.d(TAG, "✅ All vote prerequisites validated")

            // Step 2: Enhanced user key validation
            if (!validateUserKeys()) {
                Log.e(TAG, "❌ User key validation failed")

                // Provide specific error message based on the validation failure
                val errorMessage = when {
                    !cryptoKeyManager.hasStoredKeyPair() ->
                        "No wallet found. Please register first."

                    !cryptoKeyManager.validateKeyAccess() ->
                        "Key access error. The app will reset your keys. Please restart and register again."

                    cryptoKeyManager.getPrivateKey() == null ->
                        "Private key not accessible. Please restart the app and try again."

                    else ->
                        "Key validation failed. Please contact support if this persists."
                }

                emit(Result.failure(Exception(errorMessage)))
                return@flow
            }

            // Step 3: Get authentication token
            val token = getAuthToken()
            if (token.isNullOrEmpty()) {
                Log.e(TAG, "❌ No authentication token available")
                emit(Result.failure(Exception("Authentication required. Please login again.")))
                return@flow
            }

            // Step 4: Get or validate OTP token - IMPROVED OTP HANDLING
            val finalOtpToken = otpToken ?: getValidOtpToken()
            if (finalOtpToken.isNullOrEmpty()) {
                Log.e(TAG, "❌ No valid OTP token available - Please verify OTP again")
                emit(Result.failure(Exception("OTP verification required or token expired. Please verify OTP again.")))
                return@flow
            }

            Log.d(TAG, "✅ Valid OTP token found: ${finalOtpToken.length} chars")

            // Step 5: Generate signed transaction
            val signedTransaction = signedTransactionGenerator.generateVoteTransaction(
                electionPairId = electionPairId,
                voterId = getVoterId() ?: "",
                region = region,
                timestamp = System.currentTimeMillis()
            )

            if (signedTransaction.isNullOrEmpty()) {
                Log.e(TAG, "❌ Failed to generate signed transaction")
                emit(Result.failure(Exception("Failed to generate signed transaction. Please try again.")))
                return@flow
            }

            Log.d(TAG, "✅ Transaction signed successfully, hex length: ${signedTransaction.length}")
            Log.d(TAG, "✅ Signed transaction generated: ${signedTransaction.take(16)}...")
            Log.d(TAG, "✅ Signed transaction generated successfully")

            // Step 6: Create vote request with validated OTP token
            val voteRequest = VoteCastRequest(
                election_pair_id = electionPairId,
                region = region,
                voter_id = getVoterId() ?: "",
                signed_transaction = signedTransaction,
                otp_token = finalOtpToken
            )

            // Log detailed OTP and request information
            logVoteRequestDetails(voteRequest)
            Log.d(TAG, "📤 Sending vote request to server...")

            // Step 7: Submit vote to server
            val response = voteApiService.castVoteWithOTP(
                token = "Bearer $token",
                request = voteRequest
            )

            if (response.isSuccessful) {
                val voteResponse = response.body()
                if (voteResponse != null) {
                    Log.d(TAG, "✅ Vote cast successfully!")
                    Log.d(TAG, "  - Transaction Hash: ${voteResponse.data?.tx_hash}")
                    Log.d(TAG, "  - Status: ${voteResponse.data?.status}")

                    // Mark as voted
                    updateLocalVotingStatus(electionPairId, voteResponse.data?.tx_hash, signedTransaction)

                    // Clear OTP token after successful vote
                    otpRepository.clearOTPToken()

                    emit(Result.success(voteResponse))
                } else {
                    Log.e(TAG, "❌ Empty response from server")
                    emit(Result.failure(Exception("Empty response from server")))
                }
            } else {
                val errorBody = response.errorBody()?.string()
                val errorMessage = when (response.code()) {
                    400 -> "Invalid vote data. Please check your selection and try again."
                    401 -> "Authentication failed. Please login again."
                    403 -> "You have already voted or are not authorized to vote."
                    422 -> "Invalid transaction signature. Please restart app and try again."
                    429 -> "Too many requests. Please wait and try again."
                    500 -> "Server error. Please try again later."
                    else -> "Vote failed: HTTP ${response.code()} - $errorBody"
                }

                // Clear OTP token if it's an auth or OTP-related error
                if (response.code() in listOf(401, 422)) {
                    Log.w(TAG, "⚠️ Clearing OTP token due to auth/OTP error")
                    otpRepository.clearOTPToken()
                }

                Log.e(TAG, "❌ Vote casting failed: $errorMessage")
                emit(Result.failure(Exception(errorMessage)))
            }

        } catch (e: Exception) {
            Log.e(TAG, "❌ Exception during vote casting: ${e.message}", e)
            emit(Result.failure(Exception("Unexpected error: ${e.message}")))
        }
    }.flowOn(Dispatchers.IO)

    /**
     * Validate all prerequisites for voting
     */
    private fun validateVotePrerequisites(electionPairId: String, region: String): ValidationResult {
        // Validate inputs
        if (electionPairId.isBlank()) {
            return ValidationResult(false, "Election pair ID is required")
        }

        if (region.isBlank()) {
            return ValidationResult(false, "Region is required")
        }

        if (electionPairId.length > 100) {
            return ValidationResult(false, "Election pair ID is too long")
        }

        if (region.length > 50) {
            return ValidationResult(false, "Region name is too long")
        }

        return ValidationResult(true, "All prerequisites validated")
    }

    /**
     * Get authentication token from stored credentials
     */
    private fun getAuthToken(): String? {
        val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return sharedPreferences.getString("auth_token", null)
            ?: sharedPreferences.getString("user_token", null)
            ?: sharedPreferences.getString("access_token", null)
    }

    /**
     * Get voter ID from stored user data
     */
    private fun getVoterId(): String? {
        val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return sharedPreferences.getString("user_id", null)
            ?: sharedPreferences.getString("voter_id", null)
            ?: sharedPreferences.getString("nik", null)
    }

    /**
     * Get the OTP token, ensuring it's fresh and valid
     * Added to fix the OTP expiration issue
     */
    private fun getValidOtpToken(): String? {
        // First check if we have a stored token
        val storedToken = otpRepository.getStoredOTPToken()

        if (storedToken.isNullOrEmpty()) {
            Log.w(TAG, "⚠️ No OTP token found")
            return null
        }

        // Check if the token is still valid
        if (otpRepository.isOTPTokenValid()) {
            // Token is valid
            Log.d(TAG, "✅ OTP token is valid")
            return storedToken
        } else {
            Log.w(TAG, "⚠️ OTP token is expired or invalid, clearing it")
            otpRepository.clearOTPToken()
            return null
        }
    }

    /**
     * Get active voting categories
     */
    fun getActiveVotings(): Flow<Result<List<VotingCategory>>> = flow {
        try {
            // Simulate network delay
            delay(1000)

            // Instead of returning empty list, return default Presidential election card
            val defaultPresidentialElection = VotingCategory(
                id = "presidential_2024",
                title = "Presidential Election 2024 - Indonesia",
                description = "Choose the leaders you trust to guide Indonesia forward",
                isActive = true
            )

            // Return dummy data for now - replace with actual API call
            emit(Result.success(listOf(defaultPresidentialElection)))
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }.flowOn(Dispatchers.IO)

    /**
     * Get voting results
     */
    fun getVotingResults(): Flow<Result<List<VotingCategory>>> = flow {
        try {
            // Simulate network delay
            delay(1000)

            val defaultPresidentialResult = VotingCategory(
                id = "presidential_2024",
                title = "Presidential Election 2024 - Indonesia",
                description = "View the election results and vote distribution",
                isActive = false // For results, set to false to indicate it's completed
            )

            emit(Result.success(listOf(defaultPresidentialResult)))
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }.flowOn(Dispatchers.IO)

    /**
     * Check if user has already voted
     */
    fun hasUserVoted(): Boolean {
        val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return sharedPreferences.getBoolean(KEY_HAS_VOTED, false)
    }

    /**
     * Update local voting status with additional transaction details
     */
    private fun updateLocalVotingStatus(electionPairId: String, txHash: String?, signedTransaction: String) {
        val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        with(sharedPreferences.edit()) {
            putBoolean("has_voted", true)
            putString("last_vote_election_pair_id", electionPairId)
            putString("last_vote_tx_hash", txHash)
            putString("last_vote_signed_transaction", signedTransaction)
            putLong("last_vote_timestamp", System.currentTimeMillis())
            apply()
        }
        Log.d(TAG, "✅ Local voting status updated")
    }

    class Factory(private val context: Context) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            if (modelClass.isAssignableFrom(VotingViewModel::class.java)) {
                return VotingViewModel(
                    context = context,
                    repository = VotingRepository(context, CryptoKeyManager(context))
                ) as T
            }
            throw IllegalArgumentException("Unknown ViewModel class")
        }
    }

    /**
     * Log detailed vote request information
     */
    private fun logVoteRequestDetails(voteRequest: VoteCastRequest) {
        Log.d(TAG, "📋 Vote Request Details:")
        Log.d(TAG, "  - Election Pair ID: ${voteRequest.election_pair_id}")
        Log.d(TAG, "  - Region: ${voteRequest.region}")
        Log.d(TAG, "  - Voter ID: ${voteRequest.voter_id}")
        Log.d(TAG, "  - OTP Token: ${if (voteRequest.otp_token.isNotEmpty()) "✅ Present (${voteRequest.otp_token.length} chars)" else "❌ Missing"}")
        Log.d(TAG, "  - Signed Transaction: ${if (voteRequest.signed_transaction.isNotEmpty()) "✅ Present (${voteRequest.signed_transaction.length} chars)" else "❌ Missing"}")
        Log.d(TAG, "  - Transaction preview: ${voteRequest.signed_transaction.take(32)}...")
    }

    /**
     * Data classes for validation results
     */
    data class ValidationResult(
        val isValid: Boolean,
        val errorMessage: String
    )
}
