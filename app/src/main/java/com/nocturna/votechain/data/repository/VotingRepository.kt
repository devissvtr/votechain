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
import com.nocturna.votechain.utils.VoteValidationHelper
import com.nocturna.votechain.utils.VoteValidationHelper.ValidationResult
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
     * Cast a vote with enhanced signed transaction validation
     * @param electionPairId The ID of the selected candidate pair
     * @param region The voter's region
     * @param otpToken Optional OTP token (will be retrieved if not provided)
     * @return Flow with the result of the vote casting operation
     */
    fun castVoteWithSignedTransaction(
        electionPairId: String,
        region: String,
        otpToken: String? = null
    ): Flow<Result<VoteCastResponse>> = flow {
        try {
            Log.d(TAG, "🗳️ Starting enhanced vote casting process")
            Log.d(TAG, "  - Election Pair ID: $electionPairId")
            Log.d(TAG, "  - Region: $region")

            // Step 1: Validate all prerequisites
            val validationResult = validateVotePrerequisites(electionPairId, region)
            if (!validationResult.isValid) {
                Log.e(TAG, "❌ Vote prerequisites validation failed")
                emit(Result.failure(Exception(validationResult.errorMessage)))
                return@flow
            }

            Log.d(TAG, "✅ All vote prerequisites validated")

            // Step 2: Get or validate OTP token
            val finalOtpToken = otpToken ?: otpRepository.getStoredOTPToken()
            if (finalOtpToken.isNullOrEmpty()) {
                Log.e(TAG, "❌ OTP token is required")
                emit(Result.failure(Exception("OTP verification required. Please verify OTP first.")))
                return@flow
            }

            // Step 3: Get user credentials
            val authToken = getAuthToken()
            val voterId = getVoterId()

            if (authToken.isNullOrEmpty() || voterId.isNullOrEmpty()) {
                Log.e(TAG, "❌ Authentication credentials missing")
                emit(Result.failure(Exception("Authentication required. Please login again.")))
                return@flow
            }

            Log.d(TAG, "✅ Authentication credentials validated")

            // Step 4: Validate cryptographic keys from user profile
            val keyValidation = validateUserKeys()
            if (!keyValidation.isValid) {
                Log.e(TAG, "❌ User key validation failed: ${keyValidation.error}")
                emit(Result.failure(Exception("Cryptographic keys validation failed: ${keyValidation.error}")))
                return@flow
            }

            Log.d(TAG, "✅ User cryptographic keys validated")

            // Step 5: Generate signed transaction using user's private/public keys
            Log.d(TAG, "🔐 Generating signed transaction...")
            val signedTransaction = signedTransactionGenerator.generateVoteTransaction(
                electionPairId = electionPairId,
                voterId = voterId,
                region = region,
                timestamp = System.currentTimeMillis()
            )

            if (signedTransaction.isNullOrEmpty()) {
                Log.e(TAG, "❌ Failed to generate signed transaction")
                emit(Result.failure(Exception("Failed to generate signed transaction. Please try again.")))
                return@flow
            }

            // Step 6: Validate the generated signed transaction
            val transactionValidation = signedTransactionGenerator.validateSignedTransaction(signedTransaction)
            if (!transactionValidation.isValid) {
                Log.e(TAG, "❌ Signed transaction validation failed: ${transactionValidation.error}")
                emit(Result.failure(Exception("Invalid signed transaction generated: ${transactionValidation.error}")))
                return@flow
            }

            Log.d(TAG, "✅ Signed transaction generated and validated successfully")
            Log.d(TAG, "  - Transaction length: ${signedTransaction.length} characters")
            Log.d(TAG, "  - Transaction hash preview: ${signedTransaction.take(16)}...")

            // Step 7: Create vote request exactly as specified
            val voteRequest = VoteCastRequest(
                election_pair_id = electionPairId,
                otp_token = finalOtpToken,
                region = region,
                signed_transaction = signedTransaction,
                voter_id = voterId
            )

            // Step 8: Log request details for debugging
            logVoteRequestDetails(voteRequest)

            Log.d(TAG, "🌐 Sending vote to v1/vote/cast endpoint")

            // Step 9: Make API call to v1/vote/cast
            val response = voteApiService.castVoteWithOTP(
                token = "Bearer $authToken",
                request = voteRequest
            )

            Log.d(TAG, "📡 API response received - HTTP ${response.code()}")

            // Step 10: Handle response
            if (response.isSuccessful) {
                val voteResponse = response.body()
                if (voteResponse != null) {
                    Log.d(TAG, "✅ Vote cast successfully!")
                    Log.d(TAG, "  - Response code: ${voteResponse.code}")
                    Log.d(TAG, "  - Vote ID: ${voteResponse.data?.id}")
                    Log.d(TAG, "  - Status: ${voteResponse.data?.status}")
                    Log.d(TAG, "  - TX Hash: ${voteResponse.data?.tx_hash}")
                    Log.d(TAG, "  - Voted At: ${voteResponse.data?.voted_at}")
                    Log.d(TAG, "  - Message: ${voteResponse.message}")

                    // Clear OTP token after successful vote
                    otpRepository.clearOTPToken()

                    // Update local voting status
                    updateLocalVotingStatus(electionPairId, voteResponse.data?.tx_hash, signedTransaction)

                    emit(Result.success(voteResponse))
                } else {
                    Log.e(TAG, "❌ Empty response body from vote API")
                    emit(Result.failure(Exception("Empty response from server")))
                }
            } else {
                handleVoteApiError(response.code(), response.errorBody()?.string())?.let { error ->
                    emit(Result.failure(error))
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "❌ Exception during vote casting", e)
            emit(Result.failure(e))
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
     * Validate user's cryptographic keys from profile
     */
    private fun validateUserKeys(): KeyValidationResult {
        try {
            // Check if key pair exists
            if (!cryptoKeyManager.hasStoredKeyPair()) {
                return KeyValidationResult(false, "No key pair found in user profile")
            }

            // Validate private key
            val privateKey = cryptoKeyManager.getPrivateKey()
            if (privateKey.isNullOrEmpty()) {
                return KeyValidationResult(false, "Private key not accessible from profile")
            }

            if (!cryptoKeyManager.validatePrivateKeyFormat(privateKey)) {
                return KeyValidationResult(false, "Private key format is invalid")
            }

            // Validate public key
            val publicKey = cryptoKeyManager.getPublicKey()
            if (publicKey.isNullOrEmpty()) {
                return KeyValidationResult(false, "Public key not accessible from profile")
            }

            // Test signing capability
            val testData = "test_${System.currentTimeMillis()}"
            val signature = cryptoKeyManager.signData(testData)
            if (signature.isNullOrEmpty()) {
                return KeyValidationResult(false, "Cannot generate signatures with current keys")
            }

            Log.d(TAG, "✅ User keys validation successful")
            Log.d(TAG, "  - Private key length: ${privateKey.length}")
            Log.d(TAG, "  - Public key length: ${publicKey.length}")

            return KeyValidationResult(true, "Keys validated successfully")

        } catch (e: Exception) {
            Log.e(TAG, "❌ Key validation exception: ${e.message}", e)
            return KeyValidationResult(false, "Key validation failed: ${e.message}")
        }
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
     * Handle API error responses
     */
    private fun handleVoteApiError(statusCode: Int, errorBody: String?): Exception? {
        Log.e(TAG, "❌ Vote API failed with code: $statusCode")
        Log.e(TAG, "Error body: $errorBody")

        val errorMessage = when (statusCode) {
            400 -> "Invalid vote data. Please check your selection and try again."
            401 -> "Authentication failed. Please login again."
            403 -> "You have already voted or are not authorized to vote."
            404 -> "Election not found or no longer available."
            422 -> "Invalid or expired OTP token. Please verify OTP again."
            429 -> "Too many requests. Please wait a moment and try again."
            500 -> "Server error. Please try again later."
            503 -> "Service temporarily unavailable. Please try again later."
            else -> "Failed to cast vote: HTTP $statusCode"
        }

        // Clear invalid tokens for specific error codes
        if (statusCode in listOf(401, 422)) {
            otpRepository.clearOTPToken()
        }

        return Exception(errorMessage)
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

    data class KeyValidationResult(
        val isValid: Boolean,
        val error: String?
    )
}