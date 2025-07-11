package com.nocturna.votechain.data.repository

import android.content.Context
import android.util.Log
import com.nocturna.votechain.blockchain.BlockchainManager
import com.nocturna.votechain.blockchain.VoteResult
import com.nocturna.votechain.data.model.VoteCastData
import com.nocturna.votechain.data.model.VoteCastResponse
import com.nocturna.votechain.data.model.VotingCategory
import com.nocturna.votechain.data.network.NetworkClient
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import retrofit2.HttpException
import java.io.IOException

/**
 * Enhanced VotingRepository with proper blockchain integration
 */
class VotingRepository(
    private val context: Context,
    private val cryptoKeyManager: CryptoKeyManager
) {
    private val TAG = "VotingRepository"
    private val apiService = NetworkClient.apiService
    private val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)

    /**
     * Cast vote with signed blockchain transaction
     */
    fun castVoteWithSignedTransaction(
        electionPairId: String,
        region: String,
        otpToken: String? = null
    ): Flow<Result<VoteCastResponse>> = flow {
        try {
            Log.d(TAG, "🗳️ Starting enhanced vote casting with blockchain integration")
            Log.d(TAG, "- Election Pair ID: $electionPairId")
            Log.d(TAG, "- Region: $region")
            Log.d(TAG, "- OTP Token: ${if (otpToken != null) "✅ Provided" else "❌ Not provided"}")

            // Step 1: Get private key from crypto manager
            val privateKey = cryptoKeyManager.getPrivateKey()
            if (privateKey == null) {
                Log.e(TAG, "❌ Private key not found")
                emit(Result.failure(SecurityException("Private key not found. Please check your wallet configuration.")))
                return@flow
            }

            val voterAddress = cryptoKeyManager.getVoterAddress()
            if (voterAddress == null) {
                Log.e(TAG, "❌ Voter address not found")
                emit(Result.failure(SecurityException("Voter address not found. Please check your wallet configuration.")))
                return@flow
            }

            Log.d(TAG, "✅ Crypto keys loaded successfully")
            Log.d(TAG, "- Voter Address: $voterAddress")
            Log.d(TAG, "- Private Key Available: ${privateKey.length == 66}")

            // Step 2: Check blockchain connection
            if (!BlockchainManager.isConnected()) {
                Log.w(TAG, "⚠️ Blockchain not connected, will proceed with API-only vote")
            } else {
                Log.d(TAG, "✅ Blockchain connected")
            }

            // Step 3: Cast vote on blockchain first (if connected)
            var blockchainTxHash: String? = null
            if (BlockchainManager.isConnected()) {
                try {
                    Log.d(TAG, "🔗 Casting vote on blockchain...")

                    // For voting, we use the election pair ID as both electionId and electionNo
                    // This matches the web wallet implementation
                    val voteResult = BlockchainManager.castVote(
                        privateKey = privateKey,
                        electionId = electionPairId,
                        electionNo = electionPairId
                    )

                    when (voteResult) {
                        is VoteResult.Success -> {
                            blockchainTxHash = voteResult.transactionHash
                            Log.d(TAG, "✅ Blockchain vote successful: $blockchainTxHash")
                        }
                        is VoteResult.Pending -> {
                            blockchainTxHash = voteResult.transactionHash
                            Log.d(TAG, "⏳ Blockchain vote pending: $blockchainTxHash")
                        }
                        is VoteResult.Error -> {
                            Log.e(TAG, "❌ Blockchain vote failed: ${voteResult.message}")
                            // Continue with API call even if blockchain fails
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "❌ Blockchain vote exception: ${e.message}", e)
                    // Continue with API call even if blockchain fails
                }
            }

            // Step 4: Create vote request data
            val voteRequestData = createVoteRequestData(
                electionPairId = electionPairId,
                region = region,
                voterAddress = voterAddress,
                blockchainTxHash = blockchainTxHash,
                otpToken = otpToken
            )

            // Step 5: Submit vote to API
            Log.d(TAG, "📡 Submitting vote to API...")
            val response = apiService.castVote(voteRequestData)

            if (response.isSuccessful) {
                val voteResponse = response.body()
                if (voteResponse != null) {
                    Log.d(TAG, "✅ API vote successful")
                    Log.d(TAG, "- Response Code: ${voteResponse.code}")
                    Log.d(TAG, "- Message: ${voteResponse.message}")
                    Log.d(TAG, "- Vote ID: ${voteResponse.data?.id}")
                    Log.d(TAG, "- Transaction Hash: ${voteResponse.data?.tx_hash}")

                    // Step 6: Update local vote status
                    updateLocalVoteStatus(electionPairId, voteResponse.data?.id, blockchainTxHash)

                    emit(Result.success(voteResponse) as Result<*>)
                } else {
                    Log.e(TAG, "❌ API response body is null")
                    emit(Result.failure(Exception("Empty response from server")))
                }
            } else {
                Log.e(TAG, "❌ API vote failed: ${response.code()} - ${response.message()}")
                val errorBody = response.errorBody()?.string()
                emit(Result.failure(HttpException(response)))
            }

        } catch (e: IOException) {
            Log.e(TAG, "❌ Network error during vote casting: ${e.message}", e)
            emit(Result.failure(IOException("Network error. Please check your internet connection.", e)))
        } catch (e: HttpException) {
            Log.e(TAG, "❌ HTTP error during vote casting: ${e.message}", e)
            emit(Result.failure(e))
        } catch (e: SecurityException) {
            Log.e(TAG, "❌ Security error during vote casting: ${e.message}", e)
            emit(Result.failure(e))
        } catch (e: Exception) {
            Log.e(TAG, "❌ Unexpected error during vote casting: ${e.message}", e)
            emit(Result.failure(Exception("Unexpected error occurred: ${e.message}", e)))
        }
    }

    /**
     * Create vote request data for API
     */
    private fun createVoteRequestData(
        electionPairId: String,
        region: String,
        voterAddress: String,
        blockchainTxHash: String?,
        otpToken: String?
    ): Map<String, Any> {
        val voteData = mutableMapOf<String, Any>(
            "election_pair_id" to electionPairId,
            "region" to region,
            "voter_address" to voterAddress
        )

        // Add blockchain transaction hash if available
        blockchainTxHash?.let {
            voteData["blockchain_tx_hash"] = it
        }

        // Add OTP token if provided
        otpToken?.let {
            voteData["otp_token"] = it
        }

        // Add timestamp
        voteData["timestamp"] = System.currentTimeMillis()

        return voteData
    }

    /**
     * Update local vote status
     */
    private fun updateLocalVoteStatus(electionPairId: String, voteId: String?, blockchainTxHash: String?) {
        try {
            with(sharedPreferences.edit()) {
                putBoolean("has_voted", true)
                putString("voted_election_pair_id", electionPairId)
                putLong("vote_timestamp", System.currentTimeMillis())

                voteId?.let {
                    putString("vote_id", it)
                }

                blockchainTxHash?.let {
                    putString("blockchain_tx_hash", it)
                }

                apply()
            }
            Log.d(TAG, "✅ Local vote status updated")
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error updating local vote status: ${e.message}", e)
        }
    }

    /**
     * Get active voting categories
     */
    fun getActiveVotings(): Flow<Result<List<VotingCategory>>> = flow {
        try {
            Log.d(TAG, "📋 Fetching active voting categories")

            val response = apiService.getActiveVotings()
            if (response.isSuccessful) {
                val votings = response.body()?.data ?: emptyList()
                Log.d(TAG, "✅ Active votings fetched: ${votings.size} categories")
                emit(Result.success(votings))
            } else {
                Log.e(TAG, "❌ Failed to fetch active votings: ${response.code()}")
                emit(Result.failure(HttpException(response)))
            }
        } catch (e: IOException) {
            Log.e(TAG, "❌ Network error fetching active votings: ${e.message}", e)
            emit(Result.failure(e))
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error fetching active votings: ${e.message}", e)
            emit(Result.failure(e))
        }
    }

    /**
     * Get voting results
     */
    fun getVotingResults(): Flow<Result<List<VotingCategory>>> = flow {
        try {
            Log.d(TAG, "📊 Fetching voting results")

            val response = apiService.getVotingResults()
            if (response.isSuccessful) {
                val results = response.body()?.data ?: emptyList()
                Log.d(TAG, "✅ Voting results fetched: ${results.size} categories")
                emit(Result.success(results))
            } else {
                Log.e(TAG, "❌ Failed to fetch voting results: ${response.code()}")
                emit(Result.failure(HttpException(response)))
            }
        } catch (e: IOException) {
            Log.e(TAG, "❌ Network error fetching voting results: ${e.message}", e)
            emit(Result.failure(e))
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error fetching voting results: ${e.message}", e)
            emit(Result.failure(e))
        }
    }

    /**
     * Check if user has voted
     */
    fun hasUserVoted(): Boolean {
        return sharedPreferences.getBoolean("has_voted", false)
    }

    /**
     * Get user's vote information
     */
    fun getUserVoteInfo(): VoteInfo? {
        return try {
            if (!hasUserVoted()) {
                null
            } else {
                VoteInfo(
                    electionPairId = sharedPreferences.getString("voted_election_pair_id", null),
                    voteId = sharedPreferences.getString("vote_id", null),
                    blockchainTxHash = sharedPreferences.getString("blockchain_tx_hash", null),
                    timestamp = sharedPreferences.getLong("vote_timestamp", 0)
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting user vote info: ${e.message}", e)
            null
        }
    }

    /**
     * Clear vote status (for testing purposes)
     */
    fun clearVoteStatus() {
        try {
            with(sharedPreferences.edit()) {
                remove("has_voted")
                remove("voted_election_pair_id")
                remove("vote_id")
                remove("blockchain_tx_hash")
                remove("vote_timestamp")
                apply()
            }
            Log.d(TAG, "✅ Vote status cleared")
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error clearing vote status: ${e.message}", e)
        }
    }

    /**
     * Check voting status on blockchain
     */
    suspend fun checkVotingStatusOnBlockchain(): Boolean {
        return try {
            BlockchainManager.isVotingActive()
        } catch (e: Exception) {
            Log.e(TAG, "Error checking voting status on blockchain: ${e.message}", e)
            false
        }
    }

    /**
     * Get transaction status from blockchain
     */
    suspend fun getTransactionStatus(txHash: String): String {
        return try {
            val status = BlockchainManager.getTransactionStatus(txHash)
            when (status) {
                is com.nocturna.votechain.blockchain.TransactionStatus.Confirmed -> "confirmed"
                is com.nocturna.votechain.blockchain.TransactionStatus.Failed -> "failed"
                is com.nocturna.votechain.blockchain.TransactionStatus.Pending -> "pending"
                is com.nocturna.votechain.blockchain.TransactionStatus.Unknown -> "unknown"
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting transaction status: ${e.message}", e)
            "unknown"
        }
    }

    /**
     * Legacy vote casting method for backward compatibility
     */
    fun submitVote(categoryId: String, optionId: String): Flow<Result<Unit>> = flow {
        try {
            Log.d(TAG, "📝 Legacy vote submission")
            Log.d(TAG, "- Category ID: $categoryId")
            Log.d(TAG, "- Option ID: $optionId")

            // For legacy compatibility, we'll map this to the new vote casting method
            // This assumes optionId is the election pair ID
            val voteFlow = castVoteWithSignedTransaction(
                electionPairId = optionId,
                region = getUserRegion() ?: "default",
                otpToken = null
            )

            voteFlow.collect { result ->
                result.fold(
                    onSuccess = {
                        emit(Result.success(Unit))
                    },
                    onFailure = { error ->
                        emit(Result.failure(error))
                    }
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error in legacy vote submission: ${e.message}", e)
            emit(Result.failure(e))
        }
    }

    /**
     * Get user region from preferences
     */
    private fun getUserRegion(): String? {
        return sharedPreferences.getString("user_region", null)
    }

    /**
     * Data class to hold user vote information
     */
    data class VoteInfo(
        val electionPairId: String?,
        val voteId: String?,
        val blockchainTxHash: String?,
        val timestamp: Long
    )
}