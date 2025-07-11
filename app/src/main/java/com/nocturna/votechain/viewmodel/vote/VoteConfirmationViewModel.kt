package com.nocturna.votechain.viewmodel.vote

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.nocturna.votechain.blockchain.BlockchainTransactionHelper
import com.nocturna.votechain.data.repository.VotingRepository
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Enhanced VoteConfirmationViewModel with proper blockchain integration
 */
class VoteConfirmationViewModel(
    private val context: Context,
    private val categoryId: String,
    private val electionPairId: String
) : ViewModel() {

    private val TAG = "VoteConfirmationViewModel"
    private val votingRepository = VotingRepository(context, CryptoKeyManager(context))
    private val blockchainTransactionHelper = BlockchainTransactionHelper(context)

    private val _uiState = MutableStateFlow(VoteConfirmationUiState())
    val uiState: StateFlow<VoteConfirmationUiState> = _uiState.asStateFlow()

    /**
     * Cast vote with enhanced blockchain integration
     */
    fun castVoteWithBlockchainIntegration(
        electionPairId: String,
        region: String,
        otpToken: String? = null
    ) {
        viewModelScope.launch {
            try {
                Log.d(TAG, "🗳️ Starting enhanced vote casting with blockchain integration")

                _uiState.value = _uiState.value.copy(
                    isLoading = true,
                    error = null,
                    step = VoteStep.VALIDATING_PREREQUISITES
                )

                // Step 1: Validate prerequisites
                if (!validatePrerequisites()) {
                    return@launch
                }

                // Step 2: Create blockchain transaction
                _uiState.value = _uiState.value.copy(step = VoteStep.CREATING_BLOCKCHAIN_TRANSACTION)

                val transactionResult = blockchainTransactionHelper.createVoteTransaction(
                    electionId = electionPairId,
                    electionNo = electionPairId
                )

                if (transactionResult.isFailure) {
                    Log.e(TAG, "❌ Failed to create blockchain transaction: ${transactionResult.exceptionOrNull()?.message}")
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        error = "Failed to create blockchain transaction: ${transactionResult.exceptionOrNull()?.message}",
                        step = VoteStep.ERROR
                    )
                    return@launch
                }

                val signedTransaction = transactionResult.getOrNull()!!

                // Step 3: Broadcast transaction to blockchain
                _uiState.value = _uiState.value.copy(step = VoteStep.BROADCASTING_TRANSACTION)

                val broadcastResult = blockchainTransactionHelper.broadcastTransaction(signedTransaction)

                if (broadcastResult.isFailure) {
                    Log.e(TAG, "❌ Failed to broadcast transaction: ${broadcastResult.exceptionOrNull()?.message}")
                    _uiState.value = _uiState.value.copy(
                        isLoading = false,
                        error = "Failed to broadcast transaction: ${broadcastResult.exceptionOrNull()?.message}",
                        step = VoteStep.ERROR
                    )
                    return@launch
                }

                val transactionHash = broadcastResult.getOrNull()!!

                // Step 4: Monitor transaction
                _uiState.value = _uiState.value.copy(
                    step = VoteStep.MONITORING_TRANSACTION,
                    transactionHash = transactionHash
                )

                // Step 5: Submit to API while monitoring blockchain
                _uiState.value = _uiState.value.copy(step = VoteStep.SUBMITTING_TO_API)

                votingRepository.castVoteWithSignedTransaction(electionPairId, region, otpToken)
                    .collect { result ->
                        result.fold(
                            onSuccess = { voteResponse ->
                                Log.d(TAG, "✅ Vote cast successfully!")
                                Log.d(TAG, "- API Response: ${voteResponse.message}")
                                Log.d(TAG, "- Vote ID: ${voteResponse.data?.id}")
                                Log.d(TAG, "- Transaction Hash: $transactionHash")

                                // Step 6: Monitor blockchain transaction
                                monitorBlockchainTransaction(transactionHash, voteResponse)
                            },
                            onFailure = { exception ->
                                Log.e(TAG, "❌ API vote submission failed: ${exception.message}")
                                _uiState.value = _uiState.value.copy(
                                    isLoading = false,
                                    error = "Vote submission failed: ${exception.message}",
                                    step = VoteStep.ERROR
                                )
                            }
                        )
                    }

            } catch (e: Exception) {
                Log.e(TAG, "❌ Unexpected error during vote casting: ${e.message}", e)
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    error = "Unexpected error: ${e.message}",
                    step = VoteStep.ERROR
                )
            }
        }
    }

    /**
     * Monitor blockchain transaction confirmation
     */
    private fun monitorBlockchainTransaction(
        transactionHash: String,
        voteResponse: com.nocturna.votechain.data.model.VoteCastResponse
    ) {
        viewModelScope.launch {
            try {
                Log.d(TAG, "👁️ Starting blockchain transaction monitoring")

                blockchainTransactionHelper.monitorTransaction(transactionHash)
                    .collect { status ->
                        when (status) {
                            is BlockchainTransactionHelper.TransactionStatus.Pending -> {
                                Log.d(TAG, "⏳ Transaction pending...")
                                _uiState.value = _uiState.value.copy(
                                    step = VoteStep.CONFIRMING_BLOCKCHAIN,
                                    blockchainStatus = "pending"
                                )
                            }
                            is BlockchainTransactionHelper.TransactionStatus.Confirmed -> {
                                Log.d(TAG, "✅ Transaction confirmed on blockchain!")
                                _uiState.value = _uiState.value.copy(
                                    isLoading = false,
                                    isVoteSuccess = true,
                                    step = VoteStep.COMPLETED,
                                    blockchainStatus = "confirmed",
                                    gasUsed = status.gasUsed,
                                    voteId = voteResponse.data?.id,
                                    voteStatus = voteResponse.data?.status,
                                    votedAt = voteResponse.data?.voted_at,
                                    responseMessage = voteResponse.message
                                )
                            }
                            is BlockchainTransactionHelper.TransactionStatus.Failed -> {
                                Log.e(TAG, "❌ Transaction failed on blockchain: ${status.reason}")
                                _uiState.value = _uiState.value.copy(
                                    isLoading = false,
                                    error = "Blockchain transaction failed: ${status.reason}",
                                    step = VoteStep.ERROR,
                                    blockchainStatus = "failed"
                                )
                            }
                            is BlockchainTransactionHelper.TransactionStatus.Timeout -> {
                                Log.w(TAG, "⏰ Transaction confirmation timeout")
                                _uiState.value = _uiState.value.copy(
                                    isLoading = false,
                                    isVoteSuccess = true, // API succeeded, blockchain timed out
                                    step = VoteStep.COMPLETED,
                                    blockchainStatus = "timeout",
                                    voteId = voteResponse.data?.id,
                                    voteStatus = voteResponse.data?.status,
                                    votedAt = voteResponse.data?.voted_at,
                                    responseMessage = voteResponse.message,
                                    error = "Vote submitted successfully but blockchain confirmation timed out"
                                )
                            }
                            is BlockchainTransactionHelper.TransactionStatus.Error -> {
                                Log.e(TAG, "❌ Error monitoring transaction: ${status.message}")
                                _uiState.value = _uiState.value.copy(
                                    isLoading = false,
                                    isVoteSuccess = true, // API succeeded, blockchain monitoring failed
                                    step = VoteStep.COMPLETED,
                                    blockchainStatus = "error",
                                    voteId = voteResponse.data?.id,
                                    voteStatus = voteResponse.data?.status,
                                    votedAt = voteResponse.data?.voted_at,
                                    responseMessage = voteResponse.message,
                                    error = "Vote submitted successfully but blockchain monitoring failed"
                                )
                            }
                        }
                    }
            } catch (e: Exception) {
                Log.e(TAG, "❌ Error monitoring blockchain transaction: ${e.message}", e)
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    isVoteSuccess = true, // API succeeded, monitoring failed
                    step = VoteStep.COMPLETED,
                    blockchainStatus = "error",
                    voteId = voteResponse.data?.id,
                    voteStatus = voteResponse.data?.status,
                    votedAt = voteResponse.data?.voted_at,
                    responseMessage = voteResponse.message,
                    error = "Vote submitted successfully but blockchain monitoring failed"
                )
            }
        }
    }

    /**
     * Validate prerequisites for voting
     */
    private fun validatePrerequisites(): Boolean {
        try {
            val cryptoKeyManager = CryptoKeyManager(context)

            // Check if user has valid keys
            if (!cryptoKeyManager.hasStoredKeyPair()) {
                Log.e(TAG, "❌ No stored key pair found")
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    error = "Wallet not found. Please check your account setup.",
                    step = VoteStep.ERROR
                )
                return false
            }

            val privateKey = cryptoKeyManager.getPrivateKey()
            val voterAddress = cryptoKeyManager.getVoterAddress()

            if (privateKey == null || voterAddress == null) {
                Log.e(TAG, "❌ Invalid keys found")
                _uiState.value = _uiState.value.copy(
                    isLoading = false,
                    error = "Invalid wallet keys. Please check your account setup.",
                    step = VoteStep.ERROR
                )
                return false
            }

            Log.d(TAG, "✅ Prerequisites validated successfully")
            return true
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error validating prerequisites: ${e.message}", e)
            _uiState.value = _uiState.value.copy(
                isLoading = false,
                error = "Error validating prerequisites: ${e.message}",
                step = VoteStep.ERROR
            )
            return false
        }
    }

    /**
     * Legacy method for backward compatibility
     */
    fun castVoteWithSignedTransaction(
        electionPairId: String,
        region: String,
        otpToken: String? = null
    ) {
        castVoteWithBlockchainIntegration(electionPairId, region, otpToken)
    }

    /**
     * Retry vote casting
     */
    fun retryVote() {
        val region = getStoredRegion() ?: "default"
        val otpToken = getStoredOtpToken()
        castVoteWithBlockchainIntegration(electionPairId, region, otpToken)
    }

    /**
     * Clear error state
     */
    fun clearError() {
        _uiState.value = _uiState.value.copy(
            error = null,
            step = VoteStep.READY
        )
    }

    /**
     * Get stored region from preferences
     */
    private fun getStoredRegion(): String? {
        val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
        return sharedPreferences.getString("user_region", null)
    }

    /**
     * Get stored OTP token from preferences
     */
    private fun getStoredOtpToken(): String? {
        val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
        return sharedPreferences.getString("otp_token", null)
    }

    /**
     * Get transaction explorer URL
     */
    fun getTransactionExplorerUrl(): String? {
        val txHash = _uiState.value.transactionHash
        return if (txHash != null) {
            com.nocturna.votechain.blockchain.BlockchainConfig.getTransactionUrl(txHash)
        } else {
            null
        }
    }

    /**
     * Check if blockchain is connected
     */
    suspend fun isBlockchainConnected(): Boolean {
        return try {
            com.nocturna.votechain.blockchain.BlockchainManager.isConnected()
        } catch (e: Exception) {
            Log.e(TAG, "Error checking blockchain connection: ${e.message}", e)
            false
        }
    }

    /**
     * Factory for creating VoteConfirmationViewModel
     */
    class Factory(
        private val context: Context,
        private val categoryId: String,
        private val electionPairId: String
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            if (modelClass.isAssignableFrom(VoteConfirmationViewModel::class.java)) {
                return VoteConfirmationViewModel(context, categoryId, electionPairId) as T
            }
            throw IllegalArgumentException("Unknown ViewModel class")
        }
    }
}

/**
 * Enhanced UI State for Vote Confirmation Screen
 */
data class VoteConfirmationUiState(
    val isLoading: Boolean = false,
    val isVoteSuccess: Boolean = false,
    val error: String? = null,
    val step: VoteStep = VoteStep.READY,
    val transactionHash: String? = null,
    val blockchainStatus: String? = null,
    val gasUsed: String? = null,
    val voteId: String? = null,
    val voteStatus: String? = null,
    val votedAt: String? = null,
    val responseMessage: String? = null
)

/**
 * Enhanced enum for tracking vote process steps
 */
enum class VoteStep {
    READY,
    VALIDATING_PREREQUISITES,
    CREATING_BLOCKCHAIN_TRANSACTION,
    BROADCASTING_TRANSACTION,
    MONITORING_TRANSACTION,
    SUBMITTING_TO_API,
    CONFIRMING_BLOCKCHAIN,
    COMPLETED,
    ERROR
}