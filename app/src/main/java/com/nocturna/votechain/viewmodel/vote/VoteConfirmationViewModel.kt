package com.nocturna.votechain.viewmodel.vote

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.nocturna.votechain.data.repository.VotingRepository
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * ViewModel for Vote Confirmation Screen
 */
class VoteConfirmationViewModel(
    private val context: Context,
    private val categoryId: String,
    private val electionPairId: String
) : ViewModel() {

    private val TAG = "VoteConfirmationViewModel"
    private val votingRepository = VotingRepository(context, CryptoKeyManager(context))

    private val _uiState = MutableStateFlow(EnhancedVoteConfirmationUiState())
    val uiState: StateFlow<EnhancedVoteConfirmationUiState> = _uiState.asStateFlow()

    /**
     * Cast vote with enhanced signed transaction validation
     * @param electionPairId The ID of the election pair to vote for
     * @param region The voter's region
     * @param otpToken The OTP token for verification (optional)
     */
    fun castVoteWithSignedTransaction(
        electionPairId: String,
        region: String,
        otpToken: String? = null
    ) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isLoading = true,
                error = null,
                step = VoteStep.VALIDATING_PREREQUISITES
            )

            Log.d(TAG, "🗳️ Starting enhanced vote casting process...")
            Log.d(TAG, "  - Election Pair ID: $electionPairId")
            Log.d(TAG, "  - Region: $region")
            Log.d(TAG, "  - OTP Token provided: ${!otpToken.isNullOrEmpty()}")

            // Update UI to show transaction generation step
            _uiState.value = _uiState.value.copy(step = VoteStep.GENERATING_TRANSACTION)

            votingRepository.castVoteWithSignedTransaction(electionPairId, region)
                .collect { result ->
                    result.fold(
                        onSuccess = { voteResponse ->
                            Log.d(TAG, "✅ Vote cast successfully!")
                            Log.d(TAG, "  - Response code: ${voteResponse.code}")
                            Log.d(TAG, "  - Message: ${voteResponse.message}")
                            Log.d(TAG, "  - Vote ID: ${voteResponse.data?.id}")
                            Log.d(TAG, "  - Status: ${voteResponse.data?.status}")
                            Log.d(TAG, "  - Transaction Hash: ${voteResponse.data?.tx_hash}")
                            Log.d(TAG, "  - Voted At: ${voteResponse.data?.voted_at}")

                            _uiState.value = _uiState.value.copy(
                                isLoading = false,
                                isVoteSuccess = true,
                                error = null,
                                step = VoteStep.COMPLETED,
                                transactionHash = voteResponse.data?.tx_hash,
                                voteId = voteResponse.data?.id,
                                voteStatus = voteResponse.data?.status,
                                votedAt = voteResponse.data?.voted_at,
                                responseMessage = voteResponse.message
                            )
                        },
                        onFailure = { exception ->
                            Log.e(TAG, "❌ Vote casting failed: ${exception.message}")
                            _uiState.value = _uiState.value.copy(
                                isLoading = false,
                                error = exception.message ?: "Failed to cast vote",
                                step = VoteStep.ERROR
                            )
                        }
                    )
                }
        }
    }

    /**
     * Retry vote casting
     */
    fun retryVote() {
        val region = getStoredRegion() ?: "default"
        val otpToken = getStoredOtpToken()
        castVoteWithSignedTransaction(electionPairId, region, otpToken)
    }

    /**
     * Clear error state
     */
    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null, step = VoteStep.READY)
    }

    private fun getStoredRegion(): String? {
        val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
        return sharedPreferences.getString("user_region", null)
    }

    private fun getStoredOtpToken(): String? {
        val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
        return sharedPreferences.getString("otp_token", null)
    }

    /**
     * Factory for creating EnhancedVoteConfirmationViewModel
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
data class EnhancedVoteConfirmationUiState(
    val isLoading: Boolean = false,
    val isVoteSuccess: Boolean = false,
    val error: String? = null,
    val step: VoteStep = VoteStep.READY,
    val transactionHash: String? = null,
    val voteId: String? = null,
    val voteStatus: String? = null,
    val votedAt: String? = null,
    val responseMessage: String? = null
)

/**
 * Enum for tracking vote process steps
 */
enum class VoteStep {
    READY,
    VALIDATING_PREREQUISITES,
    GENERATING_TRANSACTION,
    SUBMITTING_VOTE,
    COMPLETED,
    ERROR
}