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

    private val _uiState = MutableStateFlow(VoteConfirmationUiState())
    val uiState: StateFlow<VoteConfirmationUiState> = _uiState.asStateFlow()

    /**
     * Cast the vote using the verified OTP token
     * This method now properly accepts parameters from the UI
     *
     * @param electionPairId The ID of the election pair to vote for
     * @param region The voter's region
     * @param otpToken The OTP token for verification
     */
    fun castVote(electionPairId: String, region: String, otpToken: String) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, error = null)

            Log.d(TAG, "Starting vote casting process...")
            Log.d(TAG, "Election Pair ID: $electionPairId")
            Log.d(TAG, "Region: $region")
            Log.d(TAG, "OTP Token present: ${otpToken.isNotEmpty()}")

            // Use the castVoteWithOTPVerification method which already handles:
            // 1. Validation of prerequisites
            // 2. Generation of signed transaction using private/public keys
            // 3. Sending to /v1/vote/cast endpoint
            votingRepository.castVoteWithOTPVerification(electionPairId, region)
                .collect { result ->
                    result.fold(
                        onSuccess = { voteResponse ->
                            Log.d(TAG, "✅ Vote cast successfully!")
                            Log.d(TAG, "Response: ${voteResponse.message}")
                            Log.d(TAG, "Transaction Hash: ${voteResponse.data?.tx_hash}")

                            _uiState.value = _uiState.value.copy(
                                isLoading = false,
                                isVoteSuccess = true,
                                error = null,
                                transactionHash = voteResponse.data?.tx_hash
                            )
                        },
                        onFailure = { e ->
                            Log.e(TAG, "❌ Vote casting failed: ${e.message}")
                            _uiState.value = _uiState.value.copy(
                                isLoading = false,
                                error = e.message ?: "Failed to cast vote"
                            )
                        }
                    )
                }
        }
    }

    /**
     * Alternative method without parameters for backward compatibility
     * Uses the electionPairId from constructor
     */
    fun castVote() {
        val region = getStoredRegion() ?: "default"
        val otpToken = getStoredOtpToken() ?: ""
        castVote(electionPairId, region, otpToken)
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
 * UI State for Vote Confirmation Screen
 */
data class VoteConfirmationUiState(
    val isLoading: Boolean = false,
    val isVoteSuccess: Boolean = false,
    val error: String? = null,
    val transactionHash: String? = null
)