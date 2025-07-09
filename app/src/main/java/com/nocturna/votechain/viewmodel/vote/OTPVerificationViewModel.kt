package com.nocturna.votechain.viewmodel.vote

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.nocturna.votechain.data.model.OTPData
import com.nocturna.votechain.data.model.VoterData
import com.nocturna.votechain.data.repository.OTPRepository
import com.nocturna.votechain.data.repository.VoterRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch

/**
 * ViewModel for handling OTP verification logic
 */
class OTPVerificationViewModel(
    private val context: Context,
    private val categoryId: String
) : ViewModel() {

    private val TAG = "OTPVerificationViewModel"
    private val otpRepository = OTPRepository(context)
    private val voterRepository = VoterRepository(context)

    // UI State
    private val _uiState = MutableStateFlow(OTPVerificationUiState())
    val uiState: StateFlow<OTPVerificationUiState> = _uiState.asStateFlow()

    // Initialize and generate OTP when ViewModel is created
    init {
        generateOTP()
    }

    /**
     * Generate OTP for voting verification
     */
    fun generateOTP() {
        Log.d(TAG, "Generating OTP for category: $categoryId")

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isLoading = true, error = null)

            otpRepository.generateVotingOTP(categoryId).collect { result ->
                result.fold(
                    onSuccess = { response ->
                        Log.d(TAG, "OTP generation successful")
                        response.data?.let { otpData ->
                            _uiState.value = _uiState.value.copy(
                                isLoading = false,
                                otpData = otpData,
                                remainingAttempts = otpData.remaining_attempts,
                                timeRemainingSeconds = otpData.time_remaining_seconds.toIntOrNull() ?: 300,
                                error = null
                            )
                        } ?: run {
                            _uiState.value = _uiState.value.copy(
                                isLoading = false,
                                error = "Failed to generate OTP: No data received"
                            )
                        }
                    },
                    onFailure = { e ->
                        Log.e(TAG, "OTP generation failed: ${e.message}")
                        _uiState.value = _uiState.value.copy(
                            isLoading = false,
                            error = "Failed to generate OTP: ${e.message}"
                        )
                    }
                )
            }
        }
    }

    /**
     * Resend OTP
     */
    fun resendOTP() {
        Log.d(TAG, "Resending OTP for category: $categoryId")

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isResending = true, error = null)

            otpRepository.resendVotingOTP(categoryId).collect { result ->
                result.fold(
                    onSuccess = { response ->
                        Log.d(TAG, "OTP resend successful")
                        response.data?.let { otpData ->
                            _uiState.value = _uiState.value.copy(
                                isResending = false,
                                otpData = otpData,
                                remainingAttempts = otpData.remaining_attempts,
                                timeRemainingSeconds = otpData.time_remaining_seconds.toIntOrNull() ?: 300,
                                error = null
                            )
                        } ?: run {
                            _uiState.value = _uiState.value.copy(
                                isResending = false,
                                error = "Failed to resend OTP: No data received"
                            )
                        }
                    },
                    onFailure = { e ->
                        Log.e(TAG, "OTP resend failed: ${e.message}")
                        _uiState.value = _uiState.value.copy(
                            isResending = false,
                            error = "Failed to resend OTP: ${e.message}"
                        )
                    }
                )
            }
        }
    }

    /**
     * Verify OTP code
     */
    fun verifyOTP(otpCode: String) {
        Log.d(TAG, "Verifying OTP code: $otpCode")

        if (otpCode.length != 4) {
            _uiState.value = _uiState.value.copy(error = "Please enter a valid 4-digit OTP")
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isVerifying = true, error = null)

            otpRepository.verifyVotingOTP(categoryId, otpCode).collect { result ->
                result.fold(
                    onSuccess = { response ->
                        Log.d(TAG, "OTP verification response received")
                        if (response.data?.is_valid == true) {
                            Log.d(TAG, "OTP verification successful")
                            _uiState.value = _uiState.value.copy(
                                isVerifying = false,
                                isVerificationSuccess = true,
                                otpToken = response.data.otp_token,
                                error = null
                            )
                        } else {
                            Log.w(TAG, "OTP verification failed: Invalid code")
                            val currentAttempts = _uiState.value.remainingAttempts
                            _uiState.value = _uiState.value.copy(
                                isVerifying = false,
                                error = response.data?.message ?: "Invalid OTP code",
                                remainingAttempts = maxOf(0, currentAttempts - 1)
                            )
                        }
                    },
                    onFailure = { e ->
                        Log.e(TAG, "OTP verification failed: ${e.message}")
                        val currentAttempts = _uiState.value.remainingAttempts
                        _uiState.value = _uiState.value.copy(
                            isVerifying = false,
                            error = "Verification failed: ${e.message}",
                            remainingAttempts = maxOf(0, currentAttempts - 1)
                        )
                    }
                )
            }
        }
    }

    /**
     * Update timer countdown
     */
    fun updateTimer(seconds: Int) {
        _uiState.value = _uiState.value.copy(timeRemainingSeconds = seconds)
    }

    /**
     * Clear error message
     */
    fun clearError() {
        _uiState.value = _uiState.value.copy(error = null)
    }

    /**
     * Reset verification state
     */
    fun resetVerificationState() {
        _uiState.value = _uiState.value.copy(
            isVerificationSuccess = false,
            otpToken = null,
            error = null
        )
    }

    /**
     * Get OTP token for voting process
     */
    fun getOTPToken(): String? {
        return _uiState.value.otpToken ?: otpRepository.getStoredOTPToken()
    }

    /**
     * Factory for creating OTPVerificationViewModel with dependencies
     */
    class Factory(
        private val context: Context,
        private val categoryId: String
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            if (modelClass.isAssignableFrom(OTPVerificationViewModel::class.java)) {
                return OTPVerificationViewModel(context, categoryId) as T
            }
            throw IllegalArgumentException("Unknown ViewModel class")
        }
    }
}

/**
 * UI State for OTP Verification Screen
 */
data class OTPVerificationUiState(
    val isLoading: Boolean = false,
    val isResending: Boolean = false,
    val isVerifying: Boolean = false,
    val isVerificationSuccess: Boolean = false,
    val otpData: OTPData? = null,
    val otpToken: String? = null,
    val remainingAttempts: Int = 3,
    val timeRemainingSeconds: Int = 300,
    val error: String? = null
)