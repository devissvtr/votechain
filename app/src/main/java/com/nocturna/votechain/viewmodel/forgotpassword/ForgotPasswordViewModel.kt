package com.nocturna.votechain.viewmodel.forgotpassword

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.nocturna.votechain.data.repository.ForgotPasswordRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch

class ForgotPasswordViewModel(private val context: Context) : ViewModel() {

    private val repository = ForgotPasswordRepository()

    // Remove local OTP storage - OTP will be handled server-side
    private val _uiState = MutableStateFlow<ForgotPasswordUiState>(ForgotPasswordUiState.Initial)
    val uiState: StateFlow<ForgotPasswordUiState> = _uiState

    /**
     * Send OTP to the provided email address via server
     * Server will generate OTP and send email using open source email API
     */
    fun sendOtpToEmail(email: String) {
        viewModelScope.launch {
            try {
                _uiState.value = ForgotPasswordUiState.Loading

                // Call server endpoint to generate OTP and send email
                val result = repository.sendVerificationEmail(email)

                if (result.isSuccess) {
                    val response = result.getOrNull()
                    // Check if the response indicates success
                    _uiState.value = ForgotPasswordUiState.OtpSent(email)
                } else {
                    _uiState.value = ForgotPasswordUiState.Error(
                        result.exceptionOrNull()?.message ?: "Failed to send verification code. Please check your email address and try again."
                    )
                }
            } catch (e: Exception) {
                _uiState.value = ForgotPasswordUiState.Error(
                    e.message ?: "Network error. Please check your connection and try again."
                )
            }
        }
    }

    /**
     * Resend OTP to the same email address
     */
    fun resendOtp(email: String) {
        sendOtpToEmail(email)
    }

    /**
     * Verify the entered OTP with server
     */
    fun verifyOtp(email: String, otp: String) {
        viewModelScope.launch {
            try {
                _uiState.value = ForgotPasswordUiState.Loading

                // Server-side verification
                val result = repository.verifyOTP(email, otp)

                if (result.isSuccess) {
                    val response = result.getOrNull()
                    if (response != null) {
                        _uiState.value = ForgotPasswordUiState.OtpVerified(email, otp)
                    } else {
                        _uiState.value = ForgotPasswordUiState.Error(
                            response?.message ?: "Invalid verification code. Please try again."
                        )
                    }
                } else {
                    _uiState.value = ForgotPasswordUiState.Error(
                        result.exceptionOrNull()?.message ?: "Verification failed. Please try again."
                    )
                }
            } catch (e: Exception) {
                _uiState.value = ForgotPasswordUiState.Error(
                    e.message ?: "An unexpected error occurred during verification."
                )
            }
        }
    }

    /**
     * Reset password with verified OTP
     */
    fun resetPassword(email: String, otp: String, newPassword: String) {
        viewModelScope.launch {
            try {
                _uiState.value = ForgotPasswordUiState.Loading

                val result = repository.resetPassword(email, otp, newPassword)

                if (result.isSuccess) {
                    val response = result.getOrNull()
                    if (response != null) {
                        _uiState.value = ForgotPasswordUiState.PasswordResetSuccess
                    } else {
                        _uiState.value = ForgotPasswordUiState.Error(
                            response?.message ?: "Failed to reset password. Please try again."
                        )
                    }
                } else {
                    _uiState.value = ForgotPasswordUiState.Error(
                        result.exceptionOrNull()?.message ?: "Password reset failed. Please try again."
                    )
                }
            } catch (e: Exception) {
                _uiState.value = ForgotPasswordUiState.Error(
                    e.message ?: "An unexpected error occurred"
                )
            }
        }
    }

    /**
     * Clear error state
     */
    fun clearError() {
        if (_uiState.value is ForgotPasswordUiState.Error) {
            _uiState.value = ForgotPasswordUiState.Initial
        }
    }

    // UI States
    sealed class ForgotPasswordUiState {
        object Initial : ForgotPasswordUiState()
        object Loading : ForgotPasswordUiState()
        data class OtpSent(val email: String) : ForgotPasswordUiState()
        data class OtpVerified(val email: String, val otp: String) : ForgotPasswordUiState()
        object PasswordResetSuccess : ForgotPasswordUiState()
        data class Error(val message: String) : ForgotPasswordUiState()
    }

    // Factory to provide context to ViewModel
    class Factory(private val context: Context) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            if (modelClass.isAssignableFrom(ForgotPasswordViewModel::class.java)) {
                return ForgotPasswordViewModel(context) as T
            }
            throw IllegalArgumentException("Unknown ViewModel class")
        }
    }
}