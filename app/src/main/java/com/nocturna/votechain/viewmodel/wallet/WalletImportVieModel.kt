package com.nocturna.votechain.viewmodel.wallet

import android.app.Application
import android.content.Context
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.bouncycastle.crypto.params.Blake3Parameters.context

/**
 * UI State for wallet import
 */
sealed class WalletImportUiState {
    object Initial : WalletImportUiState()
    object Loading : WalletImportUiState()
    data class Success(val walletAddress: String) : WalletImportUiState()
    data class Error(val message: String) : WalletImportUiState()
    object PasswordRequired : WalletImportUiState()
}

/**
 * Import step tracking
 */
enum class ImportStep {
    PRIVATE_KEY_INPUT,
    PASSWORD_SETUP,
    CONFIRMATION,
    PROCESSING
}

/**
 * ViewModel for wallet import functionality
 */
class WalletImportViewModel(application: Application) : AndroidViewModel(application) {

    private val context: Context = application.applicationContext

    private val cryptoKeyManager = CryptoKeyManager(context)
    private val TAG = "WalletImportViewModel"

    // UI State
    private val _uiState = MutableStateFlow<WalletImportUiState>(WalletImportUiState.Initial)
    val uiState: StateFlow<WalletImportUiState> = _uiState.asStateFlow()

    // Import step tracking
    private val _currentStep = MutableStateFlow(ImportStep.PRIVATE_KEY_INPUT)
    val currentStep: StateFlow<ImportStep> = _currentStep.asStateFlow()

    // Form state
    private val _privateKey = MutableStateFlow("")
    val privateKey: StateFlow<String> = _privateKey.asStateFlow()

    private val _password = MutableStateFlow("")
    val password: StateFlow<String> = _password.asStateFlow()

    private val _confirmPassword = MutableStateFlow("")
    val confirmPassword: StateFlow<String> = _confirmPassword.asStateFlow()

    private val _isPrivateKeyVisible = MutableStateFlow(false)
    val isPrivateKeyVisible: StateFlow<Boolean> = _isPrivateKeyVisible.asStateFlow()

    private val _isPasswordVisible = MutableStateFlow(false)
    val isPasswordVisible: StateFlow<Boolean> = _isPasswordVisible.asStateFlow()

    // Validation state
    private val _privateKeyError = MutableStateFlow<String?>(null)
    val privateKeyError: StateFlow<String?> = _privateKeyError.asStateFlow()

    private val _passwordError = MutableStateFlow<String?>(null)
    val passwordError: StateFlow<String?> = _passwordError.asStateFlow()

    /**
     * Update private key input
     */
    fun updatePrivateKey(key: String) {
        _privateKey.value = key
        _privateKeyError.value = null

        // Real-time validation
        if (key.isNotBlank() && !isValidPrivateKeyFormat(key)) {
            _privateKeyError.value = "Invalid private key format"
        }
    }

    /**
     * Update password
     */
    fun updatePassword(pwd: String) {
        _password.value = pwd
        _passwordError.value = null

        // Real-time validation
        if (pwd.isNotBlank() && pwd.length < 8) {
            _passwordError.value = "Password must be at least 8 characters"
        }
    }

    /**
     * Update confirm password
     */
    fun updateConfirmPassword(pwd: String) {
        _confirmPassword.value = pwd
        _passwordError.value = null

        // Check password match
        if (pwd.isNotBlank() && pwd != _password.value) {
            _passwordError.value = "Passwords do not match"
        }
    }

    /**
     * Toggle private key visibility
     */
    fun togglePrivateKeyVisibility() {
        _isPrivateKeyVisible.value = !_isPrivateKeyVisible.value
    }

    /**
     * Toggle password visibility
     */
    fun togglePasswordVisibility() {
        _isPasswordVisible.value = !_isPasswordVisible.value
    }

    /**
     * Validate private key input
     */
    private fun validatePrivateKeyInput(): Boolean {
        val key = _privateKey.value.trim()

        return when {
            key.isBlank() -> {
                _privateKeyError.value = "Private key is required"
                false
            }
            !isValidPrivateKeyFormat(key) -> {
                _privateKeyError.value = "Invalid private key format. Must be 64 characters (with or without 0x prefix)"
                false
            }
            else -> {
                _privateKeyError.value = null
                true
            }
        }
    }

    /**
     * Validate password setup
     */
    private fun validatePasswordSetup(): Boolean {
        val pwd = _password.value
        val confirmPwd = _confirmPassword.value

        return when {
            pwd.length < 8 -> {
                _passwordError.value = "Password must be at least 8 characters"
                false
            }
            pwd != confirmPwd -> {
                _passwordError.value = "Passwords do not match"
                false
            }
            else -> {
                _passwordError.value = null
                true
            }
        }
    }

    /**
     * Proceed to next step
     */
    fun proceedToNextStep() {
        when (_currentStep.value) {
            ImportStep.PRIVATE_KEY_INPUT -> {
                if (validatePrivateKeyInput()) {
                    _currentStep.value = ImportStep.PASSWORD_SETUP
                }
            }
            ImportStep.PASSWORD_SETUP -> {
                if (validatePasswordSetup()) {
                    _currentStep.value = ImportStep.CONFIRMATION
                }
            }
            ImportStep.CONFIRMATION -> {
                importWallet()
            }
            ImportStep.PROCESSING -> {
                // Do nothing, processing in progress
            }
        }
    }

    /**
     * Go back to previous step
     */
    fun goBackToPreviousStep() {
        when (_currentStep.value) {
            ImportStep.PASSWORD_SETUP -> {
                _currentStep.value = ImportStep.PRIVATE_KEY_INPUT
            }
            ImportStep.CONFIRMATION -> {
                _currentStep.value = ImportStep.PASSWORD_SETUP
            }
            else -> {
                // Can't go back from first step or processing
            }
        }
    }

    /**
     * Import wallet with private key and password
     */
    fun importWallet() {
        if (!validatePrivateKeyInput() || !validatePasswordSetup()) {
            return
        }

        _currentStep.value = ImportStep.PROCESSING
        _uiState.value = WalletImportUiState.Loading

        viewModelScope.launch {
            try {
                Log.d(TAG, "Starting wallet import process")

                val result = cryptoKeyManager.importWalletFromPrivateKey(
                    privateKey = _privateKey.value.trim(),
                    userPassword = _password.value
                )

                result.fold(
                    onSuccess = { walletAddress ->
                        Log.d(TAG, "Wallet import successful: $walletAddress")
                        _uiState.value = WalletImportUiState.Success(walletAddress)
                        clearSensitiveData()
                    },
                    onFailure = { error ->
                        Log.e(TAG, "Wallet import failed: ${error.message}")
                        _uiState.value = WalletImportUiState.Error(
                            error.message ?: "Failed to import wallet"
                        )
                        _currentStep.value = ImportStep.PRIVATE_KEY_INPUT
                    }
                )

            } catch (e: Exception) {
                Log.e(TAG, "Unexpected error during wallet import", e)
                _uiState.value = WalletImportUiState.Error("An unexpected error occurred")
                _currentStep.value = ImportStep.PRIVATE_KEY_INPUT
            }
        }
    }

    /**
     * Reset the import process
     */
    fun resetImport() {
        clearSensitiveData()
        _currentStep.value = ImportStep.PRIVATE_KEY_INPUT
        _uiState.value = WalletImportUiState.Initial
        _privateKeyError.value = null
        _passwordError.value = null
    }

    /**
     * Clear sensitive data from memory
     */
    private fun clearSensitiveData() {
        _privateKey.value = ""
        _password.value = ""
        _confirmPassword.value = ""
        _isPrivateKeyVisible.value = false
        _isPasswordVisible.value = false
    }

    /**
     * Simple private key format validation
     */
    private fun isValidPrivateKeyFormat(privateKey: String): Boolean {
        val cleanKey = privateKey.trim().lowercase()

        return when {
            cleanKey.startsWith("0x") -> {
                cleanKey.length == 66 && cleanKey.substring(2).all { it.isDigit() || it in 'a'..'f' }
            }
            else -> {
                cleanKey.length == 64 && cleanKey.all { it.isDigit() || it in 'a'..'f' }
            }
        }
    }
}