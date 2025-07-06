package com.nocturna.votechain.viewmodel.wallet

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.math.BigInteger

/**
 * Enhanced WalletImportViewModel with strict private key format validation
 */
class WalletImportViewModel(
    private val context: Context
) : ViewModel() {

    private val TAG = "WalletImportViewModel"
    private val cryptoKeyManager = CryptoKeyManager(context)

    // Private key format constants
    private companion object {
        const val PRIVATE_KEY_HEX_LENGTH = 64 // 32 bytes = 64 hex characters
        const val PRIVATE_KEY_TOTAL_LENGTH = 66 // "0x" + 64 hex = 66 total
    }

    // UI State flows
    private val _privateKey = MutableStateFlow("")
    val privateKey: StateFlow<String> = _privateKey.asStateFlow()

    private val _password = MutableStateFlow("")
    val password: StateFlow<String> = _password.asStateFlow()

    private val _confirmPassword = MutableStateFlow("")
    val confirmPassword: StateFlow<String> = _confirmPassword.asStateFlow()

    private val _currentStep = MutableStateFlow(ImportStep.PRIVATE_KEY_INPUT)
    val currentStep: StateFlow<ImportStep> = _currentStep.asStateFlow()

    private val _uiState = MutableStateFlow<WalletImportUiState>(WalletImportUiState.Initial)
    val uiState: StateFlow<WalletImportUiState> = _uiState.asStateFlow()

    private val _privateKeyVisible = MutableStateFlow(false)
    val privateKeyVisible: StateFlow<Boolean> = _privateKeyVisible.asStateFlow()

    private val _passwordVisible = MutableStateFlow(false)
    val passwordVisible: StateFlow<Boolean> = _passwordVisible.asStateFlow()

    private val _confirmPasswordVisible = MutableStateFlow(false)
    val confirmPasswordVisible: StateFlow<Boolean> = _confirmPasswordVisible.asStateFlow()

    // Validation error states
    private val _privateKeyError = MutableStateFlow<String?>(null)
    val privateKeyError: StateFlow<String?> = _privateKeyError.asStateFlow()

    private val _passwordError = MutableStateFlow<String?>(null)
    val passwordError: StateFlow<String?> = _passwordError.asStateFlow()

    /**
     * Update private key with real-time validation
     */
    fun updatePrivateKey(key: String) {
        _privateKey.value = key
        validatePrivateKeyRealTime(key)
    }

    /**
     * Real-time private key validation with detailed feedback
     */
    private fun validatePrivateKeyRealTime(key: String) {
        val cleanKey = key.trim()

        when {
            cleanKey.isEmpty() -> {
                _privateKeyError.value = null
            }
            cleanKey.length < 64 -> {
                _privateKeyError.value = "Private key too short (${cleanKey.length}/64 characters)"
            }
            cleanKey.length > 66 -> {
                _privateKeyError.value = "Private key too long (${cleanKey.length} characters max 66)"
            }
            !isValidHexString(cleanKey) -> {
                _privateKeyError.value = "Private key must contain only hexadecimal characters (0-9, a-f, A-F)"
            }
            !isValidPrivateKeyFormat(cleanKey) -> {
                _privateKeyError.value = "Invalid private key format. Must be exactly 64 hex characters (with or without 0x prefix)"
            }
            !isValidSecp256k1Range(cleanKey) -> {
                _privateKeyError.value = "Private key is outside valid range for secp256k1 curve"
            }
            else -> {
                _privateKeyError.value = null
            }
        }
    }

    /**
     * Enhanced private key format validation
     */
    private fun isValidPrivateKeyFormat(privateKey: String): Boolean {
        val cleanKey = if (privateKey.startsWith("0x", ignoreCase = true)) {
            privateKey.substring(2)
        } else {
            privateKey
        }

        return cleanKey.length == PRIVATE_KEY_HEX_LENGTH &&
                cleanKey.matches(Regex("^[0-9a-fA-F]{$PRIVATE_KEY_HEX_LENGTH}$"))
    }

    /**
     * Check if string contains only valid hex characters
     */
    private fun isValidHexString(str: String): Boolean {
        val cleanStr = if (str.startsWith("0x", ignoreCase = true)) {
            str.substring(2)
        } else {
            str
        }
        return cleanStr.matches(Regex("^[0-9a-fA-F]*$"))
    }

    /**
     * Validate private key is in valid secp256k1 range
     */
    private fun isValidSecp256k1Range(privateKey: String): Boolean {
        return try {
            val cleanKey = if (privateKey.startsWith("0x", ignoreCase = true)) {
                privateKey.substring(2)
            } else {
                privateKey
            }

            if (cleanKey.length != PRIVATE_KEY_HEX_LENGTH) {
                return false
            }

            val privateKeyBigInt = BigInteger(cleanKey, 16)
            val secp256k1Order = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

            privateKeyBigInt.compareTo(BigInteger.ZERO) > 0 &&
                    privateKeyBigInt.compareTo(secp256k1Order) < 0
        } catch (e: Exception) {
            Log.w(TAG, "Error validating secp256k1 range: ${e.message}")
            false
        }
    }

    /**
     * Update password with validation
     */
    fun updatePassword(pwd: String) {
        _password.value = pwd
        validatePasswordRealTime(pwd, _confirmPassword.value)
    }

    /**
     * Update confirm password with validation
     */
    fun updateConfirmPassword(pwd: String) {
        _confirmPassword.value = pwd
        validatePasswordRealTime(_password.value, pwd)
    }

    /**
     * Real-time password validation
     */
    private fun validatePasswordRealTime(password: String, confirmPassword: String) {
        when {
            password.isEmpty() -> {
                _passwordError.value = null
            }
            password.length < 8 -> {
                _passwordError.value = "Password must be at least 8 characters long"
            }
            confirmPassword.isNotEmpty() && password != confirmPassword -> {
                _passwordError.value = "Passwords do not match"
            }
            else -> {
                _passwordError.value = null
            }
        }
    }

    /**
     * Toggle private key visibility
     */
    fun togglePrivateKeyVisibility() {
        _privateKeyVisible.value = !_privateKeyVisible.value
    }

    /**
     * Toggle password visibility
     */
    fun togglePasswordVisibility() {
        _passwordVisible.value = !_passwordVisible.value
    }

    /**
     * Toggle confirm password visibility
     */
    fun toggleConfirmPasswordVisibility() {
        _confirmPasswordVisible.value = !_confirmPasswordVisible.value
    }

    /**
     * Proceed to next step with enhanced validation
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
     * Enhanced private key input validation
     */
    private fun validatePrivateKeyInput(): Boolean {
        val key = _privateKey.value.trim()

        Log.d(TAG, "Validating private key input: length=${key.length}")

        when {
            key.isEmpty() -> {
                _privateKeyError.value = "Private key cannot be empty"
                return false
            }
            !isValidPrivateKeyFormat(key) -> {
                _privateKeyError.value = "Invalid private key format. Must be exactly 64 hexadecimal characters (with or without 0x prefix)"
                return false
            }
            !isValidSecp256k1Range(key) -> {
                _privateKeyError.value = "Private key is outside valid range for secp256k1 curve"
                return false
            }
            else -> {
                _privateKeyError.value = null
                Log.d(TAG, "✅ Private key validation passed")
                return true
            }
        }
    }

    /**
     * Enhanced password setup validation
     */
    private fun validatePasswordSetup(): Boolean {
        val password = _password.value
        val confirmPassword = _confirmPassword.value

        when {
            password.isEmpty() -> {
                _passwordError.value = "Password cannot be empty"
                return false
            }
            password.length < 8 -> {
                _passwordError.value = "Password must be at least 8 characters long"
                return false
            }
            password != confirmPassword -> {
                _passwordError.value = "Passwords do not match"
                return false
            }
            else -> {
                _passwordError.value = null
                return true
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
     * Import wallet with enhanced validation and error handling
     */
    fun importWallet() {
        if (!validatePrivateKeyInput() || !validatePasswordSetup()) {
            Log.w(TAG, "Validation failed before import")
            return
        }

        _currentStep.value = ImportStep.PROCESSING
        _uiState.value = WalletImportUiState.Loading

        viewModelScope.launch {
            try {
                Log.d(TAG, "Starting wallet import process")

                // Normalize private key format
                val normalizedPrivateKey = normalizePrivateKey(_privateKey.value.trim())
                Log.d(TAG, "Normalized private key length: ${normalizedPrivateKey.length}")

                val result = cryptoKeyManager.importWalletFromPrivateKey(
                    privateKey = normalizedPrivateKey,
                    userPassword = _password.value
                )

                result.fold(
                    onSuccess = { walletAddress ->
                        Log.d(TAG, "✅ Wallet import successful: $walletAddress")
                        _uiState.value = WalletImportUiState.Success(walletAddress)
                        clearSensitiveData()
                    },
                    onFailure = { error ->
                        Log.e(TAG, "❌ Wallet import failed: ${error.message}")
                        _uiState.value = WalletImportUiState.Error(
                            error.message ?: "Import failed: Unknown error"
                        )
                        _currentStep.value = ImportStep.PRIVATE_KEY_INPUT
                    }
                )
            } catch (e: Exception) {
                Log.e(TAG, "❌ Unexpected error during wallet import", e)
                _uiState.value = WalletImportUiState.Error("Unexpected error: ${e.message}")
                _currentStep.value = ImportStep.PRIVATE_KEY_INPUT
            }
        }
    }

    /**
     * Normalize private key to standard format
     */
    private fun normalizePrivateKey(privateKey: String): String {
        val cleanKey = if (privateKey.startsWith("0x", ignoreCase = true)) {
            privateKey.substring(2)
        } else {
            privateKey
        }

        // Ensure it's lowercase and exactly 64 characters
        return "0x${cleanKey.lowercase().padStart(PRIVATE_KEY_HEX_LENGTH, '0')}"
    }

    /**
     * Clear sensitive data from memory
     */
    private fun clearSensitiveData() {
        _privateKey.value = ""
        _password.value = ""
        _confirmPassword.value = ""
        _privateKeyError.value = null
        _passwordError.value = null

        // Force garbage collection to clear sensitive data from memory
        System.gc()
    }

    /**
     * Reset import process
     */
    fun resetImport() {
        _currentStep.value = ImportStep.PRIVATE_KEY_INPUT
        _uiState.value = WalletImportUiState.Initial
        clearSensitiveData()
        _privateKeyVisible.value = false
        _passwordVisible.value = false
        _confirmPasswordVisible.value = false
    }

    /**
     * Get preview address for confirmation step
     */
    fun getPreviewAddress(): String {
        val key = _privateKey.value.trim()
        return if (key.length >= 8) {
            "0x..." + key.takeLast(8)
        } else {
            "0x..."
        }
    }

    override fun onCleared() {
        super.onCleared()
        clearSensitiveData()
        Log.d(TAG, "WalletImportViewModel cleared")
    }
}

/**
 * Import step enumeration
 */
enum class ImportStep {
    PRIVATE_KEY_INPUT,
    PASSWORD_SETUP,
    CONFIRMATION,
    PROCESSING
}

/**
 * UI State for wallet import
 */
sealed class WalletImportUiState {
    data object Initial : WalletImportUiState()
    data object Loading : WalletImportUiState()
    data class Success(val walletAddress: String) : WalletImportUiState()
    data class Error(val message: String) : WalletImportUiState()
}

/**
 * Factory for creating WalletImportViewModel
 */
class WalletImportViewModelFactory(
    private val context: Context
) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(WalletImportViewModel::class.java)) {
            return WalletImportViewModel(context) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}
