package com.nocturna.votechain.viewmodel.register

import android.content.Context
import android.net.Uri
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.nocturna.votechain.blockchain.BlockchainManager
import com.nocturna.votechain.data.model.ApiResponse
import com.nocturna.votechain.data.model.Province
import com.nocturna.votechain.data.model.Regency
import com.nocturna.votechain.data.model.UserRegistrationData
import com.nocturna.votechain.data.model.VerificationStatusData
import com.nocturna.votechain.data.network.NetworkClient
import com.nocturna.votechain.data.network.WilayahApiClient
import com.nocturna.votechain.data.repository.EnhancedUserRepository
import com.nocturna.votechain.data.repository.RegistrationStateManager
import com.nocturna.votechain.data.repository.UserLoginRepository
import com.nocturna.votechain.data.repository.UserRepository
import com.nocturna.votechain.data.repository.VoterRepository
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Locale

/**
 * States for key generation process
 */
sealed class KeyGenerationState {
    data object NotStarted : KeyGenerationState()
    data object Generating : KeyGenerationState()
    data object Generated : KeyGenerationState()
    data object AlreadyExists : KeyGenerationState()
    data object Invalid : KeyGenerationState()
    data class Failed(val message: String) : KeyGenerationState()
}

/**
 * States for security auditing process
 */
sealed class SecurityAuditState {
    data object NotChecked : SecurityAuditState()
    data object Checking : SecurityAuditState()
    data class Checked(
        val keystoreAvailable: Boolean,
        val hardwareBackedKeys: Boolean,
        val encryptionStrength: String,
        val securityLevel: String
    ) : SecurityAuditState()
    data class Failed(val message: String) : SecurityAuditState()
}

/**
 * Data class to hold key generation results
 */
data class KeyGenerationResult(
    val success: Boolean,
    val keyPairInfo: CryptoKeyManager.KeyPairInfo? = null,
    val error: String? = null
)

/**
 * Data class for security check results
 */
data class SecurityCheck(
    val passed: Boolean,
    val reason: String = ""
)

/**
 * ViewModel for the Register Screen with verification status checking
 */
class RegisterViewModel(
    private val userRepository: UserRepository,
    private val userLoginRepository: UserLoginRepository,
    private val voterRepository: VoterRepository,
    private val context: Context
) : ViewModel() {
    private val TAG = "RegisterViewModel"

    // UI State
    private val _uiState = MutableStateFlow<RegisterUiState>(RegisterUiState.Initial)
    val uiState: StateFlow<RegisterUiState> = _uiState.asStateFlow()

    // Dependencies
    private val enhancedUserRepository = EnhancedUserRepository(context)
    private val cryptoKeyManager = CryptoKeyManager(context)
    private val apiService = NetworkClient.apiService
    private val registrationApiService = NetworkClient.registrationApiService // Added for registration flow
    private val registrationStateManager = RegistrationStateManager(context)

    // Node connection state
    private val _nodeConnected = MutableStateFlow(false)
    val nodeConnected: StateFlow<Boolean> = _nodeConnected.asStateFlow()

    // Key generation state for UI feedback
    private val _keyGenerationState = MutableStateFlow<KeyGenerationState>(KeyGenerationState.NotStarted)
    val keyGenerationState: StateFlow<KeyGenerationState> = _keyGenerationState.asStateFlow()

    // Security audit state
    private val _securityAuditState = MutableStateFlow<SecurityAuditState>(SecurityAuditState.NotChecked)
    val securityAuditState: StateFlow<SecurityAuditState> = _securityAuditState.asStateFlow()

    // Province and regency data states
    private val _provinces = MutableStateFlow<List<Province>>(emptyList())
    val provinces: StateFlow<List<Province>> = _provinces.asStateFlow()

    private val _regencies = MutableStateFlow<List<Regency>>(emptyList())
    val regencies: StateFlow<List<Regency>> = _regencies.asStateFlow()

    private val _isProvincesLoading = MutableStateFlow(false)
    val isProvincesLoading: StateFlow<Boolean> = _isProvincesLoading.asStateFlow()

    private val _isRegenciesLoading = MutableStateFlow(false)
    val isRegenciesLoading: StateFlow<Boolean> = _isRegenciesLoading.asStateFlow()

    init {
        // Perform security audit on initialization
        performSecurityAudit()

        // Check blockchain connection
        checkNodeConnection()

        // Initialize location data
        fetchProvinces()

        // Check initial registration state
        checkInitialRegistrationState()

        // Check existing crypto keys with enhanced validation
        checkExistingCryptoKeys()
    }

    /**
     * Check if user already has a registration and redirect accordingly
     * Called when user clicks register button or tries to access register screen
     */
    fun checkExistingRegistration(email: String) {
        val currentState = registrationStateManager.getRegistrationState()
        val savedEmail = registrationStateManager.getSavedEmail()

        if (currentState != RegistrationStateManager.STATE_NONE && savedEmail == email) {
            Log.d(TAG, "User already has registration with state: $currentState")
            when (currentState) {
                RegistrationStateManager.STATE_WAITING -> {
                    _uiState.value = RegisterUiState.Waiting
                    checkVerificationStatus(email)
                }
                RegistrationStateManager.STATE_APPROVED -> {
                    _uiState.value = RegisterUiState.Approved
                }
                RegistrationStateManager.STATE_REJECTED -> {
                    // Allow new registration for rejected state
                    registrationStateManager.clearRegistrationState()
                    _uiState.value = RegisterUiState.Initial
                }
            }
        } else {
            // Check verification status from API for new email
            checkVerificationStatus(email)
        }
    }

    /**
     * Check verification status from API
     */
    fun checkVerificationStatus(email: String) {
        viewModelScope.launch {
            try {
                Log.d(TAG, "Checking verification status for email: $email")

                val response = withContext(Dispatchers.IO) {
                    apiService.getVerificationStatus(email)
                }

                if (response.isSuccessful && response.body() != null) {
                    val verificationData = response.body()!!.data
                    if (verificationData != null) {
                        handleVerificationStatusResponse(verificationData, email)
                    } else {
                        Log.d(TAG, "No verification data found for email: $email")
                        // Allow new registration if no existing data
                        if (_uiState.value == RegisterUiState.Waiting) {
                            // Keep current state if we're checking from waiting screen
                        } else {
                            _uiState.value = RegisterUiState.Initial
                        }
                    }
                } else {
                    Log.d(TAG, "No verification status found for email: $email")
                    // Allow new registration if no existing data
                    if (_uiState.value == RegisterUiState.Waiting) {
                        // Keep current state if we're checking from waiting screen
                    } else {
                        _uiState.value = RegisterUiState.Initial
                    }
                }
            } catch (e: Exception) {
                Log.d(TAG, "Error checking verification status: ${e.message}")
                // Allow new registration on error
                if (_uiState.value == RegisterUiState.Waiting) {
                    // Keep current state if we're checking from waiting screen
                } else {
                    _uiState.value = RegisterUiState.Initial
                }
            }
        }
    }

    /**
     * Handle verification status response and update states accordingly
     */
    private fun handleVerificationStatusResponse(verificationData: VerificationStatusData, email: String) {
        val status = verificationData.verification_status.lowercase()
        Log.d(TAG, "Verification status for $email: $status")

        when (status) {
            "pending", "waiting" -> {
                registrationStateManager.saveRegistrationState(
                    RegistrationStateManager.STATE_WAITING,
                    email,
                    "" // NIK not available from this response
                )
                _uiState.value = RegisterUiState.Waiting
            }
            "approved", "accepted" -> {
                registrationStateManager.saveRegistrationState(
                    RegistrationStateManager.STATE_APPROVED,
                    email,
                    ""
                )
                _uiState.value = RegisterUiState.Approved
            }
            "denied", "rejected" -> {
                registrationStateManager.saveRegistrationState(
                    RegistrationStateManager.STATE_REJECTED,
                    email,
                    ""
                )
                _uiState.value = RegisterUiState.Rejected
            }
            else -> {
                Log.d(TAG, "Unknown verification status: $status")
                _uiState.value = RegisterUiState.Initial
            }
        }
    }

    /**
     * Handle close action from waiting screen
     */
    fun onWaitingScreenClose() {
        Log.d(TAG, "Waiting screen closed, maintaining registration state")
        // Don't clear the registration state, just set flag for navigation
        _uiState.value = RegisterUiState.NavigateToLogin
    }

    /**
     * Check if user has any pending registration state
     */
    fun getCurrentRegistrationState(): Int {
        return registrationStateManager.getRegistrationState()
    }

    /**
     * Check blockchain node connection
     */
    private fun checkNodeConnection() {
        viewModelScope.launch {
            try {
                val isConnected = withContext(Dispatchers.IO) {
                    BlockchainManager.isConnected()
                }
                _nodeConnected.value = isConnected
                Log.d(TAG, "Ethereum node connection: ${if (isConnected) "CONNECTED" else "DISCONNECTED"}")
            } catch (e: Exception) {
                Log.e(TAG, "Error checking node connection: ${e.message}", e)
                _nodeConnected.value = false
            }
        }
    }

    /**
     * Fetch provinces data
     */
    fun fetchProvinces() {
        viewModelScope.launch {
            _isProvincesLoading.value = true
            try {
                val response = WilayahApiClient.apiService.getProvinces()
                _provinces.value = response.data
                Log.d(TAG, "Fetched ${response.data.size} provinces")
            } catch (e: Exception) {
                Log.e(TAG, "Error fetching provinces: ${e.message}", e)
            } finally {
                _isProvincesLoading.value = false
            }
        }
    }

    /**
     * Fetch regencies for selected province
     */
    fun fetchRegencies(provinceCode: String) {
        viewModelScope.launch {
            _isRegenciesLoading.value = true
            try {
                val response = WilayahApiClient.apiService.getRegencies(provinceCode)
                _regencies.value = response.data
                Log.d(TAG, "Fetched ${response.data.size} regencies for province $provinceCode")
            } catch (e: Exception) {
                Log.e(TAG, "Error fetching regencies: ${e.message}", e)
            } finally {
                _isRegenciesLoading.value = false
            }
        }
    }

    /**
     * Register a new user
     */
    fun registerUser(
        email: String,
        password: String,
        nationalId: String,
        fullName: String,
        gender: String,
        birthPlace: String,
        birthDate: String,
        address: String,
        region: String,
        role: String = "voter",
        telephone: String,
        ktpFileUri: Uri?
    ) {
        _uiState.value = RegisterUiState.Loading

        // Format birth date to YYYY-MM-DD
        val formattedBirthDate = try {
            val inputFormat = SimpleDateFormat("dd/MM/yyyy", Locale.getDefault())
            val outputFormat = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault())
            val date = inputFormat.parse(birthDate)
            outputFormat.format(date ?: throw Exception("Invalid date"))
        } catch (e: Exception) {
            Log.e(TAG, "Error formatting birth date: ${e.message}", e)
            birthDate // Fallback to original format if parsing fails
        }

        viewModelScope.launch {
            try {
                Log.d(TAG, "Using EnhancedUserRepository with new wallet generation")

                // Save registration as waiting state immediately
                registrationStateManager.saveRegistrationState(
                    RegistrationStateManager.STATE_WAITING,
                    email,
                    nationalId
                )

                val result = enhancedUserRepository.registerWithVoterAddress(
                    email = email,
                    password = password,
                    nik = nationalId,
                    fullName = fullName,
                    gender = gender,
                    birthPlace = birthPlace,
                    birthDate = formattedBirthDate,
                    residentialAddress = address,
                    region = region,
                    role = role,
                    telephone = telephone,
                    ktpFileUri = ktpFileUri
                )

                result.fold(
                    onSuccess = { response ->
                        Log.d(TAG, "Registration API call successful: ${response.message}")

                        // Parse the verification status and save appropriate state
                        val verificationStatus = response.data?.verification_status?.lowercase()
                        Log.d(TAG, "Verification status received: $verificationStatus")

                        when (verificationStatus) {
                            "pending", "waiting" -> {
                                registrationStateManager.saveRegistrationState(
                                    RegistrationStateManager.STATE_WAITING,
                                    email,
                                    nationalId
                                )
                                _uiState.value = RegisterUiState.Waiting
                            }
                            "accepted", "approved" -> {
                                registrationStateManager.saveRegistrationState(
                                    RegistrationStateManager.STATE_APPROVED,
                                    email,
                                    nationalId
                                )
                                _uiState.value = RegisterUiState.Approved
                            }
                            "rejected" -> {
                                registrationStateManager.saveRegistrationState(
                                    RegistrationStateManager.STATE_REJECTED,
                                    email,
                                    nationalId
                                )
                                _uiState.value = RegisterUiState.Rejected
                            }
                            else -> {
                                _uiState.value = RegisterUiState.Waiting
                            }
                        }

                        // Save the generated keys associated with this email
                        saveKeysForUser(email)
                    },
                    onFailure = { error ->
                        Log.e(TAG, "Registration failed: ${error.message}", error)
                        _uiState.value = RegisterUiState.Error(error.message ?: "Unknown error occurred")

                        // Even if registration API failed, we can still save key info
                        // if they were generated
                        if (keyGenerationState.value == KeyGenerationState.Generated) {
                            saveKeysForUser(email)
                        }
                    }
                )
            } catch (e: Exception) {
                Log.e(TAG, "Exception during registration: ${e.message}", e)
                // Clear the waiting state since registration failed
                registrationStateManager.clearRegistrationState()
                _uiState.value = RegisterUiState.Error(e.message ?: "Unknown error occurred")
            }
        }
    }

    /**
     * Clear registration state when user successfully completes the process
     * This should be called when user successfully logs in after approval
     */
    fun clearRegistrationState() {
        Log.d(TAG, "Clearing registration state")
        registrationStateManager.clearRegistrationState()
        _uiState.value = RegisterUiState.Initial
    }

    /**
     * Handle retry registration - only allowed for rejected registrations
     */
    fun retryRegistration() {
        val currentState = registrationStateManager.getRegistrationState()
        if (currentState == RegistrationStateManager.STATE_REJECTED) {
            Log.d(TAG, "Retrying registration after rejection")
            registrationStateManager.clearRegistrationState()
            _uiState.value = RegisterUiState.Initial
        } else {
            Log.w(TAG, "Retry registration not allowed for current state: $currentState")
        }
    }

    /**
     * Reset the UI state to initial
     */
    fun resetState() {
        _uiState.value = RegisterUiState.Initial
    }

    /**
     * Reset to register form (used when navigating back from waiting screen)
     */
    fun resetToRegisterForm() {
        Log.d(TAG, "Resetting to register form")
        _uiState.value = RegisterUiState.Initial
    }

    /**
     * For testing/admin purposes - force clear registration state
     */
    fun forceClearRegistrationState() {
        Log.d(TAG, "Force clearing registration state")
        registrationStateManager.clearRegistrationState()
        _uiState.value = RegisterUiState.Initial
    }

    /**
     * UI State for Register Screen with additional states
     */
    sealed class RegisterUiState {
        data object Initial : RegisterUiState()
        data object Loading : RegisterUiState()
        data class Success(val data: ApiResponse<UserRegistrationData>) : RegisterUiState()
        data class Error(val message: String) : RegisterUiState()
        data object Waiting : RegisterUiState()
        data object Approved : RegisterUiState()
        data object Rejected : RegisterUiState()
        data object NavigateToLogin : RegisterUiState()
    }

    /**
     * Factory for creating RegisterViewModel
     */
    class Factory(private val context: Context) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            if (modelClass.isAssignableFrom(RegisterViewModel::class.java)) {
                val userRepository = UserRepository(context)
                val userLoginRepository = UserLoginRepository(context)
                val voterRepository = VoterRepository(context)
                return RegisterViewModel(
                    context = context,
                    userRepository = userRepository,
                    userLoginRepository = userLoginRepository,
                    voterRepository = voterRepository
                ) as T
            }
            throw IllegalArgumentException("Unknown ViewModel class")
        }
    }

    /**
     * Enhanced security audit for crypto infrastructure
     */
    private fun performSecurityAudit() {
        viewModelScope.launch {
            try {
                _securityAuditState.value = SecurityAuditState.Checking

                // Check Android Keystore availability
                val keystoreAvailable = checkKeystoreAvailability()

                // Check hardware security module
                val hsmAvailable = checkHardwareSecurityModule()

                // Check encryption strength
                val encryptionStrong = checkEncryptionStrength()

                val auditResult = SecurityAuditState.Checked(
                    keystoreAvailable = keystoreAvailable,
                    hardwareBackedKeys = hsmAvailable,
                    encryptionStrength = if (encryptionStrong) "AES-256" else "AES-128",
                    securityLevel = calculateSecurityLevel(keystoreAvailable, hsmAvailable, encryptionStrong)
                )

                _securityAuditState.value = auditResult

                Log.d(TAG, "Security audit completed: $auditResult")
            } catch (e: Exception) {
                Log.e(TAG, "Security audit failed", e)
                _securityAuditState.value = SecurityAuditState.Failed(e.message ?: "Unknown error")
            }
        }
    }

    /**
     * Enhanced check for existing crypto keys with validation
     */
    private fun checkExistingCryptoKeys() {
        viewModelScope.launch {
            try {
                val hasKeys = cryptoKeyManager.hasStoredKeyPair()

                if (hasKeys) {
                    // Validate stored keys
                    val isValid = cryptoKeyManager.validateStoredKeys()

                    if (isValid) {
                        _keyGenerationState.value = KeyGenerationState.AlreadyExists

                        // Get key info for logging (without exposing private key)
                        val voterAddress = cryptoKeyManager.getVoterAddress()
                        Log.d(TAG, "Valid crypto keys found for address: $voterAddress")
                    } else {
                        _keyGenerationState.value = KeyGenerationState.Invalid
                        Log.w(TAG, "Found invalid crypto keys, will regenerate during registration")

                        // Clear invalid keys
                        cryptoKeyManager.clearStoredKeys()
                    }
                } else {
                    Log.d(TAG, "No existing crypto keys found")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error checking existing crypto keys", e)
                _keyGenerationState.value = KeyGenerationState.Failed("Key validation error: ${e.message}")
            }
        }
    }

//    /**
//     * Enhanced registerUserWithVoterAddress method that checks existing registration first
//     * This method will be called by RegisterScreen
//     */
//    fun registerUserWithVoterAddress(
//        nationalId: String,
//        fullName: String,
//        email: String,
//        password: String,
//        birthPlace: String,
//        birthDate: String,
//        address: String,
//        region: String,
//        gender: String,
//        ktpFileUri: Uri?,
//        role: String = "voter"
//    ) {
//        // First check if user already has a registration
//        Log.d(TAG, "Starting registration process for email: $email")
//
//        // Check existing registration status first
//        checkExistingRegistrationBeforeRegister(email) { shouldProceed ->
//            if (shouldProceed) {
//                // Proceed with new registration
//                proceedWithNewRegistration(
//                    nationalId = nationalId,
//                    fullName = fullName,
//                    email = email,
//                    password = password,
//                    birthPlace = birthPlace,
//                    birthDate = birthDate,
//                    address = address,
//                    region = region,
//                    gender = gender,
//                    ktpFileUri = ktpFileUri,
//                    role = role
//                )
//            }
//            // If shouldProceed is false, the user will be redirected to appropriate status screen
//            // by the existing registration checking logic
//        }
//    }

    /**
     * Check existing registration before proceeding with new registration
     */
    private fun checkExistingRegistrationBeforeRegister(email: String, onResult: (Boolean) -> Unit) {
        val currentState = registrationStateManager.getRegistrationState()
        val savedEmail = registrationStateManager.getSavedEmail()

        if (currentState != RegistrationStateManager.STATE_NONE && savedEmail == email) {
            Log.d(TAG, "User already has registration with state: $currentState")
            when (currentState) {
                RegistrationStateManager.STATE_WAITING -> {
                    _uiState.value = RegisterUiState.Waiting
                    checkVerificationStatus(email)
                    onResult(false) // Don't proceed with new registration
                }
                RegistrationStateManager.STATE_APPROVED -> {
                    _uiState.value = RegisterUiState.Approved
                    onResult(false) // Don't proceed with new registration
                }
                RegistrationStateManager.STATE_REJECTED -> {
                    // Allow new registration for rejected state
                    registrationStateManager.clearRegistrationState()
                    onResult(true) // Proceed with new registration
                }
                else -> {
                    onResult(true) // Proceed with new registration
                }
            }
        } else {
            // Check verification status from API for potentially different email
            viewModelScope.launch {
                try {
                    Log.d(TAG, "Checking verification status for email: $email")

                    val response = withContext(Dispatchers.IO) {
                        apiService.getVerificationStatus(email)
                    }

                    if (response.isSuccessful && response.body() != null) {
                        val verificationData = response.body()!!.data
                        if (verificationData != null) {
                            handleVerificationStatusResponse(verificationData, email)
                            onResult(false) // Don't proceed with new registration
                        } else {
                            Log.d(TAG, "No verification data found for email: $email")
                            onResult(true) // Proceed with new registration
                        }
                    } else {
                        Log.d(TAG, "No verification status found for email: $email")
                        onResult(true) // Proceed with new registration
                    }
                } catch (e: Exception) {
                    Log.d(TAG, "Error checking verification status: ${e.message}")
                    onResult(true) // Proceed with new registration on error
                }
            }
        }
    }

    /**
     * Check if current email has pending registration
     */
    fun checkEmailRegistrationStatus(email: String, onResult: (hasRegistration: Boolean, state: Int) -> Unit) {
        val currentState = registrationStateManager.getRegistrationState()
        val savedEmail = registrationStateManager.getSavedEmail()

        if (currentState != RegistrationStateManager.STATE_NONE && savedEmail == email) {
            Log.d(TAG, "Email $email has existing registration with state: $currentState")
            onResult(true, currentState)
        } else {
            // Check with API
            viewModelScope.launch {
                try {
                    val response = withContext(Dispatchers.IO) {
                        apiService.getVerificationStatus(email)
                    }

                    if (response.isSuccessful && response.body() != null) {
                        val verificationData = response.body()!!.data
                        if (verificationData != null) {
                            val status = verificationData.verification_status.lowercase()
                            val state = when (status) {
                                "pending", "waiting" -> RegistrationStateManager.STATE_WAITING
                                "approved", "accepted" -> RegistrationStateManager.STATE_APPROVED
                                "denied", "rejected" -> RegistrationStateManager.STATE_REJECTED
                                else -> RegistrationStateManager.STATE_NONE
                            }

                            if (state != RegistrationStateManager.STATE_NONE) {
                                // Save this state locally
                                registrationStateManager.saveRegistrationState(state, email, "")
                                onResult(true, state)
                            } else {
                                onResult(false, RegistrationStateManager.STATE_NONE)
                            }
                        } else {
                            onResult(false, RegistrationStateManager.STATE_NONE)
                        }
                    } else {
                        onResult(false, RegistrationStateManager.STATE_NONE)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error checking email registration status: ${e.message}")
                    onResult(false, RegistrationStateManager.STATE_NONE)
                }
            }
        }
    }

    /**
     * Proceed with new registration (existing logic)
     */
    private fun proceedWithNewRegistration(
        nationalId: String,
        fullName: String,
        email: String,
        password: String,
        birthPlace: String,
        birthDate: String,
        address: String,
        region: String,
        gender: String,
        ktpFileUri: Uri?,
        role: String,
        telephone: String
    ) {
        // This is the existing registration logic
        // Copy your existing registerUser implementation here

        _uiState.value = RegisterUiState.Loading

        // Format birth date to YYYY-MM-DD
        val formattedBirthDate = try {
            val inputFormat = SimpleDateFormat("dd/MM/yyyy", Locale.getDefault())
            val outputFormat = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault())
            val date = inputFormat.parse(birthDate)
            outputFormat.format(date ?: throw Exception("Invalid date"))
        } catch (e: Exception) {
            Log.e(TAG, "Error formatting birth date: ${e.message}", e)
            birthDate // Fallback to original format if parsing fails
        }

        viewModelScope.launch {
            try {
                Log.d(TAG, "Using EnhancedUserRepository with new wallet generation")

                // Save registration as waiting state immediately
                registrationStateManager.saveRegistrationState(
                    RegistrationStateManager.STATE_WAITING,
                    email,
                    nationalId
                )

                val result = enhancedUserRepository.registerWithVoterAddress(
                    email = email,
                    password = password,
                    nik = nationalId,
                    fullName = fullName,
                    gender = gender,
                    birthPlace = birthPlace,
                    birthDate = formattedBirthDate,
                    residentialAddress = address,
                    region = region,
                    role = role,
                    ktpFileUri = ktpFileUri,
                    telephone = telephone
                )

                result.fold(
                    onSuccess = { response ->
                        Log.d(TAG, "Registration API call successful: ${response.message}")

                        // Parse the verification status and save appropriate state
                        val verificationStatus = response.data?.verification_status?.lowercase()
                        Log.d(TAG, "Verification status received: $verificationStatus")

                        when (verificationStatus) {
                            "pending", "waiting" -> {
                                registrationStateManager.saveRegistrationState(
                                    RegistrationStateManager.STATE_WAITING,
                                    email,
                                    nationalId
                                )
                                _uiState.value = RegisterUiState.Waiting
                            }
                            "accepted", "approved" -> {
                                registrationStateManager.saveRegistrationState(
                                    RegistrationStateManager.STATE_APPROVED,
                                    email,
                                    nationalId
                                )
                                _uiState.value = RegisterUiState.Approved
                            }
                            "rejected" -> {
                                registrationStateManager.saveRegistrationState(
                                    RegistrationStateManager.STATE_REJECTED,
                                    email,
                                    nationalId
                                )
                                _uiState.value = RegisterUiState.Rejected
                            }
                            else -> {
                                // Default to waiting if status is unclear
                                registrationStateManager.saveRegistrationState(
                                    RegistrationStateManager.STATE_WAITING,
                                    email,
                                    nationalId
                                )
                                _uiState.value = RegisterUiState.Waiting
                            }
                        }
                    },
                    onFailure = { exception ->
                        Log.e(TAG, "Registration failed: ${exception.message}", exception)
                        // Clear the waiting state since registration failed
                        registrationStateManager.clearRegistrationState()
                        _uiState.value = RegisterUiState.Error(exception.message ?: "Unknown error occurred")
                    }
                )
            } catch (e: Exception) {
                Log.e(TAG, "Exception during registration: ${e.message}", e)
                // Clear the waiting state since registration failed
                registrationStateManager.clearRegistrationState()
                _uiState.value = RegisterUiState.Error(e.message ?: "Unknown error occurred")
            }
        }
    }

    /**
     * Register user with automatic secure key generation
     * Keys will be stored in Android Keystore for maximum security
     */
    fun registerUserWithAutoKeyGeneration(
        nationalId: String,
        fullName: String,
        email: String,
        telephone: String,
        password: String,
        birthPlace: String,
        birthDate: String,
        address: String,
        region: String,
        gender: String,
        ktpFileUri: Uri?,
        role: String = "voter"
    ) {
        // Check existing registration first
        checkExistingRegistration(email) { shouldProceed ->
            if (shouldProceed) {
                // Proceed with secure registration with key generation
                proceedWithSecureRegistration(
                    nationalId, fullName, email, telephone, password, birthPlace,
                    birthDate, address, region, gender, ktpFileUri, role
                )
            }
        }
    }

    /**
     * Main registration method with enhanced security
     */
    fun registerUserWithVoterAddress(
        nationalId: String,
        fullName: String,
        email: String,
        telephone: String,
        password: String,
        birthPlace: String,
        birthDate: String,
        address: String,
        region: String,
        gender: String,
        ktpFileUri: Uri?,
        role: String = "voter"
    ) {
        // Check existing registration first
        checkExistingRegistration(email) { shouldProceed ->
            if (shouldProceed) {
                // Proceed with secure registration
                proceedWithSecureRegistration(
                    nationalId, fullName, email, telephone, password, birthPlace, birthDate, address, region, gender, ktpFileUri, role
                )
            }
        }
    }

    /**
     * Enhanced registration with secure key generation
     */
    /**
     * Enhanced registration with secure key generation
     */
    private fun proceedWithSecureRegistration(
        nationalId: String,
        fullName: String,
        email: String,
        telephone: String,
        password: String,
        birthPlace: String,
        birthDate: String,
        address: String,
        region: String,
        gender: String,
        ktpFileUri: Uri?,
        role: String
    ) {
        _uiState.value = RegisterUiState.Loading
        _keyGenerationState.value = KeyGenerationState.Generating

        // Format birth date
        val formattedBirthDate = formatBirthDate(birthDate)

        viewModelScope.launch {
            try {
                Log.d(TAG, "Starting secure registration for: $email")

                // Step 1: Generate crypto keys with enhanced security
                val keyGenerationResult = generateSecureCryptoKeys()
                if (!keyGenerationResult.success) {
                    throw SecurityException(keyGenerationResult.error ?: "Key generation failed")
                }

                val keyPairInfo = keyGenerationResult.keyPairInfo!!
                Log.d(TAG, "✅ Secure crypto keys generated - Voter Address: ${keyPairInfo.voterAddress}")

                // Step 2: Store keys with maximum security
                cryptoKeyManager.storeKeyPair(keyPairInfo)
                _keyGenerationState.value = KeyGenerationState.Generated
                Log.d(TAG, "✅ Crypto keys stored securely in Android Keystore")

                // Step 3: Save registration state
                registrationStateManager.saveRegistrationState(
                    RegistrationStateManager.STATE_WAITING,
                    email,
                    nationalId
                )

                // Step 4: Blockchain integration (optional, non-blocking)
                trySecureBlockchainIntegration(keyPairInfo.voterAddress)

                // Step 5: Register with API using generated voter address
                val result = enhancedUserRepository.registerWithVoterAddress(
                    email = email,
                    password = password,
                    nik = nationalId,
                    telephone = telephone,
                    fullName = fullName,
                    gender = gender,
                    birthPlace = birthPlace,
                    birthDate = formattedBirthDate,
                    residentialAddress = address,
                    region = region,
                    role = role,
                    ktpFileUri = ktpFileUri
                )

                result.fold(
                    onSuccess = { response ->
                        handleRegistrationSuccess(response, email, nationalId, fullName, keyPairInfo)
                    },
                    onFailure = { exception ->
                        handleRegistrationFailure(exception, email)
                    }
                )
            } catch (e: SecurityException) {
                Log.e(TAG, "❌ Security exception during registration: ${e.message}", e)
                handleSecurityException(e)
            } catch (e: Exception) {
                Log.e(TAG, "❌ Exception during registration: ${e.message}", e)
                handleGeneralException(e)
            }
        }
    }

    /**
     * Generate crypto keys with enhanced security checks
     */
    private suspend fun generateSecureCryptoKeys(): KeyGenerationResult {
        return withContext(Dispatchers.Default) {
            try {
                // Check security prerequisites
                val securityCheck = performPreKeyGenerationSecurityCheck()
                if (!securityCheck.passed) {
                    return@withContext KeyGenerationResult(
                        success = false,
                        error = "Security check failed: ${securityCheck.reason}"
                    )
                }

                // Generate keys
                val keyPairInfo = cryptoKeyManager.generateKeyPair()

                // Validate generated keys
                if (!validateGeneratedKeys(keyPairInfo)) {
                    return@withContext KeyGenerationResult(
                        success = false,
                        error = "Generated keys validation failed"
                    )
                }

                KeyGenerationResult(
                    success = true,
                    keyPairInfo = keyPairInfo
                )
            } catch (e: Exception) {
                Log.e(TAG, "Key generation failed", e)
                KeyGenerationResult(
                    success = false,
                    error = e.message ?: "Unknown error"
                )
            }
        }
    }

    /**
     * Perform security check before key generation
     */
    private fun performPreKeyGenerationSecurityCheck(): SecurityCheck {
        // Check if device is rooted (basic check)
        val isRooted = checkIfDeviceRooted()
        if (isRooted) {
            return SecurityCheck(false, "Device appears to be rooted")
        }

        // Check if debugging is enabled
        val isDebugging = checkIfDebuggingEnabled()
        if (isDebugging) {
            Log.w(TAG, "Debugging is enabled - proceeding with caution")
        }

        return SecurityCheck(true, "Security checks passed")
    }

    /**
     * Validate generated keys
     */
    private fun validateGeneratedKeys(keyPairInfo: CryptoKeyManager.KeyPairInfo): Boolean {
        return try {
            // Check key lengths
            val privateKeyValid = keyPairInfo.privateKey.length >= 66 // 0x + 64 chars
            val publicKeyValid = keyPairInfo.publicKey.length >= 130 // 0x + 128 chars
            val addressValid = keyPairInfo.voterAddress.length == 42 // 0x + 40 chars

            privateKeyValid && publicKeyValid && addressValid
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Handle registration success
     */
    private fun handleRegistrationSuccess(
        response: ApiResponse<UserRegistrationData>,
        email: String,
        nationalId: String,
        fullName: String,
        keyPairInfo: CryptoKeyManager.KeyPairInfo
    ) {
        try {
            Log.d(TAG, "✅ Registration successful, processing results...")

            // Step 1: Save keys dengan method yang benar
            cryptoKeyManager.storeKeyPair(keyPairInfo)

            // Step 2: TAMBAHAN - Simpan juga ke UserLoginRepository untuk kompatibilitas
            userLoginRepository.saveKeysForUser(
                email = email,
                privateKey = keyPairInfo.privateKey,
                publicKey = keyPairInfo.publicKey
            )

            // Step 3: Save ke VoterRepository
//            voterRepository.saveVoterDataLocally(
//                fullName = fullName,  // Perbaiki typo
//                nik = nationalId,
//                publicKey = keyPairInfo.publicKey,
//                privateKey = keyPairInfo.privateKey,
//                voterAddress = keyPairInfo.voterAddress,
//                hasVoted = false
//            )

            // Step 4: Verify penyimpanan
            val savedPrivateKey = cryptoKeyManager.getPrivateKey()
            val backupPrivateKey = userLoginRepository.getPrivateKey(email)

            Log.d(TAG, "Private key verification:")
            Log.d(TAG, "- From CryptoKeyManager: ${if (savedPrivateKey != null) "✅ Found" else "❌ Not found"}")
            Log.d(TAG, "- From UserLoginRepository: ${if (backupPrivateKey != null) "✅ Found" else "❌ Not found"}")

            // Step 5: Update UI state
            _keyGenerationState.value = KeyGenerationState.Generated
            _uiState.value = RegisterUiState.Success(response)

            // Step 6: Clear registration state
            registrationStateManager.clearRegistrationState()

            Log.d(TAG, "✅ Registration process completed successfully")

        } catch (e: Exception) {
            Log.e(TAG, "❌ Error in handleRegistrationSuccess: ${e.message}", e)
            _uiState.value = RegisterUiState.Error("Registration completed but failed to save user data: ${e.message}")
        }
    }

    /**
     * Start periodic verification status check
     */
    private fun startVerificationStatusCheck(email: String) {
        viewModelScope.launch {
            try {
                Log.d(TAG, "Starting periodic verification status check for $email")
                checkVerificationStatus(email)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start verification status check", e)
            }
        }
    }

    /**
     * Handle registration failure
     */
    private fun handleRegistrationFailure(exception: Throwable, email: String) {
        Log.e(TAG, "❌ Registration failed: ${exception.message}")

        // Cleanup on failure
        cryptoKeyManager.clearStoredKeys()
        _keyGenerationState.value = KeyGenerationState.Failed(exception.message ?: "Unknown error")

        registrationStateManager.clearRegistrationState()
        _uiState.value = RegisterUiState.Error(exception.message ?: "Unknown error occurred")
    }

    /**
     * Handle security exceptions
     */
    private fun handleSecurityException(e: SecurityException) {
        cryptoKeyManager.clearStoredKeys()
        _keyGenerationState.value = KeyGenerationState.Failed("Security error: ${e.message}")

        registrationStateManager.clearRegistrationState()
        _uiState.value = RegisterUiState.Error("Security error occurred. Please try again.")
    }

    /**
     * Handle general exceptions
     */
    private fun handleGeneralException(e: Exception) {
        cryptoKeyManager.clearStoredKeys()
        _keyGenerationState.value = KeyGenerationState.Failed(e.message ?: "Unknown error")

        registrationStateManager.clearRegistrationState()
        _uiState.value = RegisterUiState.Error(e.message ?: "Unknown error occurred")
    }

    /**
     * Secure blockchain integration
     */
    private suspend fun trySecureBlockchainIntegration(voterAddress: String) {
        try {
            Log.d(TAG, "🔗 Attempting secure blockchain integration...")

            if (withContext(Dispatchers.IO) { BlockchainManager.isConnected() }) {
                Log.d(TAG, "✅ Blockchain connected, attempting address funding...")

                val txHash = withContext(Dispatchers.IO) {
                    BlockchainManager.fundVoterAddress(voterAddress)
                }

                if (txHash.isNotEmpty()) {
                    Log.d(TAG, "✅ Address funded successfully: $txHash")

                    // Store transaction hash for audit
                    storeBlockchainTransaction(voterAddress, txHash, "FUNDING")
                }
            } else {
                Log.w(TAG, "⚠️ Blockchain not connected, skipping integration")
            }
        } catch (e: Exception) {
            Log.e(TAG, "⚠️ Blockchain integration failed (non-critical): ${e.message}")
        }
    }

    /**
     * Store voter data securely with crypto reference
     */
    private fun storeVoterDataSecurely(
        nik: String,
        fullName: String,
        keyPairInfo: CryptoKeyManager.KeyPairInfo
    ) {
        try {
            val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
            with(sharedPreferences.edit()) {
                putString("voter_nik", nik)
                putString("voter_full_name", fullName)
                putString("voter_public_key", keyPairInfo.publicKey)
                putString("voter_address", keyPairInfo.voterAddress)
                putBoolean("voter_has_voted", false)
                putLong("voter_registration_time", System.currentTimeMillis())
                apply()
            }
            Log.d(TAG, "✅ Voter data stored securely")
        } catch (e: Exception) {
            Log.e(TAG, "❌ Failed to store voter data", e)
        }
    }

    /**
     * Store blockchain transaction for audit trail
     */
    private fun storeBlockchainTransaction(address: String, txHash: String, type: String) {
        try {
            val sharedPreferences = context.getSharedPreferences("VoteChainBlockchain", Context.MODE_PRIVATE)
            val key = "tx_${System.currentTimeMillis()}"
            val value = "$type|$address|$txHash"

            with(sharedPreferences.edit()) {
                putString(key, value)
                apply()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to store blockchain transaction", e)
        }
    }

    // ===== Security Helper Methods =====

    private fun checkKeystoreAvailability(): Boolean {
        return try {
            val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun checkHardwareSecurityModule(): Boolean {
        return try {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as android.app.KeyguardManager
                keyguardManager.isDeviceSecure
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }

    private fun checkEncryptionStrength(): Boolean {
        return try {
            // Check if AES-256 is available
            javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").blockSize == 16
        } catch (e: Exception) {
            false
        }
    }

    private fun calculateSecurityLevel(keystore: Boolean, hsm: Boolean, encryption: Boolean): String {
        val score = listOf(keystore, hsm, encryption).count { it }
        return when (score) {
            3 -> "HIGH"
            2 -> "MEDIUM"
            1 -> "LOW"
            else -> "MINIMAL"
        }
    }

    private fun checkIfDeviceRooted(): Boolean {
        // Basic root detection (can be enhanced)
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su"
        )
        return paths.any { java.io.File(it).exists() }
    }

    private fun checkIfDebuggingEnabled(): Boolean {
        return android.os.Debug.isDebuggerConnected()
    }

    private fun formatBirthDate(birthDate: String): String {
        return try {
            val inputFormat = SimpleDateFormat("dd/MM/yyyy", Locale.getDefault())
            val outputFormat = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault())
            val date = inputFormat.parse(birthDate)
            outputFormat.format(date ?: throw Exception("Invalid date"))
        } catch (e: Exception) {
            Log.e(TAG, "Error formatting birth date: ${e.message}", e)
            birthDate
        }
    }

    // ===== Existing methods (abbreviated for space) =====

    private fun checkInitialRegistrationState() {
        val state = registrationStateManager.getRegistrationState()
        Log.d(TAG, "Initial registration state: $state")

        when (state) {
            RegistrationStateManager.STATE_WAITING -> {
                _uiState.value = RegisterUiState.Waiting
                val email = registrationStateManager.getSavedEmail()
                if (email.isNotEmpty()) {
                    checkVerificationStatus(email)
                }
            }
            RegistrationStateManager.STATE_APPROVED -> {
                _uiState.value = RegisterUiState.Approved
            }
            RegistrationStateManager.STATE_REJECTED -> {
                registrationStateManager.clearRegistrationState()
                _uiState.value = RegisterUiState.Initial
            }
        }
    }

    private fun checkExistingRegistration(email: String, onResult: (Boolean) -> Unit) {
        val currentState = registrationStateManager.getRegistrationState()

        if (currentState != RegistrationStateManager.STATE_NONE) {
            onResult(false)
            return
        }

        viewModelScope.launch {
            try {
                val response = withContext(Dispatchers.IO) {
                    apiService.getVerificationStatus(email)
                }

                if (response.isSuccessful && response.body() != null) {
                    val verificationData = response.body()!!.data
                    if (verificationData != null) {
                        handleVerificationStatusResponse(verificationData, email)
                        onResult(false)
                    } else {
                        onResult(true)
                    }
                } else {
                    onResult(true)
                }
            } catch (e: Exception) {
                Log.d(TAG, "Error checking verification status: ${e.message}")
                onResult(true)
            }
        }
    }

    /**
     * Save the private and public keys in SharedPreferences for the given email
     */
    private fun saveKeysForUser(email: String) {
        viewModelScope.launch {
            try {
                // Instead of using getKeyPairInfo which is unavailable, we'll use the individual getter methods
                val privateKey = cryptoKeyManager.getPrivateKey()
                val publicKey = cryptoKeyManager.getPublicKey()
                val voterAddress = cryptoKeyManager.getVoterAddress()

                if (privateKey != null && publicKey != null) {
                    val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
                    val editor = sharedPreferences.edit()

                    editor.putString("${email}_private_key", privateKey)
                    editor.putString("${email}_public_key", publicKey)
                    editor.putString("${email}_voter_address", voterAddress)
                    editor.apply()

                    Log.d(TAG, "✅ Keys saved for user: $email")
                } else {
                    Log.e(TAG, "❌ Unable to save keys for user $email: Keys not available")
                }
            } catch (e: Exception) {
                Log.e(TAG, "❌ Failed to save keys for user $email", e)
            }
        }
    }
}
