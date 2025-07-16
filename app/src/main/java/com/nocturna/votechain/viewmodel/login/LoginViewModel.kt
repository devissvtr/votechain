package com.nocturna.votechain.viewmodel.login

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.nocturna.votechain.VoteChainApplication
import com.nocturna.votechain.blockchain.ContractCall
import com.nocturna.votechain.data.model.ApiResponse
import com.nocturna.votechain.data.model.CompleteUserData
import com.nocturna.votechain.data.model.UserLoginData
import com.nocturna.votechain.data.network.NetworkClient.apiService
import com.nocturna.votechain.data.repository.IntegratedEnhancedUserRepository
import com.nocturna.votechain.data.repository.RegistrationStateManager
import com.nocturna.votechain.data.repository.UserLoginRepository
import com.nocturna.votechain.data.repository.VoterRepository
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * ViewModel for the Login Screen
 */
class LoginViewModel(
    private val userLoginRepository: UserLoginRepository,
    private val integratedUserRepository: IntegratedEnhancedUserRepository,
    private val voterRepository: VoterRepository,
    private val context: Context
) : ViewModel() {
    private val TAG = "LoginViewModel"

    // Initialize CryptoKeyManager
    private val cryptoKeyManager = CryptoKeyManager(context)

    // UI State
    private val _uiState = MutableStateFlow<LoginUiState>(LoginUiState.Initial)
    val uiState: StateFlow<LoginUiState> = _uiState.asStateFlow()

    // Complete User Data State
    private val _completeUserData = MutableStateFlow<CompleteUserData?>(null)
    val completeUserData: StateFlow<CompleteUserData?> = _completeUserData.asStateFlow()

    // Session State
    private val _isLoggedIn = MutableStateFlow(false)
    val isLoggedIn: StateFlow<Boolean> = _isLoggedIn.asStateFlow()

    // Check initial login state
    init {
        checkLoginState()
    }

    /**
     * UI State for Login Screen
     */
    sealed class LoginUiState {
        data object Initial : LoginUiState()
        data object Loading : LoginUiState()
        data class Success(val userData: CompleteUserData) : LoginUiState()
        data class Error(val message: String) : LoginUiState()
        data object NavigateToHome : LoginUiState()

        // User data states
        data class PartialSuccess(val userData: CompleteUserData, val message: String) : LoginUiState()
        data class RefreshError(val userData: CompleteUserData, val message: String) : LoginUiState()
        data object LoggedOut : LoginUiState()

        // New states for registration status
        data object NavigateToWaiting : LoginUiState()
        data object NavigateToAccepted : LoginUiState()
        data object NavigateToRejected : LoginUiState()
    }

    // Add registration state manager
    private val registrationStateManager = RegistrationStateManager(context)

    /**
     * Login user with email and password
     */
    fun loginUser(email: String, password: String) {
        _uiState.value = LoginUiState.Loading
        viewModelScope.launch {
            try {
                _uiState.value = LoginUiState.Loading

                Log.d(TAG, "🔐 Starting enhanced login with auto key loading for: $email")

                // Step 1: Authenticate user dengan enhanced login
                val loginResult = userLoginRepository.loginUserWithCryptoKeys(email, password)

                loginResult.fold(
                    onSuccess = { loginResponse ->
                        Log.d(TAG, "✅ Enhanced login successful, checking registration status...")

                        // Step 2: Verify key loading success
                        val keyVerification = userLoginRepository.verifyKeysIntegrityAfterLogin(email)
                        Log.d(TAG, "🔍 Key loading verification: ${if (keyVerification) "✅ Success" else "⚠️ Needs attention"}")

                        // Step 3: Check registration status after successful login
                        checkRegistrationStatusAfterLogin(email, loginResponse.data)
                    },
                    onFailure = { error ->
                        Log.e(TAG, "❌ Enhanced login failed: ${error.message}")
                        _uiState.value = LoginUiState.Error(error.message ?: "Login failed")
                    }
                )
            } catch (e: Exception) {
                Log.e(TAG, "❌ Login exception: ${e.message}", e)
                _uiState.value = LoginUiState.Error(e.message ?: "Unknown error occurred")
            }
        }
    }

    /**
     * Generate signed vote transaction
     */
    suspend fun generateSignedVoteTransaction(electionId: String, electionNo: String): String? {
        try {
            Log.d(TAG, "Generating signed vote transaction for election: $electionId, number: $electionNo")

            // Get private key from CryptoKeyManager
            val privateKey = cryptoKeyManager.getPrivateKey()

            if (privateKey == null) {
                Log.e(TAG, "Failed to get private key for transaction signing")
                return null
            }

            // Call executeVoteFunction with the required parameters
            return ContractCall.executeVoteFunction(
                privateKey = privateKey,
                electionId = electionId,
                electionNo = electionNo
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error generating signed vote transaction: ${e.message}", e)
            return null
        }
    }

    /**
     * Load user crypto keys with fallback mechanisms
     */
    private suspend fun loadUserCryptoKeys(email: String): KeyLoadResult {
        return try {
            Log.d(TAG, "🔑 Loading crypto keys for: $email")

            // Step 1: Check if keys already loaded
            val hasKeys = integratedUserRepository.hasStoredKeys()

            if (hasKeys) {
                Log.d(TAG, "✅ Crypto keys already available")
                return KeyLoadResult.Success("Keys already loaded")
            }

//            if (hasKeys && privateKey != null && publicKey != null && voterAddress != null) {
//                Log.d(TAG, "✅ Crypto keys already available")
//                return KeyLoadResult.Success("Keys already loaded")
//            }

            // Step 2: Try to load from enhanced login repository
            Log.d(TAG, "🔄 Attempting to load keys using enhanced method...")
            val enhancedLoadResult = userLoginRepository.loginUserWithCryptoKeys(email, "")

            // Step 3: Re-check after enhanced loading
            // Step 3: Re-check after enhanced loading
            val hasKeysAfterLoad = integratedUserRepository.hasStoredKeys()

            if (hasKeysAfterLoad) {
                Log.d(TAG, "✅ Keys loaded successfully via enhanced method")
                return KeyLoadResult.Success("Keys loaded via enhanced method")
            }
//            hasKeys = cryptoKeyManager.hasStoredKeyPair()
//            privateKey = cryptoKeyManager.getPrivateKey()
//            publicKey = cryptoKeyManager.getPublicKey()
//            voterAddress = cryptoKeyManager.getVoterAddress()
//
//            if (hasKeys && privateKey != null && publicKey != null && voterAddress != null) {
//                Log.d(TAG, "✅ Keys loaded successfully via enhanced method")
//                return KeyLoadResult.Success("Keys loaded via enhanced method")
//            }

            // Step 4: Try backup restoration
            Log.d(TAG, "🔧 Attempting key restoration from backup...")
            val backupPrivateKey = userLoginRepository.getPrivateKey(email)
            val backupPublicKey = userLoginRepository.getPublicKey(email)

            if (backupPrivateKey != null && backupPublicKey != null) {
                // Restore keys using repository method
                val restoredVoterAddress = deriveVoterAddressFromPublicKey(backupPublicKey)

                // Use repository method to store keys if available
//                val restoreSuccess = integratedUserRepository.restoreKeys(
//                    backupPrivateKey, backupPublicKey, restoredVoterAddress
//                )

//                if (restoreSuccess) {
//                    Log.d(TAG, "✅ Keys restored from backup successfully")
//                    return KeyLoadResult.Success("Keys restored from backup")
//                }
            }

            // Step 5: Keys not found
            Log.w(TAG, "⚠️ No crypto keys found for user")
            KeyLoadResult.NotFound("No crypto keys available for user")

        } catch (e: Exception) {
            Log.e(TAG, "❌ Error loading crypto keys: ${e.message}", e)
            KeyLoadResult.Error("Failed to load crypto keys: ${e.message}")
        }
    }

    /**
     * Verify key integrity after loading
     */
    private suspend fun verifyKeyIntegrity(email: String): KeyIntegrityStatus {
        return try {
//            val cryptoKeyManager = integratedUserRepository.cryptoKeyManager
//
//            val hasStoredKeys = cryptoKeyManager.hasStoredKeyPair()
//            val privateKey = cryptoKeyManager.getPrivateKey()
//            val publicKey = cryptoKeyManager.getPublicKey()
//            val voterAddress = cryptoKeyManager.getVoterAddress()
            val hasStoredKeys = integratedUserRepository.hasStoredKeys()

            // Check backup storage too
            val backupPrivateKey = userLoginRepository.getPrivateKey(email)
            val backupPublicKey = userLoginRepository.getPublicKey(email)

            Log.d(TAG, "🔍 Key integrity check:")
            Log.d(TAG, "- hasStoredKeyPair: $hasStoredKeys")
            Log.d(TAG, "- backupPrivateKey: ${if (backupPrivateKey != null) "✅" else "❌"}")
            Log.d(TAG, "- backupPublicKey: ${if (backupPublicKey != null) "✅" else "❌"}")

            when {
                hasStoredKeys -> {
                    KeyIntegrityStatus.Healthy
                }
                backupPrivateKey != null && backupPublicKey != null -> {
                    KeyIntegrityStatus.BackupOnly
                }
                else -> {
                    KeyIntegrityStatus.Missing
                }
            }

//            Log.d(TAG, "🔍 Key integrity check:")
//            Log.d(TAG, "- hasStoredKeyPair: $hasStoredKeys")
//            Log.d(TAG, "- privateKey: ${if (privateKey != null) "✅" else "❌"}")
//            Log.d(TAG, "- publicKey: ${if (publicKey != null) "✅" else "❌"}")
//            Log.d(TAG, "- voterAddress: ${if (voterAddress != null) "✅" else "❌"}")
//            Log.d(TAG, "- backupPrivateKey: ${if (backupPrivateKey != null) "✅" else "❌"}")
//            Log.d(TAG, "- backupPublicKey: ${if (backupPublicKey != null) "✅" else "❌"}")
//
//            when {
//                hasStoredKeys && privateKey != null && publicKey != null && voterAddress != null -> {
//                    KeyIntegrityStatus.Healthy
//                }
//                backupPrivateKey != null && backupPublicKey != null -> {
//                    KeyIntegrityStatus.BackupOnly
//                }
//                hasStoredKeys && (privateKey == null || publicKey == null) -> {
//                    KeyIntegrityStatus.Corrupted
//                }
//                else -> {
//                    KeyIntegrityStatus.Missing
//                }
//            }
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying key integrity: ${e.message}", e)
            KeyIntegrityStatus.Error
        }
    }


    /**
     * Check registration status after successful login
     */
    private suspend fun checkRegistrationStatusAfterLogin(email: String, loginData: UserLoginData?) {
        try {
            // Step 1: Check if the user has existing registration state
            val userExists = checkUserRegistrationData(email)

            if (userExists) {
                val registrationState = registrationStateManager.getRegistrationState()
                Log.d(TAG, "Registration state found: $registrationState")

                when (registrationState) {
                    RegistrationStateManager.STATE_WAITING -> {
                        // Check if there's been an update via API
                        checkVerificationStatusFromApi(email, loginData)
                    }
                    RegistrationStateManager.STATE_APPROVED -> {
                        proceedToHome(loginData)
                    }
                    RegistrationStateManager.STATE_REJECTED -> {
                        _uiState.value = LoginUiState.NavigateToRejected
                    }
                    else -> {
                        proceedToHome(loginData)
                    }
                }
            } else {
                // Step 2: If no local state, check API
                checkVerificationStatusFromApi(email, loginData)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error checking registration status: ${e.message}", e)
            fallbackToLocalState(email, loginData)
        }

        // Load keys for this user regardless of registration state
        loadKeysForUser(email)
    }

    /**
     * Handle successful login with complete data
     */
    private fun handleLoginSuccess(
        completeData: CompleteUserData,
        keyLoadResult: KeyLoadResult,
        keyStatus: KeyIntegrityStatus
    ) {
        _completeUserData.value = completeData
        _isLoggedIn.value = true

        // Navigate based on key status
        when (keyStatus) {
            KeyIntegrityStatus.Healthy -> {
                Log.d(TAG, "✅ Login successful with healthy keys")
                _uiState.value = LoginUiState.Success(completeData)
            }
            KeyIntegrityStatus.BackupOnly -> {
                Log.d(TAG, "⚠️ Login successful but keys only in backup")
                _uiState.value = LoginUiState.PartialSuccess(
                    completeData,
                    "Keys loaded from backup. Consider regenerating for better security."
                )
            }
            KeyIntegrityStatus.Corrupted -> {
                Log.w(TAG, "⚠️ Login successful but keys are corrupted")
                _uiState.value = LoginUiState.PartialSuccess(
                    completeData,
                    "Some cryptographic keys are corrupted. Please check your profile."
                )
            }
            KeyIntegrityStatus.Missing -> {
                Log.w(TAG, "⚠️ Login successful but no crypto keys found")
                _uiState.value = LoginUiState.PartialSuccess(
                    completeData,
                    "No cryptographic keys found. You may need to regenerate them."
                )
            }
            KeyIntegrityStatus.Error -> {
                Log.e(TAG, "❌ Error checking key status")
                _uiState.value = LoginUiState.PartialSuccess(
                    completeData,
                    "Error checking cryptographic keys. Please verify in profile."
                )
            }
        }
    }

    /**
     * Derive voter address from public key
     */
    private fun deriveVoterAddressFromPublicKey(publicKey: String): String {
        return try {
            val cleanPublicKey = if (publicKey.startsWith("0x")) {
                publicKey.substring(2)
            } else {
                publicKey
            }

            val publicKeyBigInt = java.math.BigInteger(cleanPublicKey, 16)
            val addressHex = org.web3j.crypto.Keys.getAddress(publicKeyBigInt)
            org.web3j.crypto.Keys.toChecksumAddress("0x" + addressHex)
        } catch (e: Exception) {
            Log.e(TAG, "Error deriving voter address: ${e.message}")
            "0x0000000000000000000000000000000000000000"
        }
    }

    // Data classes untuk result handling
    sealed class KeyLoadResult {
        data class Success(val message: String) : KeyLoadResult()
        data class NotFound(val message: String) : KeyLoadResult()
        data class Error(val message: String) : KeyLoadResult()
    }

    enum class KeyIntegrityStatus {
        Healthy,    // All keys present and accessible in crypto manager
        BackupOnly, // Keys only available in backup storage
        Corrupted,  // Keys exist but not accessible properly
        Missing,    // No keys found anywhere
        Error       // Error during verification
    }

    /**
     * Load keys for user from SharedPreferences
     */
    private fun loadKeysForUser(email: String) {
        viewModelScope.launch {
            try {
                // Load private and public keys from SharedPreferences
                val privateKey = userLoginRepository.getPrivateKey(email)
                val publicKey = userLoginRepository.getPublicKey(email)

                if (privateKey != null && publicKey != null) {
                    // Keys loaded successfully
                    Log.d(TAG, "Keys loaded for user $email")
                } else {
                    Log.w(TAG, "No keys found for user $email")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error loading keys for user $email: ${e.message}", e)
            }
        }
    }

    /**
     * Check verification status from API
     */
    private suspend fun checkVerificationStatusFromApi(email: String, loginData: UserLoginData?) {
        try {
            // Always check with API first to get the most up-to-date status
            val response = withContext(Dispatchers.IO) {
                apiService.getVerificationStatus(email)
            }

            if (response.isSuccessful && response.body() != null) {
                val verificationData = response.body()!!.data
                if (verificationData != null) {
                    val status = verificationData.verification_status.lowercase()
                    Log.d(TAG, "API verification status for $email: $status")

                    when (status) {
                        "pending", "waiting" -> {
                            registrationStateManager.saveRegistrationState(
                                RegistrationStateManager.STATE_WAITING, email, ""
                            )
                            _uiState.value = LoginUiState.NavigateToWaiting
                        }
                        "approved", "accepted" -> {
                            // Clear waiting state since they're approved now
                            registrationStateManager.saveRegistrationState(
                                RegistrationStateManager.STATE_APPROVED, email, ""
                            )
                            // Proceed to home instead of showing the accepted screen again
                            proceedToHome(loginData)
                        }
                        "denied", "rejected" -> {
                            registrationStateManager.saveRegistrationState(
                                RegistrationStateManager.STATE_REJECTED, email, ""
                            )
                            _uiState.value = LoginUiState.NavigateToRejected
                        }
                        else -> {
                            // User is approved/no pending registration - proceed to home
                            // Clear any previous registration state
                            registrationStateManager.saveRegistrationState(
                                RegistrationStateManager.STATE_NONE, email, ""
                            )
                            proceedToHome(loginData)
                        }
                    }
                } else {
                    // No verification data found - proceed to home
                    proceedToHome(loginData)
                }
            } else {
                // API call failed - fall back to local state
                fallbackToLocalState(email, loginData)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error checking registration status: ${e.message}")
            // On error, fall back to local state
            fallbackToLocalState(email, loginData)
        }
    }

    /**
     * Fall back to local registration state when API call fails
     */
    private suspend fun fallbackToLocalState(email: String, loginData: UserLoginData?) {
        val localState = registrationStateManager.getRegistrationState()
        val savedEmail = registrationStateManager.getSavedEmail()

        Log.d(TAG, "Falling back to local state: $localState for email: $savedEmail")

        if (localState != RegistrationStateManager.STATE_NONE && savedEmail == email) {
            handleRegistrationState(localState, email)
        } else {
            // No local state or mismatch email - proceed to home (fallback)
            proceedToHome(loginData)
        }
    }

    /**
     * Handle registration state after login
     */
    private suspend fun handleRegistrationState(state: Int, email: String) {
        when (state) {
            RegistrationStateManager.STATE_WAITING -> {
                Log.d(TAG, "User has waiting registration - navigating to waiting screen")
                _uiState.value = LoginUiState.NavigateToWaiting
            }
            RegistrationStateManager.STATE_APPROVED -> {
                Log.d(TAG, "User has approved registration - navigating to accepted screen")
                _uiState.value = LoginUiState.NavigateToAccepted
            }
            RegistrationStateManager.STATE_REJECTED -> {
                Log.d(TAG, "User has rejected registration - navigating to rejected screen")
                _uiState.value = LoginUiState.NavigateToRejected
            }
            else -> {
                // No pending registration - proceed to home
                proceedToHome(null)
            }
        }
    }

    /**
     * Proceed to home screen after successful login
     */
    private suspend fun proceedToHome(loginData: UserLoginData?) {
        try {
            // Load complete user data
            loadCompleteUserData()

            // Set navigation state
            _uiState.value = LoginUiState.NavigateToHome
        } catch (e: Exception) {
            Log.e(TAG, "Error loading user data: ${e.message}")
            _uiState.value = LoginUiState.Error("Failed to load user data")
        }
    }

    /**
     * Load complete user data after successful authentication
     */
    private suspend fun loadCompleteUserData() {
        try {
            Log.d(TAG, "Loading complete user data...")

            // Load complete user data with wallet info
            val completeData = integratedUserRepository.getCompleteUserData()

            _completeUserData.value = completeData
            _isLoggedIn.value = true

            // Check if we have all required data
            val hasRequiredData = completeData.voterData != null &&
                    completeData.walletInfo.voterAddress.isNotEmpty()

            if (hasRequiredData) {
                _uiState.value = LoginUiState.Success(completeData)
                Log.d(TAG, "✅ Login completed with complete user data")

                // Log success details (without sensitive info)
                Log.d(TAG, "User data loaded:")
                Log.d(TAG, "- Voter: ${completeData.voterData?.full_name}")
                Log.d(TAG, "- Balance: ${completeData.walletInfo.balance} ETH")
                Log.d(TAG, "- Address: ${completeData.walletInfo.voterAddress.take(10)}...")
            } else {
                Log.w(TAG, "Login successful but missing some user data")
                _uiState.value = LoginUiState.PartialSuccess(completeData, "Some account data may be incomplete")
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error loading complete user data: ${e.message}", e)
            _uiState.value = LoginUiState.Error("Login successful but failed to load account data: ${e.message}")
        }
    }

    /**
     * Refresh user data (for pull-to-refresh functionality)
     */
    fun refreshUserData() {
        viewModelScope.launch {
            try {
                Log.d(TAG, "Refreshing user data...")

                val refreshedData = integratedUserRepository.refreshCompleteUserData()

                refreshedData.fold(
                    onSuccess = { data ->
                        _completeUserData.value = data
                        _uiState.value = LoginUiState.Success(data)
                        Log.d(TAG, "✅ User data refreshed successfully")
                    },
                    onFailure = { error ->
                        Log.w(TAG, "Failed to refresh user data: ${error.message}")
                        // Keep existing data but show warning
                        _uiState.value = LoginUiState.RefreshError(
                            _completeUserData.value ?: CompleteUserData(),
                            "Failed to refresh: ${error.message}"
                        )
                    }
                )
            } catch (e: Exception) {
                Log.e(TAG, "Error refreshing user data: ${e.message}", e)
            }
        }
    }

    /**
     * Refresh only wallet balance
     */
    fun refreshBalance() {
        viewModelScope.launch {
            try {
                Log.d(TAG, "Refreshing balance...")

                val newBalance = voterRepository.refreshBalance()

                // Update the wallet info in complete user data
                _completeUserData.value?.let { currentData ->
                    val updatedWalletInfo = currentData.walletInfo.copy(
                        balance = newBalance,
                        lastUpdated = System.currentTimeMillis(),
                        hasError = false,
                        errorMessage = ""
                    )
                    val updatedData = currentData.copy(walletInfo = updatedWalletInfo)
                    _completeUserData.value = updatedData

                    Log.d(TAG, "✅ Balance refreshed: $newBalance ETH")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error refreshing balance: ${e.message}", e)

                // Update wallet info with error
                _completeUserData.value?.let { currentData ->
                    val errorWalletInfo = currentData.walletInfo.copy(
                        hasError = true,
                        errorMessage = e.message ?: "Failed to refresh balance"
                    )
                    val updatedData = currentData.copy(walletInfo = errorWalletInfo)
                    _completeUserData.value = updatedData
                }
            }
        }
    }

    /**
     * Get current user session info
     */
    fun getUserSession() = userLoginRepository.getCompleteUserSession()

    /**
     * Check if blockchain is connected
     */
    fun checkBlockchainConnection() {
        viewModelScope.launch {
            try {
                val isConnected = integratedUserRepository.checkBlockchainConnection()
                Log.d(TAG, "Blockchain connection status: $isConnected")

                // Update wallet info with connection status
                _completeUserData.value?.let { currentData ->
                    val updatedWalletInfo = currentData.walletInfo.copy(
                        hasError = !isConnected,
                        errorMessage = if (!isConnected) "Blockchain not connected" else ""
                    )
                    val updatedData = currentData.copy(walletInfo = updatedWalletInfo)
                    _completeUserData.value = updatedData
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error checking blockchain connection: ${e.message}", e)
            }
        }
    }

    /**
     * Clear error state
     */
    fun clearError() {
        if (_uiState.value is LoginUiState.Error) {
            _uiState.value = LoginUiState.Initial
        }
    }

    /**
     * Reset the UI state to initial
     */
    fun resetState() {
        _uiState.value = LoginUiState.Initial
    }

    /**
     * Check if user is already logged in
     */
    fun isUserLoggedIn(): Boolean {
        return userLoginRepository.isUserLoggedIn()
    }

    /**
     * Reset login state (used when navigating away from login result screens)
     */
    fun resetLoginState() {
        _uiState.value = LoginUiState.Initial
    }

    /**
     * Check key integrity using public methods
     */
    private suspend fun checkKeyIntegrity(email: String): Boolean {
        return try {
            // Use public methods from repositories to check key integrity
            val hasStoredKeys = integratedUserRepository.hasStoredKeys()
            val backupPrivateKey = userLoginRepository.getPrivateKey(email)
            val backupPublicKey = userLoginRepository.getPublicKey(email)

            Log.d(TAG, "🔍 Key integrity check:")
            Log.d(TAG, "- hasStoredKeyPair: $hasStoredKeys")
            Log.d(TAG, "- backupPrivateKey: ${if (backupPrivateKey != null) "✅" else "❌"}")
            Log.d(TAG, "- backupPublicKey: ${if (backupPublicKey != null) "✅" else "❌"}")

            // Return true if we have either stored keys or backup keys
            hasStoredKeys || (backupPrivateKey != null && backupPublicKey != null)
        } catch (e: Exception) {
            Log.e(TAG, "Error checking key integrity: ${e.message}", e)
            false
        }
    }

    /**
     * Enhanced check login state dengan crypto key loading
     */
    fun checkLoginState() {
        viewModelScope.launch {
            try {
                val isSessionValid = userLoginRepository.isSessionValid()

                if (isSessionValid) {
                    Log.d(TAG, "✅ Valid session found, loading user data with key verification...")
                    _uiState.value = LoginUiState.Loading

                    // Load crypto keys for current user
                    val userEmail = userLoginRepository.getUserEmail()
                    if (!userEmail.isNullOrEmpty()) {
                        // Try to load keys if not already loaded
//                        val keyStatus = userLoginRepository.verifyKeyIntegrityAfterLogin(userEmail)
                        val keyStatus = checkKeyIntegrity(userEmail)
                        if (!keyStatus) {
                            Log.w(TAG, "⚠️ Keys need attention for user: $userEmail")

                            // Try to repair keys using StartupInitializer
                            try {
                                val app = context.applicationContext as VoteChainApplication
                                val repairSuccess = app.forceReloadAllKeys()
                                Log.d(TAG, "🔧 Key repair result: ${if (repairSuccess) "✅ Success" else "❌ Failed"}")
                            } catch (e: Exception) {
                                Log.e(TAG, "❌ Error during key repair: ${e.message}")
                            }
                        }
                    }

                    loadCompleteUserData()
                } else {
                    Log.d(TAG, "❌ No valid session found")
                    _uiState.value = LoginUiState.Initial
                    _isLoggedIn.value = false
                }
            } catch (e: Exception) {
                Log.e(TAG, "❌ Error checking login state: ${e.message}", e)
                _uiState.value = LoginUiState.Initial
                _isLoggedIn.value = false
            }
        }
    }

    /**
     * Enhanced logout user dengan comprehensive cleanup
     */
    fun logoutUser() {
        viewModelScope.launch {
            try {
                Log.d(TAG, "🚪 Starting enhanced logout...")

                // Step 1: Enhanced logout dari repository
                val logoutResult = userLoginRepository.logoutUserEnhanced()

                logoutResult.fold(
                    onSuccess = {
                        Log.d(TAG, "✅ Repository logout successful")
                    },
                    onFailure = { error ->
                        Log.w(TAG, "⚠️ Repository logout had issues: ${error.message}")
                        // Continue with logout even if repository fails
                    }
                )

                // Step 2: Clear all user data dari integrated repository
                integratedUserRepository.clearAllUserData()

                // Step 3: Clear application-level keys if needed
                try {
                    val app = context.applicationContext as VoteChainApplication
                    val userEmail = userLoginRepository.getUserEmail()
                    if (!userEmail.isNullOrEmpty()) {
                        app.clearKeysNeedAttention(userEmail)
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "⚠️ Could not clear application keys: ${e.message}")
                }

                // Step 4: Reset state
                _completeUserData.value = null
                _isLoggedIn.value = false
                _uiState.value = LoginUiState.LoggedOut

                Log.d(TAG, "✅ Enhanced logout completed successfully")

            } catch (e: Exception) {
                Log.e(TAG, "❌ Error during enhanced logout: ${e.message}", e)
                // Force logout even if there's an error
                _completeUserData.value = null
                _isLoggedIn.value = false
                _uiState.value = LoginUiState.LoggedOut
            }
        }
    }

    /**
     * Manual key repair untuk troubleshooting
     */
    fun repairUserKeys() {
        viewModelScope.launch {
            try {
                val userEmail = userLoginRepository.getUserEmail()
                if (userEmail == null) {
                    Log.w(TAG, "Cannot repair keys: no user email")
                    return@launch
                }

                Log.d(TAG, "🔧 Attempting manual key repair for: $userEmail")

                // Try using application-level repair
                val app = context.applicationContext as VoteChainApplication
                val repairSuccess = app.forceReloadAllKeys()

                if (repairSuccess) {
                    Log.d(TAG, "✅ Key repair successful")
                    // Refresh current user data
                    refreshUserData()
                } else {
                    Log.e(TAG, "❌ Key repair failed")
                }
            } catch (e: Exception) {
                Log.e(TAG, "❌ Exception during key repair: ${e.message}", e)
            }
        }
    }

    /**
     * Factory for creating LoginViewModel
     */
    class Factory(private val context: Context) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            if (modelClass.isAssignableFrom(LoginViewModel::class.java)) {
                val userLoginRepository = UserLoginRepository(context)
                val integratedUserRepository = IntegratedEnhancedUserRepository(context)
                val voterRepository = VoterRepository(context)

                return LoginViewModel(
                    userLoginRepository,
                    integratedUserRepository,
                    voterRepository,
                    context
                ) as T
            }
            throw IllegalArgumentException("Unknown ViewModel class")
        }
    }

    /**
     * Check if user has registration data in local storage
     */
    private fun checkUserRegistrationData(email: String): Boolean {
        val savedEmail = registrationStateManager.getSavedEmail()
        return savedEmail == email && registrationStateManager.getRegistrationState() != RegistrationStateManager.STATE_NONE
    }
}
