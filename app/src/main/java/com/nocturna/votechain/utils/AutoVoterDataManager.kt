//package com.nocturna.votechain.utils
//
//import android.content.Context
//import android.util.Log
//import com.nocturna.votechain.data.repository.UserLoginRepository
//import com.nocturna.votechain.data.repository.VoterRepository
//import kotlinx.coroutines.Dispatchers
//import kotlinx.coroutines.withContext
//
///**
// * Utility class to handle automatic voter data fetching after password verification
// * This ensures consistent behavior across the app when user credentials are verified
// */
//class AutoVoterDataManager(private val context: Context) {
//
//    private val userLoginRepository = UserLoginRepository(context)
//    private val voterRepository = VoterRepository(context)
//
//    companion object {
//        private const val TAG = "AutoVoterDataManager"
//    }
//
//    /**
//     * Verify password and automatically fetch voter data if verification succeeds
//     * @param password The password to verify
//     * @param showLoadingCallback Callback to show/hide loading state
//     * @return AutoFetchResult containing the result of both operations
//     */
//    suspend fun verifyPasswordAndFetchData(
//        password: String,
//        showLoadingCallback: ((Boolean) -> Unit)? = null
//    ): AutoFetchResult = withContext(Dispatchers.IO) {
//
//        if (password.isEmpty()) {
//            return@withContext AutoFetchResult.Error("Password cannot be empty")
//        }
//
//        try {
//            showLoadingCallback?.invoke(true)
//            Log.d(TAG, "🔐 Starting password verification with auto-fetch...")
//
//            // Step 1: Verify password
//            val isPasswordValid = userLoginRepository.verifyPassword(password)
//
//            if (!isPasswordValid) {
//                Log.w(TAG, "❌ Password verification failed")
//                return@withContext AutoFetchResult.Error("Incorrect password. Please try again")
//            }
//
//            Log.d(TAG, "✅ Password verification successful, proceeding with auto-fetch...")
//
//            // Step 2: Auto-fetch voter data
//            val userToken = userLoginRepository.getUserToken()
//            if (userToken.isEmpty()) {
//                Log.w(TAG, "⚠️ No user token available for voter data fetch")
//                return@withContext AutoFetchResult.PartialSuccess(
//                    password = password,
//                    warning = "Password verified but no session token available"
//                )
//            }
//
//            // Fetch fresh voter data
//            val voterResult = voterRepository.fetchVoterData(userToken)
//
//            return@withContext voterResult.fold(
//                onSuccess = { voterData ->
//                    Log.d(TAG, "✅ Complete auto-fetch successful")
//                    Log.d(TAG, "- Voter: ${voterData.full_name}")
//                    Log.d(TAG, "- NIK: ${voterData.nik}")
//                    Log.d(TAG, "- Has Voted: ${voterData.has_voted}")
//
//                    // Save locally for immediate access
//                    voterRepository.saveVoterDataLocally(voterData)
//
//                    AutoFetchResult.Success(
//                        password = password,
//                        voterData = voterData,
//                        message = "Password verified and voter data updated successfully"
//                    )
//                },
//                onFailure = { error ->
//                    Log.w(TAG, "⚠️ Voter data fetch failed: ${error.message}")
//                    AutoFetchResult.PartialSuccess(
//                        password = password,
//                        warning = "Password verified but failed to refresh voter data: ${error.message}"
//                    )
//                }
//            )
//
//        } catch (e: Exception) {
//            Log.e(TAG, "❌ Exception during auto-fetch process: ${e.message}")
//            return@withContext AutoFetchResult.Error("Verification error: ${e.message}")
//        } finally {
//            showLoadingCallback?.invoke(false)
//        }
//    }
//
//    /**
//     * Quick method to just fetch voter data (without password verification)
//     * Useful for refresh operations
//     */
//    suspend fun refreshVoterData(): AutoFetchResult = withContext(Dispatchers.IO) {
//        try {
//            Log.d(TAG, "🔄 Manual voter data refresh...")
//
//            val userToken = userLoginRepository.getUserToken()
//            if (userToken.isEmpty()) {
//                return@withContext AutoFetchResult.Error("No authentication token available")
//            }
//
//            val voterResult = voterRepository.fetchVoterData(userToken)
//
//            return@withContext voterResult.fold(
//                onSuccess = { voterData ->
//                    Log.d(TAG, "✅ Manual refresh successful")
//                    voterRepository.saveVoterDataLocally(voterData)
//                    AutoFetchResult.Success(
//                        password = "", // Not applicable for refresh
//                        voterData = voterData,
//                        message = "Voter data refreshed successfully"
//                    )
//                },
//                onFailure = { error ->
//                    Log.e(TAG, "❌ Manual refresh failed: ${error.message}")
//                    AutoFetchResult.Error("Failed to refresh voter data: ${error.message}")
//                }
//            )
//
//        } catch (e: Exception) {
//            Log.e(TAG, "❌ Exception during manual refresh: ${e.message}")
//            return@withContext AutoFetchResult.Error("Refresh error: ${e.message}")
//        }
//    }
//
//    /**
//     * Check if auto-fetch is available (user has valid session)
//     */
//    suspend fun isAutoFetchAvailable(): Boolean = withContext(Dispatchers.IO) {
//        try {
//            val userEmail = userLoginRepository.getUserEmail()
//            val userToken = userLoginRepository.getUserToken()
//
//            return@withContext !userEmail.isNullOrEmpty() && userToken.isNotEmpty()
//        } catch (e: Exception) {
//            Log.e(TAG, "Error checking auto-fetch availability: ${e.message}")
//            return@withContext false
//        }
//    }
//}
//
///**
// * Sealed class representing the result of auto-fetch operations
// */
//sealed class AutoFetchResult {
//    data class Success(
//        val password: String,
//        val voterData: com.nocturna.votechain.data.model.VoterData,
//        val message: String
//    ) : AutoFetchResult()
//
//    data class PartialSuccess(
//        val password: String,
//        val warning: String
//    ) : AutoFetchResult()
//
//    data class Error(
//        val message: String
//    ) : AutoFetchResult()
//}
//
///**
// * Extension functions for easier result handling
// */
//fun AutoFetchResult.isSuccess(): Boolean = this is AutoFetchResult.Success
//fun AutoFetchResult.isPartialSuccess(): Boolean = this is AutoFetchResult.PartialSuccess
//fun AutoFetchResult.isError(): Boolean = this is AutoFetchResult.Error
//
//fun AutoFetchResult.getPassword(): String? = when (this) {
//    is AutoFetchResult.Success -> password
//    is AutoFetchResult.PartialSuccess -> password
//    is AutoFetchResult.Error -> null
//}
//
//fun AutoFetchResult.getMessage(): String = when (this) {
//    is AutoFetchResult.Success -> message
//    is AutoFetchResult.PartialSuccess -> warning
//    is AutoFetchResult.Error -> message
//}