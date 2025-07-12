package com.nocturna.votechain.data.repository

import android.content.Context
import android.util.Log
import com.nocturna.votechain.data.model.OTPGenerateRequest
import com.nocturna.votechain.data.model.OTPGenerateResponse
import com.nocturna.votechain.data.model.OTPVerifyRequest
import com.nocturna.votechain.data.model.OTPVerifyResponse
import com.nocturna.votechain.data.model.VoterData
import com.nocturna.votechain.data.network.NetworkClient
import com.nocturna.votechain.data.network.NetworkClient.otpApiService
import com.nocturna.votechain.data.network.OTPApiService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn

/**
 * Repository for handling OTP verification operations
 */
class OTPRepository(private val context: Context) {
    private val TAG = "OTPRepository"
    private val PREFS_NAME = "VoteChainPrefs"
    private val KEY_OTP_TOKEN = "otp_token"
    private val KEY_OTP_TOKEN_EXPIRY = "otp_token_expiry"
    private val KEY_OTP_TOKEN_CREATED = "otp_token_created"
    private val voterRepository = VoterRepository(context)

    /**
     * Generate OTP for voting verification
     */
    fun generateVotingOTP(categoryId: String): Flow<Result<OTPGenerateResponse>> = flow {
        try {
            Log.d(TAG, "Generating OTP for category: $categoryId")

            val token = getStoredToken()
            if (token.isNullOrEmpty()) {
                emit(Result.failure(Exception("Authentication token not found")))
                return@flow
            }

            val voterResult = voterRepository.fetchVoterData(token)
            voterResult.fold(
                onSuccess = { voterData ->
                    val request = OTPGenerateRequest(
                        phone_number = voterData.telephone,
                        purpose = "vote_cast",
                        voter_id = voterData.id
                    )

                    Log.d(TAG, "Generating OTP with request: phone=${request.phone_number}, voter_id=${request.voter_id}")
                    val response = NetworkClient.otpApiService.generateOTP("Bearer $token", request)

                    if (response.isSuccessful) {
                        response.body()?.let { otpResponse ->
                            // Use helper function for cleaner code
                            if (otpResponse.isSuccessful()) {
                                Log.d(TAG, "OTP operation successful for voter: ${voterData.id}")

                                // Handle specific scenarios
                                if (otpResponse.isOTPAlreadyExists()) {
                                    Log.d(TAG, "OTP already exists and is still valid")
                                } else {
                                    Log.d(TAG, "New OTP generated successfully")
                                }

                                emit(Result.success(otpResponse))
                            } else {
                                val errorMsg = otpResponse.getErrorMessage()
                                Log.e(TAG, "OTP generation failed: $errorMsg")
                                emit(Result.failure(Exception(errorMsg)))
                            }
                        } ?: run {
                            Log.e(TAG, "Empty response body from OTP API")
                            emit(Result.failure(Exception("Empty response from server")))
                        }
                    } else {
                        val errorBody = response.errorBody()?.string()
                        Log.e(TAG, "OTP API failed with code: ${response.code()}, body: $errorBody")
                        emit(Result.failure(Exception("Failed to generate OTP: ${response.code()}")))
                    }
                },
                onFailure = { error ->
                    Log.e(TAG, "Failed to fetch voter data: ${error.message}")
                    emit(Result.failure(Exception("Failed to fetch voter data: ${error.message}")))
                }
            )
        } catch (e: Exception) {
            Log.e(TAG, "Exception during OTP generation", e)
            emit(Result.failure(e))
        }
    }.flowOn(Dispatchers.IO)

    /**
     * Verify OTP code
     */
    fun verifyVotingOTP(categoryId: String, otpCode: String): Flow<Result<OTPVerifyResponse>> = flow {
        try {
            Log.d(TAG, "Verifying OTP code for category: $categoryId")

            val token = getStoredToken()
            if (token.isNullOrEmpty()) {
                emit(Result.failure(Exception("Authentication token not found")))
                return@flow
            }

            val voterResult = voterRepository.fetchVoterData(token)
            voterResult.fold(
                onSuccess = { voterData ->
                    val request = OTPVerifyRequest(
                        code = otpCode,
                        purpose = "vote_cast",
                        voter_id = voterData.id
                    )

                    Log.d(TAG, "Verifying OTP with voter_id: ${voterData.id}")
                    val response = otpApiService.verifyOTP("Bearer $token", request)

                    if (response.isSuccessful) {
                        response.body()?.let { verifyResponse ->
                            // Use helper function for cleaner code
                            if (verifyResponse.isVerificationSuccessful()) {
                                Log.d(TAG, "OTP verification successful")
                                val otpToken = verifyResponse.data!!.otp_token
                                val tokenExpiry = verifyResponse.data.token_expiry

                                Log.d(TAG, "  - OTP Token: ${otpToken.take(8)}...${otpToken.takeLast(8)}")
                                Log.d(TAG, "  - Token Expiry: $tokenExpiry")

                                storeOTPToken(otpToken, tokenExpiry)

                                // FIX: Validate that the token was stored correctly
                                val storedToken = getStoredOTPToken()
                                if (storedToken == otpToken) {
                                    Log.d(TAG, "✅ Token storage verification successful")
                                } else {
                                    Log.e(TAG, "❌ Token storage verification failed!")
                                    Log.e(TAG, "  - Expected: ${otpToken.take(8)}...${otpToken.takeLast(8)}")
                                    Log.e(TAG, "  - Stored: ${storedToken?.take(8)}...${storedToken?.takeLast(8)}")
                                }

                                emit(Result.success(verifyResponse))
                            } else {
                                val errorMsg = verifyResponse.getErrorMessage()
                                Log.e(TAG, "❌ OTP verification failed: $errorMsg")
                                Log.e(TAG, "  - Response code: ${verifyResponse.code}")
                                Log.e(TAG, "  - Error details: ${verifyResponse.error}")
                                emit(Result.failure(Exception(errorMsg)))
                            }
                        } ?: run {
                            Log.e(TAG, "Empty response body from OTP verify API")
                            emit(Result.failure(Exception("Empty response from server")))
                        }
                    } else {
                        val errorBody = response.errorBody()?.string()
                        Log.e(TAG, "OTP verify API failed with code: ${response.code()}, body: $errorBody")
                        emit(Result.failure(Exception("OTP verification failed: ${response.code()}")))
                    }
                },
                onFailure = { error ->
                    Log.e(TAG, "Failed to fetch voter data for verification: ${error.message}")
                    emit(Result.failure(Exception("Failed to verify voter data: ${error.message}")))
                }
            )
        } catch (e: Exception) {
            Log.e(TAG, "Exception during OTP verification", e)
            emit(Result.failure(e))
        }
    }.flowOn(Dispatchers.IO)


    /**
     * Resend OTP for voting verification - FIXED VERSION
     */
    fun resendVotingOTP(categoryId: String): Flow<Result<OTPGenerateResponse>> = flow {
        try {
            Log.d(TAG, "Resending OTP for category: $categoryId")

            val token = getStoredToken()
            if (token.isNullOrEmpty()) {
                emit(Result.failure(Exception("Authentication token not found")))
                return@flow
            }

            val voterResult = voterRepository.fetchVoterData(token)
            voterResult.fold(
                onSuccess = { voterData ->
                    val request = OTPGenerateRequest(
                        phone_number = "+6285722663467",
                        purpose = "vote_cast",
                        voter_id = voterData.id
                    )

                    val response = otpApiService.resendOTP("Bearer $token", request)

                    if (response.isSuccessful) {
                        response.body()?.let { otpResponse ->
                            // FIX: Accept HTTP status codes (200-299) and internal success code (0)
                            if (otpResponse.data != null && (otpResponse.code in 200..299 || otpResponse.code == 0)) {
                                Log.d(TAG, "OTP resent successfully for voter: ${voterData.id}")
                                Log.d(TAG, "Resend Status: ${otpResponse.data.message}")
                                emit(Result.success(otpResponse))
                            } else {
                                val errorMsg = otpResponse.error?.error_message ?: "Failed to resend OTP"
                                Log.e(TAG, "OTP resend failed: $errorMsg")
                                emit(Result.failure(Exception(errorMsg)))
                            }
                        } ?: run {
                            Log.e(TAG, "Empty response body from OTP resend API")
                            emit(Result.failure(Exception("Empty response from server")))
                        }
                    } else {
                        val errorBody = response.errorBody()?.string()
                        Log.e(TAG, "OTP resend API failed with code: ${response.code()}, body: $errorBody")
                        emit(Result.failure(Exception("API Error: ${response.code()} - $errorBody")))
                    }
                },
                onFailure = { error ->
                    Log.e(TAG, "Failed to fetch voter data for resend: ${error.message}")
                    emit(Result.failure(Exception("Failed to fetch voter data: ${error.message}")))
                }
            )
        } catch (e: Exception) {
            Log.e(TAG, "Exception during OTP resend", e)
            emit(Result.failure(e))
        }
    }.flowOn(Dispatchers.IO)

    /**
     * Get stored authentication token
     */
    private fun getStoredToken(): String? {
        val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return sharedPreferences.getString("auth_token", null)
            ?: sharedPreferences.getString("user_token", null)
    }

    /**
     * Store OTP token for voting process
     */
    private fun storeOTPToken(token: String, expiryTime: String? = null) {
        val sharedPrefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        with(sharedPrefs.edit()) {
            putString(KEY_OTP_TOKEN, token)
            putLong(KEY_OTP_TOKEN_CREATED, System.currentTimeMillis())

            // Store expiry time if provided
            expiryTime?.let {
                putString(KEY_OTP_TOKEN_EXPIRY, it)
            }

            apply()
        }
        Log.d(TAG, "✅ OTP token stored successfully with metadata")
        Log.d(TAG, "  - Token length: ${token.length}")
        Log.d(TAG, "  - Created at: ${System.currentTimeMillis()}")
        Log.d(TAG, "  - Expiry: ${expiryTime ?: "Not specified"}")
    }

    /**
     * Get stored OTP token
     */
    fun getStoredOTPToken(): String? {
        val sharedPrefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val token = sharedPrefs.getString(KEY_OTP_TOKEN, null)
        val createdTime = sharedPrefs.getLong(KEY_OTP_TOKEN_CREATED, 0)
        val expiryTime = sharedPrefs.getString(KEY_OTP_TOKEN_EXPIRY, null)

        Log.d(TAG, "🔍 Retrieving OTP token:")
        Log.d(TAG, "  - Token found: ${if (token != null) "Yes (${token.length} chars)" else "No"}")
        Log.d(TAG, "  - Created: ${if (createdTime > 0) "${System.currentTimeMillis() - createdTime}ms ago" else "Unknown"}")
        Log.d(TAG, "  - Expiry: ${expiryTime ?: "Not specified"}")

        // FIX: Check if token is too old (older than 5 minutes)
        if (token != null && createdTime > 0) {
            val tokenAge = System.currentTimeMillis() - createdTime
            val maxAge = 5 * 60 * 1000L // 5 minutes

            if (tokenAge > maxAge) {
                Log.w(TAG, "⚠️ OTP token is too old (${tokenAge / 1000}s), clearing it")
                clearOTPToken()
                return null
            }
        }

        return token
    }

    /**
     * Clear stored OTP token
     */
    fun clearOTPToken() {
        val sharedPrefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        // Log what we're clearing
        val existingToken = sharedPrefs.getString(KEY_OTP_TOKEN, null)
        val createdTime = sharedPrefs.getLong(KEY_OTP_TOKEN_CREATED, 0)

        Log.d(TAG, "🗑️ Clearing OTP token:")
        Log.d(TAG, "  - Had token: ${existingToken != null}")
        Log.d(TAG, "  - Token age: ${if (createdTime > 0) "${System.currentTimeMillis() - createdTime}ms" else "Unknown"}")

        with(sharedPrefs.edit()) {
            remove(KEY_OTP_TOKEN)
            remove(KEY_OTP_TOKEN_EXPIRY)
            remove(KEY_OTP_TOKEN_CREATED)
            apply()
        }
        Log.d(TAG, "✅ OTP token cleared successfully")
    }

    /**
     * Check if stored OTP token is still valid
     * @return true if valid, false otherwise
     */
    fun isOTPTokenValid(): Boolean {
        val sharedPrefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val token = sharedPrefs.getString(KEY_OTP_TOKEN, null)
        val createdTime = sharedPrefs.getLong(KEY_OTP_TOKEN_CREATED, 0)
        val expiryTime = sharedPrefs.getString(KEY_OTP_TOKEN_EXPIRY, null)

        // If no token exists, it's not valid
        if (token.isNullOrEmpty()) {
            Log.d(TAG, "⚠️ No OTP token found during validation")
            return false
        }

        // Check creation time - token shouldn't be older than 5 minutes unless expiry is specified
        if (createdTime > 0) {
            val tokenAge = System.currentTimeMillis() - createdTime
            val maxAge = 5 * 60 * 1000L // 5 minutes

            // If we have a specific expiry time, parse and use that
            if (!expiryTime.isNullOrEmpty()) {
                try {
                    // If expiry is in ISO format, parse it
                    val expiryMillis = if (expiryTime.contains("T")) {
                        val format = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", java.util.Locale.US)
                        format.timeZone = java.util.TimeZone.getTimeZone("UTC")
                        format.parse(expiryTime).time
                    } else {
                        // Otherwise treat as epoch time
                        expiryTime.toLong()
                    }

                    val isValid = System.currentTimeMillis() < expiryMillis
                    Log.d(TAG, "🔍 OTP token validation by expiry time:")
                    Log.d(TAG, "  - Current time: ${System.currentTimeMillis()}")
                    Log.d(TAG, "  - Expiry time: $expiryMillis")
                    Log.d(TAG, "  - Valid: $isValid")
                    return isValid
                } catch (e: Exception) {
                    Log.e(TAG, "❌ Error parsing expiry time: $expiryTime", e)
                    // Fall back to age-based validation
                }
            }

            val isValid = tokenAge <= maxAge
            Log.d(TAG, "🔍 OTP token validation by age:")
            Log.d(TAG, "  - Token age: ${tokenAge/1000}s")
            Log.d(TAG, "  - Max allowed age: ${maxAge/1000}s")
            Log.d(TAG, "  - Valid: $isValid")
            return isValid
        }
        return true
    }
}