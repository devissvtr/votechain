package com.nocturna.votechain.data.repository

import android.content.Context
import android.util.Log
import com.nocturna.votechain.data.model.ApiResponse
import com.nocturna.votechain.data.network.NetworkClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

/**
 * Repository for handling forgot password flow API interactions
 */
class ForgotPasswordRepository(private val context: Context) {
    private val TAG = "ForgotPasswordRepository"
    private val networkManager = NetworkClient.apiService

    /**
     * Send verification email with OTP to the user's email
     */
    suspend fun sendVerificationEmail(email: String): Result<ApiResponse<Any>> = withContext(Dispatchers.IO) {
        try {
            val jsonObject = JSONObject()
            jsonObject.put("email", email)

            val requestBody = jsonObject.toString().toRequestBody("application/json".toMediaTypeOrNull())
            val response = networkManager.sendPasswordResetOTP(requestBody)

            Log.d(TAG, "Send verification email response: $response")
            Result.success(response)
        } catch (e: Exception) {
            Log.e(TAG, "Error sending verification email: ${e.message}", e)
            Result.failure(e)
        }
    }

    /**
     * Verify OTP code sent to user's email
     */
    suspend fun verifyOTP(email: String, otp: String): Result<ApiResponse<Any>> = withContext(Dispatchers.IO) {
        try {
            val jsonObject = JSONObject()
            jsonObject.put("email", email)
            jsonObject.put("otp", otp)

            val requestBody = jsonObject.toString().toRequestBody("application/json".toMediaTypeOrNull())
            val response = networkManager.verifyPasswordResetOTP(requestBody)

            Log.d(TAG, "Verify OTP response: $response")
            Result.success(response)
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying OTP: ${e.message}", e)
            Result.failure(e)
        }
    }

    /**
     * Reset password with verified OTP
     */
    suspend fun resetPassword(email: String, otp: String, newPassword: String): Result<ApiResponse<Any>> = withContext(Dispatchers.IO) {
        try {
            val jsonObject = JSONObject()
            jsonObject.put("email", email)
            jsonObject.put("otp", otp)
            jsonObject.put("new_password", newPassword)

            val requestBody = jsonObject.toString().toRequestBody("application/json".toMediaTypeOrNull())
            val response = networkManager.resetPassword(requestBody)

            Log.d(TAG, "Reset password response: $response")
            Result.success(response)
        } catch (e: Exception) {
            Log.e(TAG, "Error resetting password: ${e.message}", e)
            Result.failure(e)
        }
    }
}
