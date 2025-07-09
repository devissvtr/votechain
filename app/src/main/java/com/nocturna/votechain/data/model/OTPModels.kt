package com.nocturna.votechain.data.model

/**
 * Data models for OTP verification API endpoints
 */

/**
 * Request model for /v1/otp/generate
 */
data class OTPGenerateRequest(
    val phone_number: String,
    val purpose: String,
    val voter_id: String
)

/**
 * Response model for /v1/otp/generate
 */
data class OTPGenerateResponse(
    val code: Int,
    val data: OTPData?,
    val error: OTPError?,
    val message: String
) {
    /**
     * Helper function to check if the response indicates success
     * Accepts both HTTP status codes (200-299) and internal success code (0)
     */
    fun isSuccessful(): Boolean {
        return (code in 200..299 || code == 0) && data != null
    }

    /**
     * Helper function to check if OTP already exists
     */
    fun isOTPAlreadyExists(): Boolean {
        return data?.message?.contains("already exists", ignoreCase = true) == true
    }

    /**
     * Helper function to get error message
     */
    fun getErrorMessage(): String {
        return error?.error_message ?: "Failed to generate OTP"
    }
}

/**
 * OTP data contained in generate response
 */
data class OTPData(
    val expires_at: String,
    val max_attempts: Int,
    val message: String,
    val purpose: String,
    val remaining_attempts: Int,
    val time_remaining_seconds: String,
    val voter_id: String
) {
    /**
     * Helper function to get remaining time in seconds as integer
     */
    fun getRemainingTimeInSeconds(): Int {
        return time_remaining_seconds.replace("s", "").toDoubleOrNull()?.toInt() ?: 300
    }
}

/**
 * Request model for /v1/otp/verify
 */
data class OTPVerifyRequest(
    val code: String,
    val purpose: String,
    val voter_id: String
)

/**
 * Response model for /v1/otp/verify
 */
data class OTPVerifyResponse(
    val code: Int,
    val data: OTPVerifyData?,
    val error: OTPError?,
    val message: String
) {
    /**
     * Helper function to check if verification was successful
     */
    fun isVerificationSuccessful(): Boolean {
        return (code in 200..299 || code == 0) && data?.is_valid == true
    }

    /**
     * Helper function to get error message
     */
    fun getErrorMessage(): String {
        return error?.error_message ?: "Invalid OTP code"
    }
}

/**
 * OTP verification data contained in verify response
 */
data class OTPVerifyData(
    val is_valid: Boolean,
    val message: String,
    val otp_token: String,
    val purpose: String,
    val token_expiry: String,
    val verified_at: String,
    val voter_id: String
)

/**
 * Error model for OTP API responses
 */
data class OTPError(
    val error_code: Int,
    val error_message: String
)