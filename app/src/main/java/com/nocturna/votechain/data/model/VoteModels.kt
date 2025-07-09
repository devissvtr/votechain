package com.nocturna.votechain.data.model

/** Enhanced Request model for casting a vote with OTP support
 * POST /v1/vote/cast
 */
data class VoteCastRequest(
    val election_pair_id: String,
    val otp_token: String,
    val region: String,
    val signed_transaction: String,
    val voter_id: String
)

/**
 * Response model for vote casting
 */
data class VoteCastResponse(
    val code: Int,
    val data: VoteCastData?,
    val error: VoteCastError?,
    val message: String
)

/**
 * Vote cast data in response
 */
data class VoteCastData(
    val id: String,
    val status: String,
    val tx_hash: String,
    val voted_at: String
)

/**
 * Vote cast error details
 */
data class VoteCastError(
    val error_code: Int,
    val error_message: String
)

/**
 * Sealed class representing different states of vote submission
 */
sealed class VoteState {
    object Idle : VoteState()
    object Loading : VoteState()
    data class Success(val data: VoteCastData?) : VoteState()
    data class Error(val message: String) : VoteState()
}
