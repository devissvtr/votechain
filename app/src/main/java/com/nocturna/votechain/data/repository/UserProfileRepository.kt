package com.nocturna.votechain.data.repository

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import com.nocturna.votechain.data.model.*
import com.nocturna.votechain.data.network.NetworkClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Repository class untuk mengelola user profile operations
 */
class UserProfileRepository(private val context: Context) {
    private val TAG = "UserProfileRepository"
    private val apiService = NetworkClient.apiService
    private val userLoginRepository = UserLoginRepository(context)

    private val PREFS_NAME = "VoteChainPrefs"
    private val KEY_USER_PROFILE = "user_profile"
    private val KEY_COMPLETE_PROFILE = "complete_profile"

    /**
     * Fetch complete user profile (user data + voter data)
     * Menggunakan email yang tersimpan dari login
     */
    suspend fun fetchCompleteUserProfile(): Result<CompleteUserProfile> = withContext(Dispatchers.IO) {
        try {
            val userEmail = userLoginRepository.getUserEmail()
            val userToken = userLoginRepository.getUserToken()

            if (userEmail.isNullOrEmpty() || userToken.isNullOrEmpty()) {
                return@withContext Result.failure(Exception("User not logged in"))
            }

            Log.d(TAG, "Fetching profile for email: $userEmail")

            // Step 1: Get user profile dari /v1/user/{email}
            val userProfileResult = getUserProfile(userEmail, userToken)

            return@withContext userProfileResult.fold(
                onSuccess = { userProfile ->
                    Log.d(TAG, "User profile fetched successfully for ID: ${userProfile.id}")

                    // Step 2: Get voter data menggunakan user_id dari profile
                    val voterProfileResult = getVoterProfileByUserId(userProfile.id, userToken)

                    voterProfileResult.fold(
                        onSuccess = { voterProfile ->
                            val completeProfile = CompleteUserProfile(
                                userProfile = userProfile,
                                voterProfile = voterProfile
                            )
                            saveCompleteProfile(completeProfile)
                            Result.success(completeProfile)
                        },
                        onFailure = { voterError ->
                            Log.w(TAG, "Failed to fetch voter profile: ${voterError.message}")
                            // Tetap return user profile meskipun voter data gagal
                            val completeProfile = CompleteUserProfile(
                                userProfile = userProfile,
                                voterProfile = null
                            )
                            saveCompleteProfile(completeProfile)
                            Result.success(completeProfile)
                        }
                    )
                },
                onFailure = { userError ->
                    Log.e(TAG, "Failed to fetch user profile: ${userError.message}")
                    Result.failure(userError)
                }
            )
        } catch (e: Exception) {
            Log.e(TAG, "Exception during profile fetch", e)
            Result.failure(e)
        }
    }

    /**
     * Get user profile dari API /v1/user/{email}
     */
    private suspend fun getUserProfile(email: String, token: String): Result<UserProfileData> {
        return try {
            val response = apiService.getUserProfile(email, "Bearer $token")

            if (response.isSuccessful) {
                response.body()?.let { profileResponse ->
                    if (profileResponse.data != null) {
                        Log.d(TAG, "User profile API call successful")

                        // Extract header information
                        val headers = response.headers()
                        val publicAddress = headers["x-address"]
                        val userId = headers["x-user-id"]
                        val role = headers["x-role"] ?: headers["role"]

                        Log.d(TAG, "Headers extracted - x-address: $publicAddress, x-user-id: $userId, role: $role")

                        // Create enhanced profile data with header information
                        val enhancedProfileData = profileResponse.data.copy(
                            publicAddress = publicAddress,
                            userId = userId,
                            userRole = role
                        )

                        Result.success(enhancedProfileData)
                    } else {
                        val errorMsg = profileResponse.error?.error_message ?: profileResponse.message
                        Log.e(TAG, "User profile API returned error: $errorMsg")
                        Result.failure(Exception(errorMsg))
                    }
                } ?: run {
                    Log.e(TAG, "Empty response body from user profile API")
                    Result.failure(Exception("Empty response body"))
                }
            } else {
                val errorBody = response.errorBody()?.string()
                Log.e(TAG, "User profile API failed with code: ${response.code()}, body: $errorBody")
                Result.failure(Exception("API Error: ${response.code()} - $errorBody"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception during user profile fetch", e)
            Result.failure(e)
        }
    }

    /**
     * Get voter profile berdasarkan user_id
     */
    private suspend fun getVoterProfileByUserId(userId: String, token: String): Result<VoterData> {
        return try {
            Log.d(TAG, "Fetching voter data for user_id: $userId")

            // Gunakan endpoint /v1/voter yang sudah ada
            val response = apiService.getVoterData("Bearer $token")

            if (response.isSuccessful) {
                response.body()?.let { voterResponse ->
                    Log.d(TAG, "Voter API response code: ${voterResponse.code}, data count: ${voterResponse.data.size}")

                    // Updated to handle both code == 0 and code == 200 (common API response codes)
                    if ((voterResponse.code == 0 || voterResponse.code == 200) && voterResponse.data.isNotEmpty()) {
                        // Debug: Log all voter data for troubleshooting
                        voterResponse.data.forEachIndexed { index, voter ->
                            Log.d(TAG, "Voter $index: user_id='${voter.user_id}', id='${voter.id}', name='${voter.full_name}'")
                        }

                        // Enhanced matching logic - try multiple approaches
                        val matchingVoter = findMatchingVoter(voterResponse.data, userId)

                        if (matchingVoter != null) {
                            Log.d(TAG, "Matching voter profile found: ${matchingVoter.full_name} (user_id: ${matchingVoter.user_id})")
                            Result.success(matchingVoter)
                        } else {
                            Log.w(TAG, "No voter profile found for user_id: $userId")
                            // Log available user_ids for debugging
                            val availableUserIds = voterResponse.data.map { it.user_id }
                            Log.w(TAG, "Available user_ids: $availableUserIds")
                            Result.failure(Exception("No voter profile found for this user"))
                        }
                    } else {
                        Log.e(TAG, "Voter profile API returned error code: ${voterResponse.code}")
                        Result.failure(Exception("API returned error code: ${voterResponse.code}"))
                    }
                } ?: run {
                    Log.e(TAG, "Empty response body from voter profile API")
                    Result.failure(Exception("Empty response body"))
                }
            } else {
                val errorBody = response.errorBody()?.string()
                Log.e(TAG, "Voter profile API failed with code: ${response.code()}, body: $errorBody")
                Result.failure(Exception("API Error: ${response.code()} - $errorBody"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception during voter profile fetch", e)
            Result.failure(e)
        }
    }

    /**
     * Enhanced voter matching function with multiple fallback strategies
     */
    private fun findMatchingVoter(voterData: List<VoterData>, userId: String): VoterData? {
        Log.d(TAG, "Attempting to match userId: '$userId' with ${voterData.size} voters")

        // Log all voter data for debugging
        voterData.forEachIndexed { index, voter ->
            Log.d(TAG, "Available voter $index: user_id='${voter.user_id}', id='${voter.id}', name='${voter.full_name}'")
        }

        // Strategy 1: Exact string match (case-sensitive)
        voterData.find { it.user_id == userId }?.let { voter ->
            Log.d(TAG, "Found exact match for user_id: $userId")
            return voter
        }

        // Strategy 2: Case-insensitive match
        voterData.find { it.user_id?.equals(userId, ignoreCase = true) == true }?.let { voter ->
            Log.d(TAG, "Found case-insensitive match for user_id: $userId")
            return voter
        }

        // Strategy 3: Trimmed comparison (remove whitespace)
        voterData.find { it.user_id?.trim() == userId.trim() }?.let { voter ->
            Log.d(TAG, "Found trimmed match for user_id: $userId")
            return voter
        }

        // Strategy 4: If userId is numeric, try parsing and comparing as numbers
        try {
            val userIdAsLong = userId.toLongOrNull()
            if (userIdAsLong != null) {
                voterData.find { it.user_id?.toLongOrNull() == userIdAsLong }?.let { voter ->
                    Log.d(TAG, "Found numeric match for user_id: $userId")
                    return voter
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "Could not parse user_id as number: $userId")
        }

        // Strategy 5: Check if voter.id matches userId (sometimes the ID fields get swapped)
        voterData.find { it.id == userId }?.let { voter ->
            Log.d(TAG, "Found match using voter.id instead of user_id for: $userId")
            return voter
        }

        // If nothing matches, take the first voter as a fallback
        if (voterData.isNotEmpty()) {
            Log.d(TAG, "Using first voter as fallback since no match was found")
            return voterData.first()
        }

        Log.w(TAG, "No matching voter found using any strategy for user_id: $userId")
        return null
    }

    /**
     * Alternative method: Try fetching voter data using query parameter
     * This can be used as a fallback if the main method fails
     */
    private suspend fun getVoterProfileByUserIdQuery(userId: String, token: String): Result<VoterData> {
        return try {
            Log.d(TAG, "Trying alternative voter fetch with query parameter for user_id: $userId")

            val response = apiService.getVoterByUserId("Bearer $token", userId)

            if (response.isSuccessful) {
                response.body()?.let { voterResponse ->
                    // Updated to handle both code == 0 and code == 200 (common API response codes)
                    if ((voterResponse.code == 0 || voterResponse.code == 200) && voterResponse.data.isNotEmpty()) {
                        // Find the voter with matching user_id
                        val matchingVoter = voterResponse.data.find { it.user_id == userId }
                            ?: voterResponse.data.first()


                        Log.d(TAG, "Voter data fetched successfully via query: ${matchingVoter.full_name}")
                        Result.success(matchingVoter)
                    } else {
                        Log.e(TAG, "Query-based voter API returned empty data or error")
                        Result.failure(Exception("No voter data available via query"))
                    }
                } ?: run {
                    Log.e(TAG, "Empty response body from query-based voter API")
                    Result.failure(Exception("Empty response body"))
                }
            } else {
                val errorBody = response.errorBody()?.string()
                Log.e(TAG, "Query-based voter API failed with code: ${response.code()}, body: $errorBody")
                Result.failure(Exception("API Error: ${response.code()} - $errorBody"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception during query-based voter fetch", e)
            Result.failure(e)
        }
    }

    /**
     * Enhanced fetchCompleteUserProfile with fallback strategies
     */
    suspend fun fetchCompleteUserProfileWithFallback(): Result<CompleteUserProfile> = withContext(Dispatchers.IO) {
        try {
            val userEmail = userLoginRepository.getUserEmail()
            val userToken = userLoginRepository.getUserToken()

            if (userEmail.isNullOrEmpty() || userToken.isNullOrEmpty()) {
                return@withContext Result.failure(Exception("User not logged in"))
            }

            Log.d(TAG, "Fetching complete profile with fallback for email: $userEmail")

            // Get user profile first
            val userProfileResult = getUserProfile(userEmail, userToken)

            return@withContext userProfileResult.fold(
                onSuccess = { userProfile ->
                    Log.d(TAG, "User profile fetched successfully for ID: ${userProfile.id}")

                    // Try primary voter matching method
                    var voterProfileResult = getVoterProfileByUserId(userProfile.id, userToken)

                    // If primary method fails, try query-based method
                    if (voterProfileResult.isFailure) {
                        Log.d(TAG, "Primary voter matching failed, trying query-based approach")
                        voterProfileResult = getVoterProfileByUserIdQuery(userProfile.id, userToken)
                    }

                    voterProfileResult.fold(
                        onSuccess = { voterProfile ->
                            val completeProfile = CompleteUserProfile(
                                userProfile = userProfile,
                                voterProfile = voterProfile
                            )
                            saveCompleteProfile(completeProfile)
                            Result.success(completeProfile)
                        },
                        onFailure = { voterError ->
                            Log.w(TAG, "All voter fetch methods failed: ${voterError.message}")
                            // Still return user profile without voter data
                            val completeProfile = CompleteUserProfile(
                                userProfile = userProfile,
                                voterProfile = null
                            )
                            saveCompleteProfile(completeProfile)
                            Result.success(completeProfile)
                        }
                    )
                },
                onFailure = { userError ->
                    Log.e(TAG, "Failed to fetch user profile: ${userError.message}")
                    Result.failure(userError)
                }
            )
        } catch (e: Exception) {
            Log.e(TAG, "Exception during enhanced profile fetch", e)
            Result.failure(e)
        }
    }

    /**
     * Save complete profile ke SharedPreferences
     */
    private fun saveCompleteProfile(profile: CompleteUserProfile) {
        val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val gson = Gson()
        val profileJson = gson.toJson(profile)

        with(sharedPreferences.edit()) {
            putString(KEY_COMPLETE_PROFILE, profileJson)
            apply()
        }
        Log.d(TAG, "Complete profile saved to SharedPreferences")
    }

    /**
     * Get saved complete profile dari SharedPreferences
     */
    fun getSavedCompleteProfile(): CompleteUserProfile? {
        return try {
            val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val profileJson = sharedPreferences.getString(KEY_COMPLETE_PROFILE, null)

            if (profileJson != null) {
                val gson = Gson()
                gson.fromJson(profileJson, CompleteUserProfile::class.java)
            } else {
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error parsing saved profile", e)
            null
        }
    }

    /**
     * Clear saved profile data
     */
    fun clearProfileData() {
        val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        with(sharedPreferences.edit()) {
            remove(KEY_USER_PROFILE)
            remove(KEY_COMPLETE_PROFILE)
            apply()
        }
        Log.d(TAG, "Profile data cleared")
    }
}