package com.nocturna.votechain.data.network

import android.content.Context
import android.util.Log
import com.google.gson.GsonBuilder
import com.nocturna.votechain.data.model.PartyResponse
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

/**
 * Network client for connecting to the Election API
 */
object ElectionNetworkClient {
    // Public BASE_URL to be used across the app
    const val BASE_URL = NetworkClient.BASE_URL
    private const val TAG = "ElectionNetworkClient"
    private const val PREFS_NAME = "VoteChainPrefs"
    private const val KEY_USER_TOKEN = "user_token"

    // Making this volatile to ensure visibility across threads
    @Volatile
    private var applicationContext: Context? = null

    // Making this volatile to ensure visibility across threads
    @Volatile
    private var isInitialized = false

    /**
     * Initialize the ElectionNetworkClient with application context
     */
    @Synchronized
    fun initialize(context: Context) {
        if (context.applicationContext == null) {
            Log.e(TAG, "Cannot initialize with null application context")
            return
        }

        applicationContext = context.applicationContext
        isInitialized = true
        Log.i(TAG, "ElectionNetworkClient successfully initialized with application context")

        // Check if we have a token
        val token = getUserToken()
        Log.d(TAG, "Current token status: ${if (token.isNotEmpty()) "Valid token exists" else "No token"}")
    }

    /**
     * Check if ElectionNetworkClient is initialized
     */
    fun isInitialized(): Boolean {
        val result = isInitialized && applicationContext != null
        if (!result) {
            Log.w(TAG, "ElectionNetworkClient initialization check failed: " +
                    "isInitialized=$isInitialized, applicationContext=${if (applicationContext == null) "null" else "not null"}")
        }
        return result
    }

    /**
     * Force re-initialization if needed (can be called from activities/fragments if initialization state is lost)
     */
    @Synchronized
    fun ensureInitialized(context: Context): Boolean {
        if (!isInitialized() && context != null) {
            Log.w(TAG, "Re-initializing ElectionNetworkClient")
            initialize(context)
            return true
        }
        return isInitialized()
    }

    /**
     * Get stored user token from SharedPreferences
     */
    fun getUserToken(): String {
        return applicationContext?.let { context ->
            val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val token = sharedPreferences.getString(KEY_USER_TOKEN, "") ?: ""
            Log.d(TAG, "Retrieved token: ${if (token.isNotEmpty()) "Available (${token.length} chars)" else "Empty"}")
            token
        } ?: run {
            Log.w(TAG, "Application context not initialized")
            ""
        }
    }

    /**
     * Save user token to SharedPreferences
     */
    fun saveUserToken(token: String) {
        // Clean and validate token before saving
        val cleanToken = if (token.startsWith("Bearer ", ignoreCase = true)) {
            token.substring(7).trim()
        } else {
            token.trim()
        }

        if (!validateTokenFormat(cleanToken)) {
            Log.e(TAG, "Refusing to save invalid token format")
            return
        }

        applicationContext?.let { context ->
            val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            with(sharedPreferences.edit()) {
                putString(KEY_USER_TOKEN, cleanToken) // Save without Bearer prefix
                apply()
            }
            Log.d(TAG, "✅ Valid token saved (${cleanToken.length} chars)")
        }
    }

    /**
     * Clear user token from SharedPreferences
     */
    fun clearUserToken() {
        applicationContext?.let { context ->
            val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            with(sharedPreferences.edit()) {
                remove(KEY_USER_TOKEN)
                apply()
            }
            Log.d(TAG, "Token cleared")
        } ?: run {
            Log.w(TAG, "Cannot clear token - application context not initialized")
        }
    }

    /**
     * Check if user token exists and is not empty
     */
    fun hasValidToken(): Boolean {
        val token = getUserToken()
        return token.isNotEmpty()
    }

    /**
     * Validate if token format is correct
     */
    fun validateTokenFormat(token: String): Boolean {
        if (token.isEmpty()) return false

        // Remove Bearer prefix if present
        val cleanToken = if (token.startsWith("Bearer ", ignoreCase = true)) {
            token.substring(7).trim()
        } else {
            token.trim()
        }

        // JWT should have exactly 3 parts separated by dots
        val parts = cleanToken.split(".")
        if (parts.size != 3) {
            Log.e(TAG, "Invalid JWT format: expected 3 segments, got ${parts.size}")
            return false
        }

        // Each part should not be empty
        if (parts.any { it.isEmpty() }) {
            Log.e(TAG, "Invalid JWT format: empty segments found")
            return false
        }

        return true
    }

    /**
     * Get user token with validation
     */
    fun getValidatedUserToken(): String {
        val token = getUserToken()
        return if (validateTokenFormat(token)) {
            // Remove Bearer prefix if present for consistency
            if (token.startsWith("Bearer ", ignoreCase = true)) {
                token.substring(7).trim()
            } else {
                token.trim()
            }
        } else {
            Log.w(TAG, "Invalid token format detected, clearing token")
            clearUserToken()
            ""
        }
    }

    /**
     * Create authentication interceptor for election API
     */
    private fun createAuthInterceptor(): Interceptor {
        return Interceptor { chain ->
            val originalRequest = chain.request()
            val token = getUserToken()

            val newRequest = if (token.isNotEmpty()) {
                Log.d(TAG, "Adding Bearer token to request: ${originalRequest.url}")
                originalRequest.newBuilder()
                    .addHeader("Authorization", "Bearer $token")
                    .addHeader("Accept", "application/json")
                    .addHeader("Content-Type", "application/json")
                    .build()
            } else {
                Log.w(TAG, "No token available for request: ${originalRequest.url}")
                originalRequest.newBuilder()
                    .addHeader("Accept", "application/json")
                    .addHeader("Content-Type", "application/json")
                    .build()
            }

            val response = chain.proceed(newRequest)

            // Log response for debugging
            Log.d(TAG, "Response: ${response.code} for ${originalRequest.url}")
            if (!response.isSuccessful && response.code == 401) {
                Log.w(TAG, "401 Unauthorized - token may be invalid or expired")
            }

            response
        }
    }

    /**
     * Create and configure OkHttpClient with logging and timeouts
     */
    /**
     * Create and configure OkHttpClient with logging, timeouts, and authentication
     */
    fun createOkHttpClient(): OkHttpClient {
        val loggingInterceptor = HttpLoggingInterceptor { message ->
            Log.d(TAG, message)
        }.apply {
            level = HttpLoggingInterceptor.Level.BODY
        }

        return OkHttpClient.Builder()
            .addInterceptor(loggingInterceptor)
            .addInterceptor(createAuthInterceptor())
            .connectTimeout(60, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .build()
    }

    /**
     * Create and configure Retrofit instance
     */
    val retrofit: Retrofit by lazy {
        val gson = GsonBuilder()
            .setLenient()
            .serializeNulls()
            .create()

        Retrofit.Builder()
            .baseUrl(BASE_URL)
            .client(createOkHttpClient())
            .addConverterFactory(GsonConverterFactory.create(gson))
            .build()
    }

    /**
     * Create API service instance
     */
    val electionApiService: ElectionApiService by lazy {
        retrofit.create(ElectionApiService::class.java)
    }

    /**
     * Create a new OkHttpClient with specific token for election requests
     */
    fun createClientWithToken(token: String): OkHttpClient {
        val loggingInterceptor = HttpLoggingInterceptor { message ->
            Log.d(TAG, message)
        }.apply {
            level = HttpLoggingInterceptor.Level.BODY
        }

        val tokenInterceptor = Interceptor { chain ->
            val originalRequest = chain.request()
            val newRequest = originalRequest.newBuilder()
                .addHeader("Authorization", "Bearer $token")
                .addHeader("Accept", "application/json")
                .addHeader("Content-Type", "application/json")
                .build()
            chain.proceed(newRequest)
        }

        return OkHttpClient.Builder()
            .addInterceptor(loggingInterceptor)
            .addInterceptor(tokenInterceptor)
            .connectTimeout(60, TimeUnit.SECONDS)
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .build()
    }
}

class PartyPhotoHelper {
    companion object {
        /**
         * Generate full URL untuk foto partai berdasarkan party ID
         */
        fun getPartyPhotoUrl(partyId: String): String {
            return "${ElectionNetworkClient.BASE_URL}/v1/party/$partyId/photo"
        }

        /**
         * Generate URLs untuk semua partai dari response
         */
        fun getPartyPhotoUrls(partyResponse: PartyResponse): Map<String, String> {
            val photoUrls = mutableMapOf<String, String>()

            partyResponse.data.parties.forEach { partyPair ->
                val partyId = partyPair.party.id
                val partyName = partyPair.party.name
                photoUrls[partyName] = getPartyPhotoUrl(partyId)
            }

            return photoUrls
        }
    }
}