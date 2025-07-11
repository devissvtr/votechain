package com.nocturna.votechain.data.network

import android.content.Context
import android.util.Log
import com.google.gson.GsonBuilder
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

/**
 * Singleton class for network client setup
 */
object NetworkClient {

    const val BASE_URL = "https://fc5edff56405.ngrok-free.app"
    private const val TAG = "NetworkClient"
    private const val PREFS_NAME = "VoteChainPrefs"
    private const val KEY_USER_TOKEN = "user_token"
    private const val KEY_TEMP_API_KEY = "temporary_api_key" // Added for initial registration

    private var applicationContext: Context? = null

    /**
     * Initialize the NetworkClient with application context
     * Call this from your Application class or MainActivity
     */
    fun initialize(context: Context) {
        applicationContext = context.applicationContext
    }

    /**
     * Get stored user token from SharedPreferences
     */
    private fun getUserToken(): String {
        return applicationContext?.let { context ->
            val sharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            sharedPreferences.getString(KEY_USER_TOKEN, "") ?: ""
        } ?: ""
    }

    /**
     * Get temporary API key for initial registration
     * This is used for endpoints that need authentication before the user has logged in
     */
    private fun getTemporaryApiKey(): String {
        // You can implement a more secure mechanism to obtain this key
        return "register_temp_key_123456" // Replace with your actual temporary API key for registration
    }

    /**
     * Create authentication interceptor that automatically adds Bearer token
     * with an option to use temporary API key for registration flows
     */
    private fun createAuthInterceptor(useTemporaryKeyForMissingToken: Boolean = false): Interceptor {
        return Interceptor { chain ->
            val originalRequest = chain.request()
            val token = getUserToken()

            // Check if request is multipart
            val isMultipart = originalRequest.body?.contentType()?.toString()
                ?.contains("multipart/form-data") == true

            val requestBuilder = originalRequest.newBuilder()
                .addHeader("Accept", "application/json")

            // Only add Content-Type for non-multipart requests
            if (!isMultipart) {
                requestBuilder.addHeader("Content-Type", "application/json")
            }

            // Add authorization header
            if (token.isNotEmpty()) {
                requestBuilder.addHeader("Authorization", "Bearer $token")
            } else if (useTemporaryKeyForMissingToken) {
                // Use temporary API key when no token is available and the flag is set
                requestBuilder.addHeader("Authorization", "Bearer ${getTemporaryApiKey()}")
            }

            chain.proceed(requestBuilder.build())
        }
    }

    /**
     * Create and configure OkHttpClient with logging and timeouts
     * Made public so it can be used directly if needed
     */
    fun createOkHttpClient(useTemporaryKeyForMissingToken: Boolean = false): OkHttpClient {
        val loggingInterceptor = HttpLoggingInterceptor { message ->
            Log.d(TAG, message)
        }.apply {
            level = HttpLoggingInterceptor.Level.BODY
        }

        return OkHttpClient.Builder()
            .addInterceptor(loggingInterceptor)
            .addInterceptor(createAuthInterceptor(useTemporaryKeyForMissingToken)) // Add auth interceptor with option
            .connectTimeout(60, TimeUnit.SECONDS) // Increased timeout for slow connections
            .readTimeout(60, TimeUnit.SECONDS)
            .writeTimeout(60, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true) // Enable retry on connection failure
            .build()
    }

    /**
     * Create and configure Retrofit instance
     */
    private val retrofit: Retrofit by lazy {
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
     * Create API service instance for user-related operations
     */
    val apiService: ApiService by lazy {
        retrofit.create(ApiService::class.java)
    }

    /**
     * Create API service instance for voter-related operations
     */
    val voterApiService: VoterApiService by lazy {
        retrofit.create(VoterApiService::class.java)
    }

    val voteApiService: VoteApiService = retrofit.create(VoteApiService::class.java)

    // Create OTP API service
    val otpApiService: OTPApiService = retrofit.create(OTPApiService::class.java)

    /**
     * Create a new OkHttpClient specifically for requests that need manual token injection
     * This is useful for requests where you want to pass a specific token
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

    /**
     * Create a Retrofit instance with a specific token
     * Useful for one-off requests with a specific token
     */
    fun createRetrofitWithToken(token: String): Retrofit {
        val gson = GsonBuilder()
            .setLenient()
            .serializeNulls()
            .create()

        return Retrofit.Builder()
            .baseUrl(BASE_URL)
            .client(createClientWithToken(token))
            .addConverterFactory(GsonConverterFactory.create(gson))
            .build()
    }

    /**
     * Create a Retrofit instance for registration flow API calls
     * This includes special handling for verification status checks
     */
    private val registrationRetrofit: Retrofit by lazy {
        val gson = GsonBuilder()
            .setLenient()
            .serializeNulls()
            .create()

        Retrofit.Builder()
            .baseUrl(BASE_URL)
            .client(createOkHttpClient(useTemporaryKeyForMissingToken = true))
            .addConverterFactory(GsonConverterFactory.create(gson))
            .build()
    }

    /**
     * API service specifically for registration flow API calls
     * This service will use the temporary API key for auth when needed
     */
    val registrationApiService: ApiService by lazy {
        registrationRetrofit.create(ApiService::class.java)
    }
}