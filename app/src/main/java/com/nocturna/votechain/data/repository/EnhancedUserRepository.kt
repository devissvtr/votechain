package com.nocturna.votechain.data.repository

import android.content.Context
import android.net.Uri
import android.util.Log
import com.nocturna.votechain.blockchain.BlockchainManager
import com.nocturna.votechain.blockchain.TransactionResult
import com.nocturna.votechain.data.model.ApiResponse
import com.nocturna.votechain.data.model.UserRegistrationData
import com.nocturna.votechain.data.network.NetworkClient
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import retrofit2.HttpException
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/**
 * Enhanced UserRepository with blockchain integration for voter registration
 */
class EnhancedUserRepository(
    private val context: Context
) {
    private val TAG = "EnhancedUserRepository"
    private val apiService = NetworkClient.apiService
    private val registrationApiService = NetworkClient.registrationApiService
    private val cryptoKeyManager = CryptoKeyManager(context)

    /**
     * Register user with voter address and blockchain integration
     */
    suspend fun registerWithVoterAddress(
        email: String,
        password: String,
        nik: String,
        fullName: String,
        gender: String,
        birthPlace: String,
        birthDate: String,
        residentialAddress: String,
        region: String,
        role: String = "voter",
        telephone: String,
        ktpFileUri: Uri?
    ): Result<ApiResponse<UserRegistrationData>> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "🚀 Starting enhanced user registration with blockchain integration")
            Log.d(TAG, "- Email: $email")
            Log.d(TAG, "- NIK: $nik")
            Log.d(TAG, "- Full Name: $fullName")
            Log.d(TAG, "- Region: $region")

            // Step 1: Generate or retrieve crypto keys
            val keyPairInfo = ensureUserHasKeys()
            Log.d(TAG, "✅ Crypto keys ready")
            Log.d(TAG, "- Voter Address: ${keyPairInfo.voterAddress}")
            Log.d(TAG, "- Private Key Length: ${keyPairInfo.privateKey.length}")

            // Step 2: Register on blockchain first (optional, non-blocking)
            var blockchainTxHash: String? = null
            try {
                if (BlockchainManager.isConnected()) {
                    Log.d(TAG, "🔗 Registering voter on blockchain...")

                    // For now, we'll use a default private key for blockchain registration
                    // In a real implementation, this should be managed more securely
                    val blockchainResult = BlockchainManager.registerVoter(
                        privateKey = keyPairInfo.privateKey,
                        nik = nik,
                        voterAddress = keyPairInfo.voterAddress
                    )

                    when (blockchainResult) {
                        is TransactionResult.Success -> {
                            blockchainTxHash = blockchainResult.transactionHash
                            Log.d(TAG, "✅ Blockchain registration successful: $blockchainTxHash")
                        }
                        is TransactionResult.Pending -> {
                            blockchainTxHash = blockchainResult.transactionHash
                            Log.d(TAG, "⏳ Blockchain registration pending: $blockchainTxHash")
                        }
                        is TransactionResult.Error -> {
                            Log.w(TAG, "⚠️ Blockchain registration failed: ${blockchainResult.message}")
                            // Continue with API registration even if blockchain fails
                        }
                    }
                } else {
                    Log.w(TAG, "⚠️ Blockchain not connected, skipping blockchain registration")
                }
            } catch (e: Exception) {
                Log.w(TAG, "⚠️ Blockchain registration exception: ${e.message}")
                // Continue with API registration even if blockchain fails
            }

            // Step 3: Prepare API registration data
            val registrationData = createRegistrationRequestBody(
                email = email,
                password = password,
                nik = nik,
                fullName = fullName,
                gender = gender,
                birthPlace = birthPlace,
                birthDate = birthDate,
                residentialAddress = residentialAddress,
                region = region,
                role = role,
                telephone = telephone,
                voterAddress = keyPairInfo.voterAddress,
                blockchainTxHash = blockchainTxHash
            )

            // Step 4: Handle KTP file upload if provided
            val ktpFilePart = ktpFileUri?.let { uri ->
                createKtpFilePart(uri)
            }

            // Step 5: Submit registration to API
            Log.d(TAG, "📡 Submitting registration to API...")
            val response = if (ktpFilePart != null) {
                registrationApiService.registerWithKtp(
                    registrationData = registrationData,
                    ktpFile = ktpFilePart
                )
            } else {
                registrationApiService.register(registrationData)
            }

            if (response.isSuccessful) {
                val registrationResponse = response.body()
                if (registrationResponse != null) {
                    Log.d(TAG, "✅ API registration successful")
                    Log.d(TAG, "- Response Code: ${registrationResponse.code}")
                    Log.d(TAG, "- Message: ${registrationResponse.message}")
                    Log.d(TAG, "- User ID: ${registrationResponse.data?.id}")
                    Log.d(TAG, "- Verification Status: ${registrationResponse.data?.verification_status}")

                    // Step 6: Store user data locally
                    storeUserDataLocally(
                        email = email,
                        nik = nik,
                        fullName = fullName,
                        voterAddress = keyPairInfo.voterAddress,
                        userId = registrationResponse.data?.id,
                        blockchainTxHash = blockchainTxHash
                    )

                    // Step 7: Store keys associated with user
                    storeKeysForUser(email, keyPairInfo)

                    Result.success(registrationResponse)
                } else {
                    Log.e(TAG, "❌ API registration response body is null")
                    Result.failure(Exception("Empty response from registration server"))
                }
            } else {
                Log.e(TAG, "❌ API registration failed: ${response.code()} - ${response.message()}")
                val errorBody = response.errorBody()?.string()
                Log.e(TAG, "Error body: $errorBody")
                Result.failure(HttpException(response))
            }

        } catch (e: IOException) {
            Log.e(TAG, "❌ Network error during registration: ${e.message}", e)
            Result.failure(IOException("Network error. Please check your internet connection.", e))
        } catch (e: HttpException) {
            Log.e(TAG, "❌ HTTP error during registration: ${e.message}", e)
            Result.failure(e)
        } catch (e: SecurityException) {
            Log.e(TAG, "❌ Security error during registration: ${e.message}", e)
            Result.failure(e)
        } catch (e: Exception) {
            Log.e(TAG, "❌ Unexpected error during registration: ${e.message}", e)
            Result.failure(Exception("Unexpected error occurred: ${e.message}", e))
        }
    }

    /**
     * Ensure user has crypto keys (generate if needed)
     */
    private fun ensureUserHasKeys(): CryptoKeyManager.KeyPairInfo {
        return try {
            // Check if keys already exist
            if (cryptoKeyManager.hasStoredKeyPair()) {
                Log.d(TAG, "✅ Using existing crypto keys")

                val privateKey = cryptoKeyManager.getPrivateKey()
                val publicKey = cryptoKeyManager.getPublicKey()
                val voterAddress = cryptoKeyManager.getVoterAddress()

                if (privateKey != null && publicKey != null && voterAddress != null) {
                    return CryptoKeyManager.KeyPairInfo(
                        privateKey = privateKey,
                        publicKey = publicKey,
                        voterAddress = voterAddress,
                        generationMethod = "Existing_Keys"
                    )
                }
            }

            // Generate new keys if none exist or existing keys are invalid
            Log.d(TAG, "🔑 Generating new crypto keys...")
            val keyPairInfo = cryptoKeyManager.generateKeyPair()

            // Store the generated keys
            cryptoKeyManager.storeKeyPair(keyPairInfo)

            Log.d(TAG, "✅ New crypto keys generated and stored")
            keyPairInfo
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error ensuring crypto keys: ${e.message}", e)
            throw SecurityException("Failed to generate or retrieve crypto keys: ${e.message}", e)
        }
    }

    /**
     * Create registration request body
     */
    private fun createRegistrationRequestBody(
        email: String,
        password: String,
        nik: String,
        fullName: String,
        gender: String,
        birthPlace: String,
        birthDate: String,
        residentialAddress: String,
        region: String,
        role: String,
        telephone: String,
        voterAddress: String,
        blockchainTxHash: String?
    ): Map<String, String> {
        val data = mutableMapOf(
            "email" to email,
            "password" to password,
            "nik" to nik,
            "full_name" to fullName,
            "gender" to gender,
            "birth_place" to birthPlace,
            "birth_date" to birthDate,
            "residential_address" to residentialAddress,
            "region" to region,
            "role" to role,
            "telephone" to telephone,
            "voter_address" to voterAddress,
            "timestamp" to System.currentTimeMillis().toString()
        )

        // Add blockchain transaction hash if available
        blockchainTxHash?.let {
            data["blockchain_tx_hash"] = it
        }

        return data
    }

    /**
     * Create KTP file part for multipart upload
     */
    private fun createKtpFilePart(ktpFileUri: Uri): MultipartBody.Part? {
        return try {
            val inputStream = context.contentResolver.openInputStream(ktpFileUri)
            val file = File(context.cacheDir, "ktp_${System.currentTimeMillis()}.jpg")

            inputStream?.use { input ->
                FileOutputStream(file).use { output ->
                    input.copyTo(output)
                }
            }

            val requestFile = file.asRequestBody("image/jpeg".toMediaTypeOrNull())
            MultipartBody.Part.createFormData("ktp_file", file.name, requestFile)
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error creating KTP file part: ${e.message}", e)
            null
        }
    }

    /**
     * Store user data locally
     */
    private fun storeUserDataLocally(
        email: String,
        nik: String,
        fullName: String,
        voterAddress: String,
        userId: String?,
        blockchainTxHash: String?
    ) {
        try {
            val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
            with(sharedPreferences.edit()) {
                putString("user_email", email)
                putString("user_nik", nik)
                putString("user_full_name", fullName)
                putString("user_voter_address", voterAddress)
                putLong("registration_timestamp", System.currentTimeMillis())

                userId?.let {
                    putString("user_id", it)
                }

                blockchainTxHash?.let {
                    putString("registration_blockchain_tx_hash", it)
                }

                apply()
            }
            Log.d(TAG, "✅ User data stored locally")
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error storing user data locally: ${e.message}", e)
        }
    }

    /**
     * Store keys for specific user
     */
    private fun storeKeysForUser(email: String, keyPairInfo: CryptoKeyManager.KeyPairInfo) {
        try {
            val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
            with(sharedPreferences.edit()) {
                putString("${email}_private_key", keyPairInfo.privateKey)
                putString("${email}_public_key", keyPairInfo.publicKey)
                putString("${email}_voter_address", keyPairInfo.voterAddress)
                putString("${email}_key_generation_method", keyPairInfo.generationMethod)
                putLong("${email}_key_creation_time", keyPairInfo.creationTime)
                apply()
            }
            Log.d(TAG, "✅ Keys stored for user: $email")
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error storing keys for user: ${e.message}", e)
        }
    }

    /**
     * Get user registration data
     */
    fun getUserRegistrationData(email: String): UserRegistrationLocalData? {
        return try {
            val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)

            val userEmail = sharedPreferences.getString("user_email", null)
            if (userEmail != email) {
                return null
            }

            UserRegistrationLocalData(
                email = userEmail,
                nik = sharedPreferences.getString("user_nik", null),
                fullName = sharedPreferences.getString("user_full_name", null),
                voterAddress = sharedPreferences.getString("user_voter_address", null),
                userId = sharedPreferences.getString("user_id", null),
                registrationTimestamp = sharedPreferences.getLong("registration_timestamp", 0),
                blockchainTxHash = sharedPreferences.getString("registration_blockchain_tx_hash", null)
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error getting user registration data: ${e.message}", e)
            null
        }
    }

    /**
     * Check if user is registered
     */
    fun isUserRegistered(email: String): Boolean {
        return getUserRegistrationData(email) != null
    }

    /**
     * Clear user registration data
     */
    fun clearUserRegistrationData() {
        try {
            val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
            with(sharedPreferences.edit()) {
                remove("user_email")
                remove("user_nik")
                remove("user_full_name")
                remove("user_voter_address")
                remove("user_id")
                remove("registration_timestamp")
                remove("registration_blockchain_tx_hash")
                apply()
            }
            Log.d(TAG, "✅ User registration data cleared")
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error clearing user registration data: ${e.message}", e)
        }
    }

    /**
     * Register KPU on blockchain
     */
    suspend fun registerKPUOnBlockchain(
        privateKey: String,
        address: String,
        name: String,
        region: String,
        type: KPUType
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "🏛️ Registering KPU on blockchain")
            Log.d(TAG, "- Type: $type")
            Log.d(TAG, "- Address: $address")
            Log.d(TAG, "- Name: $name")
            Log.d(TAG, "- Region: $region")

            val result = when (type) {
                KPUType.PROVINSI -> {
                    BlockchainManager.registerKPUProvinsi(
                        privateKey = privateKey,
                        address = address,
                        name = name,
                        region = region
                    )
                }
                KPUType.KOTA -> {
                    BlockchainManager.registerKPUKota(
                        privateKey = privateKey,
                        address = address,
                        name = name,
                        region = region
                    )
                }
            }

            when (result) {
                is TransactionResult.Success -> {
                    Log.d(TAG, "✅ KPU registration successful: ${result.transactionHash}")
                    Result.success(result.transactionHash)
                }
                is TransactionResult.Pending -> {
                    Log.d(TAG, "⏳ KPU registration pending: ${result.transactionHash}")
                    Result.success(result.transactionHash)
                }
                is TransactionResult.Error -> {
                    Log.e(TAG, "❌ KPU registration failed: ${result.message}")
                    Result.failure(Exception(result.message))
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error registering KPU on blockchain: ${e.message}", e)
            Result.failure(e)
        }
    }

    /**
     * Fund voter address
     */
    suspend fun fundVoterAddress(
        fundingPrivateKey: String,
        voterAddress: String,
        amount: String = "0.001"
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "💰 Funding voter address: $voterAddress")

            val txHash = BlockchainManager.fundVoterAddress(
                fundingPrivateKey = fundingPrivateKey,
                voterAddress = voterAddress,
                amount = amount
            )

            if (txHash.isNotEmpty()) {
                Log.d(TAG, "✅ Funding successful: $txHash")
                Result.success(txHash)
            } else {
                Log.e(TAG, "❌ Funding failed: Empty transaction hash")
                Result.failure(Exception("Funding transaction failed"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error funding voter address: ${e.message}", e)
            Result.failure(e)
        }
    }

    /**
     * Data class for local user registration data
     */
    data class UserRegistrationLocalData(
        val email: String,
        val nik: String?,
        val fullName: String?,
        val voterAddress: String?,
        val userId: String?,
        val registrationTimestamp: Long,
        val blockchainTxHash: String?
    )

    /**
     * Enum for KPU types
     */
    enum class KPUType {
        PROVINSI, KOTA
    }
}