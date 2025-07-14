package com.nocturna.votechain.data.repository

import android.content.Context
import android.net.Uri
import android.util.Log
import com.nocturna.votechain.blockchain.BlockchainManager
import com.nocturna.votechain.data.model.ApiResponse
import com.nocturna.votechain.data.model.UserRegistrationData
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Extended UserRepository that supports voter address generation
 */
class EnhancedUserRepository(context: Context) {
    private val userRepository = UserRepository(context)
    private val TAG = "EnhancedUserRepository"

    /**
     * Register a new user with KTP file and automatically generated voter address
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
        ktpFileUri: Uri? = null
    ): Result<ApiResponse<UserRegistrationData>> {
        try {
            // Generate Ethereum address using BlockchainManager
            val voterAddress = BlockchainManager.generateAddress()
            Log.d(TAG, "Generated voter address: $voterAddress")

            // Try to fund the new address if connected to blockchain
            tryFundingNewAddress(voterAddress)

            // Call the original repository with the generated address
            return userRepository.registerUser(
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
                voterAddress = voterAddress,
                telephone = telephone,
                ktpFileUri = ktpFileUri
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error in registerWithVoterAddress: ${e.message}", e)
            return Result.failure(e)
        }
    }

    /**
     * Attempt to fund the newly created voter address
     * This is optional and will not block registration if it fails
     */
    private suspend fun tryFundingNewAddress(voterAddress: String) {
        try {
            // Check if connected to blockchain
            if (withContext(Dispatchers.IO) { BlockchainManager.isConnected() }) {
                // Attempt to fund the address with a small amount of ETH
                val txHash = withContext(Dispatchers.IO) {
                    BlockchainManager.fundVoterAddress(voterAddress)
                }

                if (txHash.isNotEmpty()) {
                    Log.d(TAG, "Successfully funded address $voterAddress, transaction hash: $txHash")
                } else {
                    Log.w(TAG, "Funding transaction for $voterAddress failed or returned empty hash")
                }
            } else {
                Log.w(TAG, "Not connected to blockchain node, skipping funding operation")
            }
        } catch (e: Exception) {
            // Log error but don't fail the registration
            Log.e(TAG, "Failed to fund voter address: ${e.message}", e)
        }
    }
}