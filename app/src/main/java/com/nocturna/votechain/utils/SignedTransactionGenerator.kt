package com.nocturna.votechain.utils

import android.util.Log
import com.nocturna.votechain.blockchain.BlockchainConfig
import com.nocturna.votechain.blockchain.BlockchainManager
import com.nocturna.votechain.blockchain.ContractCall
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.web3j.protocol.Web3j
import org.web3j.protocol.http.HttpService
import org.web3j.utils.Numeric
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Updated SignedTransactionGenerator that creates proper Ethereum transactions
 * This replaces the custom format with standard Ethereum transaction format
 */
class SignedTransactionGenerator(private val cryptoKeyManager: CryptoKeyManager) {

    companion object {
        private const val TAG = "SignedTransactionGenerator"
        private const val TRANSACTION_VERSION = "1.0"
        private const val SIGNATURE_ALGORITHM = "ECDSA_SHA256"
    }

    /**
     * Generate enhanced signed transaction for voting using ContractCall
     * @param electionPairId The ID of the selected candidate pair
     * @param voterId The voter's unique identifier
     * @param region The voter's region
     * @param timestamp Unix timestamp of the transaction
     * @return Signed transaction string or null if failed
     */
    suspend fun generateVoteTransaction(
        electionPairId: String,
        voterId: String,
        region: String,
        timestamp: Long
    ): String? = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "🔐 Generating enhanced signed transaction")
            Log.d(TAG, "  - Election Pair ID: $electionPairId")
            Log.d(TAG, "  - Voter ID: $voterId")
            Log.d(TAG, "  - Region: $region")
            Log.d(TAG, "  - Timestamp: $timestamp")

            // Step 1: Validate inputs
            if (!validateTransactionInputs(electionPairId, voterId, region)) {
                Log.e(TAG, "❌ Transaction input validation failed")
                return@withContext null
            }

            // Step 2: Get private key
            val privateKey = cryptoKeyManager.getPrivateKey()
            if (privateKey.isNullOrEmpty()) {
                Log.e(TAG, "❌ Private key is null or empty")
                return@withContext null
            }

            // Step 3: Use ContractCall.executeVoteFunction to generate the signed transaction
            // The electionNo is derived from the region for this implementation
            val electionNo = deriveElectionNumberFromRegion(region)

            val signedTransaction = ContractCall.executeVoteFunction(
                privateKey = privateKey,
                electionId = electionPairId,
                electionNo = electionNo
            )

            if (signedTransaction.isNullOrEmpty()) {
                Log.e(TAG, "❌ Failed to generate signed transaction using ContractCall")
                return@withContext fallbackToLegacyTransactionGeneration(
                    electionPairId, voterId, region, timestamp, privateKey
                )
            }

            Log.d(TAG, "✅ Signed transaction generated using ContractCall: ${signedTransaction.take(16)}...")
            return@withContext signedTransaction

        } catch (e: Exception) {
            Log.e(TAG, "❌ Exception during transaction generation with ContractCall", e)
            try {
                // Fallback to legacy transaction generation
                val privateKey = cryptoKeyManager.getPrivateKey()
                if (privateKey != null) {
                    return@withContext fallbackToLegacyTransactionGeneration(
                        electionPairId, voterId, region, timestamp, privateKey
                    )
                }
            } catch (fallbackEx: Exception) {
                Log.e(TAG, "❌ Fallback transaction generation also failed", fallbackEx)
            }
            return@withContext null
        }
    }

    /**
     * Derive election number from region
     * This is a placeholder implementation - adjust according to your system's requirements
     */
    private fun deriveElectionNumberFromRegion(region: String): String {
        // Simple mapping from region to election number
        // In a real implementation, this might come from a lookup table or API
        return region.hashCode().rem(10).toString().replace("-", "")
    }

    /**
     * Fallback to legacy transaction generation method
     */
    private suspend fun fallbackToLegacyTransactionGeneration(
        electionPairId: String,
        voterId: String,
        region: String,
        timestamp: Long,
        privateKeyHex: String
    ): String? = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "🔄 Falling back to legacy transaction generation")

            // Step 1: Prepare transaction parameters
            val nonce = BigInteger.ZERO // Replace with actual nonce retrieval logic
            val to = BlockchainConfig.activeNetwork.votingContractAddress
            val value = BigInteger.ZERO
            val data = "ElectionPair:$electionPairId;VoterId:$voterId;Region:$region"
            val maxPriorityFeePerGas = BigInteger.valueOf(BlockchainConfig.Gas.MAX_PRIORITY_FEE_GWEI)
            val maxFeePerGas = BigInteger.valueOf(BlockchainConfig.Gas.MAX_FEE_PER_GAS_GWEI)
            val gasLimit = BigInteger.valueOf(BlockchainConfig.Gas.VOTE_GAS_LIMIT)
            val chainId = BlockchainConfig.activeNetwork.chainId
            val privateKeyClean = privateKeyHex.removePrefix("0x").padStart(64, '0')

            // Fix: Ensure the private key is properly handled to maintain 256 bits
            val privateKeyBytes = Numeric.hexStringToByteArray(privateKeyClean)
            // Use sign bit 1 (positive) to preserve all bytes including leading zeros
            val privateKey = BigInteger(1, privateKeyBytes)

            Log.d(TAG, "Private key bit length: ${privateKey.bitLength()}")

            // Only check if the key is too large, not exactly 256 bits
            if (privateKey.bitLength() > 256) {
                throw IllegalArgumentException("Invalid private key length. Expected 256 bits.")
            }

            // Step 2: Generate signed transaction
            val signedTransaction = BlockchainManager.createAndSignTransaction(
                nonce,
                to,
                value,
                data,
                maxPriorityFeePerGas,
                maxFeePerGas,
                gasLimit,
                chainId,
                privateKey
            )

            Log.d(TAG, "✅ Signed transaction generated with legacy method: ${signedTransaction.take(16)}...")
            return@withContext signedTransaction

        } catch (e: Exception) {
            Log.e(TAG, "❌ Exception during legacy transaction generation", e)
            return@withContext null
        }
    }

    /**
     * Validate transaction inputs
     */
    private fun validateTransactionInputs(
        electionPairId: String,
        voterId: String,
        region: String
    ): Boolean {
        if (electionPairId.isBlank()) {
            Log.e(TAG, "❌ Election pair ID is empty")
            return false
        }

        if (voterId.isBlank()) {
            Log.e(TAG, "❌ Voter ID is empty")
            return false
        }

        if (region.isBlank()) {
            Log.e(TAG, "❌ Region is empty")
            return false
        }

        return true
    }

    /**
     * Validate signed transaction format and signature
     */
    fun validateSignedTransaction(signedTransaction: String): TransactionValidationResult {
        try {
            if (signedTransaction.isBlank()) {
                return TransactionValidationResult(false, "Transaction is empty")
            }

            // Parse transaction components
            val parts = signedTransaction.split("|")
            if (parts.size < 5) {
                return TransactionValidationResult(false, "Invalid transaction format - insufficient parts")
            }

            val version = parts[0]
            val data = parts[1]
            val hash = parts[2]
            val signature = parts[3]
            val publicKey = parts[4]

            // Validate version
            if (version != "v$TRANSACTION_VERSION") {
                return TransactionValidationResult(false, "Invalid transaction version")
            }

            // Validate data format
            if (data.isBlank() || !data.contains(":")) {
                return TransactionValidationResult(false, "Invalid transaction data format")
            }

            // Validate hash
            if (hash.length != 64 || !hash.matches(Regex("^[0-9a-fA-F]{64}$"))) {
                return TransactionValidationResult(false, "Invalid transaction hash format")
            }

            // Validate signature
            if (signature.length != 64 || !signature.matches(Regex("^[0-9a-fA-F]{64}$"))) {
                return TransactionValidationResult(false, "Invalid signature format")
            }

            // Validate public key format
            if (!publicKey.startsWith("0x") || publicKey.length < 130) {
                return TransactionValidationResult(false, "Invalid public key format")
            }

            // Verify hash integrity
            val computedHash = generateTransactionHash(data)
            if (computedHash != hash) {
                return TransactionValidationResult(false, "Transaction hash verification failed")
            }

            Log.d(TAG, "✅ Signed transaction validation successful")
            return TransactionValidationResult(true, "Transaction validated successfully")

        } catch (e: Exception) {
            Log.e(TAG, "❌ Transaction validation exception", e)
            return TransactionValidationResult(false, "Validation failed: ${e.message}")
        }
    }

    /**
     * Create structured transaction data
     */
    private fun createTransactionData(
        electionPairId: String,
        voterId: String,
        region: String,
        timestamp: Long,
        nonce: String,
        voterAddress: String
    ): String {
        return "election_pair_id:$electionPairId|" +
                "voter_id:$voterId|" +
                "region:$region|" +
                "timestamp:$timestamp|" +
                "nonce:$nonce|" +
                "voter_address:$voterAddress|" +
                "algorithm:$SIGNATURE_ALGORITHM"
    }

    /**
     * Generate secure nonce for transaction uniqueness
     */
    private fun generateSecureNonce(): String {
        val random = SecureRandom()
        val bytes = ByteArray(16)
        random.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * Generate SHA-256 hash of transaction data
     */
    private fun generateTransactionHash(data: String): String {
        return MessageDigest.getInstance("SHA-256")
            .digest(data.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }

    /**
     * Sign transaction data using private key
     */
    private fun signTransactionData(transactionHash: String, privateKey: String): String? {
        return try {
            // Use the crypto key manager's signing method
            val signatureData = "$transactionHash:$privateKey:${System.currentTimeMillis()}"
            cryptoKeyManager.signData(signatureData)
        } catch (e: Exception) {
            Log.e(TAG, "❌ Signing failed", e)
            null
        }
    }

    /**
     * Create final signed transaction string
     */
    private fun createFinalSignedTransaction(
        transactionData: String,
        transactionHash: String,
        signature: String,
        publicKey: String
    ): String {
        return "v$TRANSACTION_VERSION|$transactionData|$transactionHash|$signature|$publicKey"
    }

    /**
     * Data class for transaction validation results
     */
    data class TransactionValidationResult(
        val isValid: Boolean,
        val error: String?
    )
}