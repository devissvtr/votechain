package com.nocturna.votechain.utils

import android.util.Log
import com.nocturna.votechain.blockchain.BlockchainConfig
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.web3j.protocol.Web3j
import org.web3j.protocol.http.HttpService

/**
 * Updated SignedTransactionGenerator that creates proper Ethereum transactions
 * This replaces the custom format with standard Ethereum transaction format
 */
class SignedTransactionGenerator(private val cryptoKeyManager: CryptoKeyManager) {

    companion object {
        private const val TAG = "SignedTransactionGenerator"
    }

    private val web3j: Web3j by lazy {
        val network = BlockchainConfig.getCurrentNetwork()
        Web3j.build(HttpService(network.rpcUrl))
    }

    private val ethereumTransactionGenerator: EthereumTransactionGenerator by lazy {
        EthereumTransactionGenerator(cryptoKeyManager, web3j)
    }

    /**
     * Generate signed transaction for voting
     * Now returns a proper Ethereum transaction in hex format
     *
     * @param electionPairId The ID of the selected candidate pair
     * @param voterId The voter's unique identifier
     * @param region The voter's region
     * @return Signed Ethereum transaction string (0x...) or null if failed
     */
    suspend fun generateVoteSignedTransaction(
        electionPairId: String,
        voterId: String,
        region: String
    ): String? = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "🔐 Starting signed transaction generation")
            Log.d(TAG, "  - Election Pair ID: $electionPairId")
            Log.d(TAG, "  - Voter ID: $voterId")
            Log.d(TAG, "  - Region: $region")

            // Validate inputs
            if (!validateInputs(electionPairId, voterId, region)) {
                Log.e(TAG, "❌ Input validation failed")
                return@withContext null
            }

            // Validate crypto prerequisites
            if (!validateCryptoPrerequisites()) {
                Log.e(TAG, "❌ Crypto prerequisites validation failed")
                return@withContext null
            }

            // Generate Ethereum transaction
            val signedTransaction = ethereumTransactionGenerator.generateVoteTransaction(
                electionPairId = electionPairId,
                voterId = voterId,
                region = region
            )

            if (signedTransaction == null) {
                Log.e(TAG, "❌ Failed to generate Ethereum transaction")
                return@withContext null
            }

            Log.d(TAG, "✅ Ethereum transaction generated successfully")
            Log.d(TAG, "  - Transaction hash: ${org.web3j.crypto.Hash.sha3(signedTransaction)}")
            Log.d(TAG, "  - Transaction length: ${signedTransaction.length} characters")

            return@withContext signedTransaction

        } catch (e: SecurityException) {
            Log.e(TAG, "❌ Security error during transaction generation: ${e.message}", e)
            null
        } catch (e: Exception) {
            Log.e(TAG, "❌ Unexpected error during transaction generation: ${e.message}", e)
            null
        }
    }

    /**
     * Validate signed transaction format
     * Now validates Ethereum transaction format
     *
     * @param signedTransaction The signed transaction to validate
     * @return true if valid Ethereum transaction, false otherwise
     */
    fun validateSignedTransaction(signedTransaction: String?): Boolean {
        return try {
            if (signedTransaction.isNullOrEmpty()) {
                Log.e(TAG, "❌ Signed transaction is null or empty")
                return false
            }

            // Must start with 0x
            if (!signedTransaction.startsWith("0x")) {
                Log.e(TAG, "❌ Transaction doesn't start with 0x")
                return false
            }

            // Check minimum length (at least 100 characters for a transaction)
            if (signedTransaction.length < 100) {
                Log.e(TAG, "❌ Transaction too short: ${signedTransaction.length} chars")
                return false
            }

            // Validate hex format
            val hex = signedTransaction.substring(2)
            if (!hex.matches(Regex("[0-9a-fA-F]+"))) {
                Log.e(TAG, "❌ Transaction contains non-hex characters")
                return false
            }

            // Additional validation: check transaction type byte
            val txBytes = org.web3j.utils.Numeric.hexStringToByteArray(signedTransaction)
            if (txBytes.isEmpty()) {
                Log.e(TAG, "❌ Failed to decode transaction bytes")
                return false
            }

            val txType = txBytes[0].toInt() and 0xFF
            val isValidType = when (txType) {
                0x00, 0x01, 0x02 -> true // Valid EIP transaction types
                in 0xc0..0xfe -> true // Legacy transaction
                else -> false
            }

            if (!isValidType) {
                Log.e(TAG, "❌ Invalid transaction type: $txType")
                return false
            }

            Log.d(TAG, "✅ Signed transaction validation passed")
            return true

        } catch (e: Exception) {
            Log.e(TAG, "❌ Error validating signed transaction: ${e.message}", e)
            false
        }
    }

    /**
     * Get transaction info for debugging
     */
    fun getTransactionInfo(signedTransaction: String): Map<String, String> {
        return ethereumTransactionGenerator.getTransactionInfo(signedTransaction)
    }

    /**
     * Validate input parameters
     */
    private fun validateInputs(electionPairId: String, voterId: String, region: String): Boolean {
        return when {
            electionPairId.isEmpty() -> {
                Log.e(TAG, "❌ Election pair ID is empty")
                false
            }
            voterId.isEmpty() -> {
                Log.e(TAG, "❌ Voter ID is empty")
                false
            }
            region.isEmpty() -> {
                Log.e(TAG, "❌ Region is empty")
                false
            }
            electionPairId.length > 100 -> {
                Log.e(TAG, "❌ Election pair ID too long")
                false
            }
            voterId.length > 100 -> {
                Log.e(TAG, "❌ Voter ID too long")
                false
            }
            region.length > 50 -> {
                Log.e(TAG, "❌ Region too long")
                false
            }
            else -> {
                Log.d(TAG, "✅ Input validation passed")
                true
            }
        }
    }

    /**
     * Validate cryptographic prerequisites
     */
    private fun validateCryptoPrerequisites(): Boolean {
        return try {
            // Check if crypto key manager has required keys
            if (!cryptoKeyManager.hasStoredKeyPair()) {
                Log.e(TAG, "❌ No key pair stored")
                return false
            }

            // Test that we can retrieve the private key
            val privateKey = cryptoKeyManager.getPrivateKey()
            if (privateKey.isNullOrEmpty()) {
                Log.e(TAG, "❌ Cannot retrieve private key")
                return false
            }

            // Validate private key format
            if (!cryptoKeyManager.validatePrivateKeyFormat(privateKey)) {
                Log.e(TAG, "❌ Private key has invalid format")
                return false
            }

            Log.d(TAG, "✅ Crypto prerequisites validation passed")
            return true

        } catch (e: Exception) {
            Log.e(TAG, "❌ Crypto validation exception: ${e.message}", e)
            return false
        }
    }
}