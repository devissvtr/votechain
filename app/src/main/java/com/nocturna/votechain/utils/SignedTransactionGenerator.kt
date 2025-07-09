package com.nocturna.votechain.utils

import android.util.Log
import com.nocturna.votechain.blockchain.BlockchainConfig
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.web3j.protocol.Web3j
import org.web3j.protocol.http.HttpService
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
     * Generate enhanced signed transaction for voting
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

            // Step 2: Get cryptographic keys from user profile
            val privateKey = cryptoKeyManager.getPrivateKey()
            val publicKey = cryptoKeyManager.getPublicKey()
            val voterAddress = cryptoKeyManager.getVoterAddress()

            if (privateKey.isNullOrEmpty() || publicKey.isNullOrEmpty()) {
                Log.e(TAG, "❌ Required keys not available from user profile")
                return@withContext null
            }

            Log.d(TAG, "✅ Keys retrieved from user profile")
            Log.d(TAG, "  - Private key length: ${privateKey.length}")
            Log.d(TAG, "  - Public key length: ${publicKey.length}")
            Log.d(TAG, "  - Voter address: $voterAddress")

            // Step 3: Create transaction data structure
            val nonce = generateSecureNonce()
            val transactionData = createTransactionData(
                electionPairId, voterId, region, timestamp, nonce, voterAddress ?: ""
            )

            Log.d(TAG, "✅ Transaction data created")
            Log.d(TAG, "  - Nonce: $nonce")
            Log.d(TAG, "  - Data length: ${transactionData.length}")

            // Step 4: Generate transaction hash
            val transactionHash = generateTransactionHash(transactionData)
            Log.d(TAG, "✅ Transaction hash generated: ${transactionHash.take(16)}...")

            // Step 5: Sign the transaction using private key
            val signature = signTransactionData(transactionHash, privateKey)
            if (signature.isNullOrEmpty()) {
                Log.e(TAG, "❌ Failed to sign transaction data")
                return@withContext null
            }

            Log.d(TAG, "✅ Transaction signed successfully")
            Log.d(TAG, "  - Signature length: ${signature.length}")

            // Step 6: Create final signed transaction
            val signedTransaction = createFinalSignedTransaction(
                transactionData, transactionHash, signature, publicKey
            )

            Log.d(TAG, "✅ Enhanced signed transaction created")
            Log.d(TAG, "  - Final transaction length: ${signedTransaction.length}")

            return@withContext signedTransaction

        } catch (e: Exception) {
            Log.e(TAG, "❌ Exception during transaction generation", e)
            return@withContext null
        }
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
     * Validate transaction inputs
     */
    private fun validateTransactionInputs(
        electionPairId: String,
        voterId: String,
        region: String
    ): Boolean {
        return when {
            electionPairId.isBlank() -> {
                Log.e(TAG, "❌ Election pair ID is blank")
                false
            }
            voterId.isBlank() -> {
                Log.e(TAG, "❌ Voter ID is blank")
                false
            }
            region.isBlank() -> {
                Log.e(TAG, "❌ Region is blank")
                false
            }
            electionPairId.length > 100 -> {
                Log.e(TAG, "❌ Election pair ID too long")
                false
            }
            voterId.length > 50 -> {
                Log.e(TAG, "❌ Voter ID too long")
                false
            }
            region.length > 50 -> {
                Log.e(TAG, "❌ Region too long")
                false
            }
            else -> {
                Log.d(TAG, "✅ Transaction inputs validated")
                true
            }
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