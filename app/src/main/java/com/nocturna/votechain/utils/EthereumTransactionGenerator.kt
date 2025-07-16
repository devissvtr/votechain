package com.nocturna.votechain.utils

import android.util.Log
import com.nocturna.votechain.blockchain.BlockchainConfig
import com.nocturna.votechain.security.CryptoKeyManager
import org.web3j.abi.FunctionEncoder
import org.web3j.abi.TypeReference
import org.web3j.abi.datatypes.Address
import org.web3j.abi.datatypes.Function
import org.web3j.abi.datatypes.Utf8String
import org.web3j.abi.datatypes.generated.Uint256
import org.web3j.crypto.*
import org.web3j.protocol.Web3j
import org.web3j.protocol.core.DefaultBlockParameterName
import org.web3j.protocol.http.HttpService
import org.web3j.utils.Numeric
import java.math.BigInteger

/**
 * Ethereum transaction generator for creating proper blockchain transactions
 * Generates EIP-1559 style transactions for voting on the blockchain
 */
class EthereumTransactionGenerator(
    private val cryptoKeyManager: CryptoKeyManager,
    private val web3j: Web3j
) {

    companion object {
        private const val TAG = "EthereumTransactionGenerator"
        private const val GWEI_TO_WEI = 1_000_000_000L
    }

    /**
     * Generate a signed Ethereum transaction for voting
     *
     * @param electionPairId The ID of the election pair being voted for
     * @param voterId The ID of the voter
     * @param region The region of the voter
     * @return Signed transaction in hex format (0x...) or null if failed
     */
    suspend fun generateVoteTransaction(
        electionPairId: String,
        voterId: String,
        region: String
    ): String? {
        return try {
            Log.d(TAG, "🔐 Starting Ethereum transaction generation")
            Log.d(TAG, "  - Election Pair ID: $electionPairId")
            Log.d(TAG, "  - Voter ID: $voterId")
            Log.d(TAG, "  - Region: $region")

            // Step 1: Get private key and create credentials
            val privateKey = cryptoKeyManager.getPrivateKey()
            if (privateKey.isNullOrEmpty()) {
                Log.e(TAG, "❌ No private key available")
                return null
            }

            // Remove 0x prefix if present and create credentials
            val cleanPrivateKey = if (privateKey.startsWith("0x")) {
                privateKey.substring(2)
            } else {
                privateKey
            }

            val credentials = try {
                Credentials.create(cleanPrivateKey)
            } catch (e: Exception) {
                Log.e(TAG, "❌ Failed to create credentials from private key: ${e.message}")
                return null
            }

            Log.d(TAG, "✅ Credentials created for address: ${credentials.address}")

            // Step 2: Get current nonce for the account
            val nonce = try {
                web3j.ethGetTransactionCount(
                    credentials.address,
                    DefaultBlockParameterName.LATEST
                ).send().transactionCount
            } catch (e: Exception) {
                Log.e(TAG, "❌ Failed to get nonce: ${e.message}")
                BigInteger.ZERO // Use 0 as fallback
            }

            Log.d(TAG, "📊 Current nonce: $nonce")

            // Step 3: Create the function call data
            val function = createVoteFunction(electionPairId, voterId, region)
            val encodedFunction = FunctionEncoder.encode(function)

            Log.d(TAG, "📝 Encoded function data: ${encodedFunction.take(10)}...")
            Log.d(TAG, "📝 Function data length: ${encodedFunction.length} characters")

            // Step 4: Get current network configuration
            val network = BlockchainConfig.getCurrentNetwork()
            val maxPriorityFee = BigInteger.valueOf(BlockchainConfig.Gas.MAX_PRIORITY_FEE_GWEI * GWEI_TO_WEI)
            val maxFeePerGas = BigInteger.valueOf(BlockchainConfig.Gas.MAX_FEE_PER_GAS_GWEI * GWEI_TO_WEI)

            // Step 5: Create the raw transaction (EIP-1559)
            val rawTransaction = RawTransaction.createTransaction(
                BigInteger.valueOf(network.chainId),
                nonce,
                BigInteger.valueOf(BlockchainConfig.Gas.VOTE_GAS_LIMIT),
                network.votingContractAddress,
                BigInteger.ZERO, // No ETH value sent
                encodedFunction,
                maxPriorityFee,
                maxFeePerGas
            )

            // Step 6: Sign the transaction
            val signedMessage = TransactionEncoder.signMessage(rawTransaction, network.chainId, credentials)

            // Ensure proper hex encoding with 0x prefix
            val hexValue = Numeric.toHexString(signedMessage)

            Log.d(TAG, "✅ Transaction signed successfully")
            Log.d(TAG, "  - Transaction length: ${hexValue.length} characters")
            Log.d(TAG, "  - Transaction preview: ${hexValue.take(66)}...")

            // Additional check to ensure correct formatting and avoid corrupted bytes
            if (!isValidTransactionFormat(hexValue)) {
                Log.e(TAG, "❌ Generated transaction has invalid format")
                return null
            }

            return hexValue

        } catch (e: Exception) {
            Log.e(TAG, "❌ Exception during transaction generation: ${e.message}", e)
            null
        }
    }

    /**
     * Create the vote function call for the smart contract
     */
    private fun createVoteFunction(
        electionPairId: String,
        voterId: String,
        region: String
    ): Function {
        // This should match your smart contract's vote function signature
        return Function(
            BlockchainConfig.ContractMethods.CAST_VOTE,
            listOf(
                Utf8String(electionPairId),
                Utf8String(region)
            ),
            emptyList()
        )
    }

    /**
     * Validate that the generated transaction has proper Ethereum format
     */
    private fun isValidTransactionFormat(transaction: String): Boolean {
        return try {
            // Check if it starts with 0x
            if (!transaction.startsWith("0x")) {
                Log.e(TAG, "❌ Transaction doesn't start with 0x")
                return false
            }

            // Check minimum length (at least 100 characters for a basic transaction)
            if (transaction.length < 100) {
                Log.e(TAG, "❌ Transaction too short: ${transaction.length}")
                return false
            }

            // Check if it's valid hex
            val hex = transaction.substring(2)
            if (!hex.matches(Regex("[0-9a-fA-F]+"))) {
                Log.e(TAG, "❌ Transaction contains non-hex characters")
                return false
            }

            // Ensure there are no corrupted byte patterns (like repeated fefe patterns)
            if (hex.contains(Regex("(fefe|efef){3,}"))) {
                Log.e(TAG, "❌ Transaction contains suspicious byte patterns")
                return false
            }

            // Try to decode to verify it's a valid RLP-encoded transaction
            val txBytes = Numeric.hexStringToByteArray(transaction)
            val txType = txBytes[0].toInt() and 0xFF

            // Check for valid transaction types (legacy, EIP-2930, EIP-1559)
            when (txType) {
                0x00, 0x01, 0x02 -> {
                    Log.d(TAG, "✅ Valid transaction type: $txType")
                    true
                }
                in 0xc0..0xfe -> {
                    Log.d(TAG, "✅ Legacy transaction detected")
                    true
                }
                else -> {
                    Log.e(TAG, "❌ Unknown transaction type: $txType")
                    false
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "❌ Error validating transaction format: ${e.message}")
            false
        }
    }

    /**
     * Get transaction info for debugging
     */
    fun getTransactionInfo(signedTransaction: String): Map<String, String> {
        return try {
            val info = mutableMapOf<String, String>()

            info["length"] = signedTransaction.length.toString()
            info["preview"] = signedTransaction.take(66) + "..."

            // Try to decode basic info
            if (signedTransaction.startsWith("0x")) {
                val txBytes = Numeric.hexStringToByteArray(signedTransaction)
                val txType = txBytes[0].toInt() and 0xFF

                info["type"] = when (txType) {
                    0x00 -> "Legacy"
                    0x01 -> "EIP-2930"
                    0x02 -> "EIP-1559"
                    else -> "Unknown ($txType)"
                }
            }

            info
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error extracting transaction info: ${e.message}")
            mapOf("error" to "Failed to extract transaction info")
        }
    }
}