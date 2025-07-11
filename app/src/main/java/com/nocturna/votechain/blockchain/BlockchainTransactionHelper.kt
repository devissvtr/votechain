package com.nocturna.votechain.blockchain

import android.content.Context
import android.util.Log
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import org.web3j.abi.FunctionEncoder
import org.web3j.abi.TypeReference
import org.web3j.abi.datatypes.Function
import org.web3j.abi.datatypes.Type
import org.web3j.abi.datatypes.Utf8String
import org.web3j.crypto.Credentials
import org.web3j.crypto.RawTransaction
import org.web3j.crypto.TransactionEncoder
import org.web3j.protocol.Web3j
import org.web3j.protocol.core.DefaultBlockParameterName
import org.web3j.protocol.core.methods.response.TransactionReceipt
import org.web3j.protocol.http.HttpService
import org.web3j.utils.Numeric
import java.math.BigInteger

/**
 * Helper class for blockchain transaction operations
 */
class BlockchainTransactionHelper(private val context: Context) {
    private val TAG = "BlockchainTransactionHelper"
    private val cryptoKeyManager = CryptoKeyManager(context)

    private val web3j: Web3j by lazy {
        Web3j.build(HttpService(BlockchainConfig.getCurrentNetwork().rpcUrl))
    }

    /**
     * Create and sign a transaction for voting
     */
    suspend fun createVoteTransaction(
        electionId: String,
        electionNo: String
    ): Result<SignedTransaction> {
        return try {
            val privateKey = cryptoKeyManager.getPrivateKey()
                ?: return Result.failure(SecurityException("Private key not found"))

            val credentials = Credentials.create(privateKey)
            val voterAddress = credentials.address

            Log.d(TAG, "🔐 Creating vote transaction")
            Log.d(TAG, "- Voter Address: $voterAddress")
            Log.d(TAG, "- Election ID: $electionId")
            Log.d(TAG, "- Election No: $electionNo")

            // Create function call
            val function = Function(
                BlockchainConfig.ContractMethods.VOTE,
                listOf(
                    Utf8String(electionId),
                    Utf8String(electionNo)
                ),
                emptyList()
            )

            val encodedFunction = FunctionEncoder.encode(function)
            val contractAddress = BlockchainConfig.getCurrentNetwork().voteChainAddress

            // Get transaction parameters
            val gasPrice = BlockchainManager.getCurrentGasPrice()
            val nonce = BlockchainManager.getNonce(voterAddress)
            val gasLimit = BigInteger.valueOf(BlockchainConfig.Gas.VOTE_GAS_LIMIT)

            // Create raw transaction
            val rawTransaction = RawTransaction.createTransaction(
                nonce,
                gasPrice,
                gasLimit,
                contractAddress,
                encodedFunction
            )

            // Sign transaction
            val signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials)
            val signedTransactionHex = Numeric.toHexString(signedMessage)

            Log.d(TAG, "✅ Vote transaction created and signed")
            Log.d(TAG, "- Gas Price: $gasPrice wei")
            Log.d(TAG, "- Gas Limit: $gasLimit")
            Log.d(TAG, "- Nonce: $nonce")

            Result.success(
                SignedTransaction(
                    signedTransactionHex = signedTransactionHex,
                    transactionHash = "", // Will be set when broadcast
                    gasPrice = gasPrice,
                    gasLimit = gasLimit,
                    nonce = nonce,
                    contractAddress = contractAddress,
                    functionData = encodedFunction
                )
            )
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error creating vote transaction: ${e.message}", e)
            Result.failure(e)
        }
    }

    /**
     * Broadcast a signed transaction
     */
    suspend fun broadcastTransaction(signedTransaction: SignedTransaction): Result<String> {
        return try {
            Log.d(TAG, "📡 Broadcasting transaction to blockchain")

            val response = web3j.ethSendRawTransaction(signedTransaction.signedTransactionHex).send()

            if (response.hasError()) {
                Log.e(TAG, "❌ Transaction broadcast failed: ${response.error.message}")
                Result.failure(Exception("Transaction failed: ${response.error.message}"))
            } else {
                val txHash = response.transactionHash
                Log.d(TAG, "✅ Transaction broadcast successful: $txHash")
                Result.success(txHash)
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error broadcasting transaction: ${e.message}", e)
            Result.failure(e)
        }
    }

    /**
     * Monitor transaction status
     */
    fun monitorTransaction(transactionHash: String): Flow<TransactionStatus> = flow {
        try {
            Log.d(TAG, "👁️ Starting transaction monitoring: $transactionHash")
            emit(TransactionStatus.Pending)

            val maxAttempts = 30 // 30 attempts * 2 seconds = 1 minute
            var attempts = 0

            while (attempts < maxAttempts) {
                try {
                    val receipt = web3j.ethGetTransactionReceipt(transactionHash).send()

                    if (receipt.transactionReceipt.isPresent) {
                        val txReceipt = receipt.transactionReceipt.get()
                        val success = txReceipt.status == "0x1"

                        if (success) {
                            Log.d(TAG, "✅ Transaction confirmed: $transactionHash")
                            emit(TransactionStatus.Confirmed(txReceipt.gasUsed.toString()))
                        } else {
                            Log.e(TAG, "❌ Transaction failed: $transactionHash")
                            emit(TransactionStatus.Failed("Transaction reverted"))
                        }
                        return@flow
                    }

                    attempts++
                    delay(2000) // Wait 2 seconds before next check

                } catch (e: Exception) {
                    Log.w(TAG, "Error checking transaction receipt: ${e.message}")
                    attempts++
                    delay(2000)
                }
            }

            Log.w(TAG, "⏰ Transaction monitoring timeout: $transactionHash")
            emit(TransactionStatus.Timeout)

        } catch (e: Exception) {
            Log.e(TAG, "❌ Error monitoring transaction: ${e.message}", e)
            emit(TransactionStatus.Error(e.message ?: "Unknown error"))
        }
    }

    /**
     * Get transaction receipt
     */
    suspend fun getTransactionReceipt(transactionHash: String): Result<TransactionReceipt> {
        return try {
            val receipt = web3j.ethGetTransactionReceipt(transactionHash).send()

            if (receipt.transactionReceipt.isPresent) {
                Result.success(receipt.transactionReceipt.get())
            } else {
                Result.failure(Exception("Transaction receipt not found"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting transaction receipt: ${e.message}", e)
            Result.failure(e)
        }
    }

    /**
     * Calculate transaction fee
     */
    fun calculateTransactionFee(gasPrice: BigInteger, gasLimit: BigInteger): BigInteger {
        return gasPrice.multiply(gasLimit)
    }

    /**
     * Format transaction fee in ETH
     */
    fun formatTransactionFeeInEth(gasPrice: BigInteger, gasLimit: BigInteger): String {
        val feeWei = calculateTransactionFee(gasPrice, gasLimit)
        val feeEth = org.web3j.utils.Convert.fromWei(feeWei.toString(), org.web3j.utils.Convert.Unit.ETHER)
        return String.format("%.6f", feeEth.toDouble())
    }

    /**
     * Validate transaction parameters
     */
    fun validateTransactionParameters(
        gasPrice: BigInteger,
        gasLimit: BigInteger,
        nonce: BigInteger
    ): ValidationResult {
        val errors = mutableListOf<String>()

        // Validate gas price
        if (gasPrice <= BigInteger.ZERO) {
            errors.add("Gas price must be greater than zero")
        }

        // Validate gas limit
        if (gasLimit <= BigInteger.ZERO) {
            errors.add("Gas limit must be greater than zero")
        }

        // Validate nonce
        if (nonce < BigInteger.ZERO) {
            errors.add("Nonce cannot be negative")
        }

        return if (errors.isEmpty()) {
            ValidationResult.Valid
        } else {
            ValidationResult.Invalid(errors)
        }
    }

    /**
     * Get current network status
     */
    suspend fun getNetworkStatus(): NetworkStatus {
        return try {
            val clientVersion = web3j.web3ClientVersion().send()
            val latestBlock = web3j.ethBlockNumber().send()
            val gasPrice = web3j.ethGasPrice().send()

            NetworkStatus(
                isConnected = true,
                clientVersion = clientVersion.web3ClientVersion,
                latestBlock = latestBlock.blockNumber.toLong(),
                gasPrice = gasPrice.gasPrice,
                networkId = BlockchainConfig.getCurrentNetwork().chainId
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error getting network status: ${e.message}", e)
            NetworkStatus(
                isConnected = false,
                clientVersion = "",
                latestBlock = 0,
                gasPrice = BigInteger.ZERO,
                networkId = 0,
                error = e.message
            )
        }
    }

    /**
     * Data class for signed transaction
     */
    data class SignedTransaction(
        val signedTransactionHex: String,
        val transactionHash: String,
        val gasPrice: BigInteger,
        val gasLimit: BigInteger,
        val nonce: BigInteger,
        val contractAddress: String,
        val functionData: String
    )

    /**
     * Transaction status sealed class
     */
    sealed class TransactionStatus {
        data object Pending : TransactionStatus()
        data class Confirmed(val gasUsed: String) : TransactionStatus()
        data class Failed(val reason: String) : TransactionStatus()
        data object Timeout : TransactionStatus()
        data class Error(val message: String) : TransactionStatus()
    }

    /**
     * Validation result sealed class
     */
    sealed class ValidationResult {
        data object Valid : ValidationResult()
        data class Invalid(val errors: List<String>) : ValidationResult()
    }

    /**
     * Network status data class
     */
    data class NetworkStatus(
        val isConnected: Boolean,
        val clientVersion: String,
        val latestBlock: Long,
        val gasPrice: BigInteger,
        val networkId: Long,
        val error: String? = null
    )
}