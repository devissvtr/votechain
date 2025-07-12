package com.nocturna.votechain.blockchain

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.web3j.crypto.Credentials
import org.web3j.crypto.ECKeyPair
import org.web3j.crypto.Keys
import org.web3j.crypto.RawTransaction
import org.web3j.crypto.Sign
import org.web3j.crypto.TransactionEncoder
import org.web3j.protocol.Web3j
import org.web3j.protocol.core.DefaultBlockParameter
import org.web3j.protocol.core.DefaultBlockParameterName
import org.web3j.protocol.core.methods.response.EthBlock
import org.web3j.protocol.http.HttpService
import org.web3j.rlp.RlpEncoder
import org.web3j.rlp.RlpList
import org.web3j.rlp.RlpString
import org.web3j.rlp.RlpType
import org.web3j.utils.Convert
import org.web3j.utils.Numeric
import java.math.BigInteger
import java.security.SecureRandom

/**
 * Singleton to manage Web3j connections and blockchain operations
 */
object BlockchainManager {
    private const val TAG = "BlockchainManager"

    private val web3j: Web3j by lazy {
        val nodeUrl = "https://5c581b707f2f.ngrok-free.app"
        Log.d(TAG, "Initializing Web3j connection to $nodeUrl")
        Web3j.build(HttpService(nodeUrl))
    }

    /**
     * Check if Web3j is connected to the Ethereum node
     * @return true if connected, false otherwise
     */
    suspend fun isConnected(): Boolean = withContext(Dispatchers.IO) {
        try {
            val clientVersion = web3j.web3ClientVersion().send()
            Log.d(TAG, "Node client version: ${clientVersion.web3ClientVersion}")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Error connecting to Ethereum node: ${e.message}", e)
            false
        }
    }

    /**
     * Generate a new Ethereum address
     * @return The generated address with 0x prefix
     */
    fun generateAddress(): String {
        try {
            // Generate random private key
            val privateKeyBytes = ByteArray(32)
            SecureRandom().nextBytes(privateKeyBytes)

            // Create ECKeyPair from private key
            val privateKey = Numeric.toBigInt(privateKeyBytes)
            val keyPair = ECKeyPair.create(privateKey)

            // Get Ethereum address from key pair
            val address = Keys.toChecksumAddress("0x" + Keys.getAddress(keyPair))
            Log.d(TAG, "Generated new Ethereum address: $address")
            return address
        } catch (e: Exception) {
            Log.e(TAG, "Error generating Ethereum address: ${e.message}", e)
            // Return a placeholder in case of error
            return "0x0000000000000000000000000000000000000000"
        }
    }

    /**
     * Get account balance from the blockchain
     * @param address Ethereum address to check
     * @return Balance in ETH as a string with 8 decimal places
     */
    suspend fun getAccountBalance(address: String): String = withContext(Dispatchers.IO) {
        try {
            val balanceWei =
                web3j.ethGetBalance(address, DefaultBlockParameterName.LATEST).send().balance
            val balanceEth = Convert.fromWei(balanceWei.toString(), Convert.Unit.ETHER)

            // Format to 8 decimal places
            return@withContext String.format("%.8f", balanceEth.toDouble())
        } catch (e: Exception) {
            Log.e(TAG, "Error fetching balance for $address: ${e.message}", e)
            return@withContext "0.00000000"
        }
    }

    /**
     * Fund a newly created voter address with a small amount of ETH
     * Note: This requires an account with funds on the local node
     * @param voterAddress Address to fund
     * @return Transaction hash if successful, empty string if failed
     */
    suspend fun fundVoterAddress(
        voterAddress: String,
        amount: String = "0.001"
    ): String = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "🔗 Attempting to fund voter address: $voterAddress with $amount ETH")

            // Check if we have a funding account configured
            val fundingAccount = getFundingAccount()
            if (fundingAccount == null) {
                Log.w(TAG, "⚠️ No funding account configured, skipping funding")
                return@withContext ""
            }

            // Check funding account balance
            val fundingBalance = getAccountBalance(fundingAccount.address)
            val fundingBalanceEth = fundingBalance.toDoubleOrNull() ?: 0.0
            val requiredAmount = amount.toDoubleOrNull() ?: 0.001

            if (fundingBalanceEth < requiredAmount) {
                Log.w(
                    TAG,
                    "⚠️ Insufficient funding balance: $fundingBalanceEth ETH (required: $requiredAmount ETH)"
                )
                return@withContext ""
            }

            // Create and send transaction
            val amountWei = Convert.toWei(amount, Convert.Unit.ETHER).toBigInteger()
            val gasPrice = web3j.ethGasPrice().send().gasPrice
            val nonce = web3j.ethGetTransactionCount(
                fundingAccount.address,
                DefaultBlockParameterName.LATEST
            ).send().transactionCount

            val transaction = RawTransaction.createEtherTransaction(
                nonce,
                gasPrice,
                BigInteger.valueOf(21000), // Standard gas limit for ETH transfer
                voterAddress,
                amountWei
            )

            val signedTransaction =
                TransactionEncoder.signMessage(transaction, fundingAccount.credentials)
            val transactionHash = web3j.ethSendRawTransaction(
                Numeric.toHexString(signedTransaction)
            ).send().transactionHash

            if (transactionHash.isNotEmpty()) {
                Log.d(TAG, "✅ Funding transaction sent: $transactionHash")

                // Wait for transaction confirmation (optional)
                waitForTransactionConfirmation(transactionHash)

                return@withContext transactionHash
            } else {
                Log.e(TAG, "❌ Failed to send funding transaction")
                return@withContext ""
            }

        } catch (e: Exception) {
            Log.e(TAG, "❌ Error funding voter address: ${e.message}", e)
            return@withContext ""
        }
    }

    /**
     * Wait for transaction confirmation
     */
    private suspend fun waitForTransactionConfirmation(
        transactionHash: String,
        maxWaitTime: Long = 60000 // 1 minute
    ): Boolean = withContext(Dispatchers.IO) {
        val startTime = System.currentTimeMillis()

        while (System.currentTimeMillis() - startTime < maxWaitTime) {
            try {
                val receipt = web3j.ethGetTransactionReceipt(transactionHash).send()
                if (receipt.transactionReceipt.isPresent) {
                    val txReceipt = receipt.transactionReceipt.get()
                    val success = txReceipt.status == "0x1"
                    Log.d(
                        TAG,
                        "Transaction $transactionHash confirmed with status: ${txReceipt.status}"
                    )
                    return@withContext success
                }
            } catch (e: Exception) {
                Log.w(TAG, "Error checking transaction receipt: ${e.message}")
            }

            delay(2000) // Check every 2 seconds
        }

        Log.w(TAG, "Transaction confirmation timeout for: $transactionHash")
        return@withContext false
    }

    /**
     * Get funding account (configure this based on your setup)
     */
    private fun getFundingAccount(): FundingAccount? {
        return try {
            // This should be configured based on your environment
            // For development: use a test account with test ETH
            // For production: use a treasury account with proper security

            val privateKey = "YOUR_FUNDING_ACCOUNT_PRIVATE_KEY" // Configure this
            val credentials = Credentials.create(privateKey)

            FundingAccount(
                address = credentials.address,
                credentials = credentials
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error loading funding account: ${e.message}")
            null
        }
    }

    /**
     * Create and sign a raw Ethereum transaction using EIP-1559 standard
     */
    suspend fun createAndSignTransaction(
        nonce: BigInteger,
        to: String,
        value: BigInteger,
        data: String,
        maxPriorityFeePerGas: BigInteger,
        maxFeePerGas: BigInteger,
        gasLimit: BigInteger,
        chainId: Long,
        privateKey: BigInteger
    ): String = withContext(Dispatchers.IO) {
        try {
            // Validate private key
            if (privateKey.bitLength() > 256) {
                throw IllegalArgumentException("Invalid private key length. Expected 256 bits.")
            }

            Log.d(TAG, "Creating transaction with chainId: $chainId")

            // Create transaction
            val rawTransaction = RawTransaction.createTransaction(
                BigInteger.valueOf(chainId),
                nonce,
                gasLimit,
                to,
                value,
                data,
                maxPriorityFeePerGas,
                maxFeePerGas
            )

            // Create Credentials object directly from the private key
            val credentials = Credentials.create(privateKey.toString(16))

            // Use the SignedRawTransaction utility for more reliable signing
            val signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials)
            val hexValue = Numeric.toHexString(signedMessage)

            Log.d(TAG, "✅ Transaction signed successfully, hex length: ${hexValue.length}")
            return@withContext hexValue

        } catch (e: Exception) {
            Log.e(TAG, "Error creating and signing transaction: ${e.message}", e)
            throw RuntimeException("Error creating and signing transaction: ${e.message}", e)
        }
    }
}

// Data classes for enhanced functionality
data class FundingAccount(
    val address: String,
    val credentials: Credentials
)