package com.nocturna.votechain.blockchain

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.web3j.abi.FunctionEncoder
import org.web3j.abi.TypeReference
import org.web3j.abi.datatypes.Function
import org.web3j.abi.datatypes.Type
import org.web3j.abi.datatypes.Utf8String
import org.web3j.abi.datatypes.Address
import org.web3j.abi.datatypes.Bool
import org.web3j.abi.datatypes.generated.Uint256
import org.web3j.crypto.Credentials
import org.web3j.crypto.RawTransaction
import org.web3j.crypto.TransactionEncoder
import org.web3j.protocol.Web3j
import org.web3j.protocol.core.DefaultBlockParameterName
import org.web3j.protocol.core.methods.request.Transaction
import org.web3j.protocol.core.methods.response.EthSendTransaction
import org.web3j.protocol.core.methods.response.TransactionReceipt
import org.web3j.protocol.http.HttpService
import org.web3j.utils.Convert
import org.web3j.utils.Numeric
import java.math.BigInteger
import java.util.concurrent.CompletableFuture

/**
 * Enhanced BlockchainManager with proper contract interaction support
 */
object BlockchainManager {
    private const val TAG = "BlockchainManager"

    private val web3j: Web3j by lazy {
        val nodeUrl = BlockchainConfig.getCurrentNetwork().rpcUrl
        Log.d(TAG, "Initializing Web3j connection to $nodeUrl")
        Web3j.build(HttpService(nodeUrl))
    }

    /**
     * Check if Web3j is connected to the blockchain node
     */
    suspend fun isConnected(): Boolean = withContext(Dispatchers.IO) {
        try {
            val clientVersion = web3j.web3ClientVersion().send()
            Log.d(TAG, "Node client version: ${clientVersion.web3ClientVersion}")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Error connecting to blockchain node: ${e.message}", e)
            false
        }
    }

    /**
     * Get account balance in ETH
     */
    suspend fun getAccountBalance(address: String): String = withContext(Dispatchers.IO) {
        try {
            val balanceWei = web3j.ethGetBalance(address, DefaultBlockParameterName.LATEST).send().balance
            val balanceEth = Convert.fromWei(balanceWei.toString(), Convert.Unit.ETHER)
            String.format("%.6f", balanceEth.toDouble())
        } catch (e: Exception) {
            Log.e(TAG, "Error fetching balance for $address: ${e.message}", e)
            "0.000000"
        }
    }

    /**
     * Get current gas price
     */
    suspend fun getCurrentGasPrice(): BigInteger = withContext(Dispatchers.IO) {
        try {
            val gasPrice = web3j.ethGasPrice().send().gasPrice
            Log.d(TAG, "Current gas price: $gasPrice wei")
            gasPrice
        } catch (e: Exception) {
            Log.w(TAG, "Failed to get gas price, using default: ${e.message}")
            BigInteger.valueOf(BlockchainConfig.Gas.GAS_PRICE_WEI)
        }
    }

    /**
     * Get nonce for address
     */
    suspend fun getNonce(address: String): BigInteger = withContext(Dispatchers.IO) {
        try {
            web3j.ethGetTransactionCount(address, DefaultBlockParameterName.LATEST).send().transactionCount
        } catch (e: Exception) {
            Log.e(TAG, "Error getting nonce for $address: ${e.message}", e)
            BigInteger.ZERO
        }
    }

    /**
     * Cast vote on blockchain
     */
    suspend fun castVote(
        privateKey: String,
        electionId: String,
        electionNo: String
    ): VoteResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "🗳️ Casting vote on blockchain")
            Log.d(TAG, "- Election ID: $electionId")
            Log.d(TAG, "- Election No: $electionNo")

            val credentials = Credentials.create(privateKey)
            val fromAddress = credentials.address

            // Create function for vote call
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

            // Get gas price and nonce
            val gasPrice = getCurrentGasPrice()
            val nonce = getNonce(fromAddress)

            // Create raw transaction
            val rawTransaction = RawTransaction.createTransaction(
                nonce,
                gasPrice,
                BigInteger.valueOf(BlockchainConfig.Gas.VOTE_GAS_LIMIT),
                contractAddress,
                encodedFunction
            )

            // Sign and send transaction
            val signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials)
            val hexValue = Numeric.toHexString(signedMessage)

            val ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send()

            if (ethSendTransaction.hasError()) {
                Log.e(TAG, "❌ Vote transaction failed: ${ethSendTransaction.error.message}")
                VoteResult.Error(ethSendTransaction.error.message)
            } else {
                val txHash = ethSendTransaction.transactionHash
                Log.d(TAG, "✅ Vote transaction sent: $txHash")

                // Wait for transaction confirmation
                val receipt = waitForTransactionReceipt(txHash)
                if (receipt != null) {
                    Log.d(TAG, "✅ Vote transaction confirmed: $txHash")
                    VoteResult.Success(txHash, receipt.gasUsed.toString())
                } else {
                    Log.w(TAG, "⚠️ Vote transaction timeout: $txHash")
                    VoteResult.Pending(txHash)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error casting vote: ${e.message}", e)
            VoteResult.Error(e.message ?: "Unknown error")
        }
    }

    /**
     * Register voter on blockchain
     */
    suspend fun registerVoter(
        privateKey: String,
        nik: String,
        voterAddress: String
    ): TransactionResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "📝 Registering voter on blockchain")
            Log.d(TAG, "- NIK: $nik")
            Log.d(TAG, "- Voter Address: $voterAddress")

            val credentials = Credentials.create(privateKey)
            val fromAddress = credentials.address

            // Create function for registerVoter call
            val function = Function(
                BlockchainConfig.ContractMethods.REGISTER_VOTER,
                listOf(
                    Utf8String(nik),
                    Address(voterAddress)
                ),
                emptyList()
            )

            val encodedFunction = FunctionEncoder.encode(function)
            val contractAddress = BlockchainConfig.getCurrentNetwork().voterManagerAddress

            // Get gas price and nonce
            val gasPrice = getCurrentGasPrice()
            val nonce = getNonce(fromAddress)

            // Create raw transaction
            val rawTransaction = RawTransaction.createTransaction(
                nonce,
                gasPrice,
                BigInteger.valueOf(BlockchainConfig.Gas.REGISTER_VOTER_GAS_LIMIT),
                contractAddress,
                encodedFunction
            )

            // Sign and send transaction
            val signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials)
            val hexValue = Numeric.toHexString(signedMessage)

            val ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send()

            if (ethSendTransaction.hasError()) {
                Log.e(TAG, "❌ Voter registration failed: ${ethSendTransaction.error.message}")
                TransactionResult.Error(ethSendTransaction.error.message)
            } else {
                val txHash = ethSendTransaction.transactionHash
                Log.d(TAG, "✅ Voter registration sent: $txHash")

                // Wait for transaction confirmation
                val receipt = waitForTransactionReceipt(txHash)
                if (receipt != null) {
                    Log.d(TAG, "✅ Voter registration confirmed: $txHash")
                    TransactionResult.Success(txHash, receipt.gasUsed.toString())
                } else {
                    Log.w(TAG, "⚠️ Voter registration timeout: $txHash")
                    TransactionResult.Pending(txHash)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error registering voter: ${e.message}", e)
            TransactionResult.Error(e.message ?: "Unknown error")
        }
    }

    /**
     * Add election to blockchain
     */
    suspend fun addElection(
        privateKey: String,
        electionId: String,
        electionNo: String
    ): TransactionResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "🗳️ Adding election to blockchain")
            Log.d(TAG, "- Election ID: $electionId")
            Log.d(TAG, "- Election No: $electionNo")

            val credentials = Credentials.create(privateKey)
            val fromAddress = credentials.address

            // Create function for addElection call
            val function = Function(
                BlockchainConfig.ContractMethods.ADD_ELECTION,
                listOf(
                    Utf8String(electionId),
                    Utf8String(electionNo)
                ),
                emptyList()
            )

            val encodedFunction = FunctionEncoder.encode(function)
            val contractAddress = BlockchainConfig.getCurrentNetwork().voteChainAddress

            // Get gas price and nonce
            val gasPrice = getCurrentGasPrice()
            val nonce = getNonce(fromAddress)

            // Create raw transaction
            val rawTransaction = RawTransaction.createTransaction(
                nonce,
                gasPrice,
                BigInteger.valueOf(BlockchainConfig.Gas.DEFAULT_GAS_LIMIT),
                contractAddress,
                encodedFunction
            )

            // Sign and send transaction
            val signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials)
            val hexValue = Numeric.toHexString(signedMessage)

            val ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send()

            if (ethSendTransaction.hasError()) {
                Log.e(TAG, "❌ Add election failed: ${ethSendTransaction.error.message}")
                TransactionResult.Error(ethSendTransaction.error.message)
            } else {
                val txHash = ethSendTransaction.transactionHash
                Log.d(TAG, "✅ Add election sent: $txHash")

                // Wait for transaction confirmation
                val receipt = waitForTransactionReceipt(txHash)
                if (receipt != null) {
                    Log.d(TAG, "✅ Add election confirmed: $txHash")
                    TransactionResult.Success(txHash, receipt.gasUsed.toString())
                } else {
                    Log.w(TAG, "⚠️ Add election timeout: $txHash")
                    TransactionResult.Pending(txHash)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error adding election: ${e.message}", e)
            TransactionResult.Error(e.message ?: "Unknown error")
        }
    }

    /**
     * Toggle election active status
     */
    suspend fun toggleElectionActive(
        privateKey: String,
        electionId: String,
        electionNo: String
    ): TransactionResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "🔄 Toggling election active status")
            Log.d(TAG, "- Election ID: $electionId")
            Log.d(TAG, "- Election No: $electionNo")

            val credentials = Credentials.create(privateKey)
            val fromAddress = credentials.address

            // Create function for toggleElectionActive call
            val function = Function(
                BlockchainConfig.ContractMethods.TOGGLE_ELECTION_ACTIVE,
                listOf(
                    Utf8String(electionId),
                    Utf8String(electionNo)
                ),
                emptyList()
            )

            val encodedFunction = FunctionEncoder.encode(function)
            val contractAddress = BlockchainConfig.getCurrentNetwork().electionManagerAddress

            // Get gas price and nonce
            val gasPrice = getCurrentGasPrice()
            val nonce = getNonce(fromAddress)

            // Create raw transaction
            val rawTransaction = RawTransaction.createTransaction(
                nonce,
                gasPrice,
                BigInteger.valueOf(BlockchainConfig.Gas.DEFAULT_GAS_LIMIT),
                contractAddress,
                encodedFunction
            )

            // Sign and send transaction
            val signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials)
            val hexValue = Numeric.toHexString(signedMessage)

            val ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send()

            if (ethSendTransaction.hasError()) {
                Log.e(TAG, "❌ Toggle election failed: ${ethSendTransaction.error.message}")
                TransactionResult.Error(ethSendTransaction.error.message)
            } else {
                val txHash = ethSendTransaction.transactionHash
                Log.d(TAG, "✅ Toggle election sent: $txHash")

                // Wait for transaction confirmation
                val receipt = waitForTransactionReceipt(txHash)
                if (receipt != null) {
                    Log.d(TAG, "✅ Toggle election confirmed: $txHash")
                    TransactionResult.Success(txHash, receipt.gasUsed.toString())
                } else {
                    Log.w(TAG, "⚠️ Toggle election timeout: $txHash")
                    TransactionResult.Pending(txHash)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error toggling election: ${e.message}", e)
            TransactionResult.Error(e.message ?: "Unknown error")
        }
    }

    /**
     * Set voting status (activate/deactivate voting)
     */
    suspend fun setVotingStatus(
        privateKey: String,
        status: Boolean
    ): TransactionResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "⚙️ Setting voting status to: $status")

            val credentials = Credentials.create(privateKey)
            val fromAddress = credentials.address

            // Create function for setVotingStatus call
            val function = Function(
                BlockchainConfig.ContractMethods.SET_VOTING_STATUS,
                listOf(Bool(status)),
                emptyList()
            )

            val encodedFunction = FunctionEncoder.encode(function)
            val contractAddress = BlockchainConfig.getCurrentNetwork().voteChainBaseAddress

            // Get gas price and nonce
            val gasPrice = getCurrentGasPrice()
            val nonce = getNonce(fromAddress)

            // Create raw transaction
            val rawTransaction = RawTransaction.createTransaction(
                nonce,
                gasPrice,
                BigInteger.valueOf(BlockchainConfig.Gas.DEFAULT_GAS_LIMIT),
                contractAddress,
                encodedFunction
            )

            // Sign and send transaction
            val signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials)
            val hexValue = Numeric.toHexString(signedMessage)

            val ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send()

            if (ethSendTransaction.hasError()) {
                Log.e(TAG, "❌ Set voting status failed: ${ethSendTransaction.error.message}")
                TransactionResult.Error(ethSendTransaction.error.message)
            } else {
                val txHash = ethSendTransaction.transactionHash
                Log.d(TAG, "✅ Set voting status sent: $txHash")

                // Wait for transaction confirmation
                val receipt = waitForTransactionReceipt(txHash)
                if (receipt != null) {
                    Log.d(TAG, "✅ Set voting status confirmed: $txHash")
                    TransactionResult.Success(txHash, receipt.gasUsed.toString())
                } else {
                    Log.w(TAG, "⚠️ Set voting status timeout: $txHash")
                    TransactionResult.Pending(txHash)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error setting voting status: ${e.message}", e)
            TransactionResult.Error(e.message ?: "Unknown error")
        }
    }

    /**
     * Register KPU Provinsi
     */
    suspend fun registerKPUProvinsi(
        privateKey: String,
        address: String,
        name: String,
        region: String
    ): TransactionResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "🏛️ Registering KPU Provinsi")
            Log.d(TAG, "- Address: $address")
            Log.d(TAG, "- Name: $name")
            Log.d(TAG, "- Region: $region")

            val credentials = Credentials.create(privateKey)
            val fromAddress = credentials.address

            // Create function for registerKPUProvinsi call
            val function = Function(
                BlockchainConfig.ContractMethods.REGISTER_KPU_PROVINSI,
                listOf(
                    Address(address),
                    Utf8String(name),
                    Utf8String(region)
                ),
                emptyList()
            )

            val encodedFunction = FunctionEncoder.encode(function)
            val contractAddress = BlockchainConfig.getCurrentNetwork().kpuManagerAddress

            // Get gas price and nonce
            val gasPrice = getCurrentGasPrice()
            val nonce = getNonce(fromAddress)

            // Create raw transaction
            val rawTransaction = RawTransaction.createTransaction(
                nonce,
                gasPrice,
                BigInteger.valueOf(BlockchainConfig.Gas.REGISTER_KPU_GAS_LIMIT),
                contractAddress,
                encodedFunction
            )

            // Sign and send transaction
            val signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials)
            val hexValue = Numeric.toHexString(signedMessage)

            val ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send()

            if (ethSendTransaction.hasError()) {
                Log.e(TAG, "❌ Register KPU Provinsi failed: ${ethSendTransaction.error.message}")
                TransactionResult.Error(ethSendTransaction.error.message)
            } else {
                val txHash = ethSendTransaction.transactionHash
                Log.d(TAG, "✅ Register KPU Provinsi sent: $txHash")

                // Wait for transaction confirmation
                val receipt = waitForTransactionReceipt(txHash)
                if (receipt != null) {
                    Log.d(TAG, "✅ Register KPU Provinsi confirmed: $txHash")
                    TransactionResult.Success(txHash, receipt.gasUsed.toString())
                } else {
                    Log.w(TAG, "⚠️ Register KPU Provinsi timeout: $txHash")
                    TransactionResult.Pending(txHash)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error registering KPU Provinsi: ${e.message}", e)
            TransactionResult.Error(e.message ?: "Unknown error")
        }
    }

    /**
     * Register KPU Kota
     */
    suspend fun registerKPUKota(
        privateKey: String,
        address: String,
        name: String,
        region: String
    ): TransactionResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "🏛️ Registering KPU Kota")
            Log.d(TAG, "- Address: $address")
            Log.d(TAG, "- Name: $name")
            Log.d(TAG, "- Region: $region")

            val credentials = Credentials.create(privateKey)
            val fromAddress = credentials.address

            // Create function for registerKPUKota call
            val function = Function(
                BlockchainConfig.ContractMethods.REGISTER_KPU_KOTA,
                listOf(
                    Address(address),
                    Utf8String(name),
                    Utf8String(region)
                ),
                emptyList()
            )

            val encodedFunction = FunctionEncoder.encode(function)
            val contractAddress = BlockchainConfig.getCurrentNetwork().kpuManagerAddress

            // Get gas price and nonce
            val gasPrice = getCurrentGasPrice()
            val nonce = getNonce(fromAddress)

            // Create raw transaction
            val rawTransaction = RawTransaction.createTransaction(
                nonce,
                gasPrice,
                BigInteger.valueOf(BlockchainConfig.Gas.REGISTER_KPU_GAS_LIMIT),
                contractAddress,
                encodedFunction
            )

            // Sign and send transaction
            val signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials)
            val hexValue = Numeric.toHexString(signedMessage)

            val ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send()

            if (ethSendTransaction.hasError()) {
                Log.e(TAG, "❌ Register KPU Kota failed: ${ethSendTransaction.error.message}")
                TransactionResult.Error(ethSendTransaction.error.message)
            } else {
                val txHash = ethSendTransaction.transactionHash
                Log.d(TAG, "✅ Register KPU Kota sent: $txHash")

                // Wait for transaction confirmation
                val receipt = waitForTransactionReceipt(txHash)
                if (receipt != null) {
                    Log.d(TAG, "✅ Register KPU Kota confirmed: $txHash")
                    TransactionResult.Success(txHash, receipt.gasUsed.toString())
                } else {
                    Log.w(TAG, "⚠️ Register KPU Kota timeout: $txHash")
                    TransactionResult.Pending(txHash)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error registering KPU Kota: ${e.message}", e)
            TransactionResult.Error(e.message ?: "Unknown error")
        }
    }

    /**
     * Check if voting is active
     */
    suspend fun isVotingActive(): Boolean = withContext(Dispatchers.IO) {
        try {
            val function = Function(
                BlockchainConfig.ContractMethods.VOTING_ACTIVE,
                emptyList(),
                listOf(object : TypeReference<Bool>() {})
            )

            val encodedFunction = FunctionEncoder.encode(function)
            val contractAddress = BlockchainConfig.getCurrentNetwork().voteChainBaseAddress

            val response = web3j.ethCall(
                Transaction.createEthCallTransaction(null, contractAddress, encodedFunction),
                DefaultBlockParameterName.LATEST
            ).send()

            if (response.hasError()) {
                Log.e(TAG, "Error checking voting status: ${response.error.message}")
                return@withContext false
            }

            // Parse the response - this is a simplified parsing
            val result = response.value
            result != "0x0000000000000000000000000000000000000000000000000000000000000000"
        } catch (e: Exception) {
            Log.e(TAG, "Error checking voting active status: ${e.message}", e)
            false
        }
    }

    /**
     * Fund voter address with small amount of ETH for gas
     */
    suspend fun fundVoterAddress(
        fundingPrivateKey: String,
        voterAddress: String,
        amount: String = "0.001"
    ): String = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "💰 Funding voter address: $voterAddress with $amount ETH")

            val credentials = Credentials.create(fundingPrivateKey)
            val fromAddress = credentials.address

            // Check funding account balance
            val fundingBalance = getAccountBalance(fromAddress)
            val fundingBalanceEth = fundingBalance.toDoubleOrNull() ?: 0.0
            val requiredAmount = amount.toDoubleOrNull() ?: 0.001

            if (fundingBalanceEth < requiredAmount) {
                Log.w(TAG, "⚠️ Insufficient funding balance: $fundingBalanceEth ETH (required: $requiredAmount ETH)")
                return@withContext ""
            }

            // Create ETH transfer transaction
            val amountWei = Convert.toWei(amount, Convert.Unit.ETHER).toBigInteger()
            val gasPrice = getCurrentGasPrice()
            val nonce = getNonce(fromAddress)

            val transaction = RawTransaction.createEtherTransaction(
                nonce,
                gasPrice,
                BigInteger.valueOf(21000), // Standard gas limit for ETH transfer
                voterAddress,
                amountWei
            )

            val signedTransaction = TransactionEncoder.signMessage(transaction, credentials)
            val transactionHash = web3j.ethSendRawTransaction(
                Numeric.toHexString(signedTransaction)
            ).send().transactionHash

            if (transactionHash.isNotEmpty()) {
                Log.d(TAG, "✅ Funding transaction sent: $transactionHash")

                // Wait for transaction confirmation
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
     * Wait for transaction receipt
     */
    private suspend fun waitForTransactionReceipt(
        transactionHash: String,
        maxWaitTime: Int = BlockchainConfig.Transaction.TIMEOUT_SECONDS * 1000
    ): TransactionReceipt? = withContext(Dispatchers.IO) {
        val startTime = System.currentTimeMillis()

        while (System.currentTimeMillis() - startTime < maxWaitTime) {
            try {
                val receipt = web3j.ethGetTransactionReceipt(transactionHash).send()
                if (receipt.transactionReceipt.isPresent) {
                    return@withContext receipt.transactionReceipt.get()
                }
            } catch (e: Exception) {
                Log.w(TAG, "Error checking transaction receipt: ${e.message}")
            }

            delay(BlockchainConfig.Transaction.POLLING_INTERVAL_MS)
        }

        Log.w(TAG, "Transaction receipt timeout for: $transactionHash")
        return@withContext null
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
                    Log.d(TAG, "Transaction $transactionHash confirmed with status: ${txReceipt.status}")
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
     * Get transaction status
     */
    suspend fun getTransactionStatus(transactionHash: String): TransactionStatus = withContext(Dispatchers.IO) {
        try {
            val receipt = web3j.ethGetTransactionReceipt(transactionHash).send()
            if (receipt.transactionReceipt.isPresent) {
                val txReceipt = receipt.transactionReceipt.get()
                val success = txReceipt.status == "0x1"
                return@withContext if (success) {
                    TransactionStatus.Confirmed(txReceipt.gasUsed.toString())
                } else {
                    TransactionStatus.Failed("Transaction failed")
                }
            } else {
                return@withContext TransactionStatus.Pending
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting transaction status: ${e.message}", e)
            return@withContext TransactionStatus.Unknown
        }
    }

    /**
     * Enhanced connection checking with retry mechanism
     */
    suspend fun isConnectedWithRetry(maxRetries: Int = 3): Boolean = withContext(Dispatchers.IO) {
        repeat(maxRetries) { attempt ->
            try {
                val isConnected = web3j.web3ClientVersion().send().web3ClientVersion.isNotEmpty()
                if (isConnected) {
                    Log.d(TAG, "✅ Blockchain connection successful on attempt ${attempt + 1}")
                    return@withContext true
                }
            } catch (e: Exception) {
                Log.w(TAG, "Connection attempt ${attempt + 1} failed: ${e.message}")
                if (attempt < maxRetries - 1) {
                    delay(1000L * (attempt + 1))
                }
            }
        }
        Log.e(TAG, "❌ All connection attempts failed")
        return@withContext false
    }
}

/**
 * Result classes for blockchain operations
 */
sealed class VoteResult {
    data class Success(val transactionHash: String, val gasUsed: String) : VoteResult()
    data class Pending(val transactionHash: String) : VoteResult()
    data class Error(val message: String) : VoteResult()
}

sealed class TransactionResult {
    data class Success(val transactionHash: String, val gasUsed: String) : TransactionResult()
    data class Pending(val transactionHash: String) : TransactionResult()
    data class Error(val message: String) : TransactionResult()
}

sealed class TransactionStatus {
    data class Confirmed(val gasUsed: String) : TransactionStatus()
    data class Failed(val reason: String) : TransactionStatus()
    data object Pending : TransactionStatus()
    data object Unknown : TransactionStatus()
}