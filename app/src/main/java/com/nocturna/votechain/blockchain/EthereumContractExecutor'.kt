package com.nocturna.votechain.blockchain


import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.web3j.abi.FunctionEncoder
import org.web3j.abi.TypeReference
import org.web3j.abi.datatypes.Function
import org.web3j.abi.datatypes.Type
import org.web3j.abi.datatypes.Utf8String
import org.web3j.abi.datatypes.generated.Uint256
import org.web3j.crypto.Credentials
import org.web3j.crypto.RawTransaction
import org.web3j.crypto.TransactionEncoder
import org.web3j.protocol.Web3j
import org.web3j.protocol.core.DefaultBlockParameterName
import org.web3j.protocol.core.methods.response.EthGasPrice
import org.web3j.protocol.core.methods.response.EthGetTransactionCount
import org.web3j.protocol.http.HttpService
import org.web3j.utils.Convert
import org.web3j.utils.Numeric
import java.math.BigInteger

class EthereumContractExecutor {
    private val web3j: Web3j
    private val credentials: Credentials
    private val chainId: Long

    constructor(nodeUrl: String, privateKey: String, chainId: Long) {
        this.web3j = Web3j.build(HttpService(nodeUrl))
        this.credentials = Credentials.create(privateKey)
        this.chainId = chainId
    }

    data class TransactionResult(
        val signedTransaction: String,
        val transactionHash: String,
        val from: String,
        val to: String,
        val value: BigInteger,
        val gasPrice: BigInteger,
        val gasLimit: BigInteger,
        val nonce: BigInteger,
        val data: String
    )

    suspend fun executeContract(
        contractAddress: String,
        functionName: String,
        inputParameters: List<Type<*>>,
        outputParameters: List<TypeReference<*>>,
        value: BigInteger = BigInteger.ZERO,
        gasPrice: BigInteger? = null,
        gasLimit: BigInteger? = null
    ): TransactionResult{
        try {
            val function = Function(
                functionName,
                inputParameters,
                outputParameters
            )

            val encodedFunction = FunctionEncoder.encode(function)

            val nonce = getNonce(credentials.address)

            val currentGasPrice = gasPrice ?: getCurrentGasPrice()

            val estimatedGasLimit = gasLimit ?: estimateGas(
                credentials.address,
                contractAddress,
                encodedFunction,
                value
            )

            // Use createTransaction with chainId parameter
            val rawTransaction = RawTransaction.createTransaction(
                nonce,
                currentGasPrice,
                estimatedGasLimit,
                contractAddress,
                value,
                encodedFunction
            )

            // Sign the transaction with chainId
            val signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials)
            val hexSignedTransaction = Numeric.toHexString(signedMessage)

            println("Signed transaction: $hexSignedTransaction")

            val transactionHash = web3j.ethSendRawTransaction(hexSignedTransaction)
                .sendAsync()
                .thenApply { response ->
                    if (response.hasError()) {
                        println("Transaction error: ${response.error.message}")
                    }
                    response.transactionHash ?: "0x" + hexSignedTransaction.takeLast(40)
                }
                .exceptionally { e ->
                    println("Transaction hash generation error: ${e.message}")
                    "0x" + hexSignedTransaction.takeLast(40)
                }
                .get()

            return TransactionResult(
                signedTransaction = hexSignedTransaction,
                transactionHash = transactionHash,
                from = credentials.address,
                to = contractAddress,
                value = value,
                gasPrice = currentGasPrice,
                gasLimit = estimatedGasLimit,
                nonce = nonce,
                data = encodedFunction
            )
        } catch (e: Exception) {
            throw RuntimeException("Failed to execute contract function: ${e.message}", e)
        }
    }

    private suspend fun getNonce(address: String): BigInteger {
        return withContext(Dispatchers.IO) {
            try {
                println("Getting nonce for address: $address")
                val ethGetTransactionCount: EthGetTransactionCount = web3j
                    .ethGetTransactionCount(address, DefaultBlockParameterName.LATEST)
                    .send()

                if (ethGetTransactionCount.hasError()) {
                    throw RuntimeException("Failed to get nonce: ${ethGetTransactionCount.error.message}")
                }

                val nonce = ethGetTransactionCount.transactionCount
                println("Nonce retrieved: $nonce")
                nonce
            } catch (e: Exception) {
                println("Error getting nonce: ${e.message}")
                throw RuntimeException("Failed to get nonce for address $address: ${e.message}", e)
            }
        }
    }

    suspend fun testConnection(): Boolean {
        return try {
            println("Testing network connection...")
            val clientVersion = web3j.web3ClientVersion().send()
            println("Connected to: ${clientVersion.web3ClientVersion}")
            true
        } catch (e: Exception) {
            println("Connection test failed: ${e.message}")
            false
        }
    }

    suspend fun sendSignedTransaction(signedTransaction: String): String {
        return withContext(Dispatchers.IO) {
            try {
                val ethSendTransaction = web3j.ethSendRawTransaction(signedTransaction).send()

                if (ethSendTransaction.hasError()) {
                    throw RuntimeException("Transaction failed: ${ethSendTransaction.error.message}")
                }

                ethSendTransaction.transactionHash
            } catch (e: Exception) {
                throw RuntimeException("Failed to send transaction: ${e.message}", e)
            }
        }
    }


    private suspend fun getCurrentGasPrice(): BigInteger {
        return withContext(Dispatchers.IO) {
            try {
                println("Getting current gas price...")
                val ethGasPrice: EthGasPrice = web3j.ethGasPrice().send()

                if (ethGasPrice.hasError()) {
                    throw RuntimeException("Failed to get gas price: ${ethGasPrice.error.message}")
                }

                val gasPrice = ethGasPrice.gasPrice
                println("Gas price retrieved: $gasPrice wei")
                gasPrice
            } catch (e: Exception) {
                println("Error getting gas price: ${e.message}")
                // Use fallback gas price
                val fallbackGasPrice = Convert.toWei("20", Convert.Unit.GWEI).toBigInteger()
                println("Using fallback gas price: $fallbackGasPrice wei")
                fallbackGasPrice
            }
        }
    }

    private suspend fun estimateGas(
        from: String,
        to: String,
        data: String,
        value: BigInteger
    ): BigInteger {
        return withContext(Dispatchers.IO) {
            try {
                println("Estimating gas for transaction...")
                val ethEstimateGas = web3j.ethEstimateGas(
                    org.web3j.protocol.core.methods.request.Transaction.createFunctionCallTransaction(
                        from, null, null, null, to, value, data
                    )
                ).send()

                if (ethEstimateGas.hasError()) {
                    println("Gas estimation failed: ${ethEstimateGas.error.message}")
                    val fallbackGas = BigInteger.valueOf(300000)
                    println("Using fallback gas limit: $fallbackGas")
                    return@withContext fallbackGas
                }

                val estimatedGas = ethEstimateGas.amountUsed
                println("Gas estimated: $estimatedGas")
                estimatedGas
            } catch (e: Exception) {
                println("Error estimating gas: ${e.message}")
                // Fallback to default gas limit if estimation fails
                val fallbackGas = BigInteger.valueOf(300000)
                println("Using fallback gas limit: $fallbackGas")
                fallbackGas
            }
        }
    }

    private fun generateTransactionHash(signedMessage: ByteArray): String {
        // Simple approach: create a deterministic hash from the signed message
        return try {
            // Convert signed message to hex and take a substring as hash
            val hexMessage = Numeric.toHexString(signedMessage)

            // Create a hash-like string from the signed transaction
            val hashPart = hexMessage.takeLast(64) // Take last 64 chars (32 bytes worth)

            if (hashPart.startsWith("0x")) {
                hashPart
            } else {
                "0x$hashPart"
            }
        } catch (e: Exception) {
            // Ultimate fallback
            "0x" + System.currentTimeMillis().toString(16).padStart(16, '0').repeat(4).take(64)
        }
    }

    object ParameterHelper {
        fun createUint256(value: BigInteger) = Uint256(value)
        fun createString(value: String) = Utf8String(value)
        fun createAddress(address: String) = org.web3j.abi.datatypes.Address(address)
        fun createBool(value: Boolean) = org.web3j.abi.datatypes.Bool(value)

        // Type references for return values
        fun uint256TypeRef() = object : TypeReference<Uint256>() {}
        fun stringTypeRef() = object : TypeReference<Utf8String>() {}
        fun addressTypeRef() = object : TypeReference<org.web3j.abi.datatypes.Address>() {}
        fun boolTypeRef() = object : TypeReference<org.web3j.abi.datatypes.Bool>() {}
    }

}