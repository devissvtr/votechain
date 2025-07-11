package com.nocturna.votechain.blockchain

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.web3j.abi.FunctionEncoder
import org.web3j.abi.TypeReference
import org.web3j.abi.datatypes.Function
import org.web3j.abi.datatypes.Type
import org.web3j.abi.datatypes.Utf8String
import org.web3j.crypto.Credentials
import org.web3j.crypto.RawTransaction
import org.web3j.crypto.TransactionEncoder
import org.web3j.protocol.Web3j
import org.web3j.protocol.core.DefaultBlockParameter
import org.web3j.protocol.core.DefaultBlockParameterName
import org.web3j.utils.Numeric
import java.math.BigInteger


class BlockchainTransactionManager(
    private val web3j: Web3j,
    private val credentials: Credentials
) {
    companion object {
        private const val TAG = "BlockchainTxManager"
        private const val DEFAULT_GAS_LIMIT = 300000L
        private const val DEFAULT_GAS_PRICE_GWEI = 20L
    }

    data class ContractConfig(
        val address: String,
        val gasLimit: BigInteger = BigInteger.valueOf(DEFAULT_GAS_LIMIT),
        val gasPrice: BigInteger = BigInteger.valueOf(DEFAULT_GAS_PRICE_GWEI * 1_000_000_000L)
    )

    data class TransactionResult(
        val success: Boolean,
        val signedTx: String? = null,
        val transactionHash: String? = null,
        val errorMessage: String? = null,
    )


    suspend fun createSignedContractTransaction(
        contractConfig: ContractConfig,
        functionName: String,
        functionInputs: List<Type<*>> = emptyList(),
        functionOutputs: List<TypeReference<*>> = emptyList()
    ): TransactionResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Create signed tx for function: $functionName")

            val function = Function(
                functionName,
                functionInputs,
                functionOutputs
            )

            val encodedFunction = FunctionEncoder.encode(function)
            Log.d(TAG, "Encoded function data: $encodedFunction")


            val nonce = web3j.ethGetTransactionCount(
                credentials.address,
                DefaultBlockParameterName.LATEST
            ).send().transactionCount

            val rawTransaction = RawTransaction.createTransaction(
                nonce,
                contractConfig.gasPrice,
                contractConfig.gasLimit,
                contractConfig.address,
                encodedFunction
            )

            val signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials)
            val signedTx = Numeric.toHexString(signedMessage)

            Log.d(TAG, "Signed Transaction: $signedTx")

            TransactionResult(
                success = true,
                signedTx = signedTx
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error creating signed transaction: ${e.message}", e)
            TransactionResult(
                success = false,
                errorMessage = e.message
            )
        }
    }

    suspend fun createVoteTransaction(
        voteChainAddress: String,
        electionId: String,
        electionNo: String
    ): TransactionResult{
        val contractConfig = ContractConfig(address = voteChainAddress)

        val functionInputs = listOf(
            Utf8String(electionId),
            Utf8String(electionNo)
        )


        return createSignedContractTransaction(
            contractConfig = contractConfig,
            functionName = "vote",
            functionInputs = functionInputs
        )
    }

    suspend fun getCurrentGasPrice(): BigInteger = withContext(Dispatchers.IO){
        try {
            web3j.ethGasPrice().send().gasPrice
        }catch (e: Exception){
            Log.w(TAG, "Failed to get gas price, using defaut: $")
            BigInteger.valueOf(DEFAULT_GAS_PRICE_GWEI * 1_000_000_000L)
        }
    }

    suspend fun estimateGas(
        contractAddress: String,
        encodedFunction: String
    ): BigInteger = withContext(Dispatchers.IO) {
        try {
           val transaction = org.web3j.protocol.core.methods.request.Transaction.createFunctionCallTransaction(
               credentials.address,
               null,
               null,
               null,
               contractAddress,
               encodedFunction
           )

            web3j.ethEstimateGas(transaction).send().amountUsed
        } catch (e: Exception) {
            Log.e(TAG, "Error estimating gas: ${e.message}", e)
            BigInteger.valueOf(DEFAULT_GAS_LIMIT)
        }
    }
}
