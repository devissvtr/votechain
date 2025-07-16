package com.nocturna.votechain.blockchain

import java.math.BigInteger


class ContractCall() {
    companion object {
        suspend fun executeVoteFunction(
            privateKey: String,
            electionId: String,
            electionNo: String
        ): String? {
            val nodeUrl = "https://81ef113790bc.ngrok-free.app"
            val contractAddress = "0x434Fe284e564432397705a76FcBC1BD82bF7b1d1"
            val chainId = 5777L

            val executor = EthereumContractExecutor(
                nodeUrl = nodeUrl,
                privateKey = privateKey,
                chainId = chainId
            )

            val inputParameters = listOf(
                EthereumContractExecutor.ParameterHelper.createString(electionId),
                EthereumContractExecutor.ParameterHelper.createString(electionNo)
            )

            val outputParameters = listOf(
                EthereumContractExecutor.ParameterHelper.boolTypeRef()
            )

            try {
                val result = executor.executeContract(
                    contractAddress = contractAddress,
                    functionName = "vote",
                    inputParameters = inputParameters,
                    outputParameters = outputParameters,
                    value = BigInteger.ZERO,
                    gasLimit = BigInteger.valueOf(3000000),
                )

                println("Signed Transaction: ${result.signedTransaction}")
                return result.signedTransaction

            } catch (e: Exception) {
                println("Error executing vote function: ${e.message}")
                e.printStackTrace()
                return null
            }
        }
    }
}