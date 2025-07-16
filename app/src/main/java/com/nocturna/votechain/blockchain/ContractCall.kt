package com.nocturna.votechain.blockchain

import java.math.BigInteger


class ContractCall() {
    companion object {
        suspend fun executeVoteFunction() {
            val nodeUrl = "https://81ef113790bc.ngrok-free.app"
            val privateKey = "0xf00e9df7764562a764fee0ff994a0941c5aceec0a877402c76113b2c59f89236"
            val contractAddress = "0x77b3cB0A4452C7Eb3fAa7D9da6979b8b74eae6D7"
            val chainId = 5777L

            val executor = EthereumContractExecutor(
                nodeUrl = nodeUrl,
                privateKey = privateKey,
                chainId = chainId
            )

            val electionId = "c3834ab2-7735-44b3-a4bc-7509c6c37d17"
            val electionNo = "1"

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

            } catch (e: Exception) {
                println("Error executing vote function: ${e.message}")
                e.printStackTrace()
            }
        }
    }
}