package com.nocturna.votechain.blockchain

/**
 * Blockchain configuration for VoteChain
 * Centralized configuration for blockchain-related settings
 */
object BlockchainConfig {

    /**
     * Network configurations for different environments
     */
    enum class Network(
        val chainId: Long,
        val rpcUrl: String,
        val votingContractAddress: String,
    ) {
        CUSTOM(
            chainId = 1337,
            rpcUrl = "https://799d-36-79-168-77.ngrok-free.app",
            votingContractAddress = "0x626b00c42351F35E48ea0b4a434c0E163eD1e2C7",
        )
    }

    // Current active network - change this based on your environment
    var activeNetwork = Network.CUSTOM

    /**
     * Gas configuration
     */
    object Gas {
        const val VOTE_GAS_LIMIT = 270964L
        const val DEFAULT_GAS_LIMIT = 200000L

        // Gas prices in Gwei (1 Gwei = 10^9 Wei)
        const val MAX_PRIORITY_FEE_GWEI = 1L
        const val MAX_FEE_PER_GAS_GWEI = 2L
    }

    /**
     * Smart contract method signatures
     */
    object ContractMethods {
        const val CAST_VOTE = "castVote"
        const val GET_VOTE_STATUS = "getVoteStatus"
        const val GET_ELECTION_RESULTS = "getElectionResults"
        const val IS_VOTER_REGISTERED = "isVoterRegistered"
        const val HAS_VOTED = "hasVoted"
    }

    /**
     * Get current network configuration
     */
    fun getCurrentNetwork(): Network = activeNetwork

    /**
     * Switch to a different network
     */
    fun switchNetwork(network: Network) {
        activeNetwork = network
    }
}