package com.nocturna.votechain.blockchain

/**
 * Enhanced Blockchain configuration for VoteChain
 * Updated to match web wallet configuration
 */
object BlockchainConfig {

    /**
     * Network configurations for different environments
     */
    enum class Network(
        val chainId: Long,
        val rpcUrl: String,
        val voteChainAddress: String,
        val voteChainBaseAddress: String,
        val kpuManagerAddress: String,
        val voterManagerAddress: String,
        val electionManagerAddress: String,
        val apiBaseUrl: String,
        val explorerUrl: String
    ) {
        GANACHE_LOCAL(
            chainId = 5777,
            rpcUrl = "http://localhost:7545",
            voteChainAddress = "0xd9c8C8f99F16f71EE133c9993A07CBB4a0b7c540",
            voteChainBaseAddress = "0xa64392f7C83B093631A4B90A9b47752Ff939C43a",
            kpuManagerAddress = "0x49D4676Ca3c329c8Ba3D98E5c2ddcB4E587C032b",
            voterManagerAddress = "0x2fBfC3C85B1f8E8f6FC994c54610387881E96181",
            electionManagerAddress = "0x626b00c42351F35E48ea0b4a434c0E163eD1e2C7",
            apiBaseUrl = "http://localhost:8900/",
            explorerUrl = "http://localhost:7545"
        ),
        CUSTOM_REMOTE(
            chainId = 1337,
            rpcUrl = "https://799d-36-79-168-77.ngrok-free.app",
            voteChainAddress = "0xd9c8C8f99F16f71EE133c9993A07CBB4a0b7c540",
            voteChainBaseAddress = "0xa64392f7C83B093631A4B90A9b47752Ff939C43a",
            kpuManagerAddress = "0x49D4676Ca3c329c8Ba3D98E5c2ddcB4E587C032b",
            voterManagerAddress = "0x2fBfC3C85B1f8E8f6FC994c54610387881E96181",
            electionManagerAddress = "0x626b00c42351F35E48ea0b4a434c0E163eD1e2C7",
            apiBaseUrl = "http://localhost:8900/",
            explorerUrl = "https://799d-36-79-168-77.ngrok-free.app"
        )
    }

    // Current active network - change this based on your environment
    var activeNetwork = Network.GANACHE_LOCAL

    /**
     * Contract ABIs from web wallet
     */
    object ContractABI {
        const val VOTECHAIN_ABI = """[{"inputs":[{"internalType":"address","name":"_baseAddress","type":"address"},{"internalType":"address","name":"_kpuManagerAddress","type":"address"},{"internalType":"address","name":"_voterManagerAddress","type":"address"},{"internalType":"address","name":"_electionManagerAddress","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AlreadyVoted","type":"error"},{"inputs":[],"name":"ElectionNotActive","type":"error"},{"inputs":[],"name":"ElectionNotFound","type":"error"},{"inputs":[],"name":"InvalidElection","type":"error"},{"inputs":[],"name":"OnlyKpuAdmin","type":"error"},{"inputs":[],"name":"OnlyKpuKota","type":"error"},{"inputs":[],"name":"OnlyKpuProvinsi","type":"error"},{"inputs":[],"name":"VoterNIKMismatch","type":"error"},{"inputs":[],"name":"VoterNotRegistered","type":"error"},{"inputs":[],"name":"VotingNotActive","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"voter","type":"address"},{"indexed":false,"internalType":"string","name":"electionId","type":"string"},{"indexed":false,"internalType":"string","name":"electionNo","type":"string"},{"indexed":false,"internalType":"string","name":"voterNik","type":"string"}],"name":"VoteAttempt","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"voter","type":"address"},{"indexed":false,"internalType":"string","name":"electionId","type":"string"},{"indexed":false,"internalType":"string","name":"electionNo","type":"string"},{"indexed":false,"internalType":"string","name":"voterNik","type":"string"}],"name":"VoteSuccessful","type":"event"},{"inputs":[{"internalType":"string","name":"electionId","type":"string"},{"internalType":"string","name":"electionNo","type":"string"}],"name":"addElection","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"base","outputs":[{"internalType":"contract IVotechainBase","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"electionManager","outputs":[{"internalType":"contract IElectionManager","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"kpuManager","outputs":[{"internalType":"contract IKPUManager","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"Address","type":"address"},{"internalType":"string","name":"name","type":"string"},{"internalType":"string","name":"region","type":"string"}],"name":"registerKPUKota","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"Address","type":"address"},{"internalType":"string","name":"name","type":"string"},{"internalType":"string","name":"region","type":"string"}],"name":"registerKPUProvinsi","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"nik","type":"string"},{"internalType":"address","name":"voterAddress","type":"address"}],"name":"registerVoter","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newAdmin","type":"address"}],"name":"setKpuAdmin","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bool","name":"status","type":"bool"}],"name":"setVotingStatus","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"electionId","type":"string"},{"internalType":"string","name":"electionNo","type":"string"}],"name":"toggleElectionActive","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"Address","type":"address"},{"internalType":"string","name":"name","type":"string"},{"internalType":"string","name":"region","type":"string"}],"name":"updateKPUKota","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"Address","type":"address"},{"internalType":"string","name":"name","type":"string"},{"internalType":"string","name":"region","type":"string"}],"name":"updateKPUProvinsi","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"electionId","type":"string"},{"internalType":"string","name":"electionNo","type":"string"}],"name":"vote","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"voterManager","outputs":[{"internalType":"contract IVoterManager","name":"","type":"address"}],"stateMutability":"view","type":"function"}]"""

        const val VOTECHAIN_BASE_ABI = """[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"OnlyKpuAdmin","type":"error"},{"inputs":[],"name":"VotingNotActive","type":"error"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"bool","name":"isActive","type":"bool"}],"name":"VotingStatusChanged","type":"event"},{"inputs":[],"name":"kpuAdmin","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"newAdmin","type":"address"}],"name":"setKpuAdmin","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bool","name":"status","type":"bool"}],"name":"setVotingStatus","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"votingActive","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]"""

        const val VOTER_MANAGER_ABI = """[{"inputs":[{"internalType":"address","name":"_baseAddress","type":"address"},{"internalType":"address","name":"_kpuManagerAddress","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"AddressAlreadyRegistered","type":"error"},{"inputs":[],"name":"AlreadyVoted","type":"error"},{"inputs":[],"name":"UnauthorizedKPU","type":"error"},{"inputs":[],"name":"VoterAlreadyRegistered","type":"error"},{"inputs":[],"name":"VoterNotRegistered","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"voterAddress","type":"address"},{"indexed":true,"internalType":"string","name":"nik","type":"string"}],"name":"VoterMarkedAsVoted","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"string","name":"nik","type":"string"},{"indexed":true,"internalType":"address","name":"voterAddress","type":"address"},{"indexed":false,"internalType":"string","name":"region","type":"string"}],"name":"VoterRegistered","type":"event"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"_voterNIKByAddresses","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"","type":"string"}],"name":"_voterss","outputs":[{"internalType":"string","name":"nik","type":"string"},{"internalType":"address","name":"voterAddress","type":"address"},{"internalType":"bool","name":"hasVoted","type":"bool"},{"internalType":"string","name":"region","type":"string"},{"internalType":"bool","name":"isRegistered","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"base","outputs":[{"internalType":"contract IVotechainBase","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getAllVoter","outputs":[{"components":[{"internalType":"string","name":"nik","type":"string"},{"internalType":"address","name":"voterAddress","type":"address"},{"internalType":"bool","name":"hasVoted","type":"bool"},{"internalType":"string","name":"region","type":"string"},{"internalType":"bool","name":"isRegistered","type":"bool"}],"internalType":"struct IVoterManager.Voter[]","name":"","type":"tuple[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"voterAddress","type":"address"}],"name":"getVoterByAddress","outputs":[{"components":[{"internalType":"string","name":"nik","type":"string"},{"internalType":"address","name":"voterAddress","type":"address"},{"internalType":"bool","name":"hasVoted","type":"bool"},{"internalType":"string","name":"region","type":"string"},{"internalType":"bool","name":"isRegistered","type":"bool"}],"internalType":"struct IVoterManager.Voter","name":"","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"nik","type":"string"}],"name":"getVoterByNIK","outputs":[{"components":[{"internalType":"string","name":"nik","type":"string"},{"internalType":"address","name":"voterAddress","type":"address"},{"internalType":"bool","name":"hasVoted","type":"bool"},{"internalType":"string","name":"region","type":"string"},{"internalType":"bool","name":"isRegistered","type":"bool"}],"internalType":"struct IVoterManager.Voter","name":"","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"region","type":"string"}],"name":"getVoterByRegion","outputs":[{"components":[{"internalType":"string","name":"nik","type":"string"},{"internalType":"address","name":"voterAddress","type":"address"},{"internalType":"bool","name":"hasVoted","type":"bool"},{"internalType":"string","name":"region","type":"string"},{"internalType":"bool","name":"isRegistered","type":"bool"}],"internalType":"struct IVoterManager.Voter[]","name":"","type":"tuple[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"voterAddress","type":"address"}],"name":"getVoterNikByAddress","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"kpuManager","outputs":[{"internalType":"contract IKPUManager","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"voterAddress","type":"address"}],"name":"markVoted","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"nik","type":"string"},{"internalType":"address","name":"voterAddress","type":"address"}],"name":"registerVoter","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"voterAddressesArray","outputs":[{"internalType":"string","name":"nik","type":"string"},{"internalType":"address","name":"voterAddress","type":"address"},{"internalType":"bool","name":"hasVoted","type":"bool"},{"internalType":"string","name":"region","type":"string"},{"internalType":"bool","name":"isRegistered","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"voter","type":"address"}],"name":"voterNIKByAddress","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"nik","type":"string"}],"name":"voters","outputs":[{"components":[{"internalType":"string","name":"nik","type":"string"},{"internalType":"address","name":"voterAddress","type":"address"},{"internalType":"bool","name":"hasVoted","type":"bool"},{"internalType":"string","name":"region","type":"string"},{"internalType":"bool","name":"isRegistered","type":"bool"}],"internalType":"struct IVoterManager.Voter","name":"","type":"tuple"}],"stateMutability":"view","type":"function"}]"""

        const val ELECTION_MANAGER_ABI = """[{"inputs":[{"internalType":"address","name":"_baseAddress","type":"address"},{"internalType":"address","name":"_voterManagerAddress","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"ElectionAlreadyExists","type":"error"},{"inputs":[],"name":"ElectionNotActive","type":"error"},{"inputs":[],"name":"ElectionNumberMismatch","type":"error"},{"inputs":[],"name":"InvalidElection","type":"error"},{"inputs":[],"name":"NIKMismatch","type":"error"},{"inputs":[],"name":"UnauthorizedCaller","type":"error"},{"inputs":[],"name":"VoterAlreadyVoted","type":"error"},{"inputs":[],"name":"VoterNotRegistered","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"string","name":"electionId","type":"string"},{"indexed":false,"internalType":"string","name":"electionNo","type":"string"}],"name":"ElectionAdded","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"string","name":"electionId","type":"string"},{"indexed":true,"internalType":"string","name":"electionNo","type":"string"},{"indexed":false,"internalType":"bool","name":"isActive","type":"bool"}],"name":"ElectionStatusChange","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"string","name":"nik","type":"string"},{"indexed":true,"internalType":"string","name":"electionId","type":"string"},{"indexed":true,"internalType":"string","name":"electionNo","type":"string"}],"name":"VoteCasted","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"votechainContract","type":"address"}],"name":"VotechainContractSet","type":"event"},{"inputs":[{"internalType":"string","name":"","type":"string"}],"name":"_electionss","outputs":[{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"electionNo","type":"string"},{"internalType":"uint256","name":"voteCount","type":"uint256"},{"internalType":"bool","name":"isActive","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"electionId","type":"string"},{"internalType":"string","name":"electionNo","type":"string"}],"name":"addElection","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"base","outputs":[{"internalType":"contract IVotechainBase","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"electionAddressArray","outputs":[{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"electionNo","type":"string"},{"internalType":"uint256","name":"voteCount","type":"uint256"},{"internalType":"bool","name":"isActive","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"electionId","type":"string"}],"name":"elections","outputs":[{"components":[{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"electionNo","type":"string"},{"internalType":"uint256","name":"voteCount","type":"uint256"},{"internalType":"bool","name":"isActive","type":"bool"}],"internalType":"struct IElectionManager.Election","name":"","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getAllElection","outputs":[{"components":[{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"electionNo","type":"string"},{"internalType":"uint256","name":"voteCount","type":"uint256"},{"internalType":"bool","name":"isActive","type":"bool"}],"internalType":"struct IElectionManager.Election[]","name":"","type":"tuple[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"electionId","type":"string"}],"name":"getElection","outputs":[{"components":[{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"electionNo","type":"string"},{"internalType":"uint256","name":"voteCount","type":"uint256"},{"internalType":"bool","name":"isActive","type":"bool"}],"internalType":"struct IElectionManager.Election","name":"","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"electionNo","type":"string"}],"name":"getElectionByNo","outputs":[{"components":[{"internalType":"string","name":"id","type":"string"},{"internalType":"string","name":"electionNo","type":"string"},{"internalType":"uint256","name":"voteCount","type":"uint256"},{"internalType":"bool","name":"isActive","type":"bool"}],"internalType":"struct IElectionManager.Election","name":"","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_votechainContract","type":"address"}],"name":"setVotechainContract","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"electionId","type":"string"},{"internalType":"string","name":"electionNo","type":"string"}],"name":"toggleElectionActive","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"electionId","type":"string"},{"internalType":"string","name":"electionNo","type":"string"},{"internalType":"string","name":"voterNik","type":"string"}],"name":"vote","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"votechainContract","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"voterManager","outputs":[{"internalType":"contract IVoterManager","name":"","type":"address"}],"stateMutability":"view","type":"function"}]"""

        const val KPU_MANAGER_ABI = """[{"inputs":[{"internalType":"address","name":"_baseAddress","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"KPUKotaAlreadyRegistered","type":"error"},{"inputs":[],"name":"KPUKotaNotActive","type":"error"},{"inputs":[],"name":"KPUNotFound","type":"error"},{"inputs":[],"name":"KPUProvinsiAlreadyRegistered","type":"error"},{"inputs":[],"name":"KPUProvinsiNotActive","type":"error"},{"inputs":[],"name":"OnlyKpuKota","type":"error"},{"inputs":[],"name":"OnlyKpuProvinsi","type":"error"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"Address","type":"address"}],"name":"KPUKotaDeactivated","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"Address","type":"address"},{"indexed":false,"internalType":"string","name":"name","type":"string"},{"indexed":false,"internalType":"string","name":"region","type":"string"}],"name":"KPUKotaRegistered","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"Address","type":"address"},{"indexed":false,"internalType":"string","name":"name","type":"string"},{"indexed":false,"internalType":"string","name":"region","type":"string"}],"name":"KPUKotaUpdated","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"Address","type":"address"}],"name":"KPUProvinsiDeactivated","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"Address","type":"address"},{"indexed":false,"internalType":"string","name":"name","type":"string"},{"indexed":false,"internalType":"string","name":"region","type":"string"}],"name":"KPUProvinsiRegistered","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"Address","type":"address"},{"indexed":false,"internalType":"string","name":"name","type":"string"},{"indexed":false,"internalType":"string","name":"region","type":"string"}],"name":"KPUProvinsiUpdated","type":"event"},{"inputs":[],"name":"base","outputs":[{"internalType":"contract IVotechainBase","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"Address","type":"address"}],"name":"deactivateKPUKota","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"Address","type":"address"}],"name":"deactivateKPUProvinsi","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"getAllKPUKota","outputs":[{"components":[{"internalType":"string","name":"name","type":"string"},{"internalType":"address","name":"Address","type":"address"},{"internalType":"bool","name":"isActive","type":"bool"},{"internalType":"string","name":"region","type":"string"}],"internalType":"struct IKPUManager.KPUKota[]","name":"","type":"tuple[]"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getAllKPUProvinsi","outputs":[{"components":[{"internalType":"string","name":"name","type":"string"},{"internalType":"address","name":"Address","type":"address"},{"internalType":"bool","name":"isActive","type":"bool"},{"internalType":"string","name":"region","type":"string"}],"internalType":"struct IKPUManager.KPUProvinsi[]","name":"","type":"tuple[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"Address","type":"address"}],"name":"getKpuKotaByAddress","outputs":[{"components":[{"internalType":"string","name":"name","type":"string"},{"internalType":"address","name":"Address","type":"address"},{"internalType":"bool","name":"isActive","type":"bool"},{"internalType":"string","name":"region","type":"string"}],"internalType":"struct IKPUManager.KPUKota","name":"","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"kpuAddress","type":"address"}],"name":"getKpuKotaRegion","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"Address","type":"address"}],"name":"getKpuProvinsiByAddress","outputs":[{"components":[{"internalType":"string","name":"name","type":"string"},{"internalType":"address","name":"Address","type":"address"},{"internalType":"bool","name":"isActive","type":"bool"},{"internalType":"string","name":"region","type":"string"}],"internalType":"struct IKPUManager.KPUProvinsi","name":"","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"kpuAddress","type":"address"}],"name":"isKPUKota","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"kpuAddress","type":"address"}],"name":"isKPUProvinsi","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"addr","type":"address"}],"name":"kpuKota","outputs":[{"components":[{"internalType":"string","name":"name","type":"string"},{"internalType":"address","name":"Address","type":"address"},{"internalType":"bool","name":"isActive","type":"bool"},{"internalType":"string","name":"region","type":"string"}],"internalType":"struct IKPUManager.KPUKota","name":"","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"kpuKotaAddressesArray","outputs":[{"internalType":"string","name":"name","type":"string"},{"internalType":"address","name":"Address","type":"address"},{"internalType":"bool","name":"isActive","type":"bool"},{"internalType":"string","name":"region","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"addr","type":"address"}],"name":"kpuProvinsi","outputs":[{"components":[{"internalType":"string","name":"name","type":"string"},{"internalType":"address","name":"Address","type":"address"},{"internalType":"bool","name":"isActive","type":"bool"},{"internalType":"string","name":"region","type":"string"}],"internalType":"struct IKPUManager.KPUProvinsi","name":"","type":"tuple"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"kpuProvinsiAddressesArray","outputs":[{"internalType":"string","name":"name","type":"string"},{"internalType":"address","name":"Address","type":"address"},{"internalType":"bool","name":"isActive","type":"bool"},{"internalType":"string","name":"region","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"Address","type":"address"},{"internalType":"string","name":"name","type":"string"},{"internalType":"string","name":"region","type":"string"}],"name":"registerKPUKota","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"Address","type":"address"},{"internalType":"string","name":"name","type":"string"},{"internalType":"string","name":"region","type":"string"}],"name":"registerKPUProvinsi","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"Address","type":"address"},{"internalType":"string","name":"name","type":"string"},{"internalType":"string","name":"region","type":"string"}],"name":"updateKPUKota","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"Address","type":"address"},{"internalType":"string","name":"name","type":"string"},{"internalType":"string","name":"region","type":"string"}],"name":"updateKPUProvinsi","outputs":[],"stateMutability":"nonpayable","type":"function"}]"""
    }

    /**
     * Gas configuration
     */
    object Gas {
        const val VOTE_GAS_LIMIT = 270964L
        const val REGISTER_VOTER_GAS_LIMIT = 500000L
        const val REGISTER_KPU_GAS_LIMIT = 400000L
        const val DEFAULT_GAS_LIMIT = 200000L

        // Gas prices in Wei
        const val GAS_PRICE_GWEI = 20L
        const val GAS_PRICE_WEI = GAS_PRICE_GWEI * 1_000_000_000L
    }

    /**
     * Smart contract method signatures
     */
    object ContractMethods {
        const val VOTE = "vote"
        const val REGISTER_VOTER = "registerVoter"
        const val REGISTER_KPU_PROVINSI = "registerKPUProvinsi"
        const val REGISTER_KPU_KOTA = "registerKPUKota"
        const val ADD_ELECTION = "addElection"
        const val TOGGLE_ELECTION_ACTIVE = "toggleElectionActive"
        const val SET_VOTING_STATUS = "setVotingStatus"
        const val GET_VOTER_BY_ADDRESS = "getVoterByAddress"
        const val VOTING_ACTIVE = "votingActive"
    }

    /**
     * Transaction configuration
     */
    object Transaction {
        const val CONFIRMATION_BLOCKS = 3
        const val TIMEOUT_SECONDS = 120
        const val MAX_RETRY_ATTEMPTS = 3
        const val POLLING_INTERVAL_MS = 2000L
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

    /**
     * Get transaction explorer URL
     */
    fun getTransactionUrl(txHash: String): String {
        return "${activeNetwork.explorerUrl}/tx/$txHash"
    }

    /**
     * Get address explorer URL
     */
    fun getAddressUrl(address: String): String {
        return "${activeNetwork.explorerUrl}/address/$address"
    }

    /**
     * Get contract addresses for current network
     */
    fun getContractAddresses(): ContractAddresses {
        return ContractAddresses(
            voteChain = activeNetwork.voteChainAddress,
            voteChainBase = activeNetwork.voteChainBaseAddress,
            kpuManager = activeNetwork.kpuManagerAddress,
            voterManager = activeNetwork.voterManagerAddress,
            electionManager = activeNetwork.electionManagerAddress
        )
    }

    /**
     * Data class for contract addresses
     */
    data class ContractAddresses(
        val voteChain: String,
        val voteChainBase: String,
        val kpuManager: String,
        val voterManager: String,
        val electionManager: String
    )
}