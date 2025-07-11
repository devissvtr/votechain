package com.nocturna.votechain.blockchain

import android.content.Context
import android.util.Log
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Centralized service for managing blockchain operations
 */
class BlockchainService(private val context: Context) {
    private val TAG = "BlockchainService"
    private val cryptoKeyManager = CryptoKeyManager(context)
    private val transactionHelper = BlockchainTransactionHelper(context)
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // Connection state
    private val _connectionState = MutableStateFlow(BlockchainConnectionState.DISCONNECTED)
    val connectionState: StateFlow<BlockchainConnectionState> = _connectionState.asStateFlow()

    // Network status
    private val _networkStatus = MutableStateFlow<BlockchainTransactionHelper.NetworkStatus?>(null)
    val networkStatus: StateFlow<BlockchainTransactionHelper.NetworkStatus?> = _networkStatus.asStateFlow()

    // Transaction monitoring
    private val _activeTransactions = MutableStateFlow<Map<String, TransactionInfo>>(emptyMap())
    val activeTransactions: StateFlow<Map<String, TransactionInfo>> = _activeTransactions.asStateFlow()

    init {
        // Start connection monitoring
        startConnectionMonitoring()
    }

    /**
     * Initialize blockchain connection
     */
    suspend fun initialize(): Boolean = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "🔗 Initializing blockchain connection...")

            _connectionState.value = BlockchainConnectionState.CONNECTING

            // Check connection
            val isConnected = BlockchainManager.isConnectedWithRetry(maxRetries = 3)

            if (isConnected) {
                Log.d(TAG, "✅ Blockchain connection established")
                _connectionState.value = BlockchainConnectionState.CONNECTED

                // Update network status
                updateNetworkStatus()

                true
            } else {
                Log.e(TAG, "❌ Failed to connect to blockchain")
                _connectionState.value = BlockchainConnectionState.DISCONNECTED
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error initializing blockchain: ${e.message}", e)
            _connectionState.value = BlockchainConnectionState.ERROR
            false
        }
    }

    /**
     * Cast vote with full blockchain integration
     */
    suspend fun castVote(
        electionId: String,
        electionNo: String,
        onProgress: (VoteProgress) -> Unit = {}
    ): VoteResult {
        return try {
            Log.d(TAG, "🗳️ Starting vote casting process")

            onProgress(VoteProgress.VALIDATING)

            // Validate prerequisites
            if (!validateVotingPrerequisites()) {
                return VoteResult.Error("Voting prerequisites not met")
            }

            onProgress(VoteProgress.CREATING_TRANSACTION)

            // Create transaction
            val transactionResult = transactionHelper.createVoteTransaction(electionId, electionNo)
            if (transactionResult.isFailure) {
                return VoteResult.Error("Failed to create transaction: ${transactionResult.exceptionOrNull()?.message}")
            }

            val signedTransaction = transactionResult.getOrNull()!!

            onProgress(VoteProgress.BROADCASTING)

            // Broadcast transaction
            val broadcastResult = transactionHelper.broadcastTransaction(signedTransaction)
            if (broadcastResult.isFailure) {
                return VoteResult.Error("Failed to broadcast transaction: ${broadcastResult.exceptionOrNull()?.message}")
            }

            val txHash = broadcastResult.getOrNull()!!

            // Add to active transactions
            addActiveTransaction(txHash, TransactionInfo(
                hash = txHash,
                type = TransactionType.VOTE,
                status = TransactionStatus.PENDING,
                timestamp = System.currentTimeMillis(),
                electionId = electionId,
                electionNo = electionNo
            ))

            onProgress(VoteProgress.MONITORING)

            // Start monitoring in background
            startTransactionMonitoring(txHash)

            VoteResult.Success(txHash, signedTransaction.gasPrice.toString())

        } catch (e: Exception) {
            Log.e(TAG, "❌ Error casting vote: ${e.message}", e)
            VoteResult.Error(e.message ?: "Unknown error")
        }
    }

    /**
     * Register voter on blockchain
     */
    suspend fun registerVoter(
        nik: String,
        voterAddress: String,
        onProgress: (RegistrationProgress) -> Unit = {}
    ): RegistrationResult {
        return try {
            Log.d(TAG, "📝 Starting voter registration process")

            onProgress(RegistrationProgress.VALIDATING)

            // Get private key
            val privateKey = cryptoKeyManager.getPrivateKey()
                ?: return RegistrationResult.Error("Private key not found")

            onProgress(RegistrationProgress.SUBMITTING_TO_BLOCKCHAIN)

            // Register on blockchain
            val result = BlockchainManager.registerVoter(privateKey, nik, voterAddress)

            when (result) {
                is TransactionResult.Success -> {
                    Log.d(TAG, "✅ Voter registration successful: ${result.transactionHash}")

                    // Add to active transactions
                    addActiveTransaction(result.transactionHash, TransactionInfo(
                        hash = result.transactionHash,
                        type = TransactionType.REGISTER_VOTER,
                        status = TransactionStatus.CONFIRMED,
                        timestamp = System.currentTimeMillis(),
                        voterAddress = voterAddress,
                        nik = nik
                    ))

                    RegistrationResult.Success(result.transactionHash)
                }
                is TransactionResult.Pending -> {
                    Log.d(TAG, "⏳ Voter registration pending: ${result.transactionHash}")

                    // Add to active transactions
                    addActiveTransaction(result.transactionHash, TransactionInfo(
                        hash = result.transactionHash,
                        type = TransactionType.REGISTER_VOTER,
                        status = TransactionStatus.PENDING,
                        timestamp = System.currentTimeMillis(),
                        voterAddress = voterAddress,
                        nik = nik
                    ))

                    // Start monitoring
                    startTransactionMonitoring(result.transactionHash)

                    RegistrationResult.Pending(result.transactionHash)
                }
                is TransactionResult.Error -> {
                    Log.e(TAG, "❌ Voter registration failed: ${result.message}")
                    RegistrationResult.Error(result.message)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error registering voter: ${e.message}", e)
            RegistrationResult.Error(e.message ?: "Unknown error")
        }
    }

    /**
     * Check if voting is active on blockchain
     */
    suspend fun isVotingActive(): Boolean {
        return try {
            BlockchainManager.isVotingActive()
        } catch (e: Exception) {
            Log.e(TAG, "Error checking voting status: ${e.message}", e)
            false
        }
    }

    /**
     * Get user's wallet balance
     */
    suspend fun getUserBalance(): String {
        return try {
            val voterAddress = cryptoKeyManager.getVoterAddress()
            if (voterAddress != null) {
                BlockchainManager.getAccountBalance(voterAddress as String)
            } else {
                "0.000000"
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting user balance: ${e.message}", e)
            "0.000000"
        }
    }

    /**
     * Get transaction status
     */
    suspend fun getTransactionStatus(txHash: String): TransactionStatus {
        return try {
            val status = BlockchainManager.getTransactionStatus(txHash)
            when (status) {
                is com.nocturna.votechain.blockchain.TransactionStatus.Confirmed -> TransactionStatus.CONFIRMED
                is com.nocturna.votechain.blockchain.TransactionStatus.Failed -> TransactionStatus.FAILED
                is com.nocturna.votechain.blockchain.TransactionStatus.Pending -> TransactionStatus.PENDING
                is com.nocturna.votechain.blockchain.TransactionStatus.Unknown -> TransactionStatus.UNKNOWN
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting transaction status: ${e.message}", e)
            TransactionStatus.UNKNOWN
        }
    }

    /**
     * Switch network
     */
    suspend fun switchNetwork(network: BlockchainConfig.Network): Boolean {
        return try {
            Log.d(TAG, "🔄 Switching to network: ${network.name}")

            BlockchainConfig.switchNetwork(network)

            // Reinitialize connection
            initialize()
        } catch (e: Exception) {
            Log.e(TAG, "Error switching network: ${e.message}", e)
            false
        }
    }

    /**
     * Start connection monitoring
     */
    private fun startConnectionMonitoring() {
        serviceScope.launch {
            while (true) {
                try {
                    val isConnected = BlockchainManager.isConnected()
                    val currentState = _connectionState.value

                    if (isConnected && currentState != BlockchainConnectionState.CONNECTED) {
                        _connectionState.value = BlockchainConnectionState.CONNECTED
                        updateNetworkStatus()
                    } else if (!isConnected && currentState == BlockchainConnectionState.CONNECTED) {
                        _connectionState.value = BlockchainConnectionState.DISCONNECTED
                    }

                    // Update network status if connected
                    if (isConnected) {
                        updateNetworkStatus()
                    }

                    kotlinx.coroutines.delay(10000) // Check every 10 seconds
                } catch (e: Exception) {
                    Log.e(TAG, "Error in connection monitoring: ${e.message}")
                    kotlinx.coroutines.delay(10000)
                }
            }
        }
    }

    /**
     * Update network status
     */
    private suspend fun updateNetworkStatus() {
        try {
            val status = transactionHelper.getNetworkStatus()
            _networkStatus.value = status
        } catch (e: Exception) {
            Log.e(TAG, "Error updating network status: ${e.message}", e)
        }
    }

    /**
     * Start transaction monitoring
     */
    private fun startTransactionMonitoring(txHash: String) {
        serviceScope.launch {
            try {
                transactionHelper.monitorTransaction(txHash)
                    .collect { status ->
                        updateTransactionStatus(txHash, when (status) {
                            is BlockchainTransactionHelper.TransactionStatus.Pending -> TransactionStatus.PENDING
                            is BlockchainTransactionHelper.TransactionStatus.Confirmed -> TransactionStatus.CONFIRMED
                            is BlockchainTransactionHelper.TransactionStatus.Failed -> TransactionStatus.FAILED
                            is BlockchainTransactionHelper.TransactionStatus.Timeout -> TransactionStatus.TIMEOUT
                            is BlockchainTransactionHelper.TransactionStatus.Error -> TransactionStatus.ERROR
                        })
                    }
            } catch (e: Exception) {
                Log.e(TAG, "Error monitoring transaction $txHash: ${e.message}", e)
                updateTransactionStatus(txHash, TransactionStatus.ERROR)
            }
        }
    }

    /**
     * Validate voting prerequisites
     */
    private fun validateVotingPrerequisites(): Boolean {
        return try {
            // Check if user has keys
            if (!cryptoKeyManager.hasStoredKeyPair()) {
                Log.e(TAG, "No stored key pair found")
                return false
            }

            // Check if keys are valid
            val privateKey = cryptoKeyManager.getPrivateKey()
            val voterAddress = cryptoKeyManager.getVoterAddress()

            if (privateKey == null || voterAddress == null) {
                Log.e(TAG, "Invalid keys found")
                return false
            }

            // Check if blockchain is connected
            if (_connectionState.value != BlockchainConnectionState.CONNECTED) {
                Log.e(TAG, "Blockchain not connected")
                return false
            }

            true
        } catch (e: Exception) {
            Log.e(TAG, "Error validating prerequisites: ${e.message}", e)
            false
        }
    }

    /**
     * Add active transaction
     */
    private fun addActiveTransaction(txHash: String, transactionInfo: TransactionInfo) {
        val currentTransactions = _activeTransactions.value.toMutableMap()
        currentTransactions[txHash] = transactionInfo
        _activeTransactions.value = currentTransactions
    }

    /**
     * Update transaction status
     */
    private fun updateTransactionStatus(txHash: String, status: TransactionStatus) {
        val currentTransactions = _activeTransactions.value.toMutableMap()
        currentTransactions[txHash]?.let { transaction ->
            currentTransactions[txHash] = transaction.copy(status = status)
            _activeTransactions.value = currentTransactions
        }
    }

    /**
     * Clear completed transactions
     */
    fun clearCompletedTransactions() {
        val currentTransactions = _activeTransactions.value.toMutableMap()
        currentTransactions.entries.removeAll {
            it.value.status == TransactionStatus.CONFIRMED ||
                    it.value.status == TransactionStatus.FAILED
        }
        _activeTransactions.value = currentTransactions
    }

    /**
     * Get transaction info
     */
    fun getTransactionInfo(txHash: String): TransactionInfo? {
        return _activeTransactions.value[txHash]
    }

    /**
     * Connection state enum
     */
    enum class BlockchainConnectionState {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        ERROR
    }

    /**
     * Transaction type enum
     */
    enum class TransactionType {
        VOTE,
        REGISTER_VOTER,
        REGISTER_KPU,
        ADD_ELECTION,
        FUND_ACCOUNT
    }

    /**
     * Transaction status enum
     */
    enum class TransactionStatus {
        PENDING,
        CONFIRMED,
        FAILED,
        TIMEOUT,
        ERROR,
        UNKNOWN
    }

    /**
     * Vote progress enum
     */
    enum class VoteProgress {
        VALIDATING,
        CREATING_TRANSACTION,
        BROADCASTING,
        MONITORING
    }

    /**
     * Registration progress enum
     */
    enum class RegistrationProgress {
        VALIDATING,
        SUBMITTING_TO_BLOCKCHAIN,
        MONITORING
    }

    /**
     * Transaction info data class
     */
    data class TransactionInfo(
        val hash: String,
        val type: TransactionType,
        val status: TransactionStatus,
        val timestamp: Long,
        val electionId: String? = null,
        val electionNo: String? = null,
        val voterAddress: String? = null,
        val nik: String? = null,
        val gasUsed: String? = null,
        val error: String? = null
    )

    /**
     * Result sealed classes
     */
    sealed class VoteResult {
        data class Success(val transactionHash: String, val gasPrice: String) : VoteResult()
        data class Error(val message: String) : VoteResult()
    }

    sealed class RegistrationResult {
        data class Success(val transactionHash: String) : RegistrationResult()
        data class Pending(val transactionHash: String) : RegistrationResult()
        data class Error(val message: String) : RegistrationResult()
    }
}