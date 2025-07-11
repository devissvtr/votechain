package com.nocturna.votechain.viewmodel.vote

import android.content.Context
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.nocturna.votechain.blockchain.BlockchainService
import com.nocturna.votechain.data.model.VoteCastData
import com.nocturna.votechain.data.model.VoteCastResponse
import com.nocturna.votechain.data.model.VotingCategory
import com.nocturna.votechain.data.repository.VotingRepository
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Enhanced VotingViewModel with blockchain integration
 */
class VotingViewModel(
    private val context: Context,
    private val repository: VotingRepository,
    private val blockchainService: BlockchainService
) : ViewModel() {

    private val TAG = "VotingViewModel"

    // Existing state flows
    private val _activeVotings = MutableStateFlow<List<VotingCategory>>(emptyList())
    val activeVotings: StateFlow<List<VotingCategory>> = _activeVotings.asStateFlow()

    private val _votingResults = MutableStateFlow<List<VotingCategory>>(emptyList())
    val votingResults: StateFlow<List<VotingCategory>> = _votingResults.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    private val _voteResult = MutableStateFlow<VoteCastResponse?>(null)
    val voteResult: StateFlow<VoteCastResponse?> = _voteResult.asStateFlow()

    private val _hasVoted = MutableStateFlow(false)
    val hasVoted: StateFlow<Boolean> = _hasVoted.asStateFlow()

    private val _voteState = MutableLiveData<VoteState>()
    val voteState: LiveData<VoteState> = _voteState

    // New blockchain-related state flows
    private val _blockchainConnectionState = MutableStateFlow<BlockchainService.BlockchainConnectionState>(BlockchainService.BlockchainConnectionState.DISCONNECTED)
    val blockchainConnectionState: StateFlow<BlockchainService.BlockchainConnectionState> = _blockchainConnectionState.asStateFlow()

    private val _votingActiveOnBlockchain = MutableStateFlow(false)
    val votingActiveOnBlockchain: StateFlow<Boolean> = _votingActiveOnBlockchain.asStateFlow()

    private val _userBalance = MutableStateFlow("0.000000")
    val userBalance: StateFlow<String> = _userBalance.asStateFlow()

    private val _activeTransactions = MutableStateFlow<Map<String, BlockchainService.TransactionInfo>>(emptyMap())
    val activeTransactions: StateFlow<Map<String, BlockchainService.TransactionInfo>> = _activeTransactions.asStateFlow()

    private val _voteProgress = MutableStateFlow<VoteProgress?>(null)
    val voteProgress: StateFlow<VoteProgress?> = _voteProgress.asStateFlow()

    init {
        // Initialize blockchain connection
        initializeBlockchain()

        // Check initial voting status
        checkVotingStatus()

        // Start monitoring blockchain state
        startBlockchainMonitoring()
    }

    /**
     * Initialize blockchain connection
     */
    private fun initializeBlockchain() {
        viewModelScope.launch {
            try {
                val isConnected = blockchainService.initialize()
                if (isConnected) {
                    // Update blockchain-related states
                    refreshBlockchainData()
                }
            } catch (e: Exception) {
                _error.value = "Failed to initialize blockchain: ${e.message}"
            }
        }
    }

    /**
     * Cast vote with enhanced blockchain integration
     */
    fun castVoteWithBlockchainIntegration(
        electionPairId: String,
        region: String,
        otpToken: String? = null
    ) {
        viewModelScope.launch {
            try {
                _voteState.value = VoteState.Loading
                _isLoading.value = true
                _error.value = null

                // Step 1: Cast vote on blockchain
                val blockchainResult = blockchainService.castVote(
                    electionId = electionPairId,
                    electionNo = electionPairId
                ) { progress ->
                    _voteProgress.value = VoteProgress.fromBlockchainProgress(progress)
                }

                when (blockchainResult) {
                    is BlockchainService.VoteResult.Success -> {
                        // Step 2: Submit to API with blockchain transaction hash
                        _voteProgress.value = VoteProgress.SUBMITTING_TO_API

                        repository.castVoteWithSignedTransaction(electionPairId, region, otpToken)
                            .collect { result ->
                                _isLoading.value = false

                                result.fold(
                                    onSuccess = { response ->
                                        if (response.code == 0) {
                                            _voteState.value = VoteState.Success(response.data)
                                            _voteResult.value = response
                                            _hasVoted.value = true
                                            _voteProgress.value = VoteProgress.COMPLETED

                                            // Refresh data after successful vote
                                            fetchActiveVotings()
                                            fetchVotingResults()
                                            refreshBlockchainData()
                                        } else {
                                            _voteState.value = VoteState.Error(
                                                response.error?.error_message ?: "Unknown error"
                                            )
                                            _error.value = response.error?.error_message
                                            _voteProgress.value = VoteProgress.ERROR
                                        }
                                    },
                                    onFailure = { error ->
                                        _voteState.value = VoteState.Error(error.message ?: "Unknown error")
                                        _error.value = error.message
                                        _voteProgress.value = VoteProgress.ERROR
                                    }
                                )
                            }
                    }
                    is BlockchainService.VoteResult.Error -> {
                        _isLoading.value = false
                        _voteState.value = VoteState.Error(blockchainResult.message)
                        _error.value = "Blockchain vote failed: ${blockchainResult.message}"
                        _voteProgress.value = VoteProgress.ERROR
                    }
                }
            } catch (e: Exception) {
                _isLoading.value = false
                _voteState.value = VoteState.Error(e.message ?: "Unknown error")
                _error.value = e.message
                _voteProgress.value = VoteProgress.ERROR
            }
        }
    }

    /**
     * Legacy method for backward compatibility
     */
    fun castVoteWithSignedTransaction(
        electionPairId: String,
        region: String,
        otpToken: String? = null
    ) {
        castVoteWithBlockchainIntegration(electionPairId, region, otpToken)
    }

    /**
     * Fetch active voting categories
     */
    fun fetchActiveVotings() {
        viewModelScope.launch {
            _isLoading.value = true
            _error.value = null

            repository.getActiveVotings().collect { result ->
                _isLoading.value = false
                result.fold(
                    onSuccess = { votings ->
                        _activeVotings.value = votings
                    },
                    onFailure = { e ->
                        _error.value = e.message ?: "Unknown error occurred"
                    }
                )
            }
        }
    }

    /**
     * Fetch voting results
     */
    fun fetchVotingResults() {
        viewModelScope.launch {
            _isLoading.value = true
            _error.value = null

            repository.getVotingResults().collect { result ->
                _isLoading.value = false
                result.fold(
                    onSuccess = { resultsList ->
                        _votingResults.value = resultsList
                    },
                    onFailure = { e ->
                        _error.value = e.message ?: "Unknown error occurred"
                    }
                )
            }
        }
    }

    /**
     * Check current voting status
     */
    private fun checkVotingStatus() {
        _hasVoted.value = repository.hasUserVoted()
    }

    /**
     * Start monitoring blockchain state
     */
    private fun startBlockchainMonitoring() {
        viewModelScope.launch {
            // Monitor connection state
            blockchainService.connectionState.collect { connectionState ->
                _blockchainConnectionState.value = connectionState
            }
        }

        viewModelScope.launch {
            // Monitor active transactions
            blockchainService.activeTransactions.collect { transactions ->
                _activeTransactions.value = transactions
            }
        }
    }

    /**
     * Refresh blockchain-related data
     */
    private fun refreshBlockchainData() {
        viewModelScope.launch {
            try {
                // Check if voting is active on blockchain
                val isVotingActive = blockchainService.isVotingActive()
                _votingActiveOnBlockchain.value = isVotingActive

                // Get user balance
                val balance = blockchainService.getUserBalance()
                _userBalance.value = balance

            } catch (e: Exception) {
                // Don't update error for background refresh failures
            }
        }
    }

    /**
     * Retry blockchain connection
     */
    fun retryBlockchainConnection() {
        viewModelScope.launch {
            try {
                val isConnected = blockchainService.initialize()
                if (isConnected) {
                    refreshBlockchainData()
                    _error.value = null
                } else {
                    _error.value = "Failed to connect to blockchain"
                }
            } catch (e: Exception) {
                _error.value = "Connection retry failed: ${e.message}"
            }
        }
    }

    /**
     * Switch blockchain network
     */
    fun switchNetwork(network: com.nocturna.votechain.blockchain.BlockchainConfig.Network) {
        viewModelScope.launch {
            try {
                val success = blockchainService.switchNetwork(network)
                if (success) {
                    refreshBlockchainData()
                    _error.value = null
                } else {
                    _error.value = "Failed to switch network"
                }
            } catch (e: Exception) {
                _error.value = "Network switch failed: ${e.message}"
            }
        }
    }

    /**
     * Get transaction status
     */
    fun getTransactionStatus(txHash: String): BlockchainService.TransactionStatus? {
        return _activeTransactions.value[txHash]?.status
    }

    /**
     * Clear completed transactions
     */
    fun clearCompletedTransactions() {
        blockchainService.clearCompletedTransactions()
    }

    /**
     * Get vote info
     */
    fun getVoteInfo(): VotingRepository.VoteInfo? {
        return repository.getUserVoteInfo()
    }

    /**
     * Clear vote status (for testing)
     */
    fun clearVoteStatus() {
        repository.clearVoteStatus()
        _hasVoted.value = false
        _voteResult.value = null
        _voteState.value = VoteState.Loading
    }

    /**
     * Clear error
     */
    fun clearError() {
        _error.value = null
    }

    /**
     * Legacy vote casting method for backward compatibility
     */
    fun castVote(electionPairId: String, region: String, otpToken: String) {
        castVoteWithBlockchainIntegration(electionPairId, region, otpToken)
    }

    /**
     * Legacy submit vote method for backward compatibility
     */
    fun submitVote(categoryId: String, optionId: String) {
        viewModelScope.launch {
            _isLoading.value = true

            repository.submitVote(categoryId, optionId).collect { result ->
                _isLoading.value = false
                result.fold(
                    onSuccess = {
                        _hasVoted.value = true
                        // Refresh data after successful vote
                        fetchActiveVotings()
                        fetchVotingResults()
                    },
                    onFailure = { e ->
                        _error.value = e.message ?: "Failed to submit vote"
                    }
                )
            }
        }
    }

    /**
     * Factory for creating VotingViewModel with dependencies
     */
    class Factory(private val context: Context) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            if (modelClass.isAssignableFrom(VotingViewModel::class.java)) {
                return VotingViewModel(
                    context = context,
                    repository = VotingRepository(context, CryptoKeyManager(context)),
                    blockchainService = BlockchainService(context)
                ) as T
            }
            throw IllegalArgumentException("Unknown ViewModel class")
        }
    }

    /**
     * Vote state sealed class
     */
    sealed class VoteState {
        data object Loading : VoteState()
        data class Success(val data: VoteCastData?) : VoteState()
        data class Error(val message: String) : VoteState()
    }

    /**
     * Vote progress enum
     */
    enum class VoteProgress {
        VALIDATING,
        CREATING_BLOCKCHAIN_TRANSACTION,
        BROADCASTING_TRANSACTION,
        MONITORING_BLOCKCHAIN,
        SUBMITTING_TO_API,
        COMPLETED,
        ERROR;

        companion object {
            fun fromBlockchainProgress(progress: BlockchainService.VoteProgress): VoteProgress {
                return when (progress) {
                    BlockchainService.VoteProgress.VALIDATING -> VALIDATING
                    BlockchainService.VoteProgress.CREATING_TRANSACTION -> CREATING_BLOCKCHAIN_TRANSACTION
                    BlockchainService.VoteProgress.BROADCASTING -> BROADCASTING_TRANSACTION
                    BlockchainService.VoteProgress.MONITORING -> MONITORING_BLOCKCHAIN
                }
            }
        }
    }
}