package com.nocturna.votechain.viewmodel.vote

import android.content.Context
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.nocturna.votechain.data.model.VoteCastData
import com.nocturna.votechain.data.model.VoteCastResponse
import com.nocturna.votechain.data.model.VotingCategory
import com.nocturna.votechain.data.model.VotingResult
import com.nocturna.votechain.data.network.NetworkClient
import com.nocturna.votechain.data.repository.VotingRepository
import com.nocturna.votechain.security.CryptoKeyManager
import com.nocturna.votechain.utils.TokenManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class VotingViewModel(private val context: Context,
                      private val repository: VotingRepository
) : ViewModel() {

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

    init {
        checkVotingStatus()
    }

    /**
     * Cast vote using enhanced signed transaction method
     */
    fun castVoteWithSignedTransaction(
        electionPairId: String,
        region: String,
        otpToken: String? = null
    ) {
        viewModelScope.launch {
            _voteState.value = VoteState.Loading
            _isLoading.value = true

            repository.castVoteWithSignedTransaction(electionPairId, region)
                .collect { result ->
                    _isLoading.value = false
                    result.fold(
                        onSuccess = { response ->
                            if (response.code == 0) {
                                _voteState.value = VoteState.Success(response.data)
                                _voteResult.value = response
                                _hasVoted.value = true
                                // Refresh data after successful vote
                                fetchActiveVotings()
                                fetchVotingResults()
                            } else {
                                _voteState.value = VoteState.Error(
                                    response.error?.error_message ?: "Unknown error"
                                )
                                _error.value = response.error?.error_message
                            }
                        },
                        onFailure = { error ->
                            _voteState.value = VoteState.Error(error.message ?: "Unknown error")
                            _error.value = error.message
                        }
                    )
                }
        }
    }

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
     * Cast a vote for a specific election pair
     * Cast a vote for a specific election pair
     * Cast a vote for a specific election pair
     * @param electionPairId The ID of the selected candidate pair
     * @param region The voter's region
     */
    fun castVote(electionPairId: String, region: String, otpToken: String) {
        viewModelScope.launch {
            _voteState.value = VoteState.Loading

            repository.castVoteWithSignedTransaction(electionPairId, region)
                .collect { result ->
                    result.fold(
                        onSuccess = { response ->
                            if (response.code == 0) {
                                _voteState.value = VoteState.Success(response.data)
                                _hasVoted.value = true
                                // Refresh data after successful vote
                                fetchActiveVotings()
                                fetchVotingResults()
                            } else {
                                _voteState.value = VoteState.Error(
                                    response.error?.error_message ?: "Unknown error"
                                )
                            }
                        },
                        onFailure = { error ->
                            _voteState.value = VoteState.Error(error.message ?: "Unknown error")
                        }
                    )
                }
        }
    }
//
//    /**
//     * Legacy method for backward compatibility
//     * @param categoryId The voting category ID
//     * @param optionId The selected option/candidate ID
//     */
//    fun submitVote(categoryId: String, optionId: String) {
//        viewModelScope.launch {
//            _isLoading.value = true
//            _error.value = null
//
//            repository.submitVote(categoryId, optionId).collect { result ->
//                _isLoading.value = false
//                result.fold(
//                    onSuccess = {
//                        _hasVoted.value = true
//                        // Refresh data after successful vote
//                        fetchActiveVotings()
//                        fetchVotingResults()
//                    },
//                    onFailure = { e ->
//                        _error.value = e.message ?: "Failed to submit vote"
//                    }
//                )
//            }
//        }
//    }
//
    /**
     * Check current voting status
     */
    private fun checkVotingStatus() {
        _hasVoted.value = repository.hasUserVoted()
    }

    // Factory for creating VotingViewModel with dependencies
    class Factory(private val context: Context) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            if (modelClass.isAssignableFrom(VotingViewModel::class.java)) {
                return VotingViewModel(
                    context = context,
                    repository = VotingRepository(context, CryptoKeyManager(context))
                ) as T
            }
            throw IllegalArgumentException("Unknown ViewModel class")
        }
    }

    sealed class VoteState {
        object Loading : VoteState()
        data class Success(val data: VoteCastData?) : VoteState()
        data class Error(val message: String) : VoteState()
    }
}