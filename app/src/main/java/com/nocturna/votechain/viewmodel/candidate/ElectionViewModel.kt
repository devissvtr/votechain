package com.nocturna.votechain.viewmodel.candidate

import android.util.Log
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.nocturna.votechain.data.model.ElectionPair
import com.nocturna.votechain.data.model.Party
import com.nocturna.votechain.data.model.PartyElectionPair
import com.nocturna.votechain.data.model.SupportingParty
import com.nocturna.votechain.data.network.ElectionNetworkClient
import com.nocturna.votechain.data.network.PartyPhotoHelper
import com.nocturna.votechain.data.repository.ElectionRepository
import com.nocturna.votechain.data.repository.PartyRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.launch

/**
 * ViewModel for managing election-related data
 */
class ElectionViewModel(
    private val electionRepository: ElectionRepository,
    private val partyRepository: PartyRepository
) : ViewModel() {

    private val TAG = "ElectionViewModel"

    private val _electionPairs = MutableStateFlow<List<ElectionPair>>(emptyList())
    val electionPairs: StateFlow<List<ElectionPair>> = _electionPairs.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    private val _parties = MutableStateFlow<List<PartyElectionPair>>(emptyList())
    val parties: StateFlow<List<PartyElectionPair>> = _parties.asStateFlow()



    /**
     * Fetch election pairs from repository
     */
    fun fetchElectionPairs() {
        Log.d(TAG, "Starting to fetch election pairs")

        // Check if ElectionNetworkClient is properly initialized
        if (!ElectionNetworkClient.isInitialized()) {
            Log.e(TAG, "ElectionNetworkClient is not initialized properly")
            _error.value = "Network client not initialized"
            return
        }

        // Check if token is available before making request
        if (!ElectionNetworkClient.hasValidToken()) {
            Log.w(TAG, "No valid authentication token - this may cause API errors")
        }

        viewModelScope.launch {
            _isLoading.value = true
            _error.value = null

            electionRepository.getElectionPairsWithSupportingParties()
                .catch { exception ->
                    Log.e(TAG, "Flow error: ${exception.message}", exception)
                    _error.value = handleError(exception)
                    _isLoading.value = false
                }
                .collect { result ->
                    _isLoading.value = false
                    result.fold(
                        onSuccess = { pairs ->
                            Log.d(TAG, "Successfully loaded ${pairs.size} election pairs")
                            _electionPairs.value = pairs
                            _error.value = null

                            // Log whether we're using fallback data
                            val usingFallback = pairs.any { it.id.startsWith("fallback-") }
                            if (usingFallback) {
                                Log.i(TAG, "Using fallback data due to API unavailability")
                            } else {
                                Log.i(TAG, "Using live API data")
                            }
                        },
                        onFailure = { exception ->
                            Log.e(TAG, "Failed to load election pairs: ${exception.message}", exception)
                            _error.value = handleError(exception)
                        }
                    )
                }
        }
    }

    /**
     * Fetch political parties from repository
     */
    fun fetchParties() {
        Log.d(TAG, "Starting to fetch parties")

        // Check if token is available before making request
        if (!ElectionNetworkClient.hasValidToken()) {
            Log.w(TAG, "No valid authentication token for parties request")
        }

        viewModelScope.launch {
            _isLoading.value = true
            _error.value = null

            try {
                val result = partyRepository.getParties()
                _isLoading.value = false

                result.fold(
                    onSuccess = { partyResponse ->
                        Log.d(TAG, "Successfully loaded ${partyResponse.data.parties.size} parties")
                        _parties.value = partyResponse.data.parties
                        _error.value = null
                    },
                    onFailure = { exception ->
                        Log.e(TAG, "Failed to load parties: ${exception.message}", exception)
                        _error.value = handleError(exception)
                    }
                )
            } catch (e: Exception) {
                _isLoading.value = false
                Log.e(TAG, "Exception while fetching parties: ${e.message}", e)
                _error.value = handleError(e)
            }
        }
    }

    /**
     * Refresh all data
     */
    fun refreshData() {
        Log.d(TAG, "Refreshing all election data")
        fetchElectionPairs()
        fetchParties()
    }

    /**
     * Clear error state
     */
    fun clearError() {
        _error.value = null
    }

    /**
     * Handle different types of errors and provide user-friendly messages
     */
    private fun handleError(exception: Throwable): String {
        return when {
            // Authentication errors
            exception.message?.contains("401") == true ||
                    exception.message?.contains("Unauthenticated") == true ||
                    exception.message?.contains("authorization") == true -> {
                Log.w(TAG, "Authentication error detected")
                "Authentication failed. Please login again."
            }

            // Network errors
            exception.message?.contains("ConnectException") == true ||
                    exception.message?.contains("UnknownHostException") == true -> {
                Log.w(TAG, "Network connectivity error")
                "Unable to connect to server. Please check your internet connection."
            }

            // Timeout errors
            exception.message?.contains("SocketTimeoutException") == true ||
                    exception.message?.contains("timeout") == true -> {
                Log.w(TAG, "Network timeout error")
                "Connection timeout. Please try again."
            }

            // Server errors
            exception.message?.contains("500") == true ||
                    exception.message?.contains("502") == true ||
                    exception.message?.contains("503") == true ||
                    exception.message?.contains("504") == true -> {
                Log.w(TAG, "Server error detected")
                "Server error. Please try again later."
            }

            // Forbidden/Access denied
            exception.message?.contains("403") == true -> {
                Log.w(TAG, "Access denied error")
                "Access denied. Please check your permissions."
            }

            // Not found
            exception.message?.contains("404") == true -> {
                Log.w(TAG, "Resource not found error")
                "Service not available. Please try again later."
            }

            // Generic error
            else -> {
                Log.e(TAG, "Generic error: ${exception.message}")
                exception.message ?: "An unexpected error occurred. Please try again."
            }
        }
    }

    /**
     * Check if current data is using fallback (offline) data
     */
    fun isUsingFallbackData(): Boolean {
        return _electionPairs.value.any { it.id.startsWith("fallback-") }
    }

    /**
     * Get authentication status
     */
    fun hasAuthenticationToken(): Boolean {
        return ElectionNetworkClient.hasValidToken()
    }

    companion object {
        /**
         * Factory for creating ElectionViewModel instances
         */
        val Factory: ViewModelProvider.Factory = viewModelFactory {
            initializer {
                ElectionViewModel(
                    electionRepository = ElectionRepository(),
                    partyRepository = PartyRepository()
                )
            }
        }
    }
}