// Update untuk LiveResultRepository.kt

package com.nocturna.votechain.data.repository

import com.nocturna.votechain.data.model.LiveElectionData
import com.nocturna.votechain.data.model.VotingResult
import com.nocturna.votechain.data.network.LiveResultsWebSocketManager
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine

/**
 * Repository for live voting results using WebSocket connection
 * Enhanced to provide raw live data access
 */
class LiveResultRepository {
    private val webSocketManager = LiveResultsWebSocketManager()

    /**
     * Get live results with real-time updates
     */
    fun getLiveResults(electionId: String, regionCode: String? = null): Flow<Result<VotingResult?>> {
        // Connect to WebSocket if not already connected
        webSocketManager.connect()

        // Combine live results with error state to return proper Result type
        return combine(
            webSocketManager.liveResults,
            webSocketManager.error
        ) { liveResult, error ->
            when {
                error != null -> Result.failure(Exception(error))
                liveResult != null -> {
                    // Filter by election ID if needed
                    val filteredResult = if (liveResult.categoryId == electionId) {
                        filterResult(liveResult, electionId, regionCode)
                    } else {
                        null
                    }
                    Result.success(filteredResult)
                }
                else -> Result.success(null)
            }
        }
    }

    /**
     * Get raw live data from WebSocket
     */
    fun getRawLiveData(): Flow<LiveElectionData?> {
        return webSocketManager.rawLiveData
    }

    /**
     * Get connection state
     */
    fun getConnectionState(): Flow<LiveResultsWebSocketManager.ConnectionState> {
        return webSocketManager.connectionState
    }

    /**
     * Disconnect from live updates
     */
    fun disconnect() {
        webSocketManager.disconnect()
    }

    /**
     * Clean up resources
     */
    fun cleanup() {
        webSocketManager.cleanup()
    }

    /**
     * Filter results based on election ID and region
     */
    private fun filterResult(result: VotingResult, electionId: String, regionCode: String?): VotingResult {
        // If no region filter, return the result as is
        if (regionCode == null) {
            return result
        }

        // Apply region-specific filtering if needed
        // This would be implemented based on your specific requirements
        return result
    }
}