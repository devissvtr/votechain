package com.nocturna.votechain.data.network

import android.util.Log
import com.google.gson.Gson
import com.google.gson.JsonSyntaxException
import com.nocturna.votechain.data.model.LiveElectionData
import com.nocturna.votechain.data.model.LiveResultsUpdateMessage
import com.nocturna.votechain.data.model.VotingOption
import com.nocturna.votechain.data.model.VotingResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import java.util.concurrent.TimeUnit

/**
 * WebSocket manager for live voting results
 * Connects to the live results API and provides real-time updates
 */
class LiveResultsWebSocketManager {
    private val TAG = "LiveResultsWebSocketManager"

    companion object {
        private const val WEBSOCKET_URL = "ws://e59519efec3b.ngrok-free.app/v1/live/ws"
        private const val RECONNECT_DELAY = 5000L // 5 seconds
        private const val MAX_RECONNECT_ATTEMPTS = 5
        private const val CONNECTION_TIMEOUT = 10L
    }

    private val gson = Gson()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // WebSocket client configuration
    private val okHttpClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(0, TimeUnit.SECONDS) // No timeout for reading (persistent connection)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

    private var webSocket: WebSocket? = null
    private var reconnectAttempts = 0

    // Connection state
    private val _connectionState = MutableStateFlow(ConnectionState.DISCONNECTED)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    // Live results data
    private val _liveResults = MutableStateFlow<VotingResult?>(null)
    val liveResults: StateFlow<VotingResult?> = _liveResults.asStateFlow()

    // Error state
    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    /**
     * Connect to the WebSocket and subscribe to live results
     */
    fun connect() {
        if (_connectionState.value == ConnectionState.CONNECTED ||
            _connectionState.value == ConnectionState.CONNECTING) {
            Log.d(TAG, "Already connected or connecting")
            return
        }

        Log.d(TAG, "Connecting to WebSocket: $WEBSOCKET_URL")
        _connectionState.value = ConnectionState.CONNECTING
        _error.value = null

        val request = Request.Builder()
            .url(WEBSOCKET_URL)
            .addHeader("Upgrade", "websocket")
            .addHeader("Connection", "Upgrade")
            .build()

        webSocket = okHttpClient.newWebSocket(request, webSocketListener)
    }

    /**
     * Disconnect from the WebSocket
     */
    fun disconnect() {
        Log.d(TAG, "Disconnecting from WebSocket")
        webSocket?.close(1000, "Manual disconnect")
        webSocket = null
        _connectionState.value = ConnectionState.DISCONNECTED
        reconnectAttempts = 0
    }

    /**
     * Send subscription message to start receiving live results
     */
//    private fun subscribeToLiveResults() {
//        val subscriptionMessage = mapOf(
//            "type" to "subscribe",
//            "subscription" to "live_results"
//        )
//
//        val jsonMessage = gson.toJson(subscriptionMessage)
//        Log.d(TAG, "Sending subscription message: $jsonMessage")
//
//        val success = webSocket?.send(jsonMessage) ?: false
//        if (!success) {
//            Log.e(TAG, "Failed to send subscription message")
//            _error.value = "Failed to send subscription message"
//        }
//    }

    /**
     * Attempt to reconnect with exponential backoff
     */
    private fun attemptReconnect() {
        if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            Log.e(TAG, "Maximum reconnection attempts reached")
            _connectionState.value = ConnectionState.FAILED
            _error.value = "Maximum reconnection attempts reached"
            return
        }

        reconnectAttempts++
        val delay = RECONNECT_DELAY * reconnectAttempts

        Log.d(TAG, "Attempting reconnection $reconnectAttempts/$MAX_RECONNECT_ATTEMPTS in ${delay}ms")

        scope.launch {
            kotlinx.coroutines.delay(delay)
            if (_connectionState.value != ConnectionState.CONNECTED) {
                connect()
            }
        }
    }

    /**
     * Process incoming WebSocket message
     */
    private fun processMessage(text: String) {
        try {
            Log.d(TAG, "Received message: $text")

            // Parse the incoming message as LiveResultsUpdateMessage
            val message = gson.fromJson(text, LiveResultsUpdateMessage::class.java)

            when (message.type) {
                "subscription_confirmed" -> {
                    Log.d(TAG, "Subscription confirmed")
                    _error.value = null
                }
                "live_results_update" -> {
                    // Convert LiveElectionData to VotingResult format
                    val votingResult = convertToVotingResult(message.data)
                    _liveResults.value = votingResult

                    // Also store the raw data for detailed views
                    _rawLiveData.value = message.data

                    Log.d(TAG, "Updated live results for election: ${message.data.electionId}")
                    Log.d(TAG, "Total votes: ${message.data.totalVotes}, Participation: ${message.data.overallPercentage}%")
                }
                "error" -> {
                    val errorMessage = "WebSocket error"
                    Log.e(TAG, "Received error from server: $errorMessage")
                    _error.value = errorMessage
                }
                else -> {
                    Log.d(TAG, "Unknown message type: ${message.type}")
                }
            }
        } catch (e: JsonSyntaxException) {
            Log.e(TAG, "Failed to parse JSON message: $text", e)
            _error.value = "Failed to parse server response"
        } catch (e: Exception) {
            Log.e(TAG, "Error processing message: $text", e)
            _error.value = "Error processing server message"
        }
    }

    /**
     * Convert LiveElectionData to VotingResult format
     * This is needed for compatibility with existing UI components
     */
    private fun convertToVotingResult(data: LiveElectionData): VotingResult {
        // Create voting options based on available data
        // In a real implementation, you would get candidate info from the election pairs
        val options = listOf(
            VotingOption(
                id = "candidate_1",
                name = "Candidate 1",
                votes = (data.totalVotes * 0.45).toInt(),
                percentage = 0.45f
            ),
            VotingOption(
                id = "candidate_2",
                name = "Candidate 2",
                votes = (data.totalVotes * 0.35).toInt(),
                percentage = 0.35f
            ),
            VotingOption(
                id = "candidate_3",
                name = "Candidate 3",
                votes = (data.totalVotes * 0.20).toInt(),
                percentage = 0.20f
            )
        )

        return VotingResult(
            categoryId = data.electionId,
            categoryTitle = "2024 Presidential Election",
            options = options,
            totalVotes = data.totalVotes
        )
    }

    // Add this to store raw live data
    private val _rawLiveData = MutableStateFlow<LiveElectionData?>(null)
    val rawLiveData: StateFlow<LiveElectionData?> = _rawLiveData.asStateFlow()

    // Update subscription message to match expected format
    private fun subscribeToLiveResults() {
        val subscriptionMessage = mapOf(
            "type" to "subscribe",
            "subscription" to "live_results",
            "filter" to mapOf(
                "election_pair_id" to "all" // Or specific election ID
            )
        )

        val jsonMessage = gson.toJson(subscriptionMessage)
        Log.d(TAG, "Sending subscription message: $jsonMessage")

        val success = webSocket?.send(jsonMessage) ?: false
        if (!success) {
            Log.e(TAG, "Failed to send subscription message")
            _error.value = "Failed to send subscription message"
        }
    }

    /**
     * Parse voting result from server data
     * Adapt this method based on your actual API response format
     */
    private fun parseVotingResult(data: Any?): VotingResult? {
        try {
            val json = gson.toJson(data)
            return gson.fromJson(json, VotingResult::class.java)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse VotingResult", e)
            return null
        }
    }

    /**
     * Clean up resources
     */
    fun cleanup() {
        disconnect()
        scope.cancel()
        okHttpClient.dispatcher.executorService.shutdown()
    }

    private val webSocketListener = object : WebSocketListener() {
        override fun onOpen(webSocket: WebSocket, response: Response) {
            Log.d(TAG, "WebSocket connection opened")
            _connectionState.value = ConnectionState.CONNECTED
            reconnectAttempts = 0
            _error.value = null

            // Send subscription message
            subscribeToLiveResults()
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            processMessage(text)
        }

        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            // Handle binary messages if needed
            Log.d(TAG, "Received binary message of ${bytes.size} bytes")
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            Log.d(TAG, "WebSocket closing: $code $reason")
            _connectionState.value = ConnectionState.DISCONNECTED
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            Log.d(TAG, "WebSocket closed: $code $reason")
            _connectionState.value = ConnectionState.DISCONNECTED

            // Attempt reconnection unless it was a manual disconnect
            if (code != 1000) {
                attemptReconnect()
            }
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            Log.e(TAG, "WebSocket connection failed", t)
            _connectionState.value = ConnectionState.FAILED
            _error.value = t.message ?: "Connection failed"

            // Attempt reconnection
            attemptReconnect()
        }
    }

    /**
     * Connection state enum
     */
    enum class ConnectionState {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        FAILED
    }
}