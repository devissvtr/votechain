package com.nocturna.votechain.ui.screens.votepage

import android.util.Log
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.paint
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.nocturna.votechain.R
import com.nocturna.votechain.data.model.Candidate
import com.nocturna.votechain.data.model.ElectionPair
import com.nocturna.votechain.data.model.LiveElectionData
import com.nocturna.votechain.data.model.LiveRegionResult
import com.nocturna.votechain.data.model.LiveCityResult
import com.nocturna.votechain.data.network.ElectionNetworkClient
import com.nocturna.votechain.data.network.LiveResultsWebSocketManager
import com.nocturna.votechain.data.network.LiveResultsWebSocketManager.ConnectionState
import com.nocturna.votechain.ui.components.ConnectionStatusIndicator
import com.nocturna.votechain.ui.components.DataUpdateNotification
import com.nocturna.votechain.ui.components.ElectionComparisonCard
import com.nocturna.votechain.ui.components.ElectionStatsSummary
import com.nocturna.votechain.ui.components.ElectionUpdateTimer
import com.nocturna.votechain.ui.components.RealTimeStatsBar
import com.nocturna.votechain.ui.components.RefreshControlPanel
import com.nocturna.votechain.ui.components.RegionalPerformanceMap
import com.nocturna.votechain.ui.screens.LoadingScreen
import com.nocturna.votechain.ui.theme.AppTypography
import com.nocturna.votechain.ui.theme.DangerColors
import com.nocturna.votechain.ui.theme.PrimaryColors
import com.nocturna.votechain.ui.theme.SuccessColors
import com.nocturna.votechain.ui.theme.WarningColors
import com.nocturna.votechain.utils.LanguageManager
import com.nocturna.votechain.viewmodel.candidate.ElectionViewModel
import com.nocturna.votechain.viewmodel.vote.LiveResultViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.text.NumberFormat
import java.util.Locale
import kotlin.collections.isNotEmpty
import kotlin.collections.sortedByDescending
import kotlin.math.cos
import kotlin.math.sin
import kotlin.random.Random

// Data class untuk kandidat dengan persentase
data class ElectionPairWithVotes(
    val electionPair: ElectionPair,
    val electionId: String,
    val votes: Int,
    val percentage: Float,
    val color: Color
)

// Aggregate data untuk pie chart
data class AggregatedElectionData(
    val totalVotes: Int,
    val totalVoters: Int,
    val participationRate: Double,
    val electionPairs: List<ElectionPairWithVotes>
)

val PieChartColors = listOf(
    PrimaryColors.Primary10,  // Lightest - untuk kontras awal yang soft
    PrimaryColors.Primary60,  // Medium dark - kontras yang jelas
    PrimaryColors.Primary30,  // Light medium - transisi yang smooth
    PrimaryColors.Primary90,  // Very dark - kontras maksimal
    PrimaryColors.Primary20,  // Light - kembali ke tone terang
    PrimaryColors.Primary80,  // Dark - kontras yang kuat
    PrimaryColors.Primary40,  // Medium - balance di tengah
    PrimaryColors.Primary100, // Darkest - untuk aksen
    PrimaryColors.Primary50,  // Medium tone - variasi tengah
    PrimaryColors.Primary70   // Dark medium - melengkapi palet
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LiveResultScreen(
    electionId: String,
    navController: NavController,
    electionViewModel: ElectionViewModel = viewModel(),
    liveResultViewModel: LiveResultViewModel = viewModel(),
    onBackClick: () -> Unit = {}
) {
    val context = LocalContext.current
    val electionPairs by electionViewModel.electionPairs.collectAsState()
    val connectionState by liveResultViewModel.connectionState.collectAsState()
    val rawLiveData by liveResultViewModel.rawLiveData.collectAsState()
    val allElectionsData by liveResultViewModel.allElectionsData.collectAsState()
    val aggregatedElectionStats by liveResultViewModel.aggregatedElectionData.collectAsState()
    val error by liveResultViewModel.error.collectAsState()
    val isLoading by liveResultViewModel.isLoading.collectAsState()

    val strings = LanguageManager.getLocalizedStrings()

    // State untuk menyimpan data agregat dari semua election_id
    var aggregatedData by remember { mutableStateOf<AggregatedElectionData?>(null) }
    var lastUpdateTime by remember { mutableStateOf<Long?>(null) }
    var showUpdateNotification by remember { mutableStateOf(false) }
    val electionStartTime = remember { System.currentTimeMillis() }

    // PERBAIKAN 1: Inisialisasi yang lebih robust
    LaunchedEffect(Unit) {
        Log.d("LiveResultScreen", "Initializing LiveResultScreen")

        try {
            // Pastikan ElectionNetworkClient terinisialisasi
            if (!ElectionNetworkClient.isInitialized()) {
                Log.w("LiveResultScreen", "ElectionNetworkClient not initialized, initializing now...")
                ElectionNetworkClient.initialize(context)
            }

            // Fetch election pairs jika belum ada
            if (electionPairs.isEmpty()) {
                Log.d("LiveResultScreen", "Election pairs empty, fetching...")
                electionViewModel.fetchElectionPairs()
            }
        } catch (e: Exception) {
            Log.e("LiveResultScreen", "Error during initialization", e)
        }
    }

    // PERBAIKAN 2: Start live results dengan proper initialization
    LaunchedEffect(electionPairs) {
        if (electionPairs.isNotEmpty()) {
            Log.d("LiveResultScreen", "Starting live results for ${electionPairs.size} election pairs")

            try {
                // Start live results untuk election yang dipilih
                liveResultViewModel.startLiveResults(electionId)

                // Start multiple elections monitoring untuk semua election pairs
                val electionIds = electionPairs.map { it.id }
                liveResultViewModel.startMultipleElections(electionIds)

                Log.d("LiveResultScreen", "Successfully started live results for elections: $electionIds")
            } catch (e: Exception) {
                Log.e("LiveResultScreen", "Error starting live results", e)
            }
        }
    }

    // Debug logging untuk tracking data state
    LaunchedEffect(electionPairs, rawLiveData, allElectionsData) {
        Log.d("LiveResultScreen", "Data state changed:")
        Log.d("LiveResultScreen", "- electionPairs.size: ${electionPairs.size}")
        Log.d("LiveResultScreen", "- rawLiveData: ${rawLiveData != null}")
        Log.d("LiveResultScreen", "- allElectionsData.size: ${allElectionsData.size}")
        Log.d("LiveResultScreen", "- connectionState: $connectionState")
    }

    // PERBAIKAN 3: Improved data processing dengan fallback
    LaunchedEffect(rawLiveData, electionPairs, allElectionsData) {
        Log.d("LiveResultScreen", "Processing aggregated data...")

        try {
            // Gunakan function robust untuk handle semua kasus
            aggregatedData = createRobustAggregatedData(electionPairs, allElectionsData, rawLiveData)

            if (aggregatedData != null) {
                lastUpdateTime = System.currentTimeMillis()
                Log.d("LiveResultScreen", "Aggregated data created with ${aggregatedData?.electionPairs?.size ?: 0} pairs")
            } else {
                Log.w("LiveResultScreen", "Failed to create aggregated data")

                // PERBAIKAN 4: Jika tidak ada data, coba refresh
                if (electionPairs.isNotEmpty() && allElectionsData.isEmpty() && rawLiveData == null) {
                    Log.d("LiveResultScreen", "No live data available, triggering refresh...")
                    delay(2000) // Wait a bit before retrying
                    liveResultViewModel.refreshAllElections()
                }
            }
        } catch (e: Exception) {
            Log.e("LiveResultScreen", "Error processing aggregated data", e)
        }
    }

    // PERBAIKAN 5: Connection monitoring dan auto-retry
    LaunchedEffect(connectionState) {
        Log.d("LiveResultScreen", "Connection state changed to: $connectionState")

        when (connectionState) {
            ConnectionState.FAILED, ConnectionState.DISCONNECTED -> {
                if (electionPairs.isNotEmpty()) {
                    Log.d("LiveResultScreen", "Connection failed, attempting retry in 5 seconds...")
                    delay(5000)
                    liveResultViewModel.retryConnection(electionId)
                }
            }
            ConnectionState.CONNECTED -> {
                Log.d("LiveResultScreen", "WebSocket connected successfully")
                showUpdateNotification = true
            }
            else -> {}
        }
    }

    // Animation states
    val rotation by animateFloatAsState(
        targetValue = if (aggregatedData != null) 360f else 0f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 10000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ), label = "rotation"
    )

    val pulseAnimation by animateFloatAsState(
        targetValue = if (connectionState == ConnectionState.CONNECTED) 1.2f else 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1000, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ), label = "pulse"
    )

    // PERBAIKAN 6: Cleanup when leaving screen
    DisposableEffect(Unit) {
        onDispose {
            Log.d("LiveResultScreen", "Cleaning up LiveResultScreen")
            // Don't disconnect here as it might be used elsewhere
        }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        // Custom top bar dengan fixed height
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(72.dp) // Fixed height untuk mencegah infinite constraints
                .padding(vertical = 24.dp)
        ) {
            Box(
                modifier = Modifier
                    .align(Alignment.CenterStart)
                    .padding(start = 24.dp)
                    .clickable(onClick = onBackClick)
                    .size(24.dp),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    painter = painterResource(id = R.drawable.back),
                    contentDescription = strings.back,
                    tint = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.size(20.dp)
                )
            }

            // Centered title
            Text(
                text = strings.results,
                style = AppTypography.heading4Regular,
                color = MaterialTheme.colorScheme.surfaceVariant,
                modifier = Modifier.align(Alignment.Center)
            )
        }

            when {
                isLoading && electionPairs.isEmpty() -> {
                    LoadingScreen()
                }
                error != null -> {
                    // Error state dengan fixed size
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = "Error: $error",
                            style = AppTypography.paragraphRegular,
                            color = MaterialTheme.colorScheme.error
                        )
                        Spacer(modifier = Modifier.height(16.dp))
                        Button(
                            onClick = {
                                electionViewModel.fetchElectionPairs()
                                liveResultViewModel.refreshAllElections()
                            }
                        ) {
                            Text("Retry")
                        }
                    }
                }
                else -> {
                    // SOLUSI UTAMA: Gunakan LazyColumn dengan fillMaxSize() dan proper constraint
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxSize() // Ini memberikan constraint yang jelas
                            .padding(horizontal = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        item {
                            // Connection Status Indicator
                            ConnectionStatusCard(
                                connectionState = connectionState,
                                onRetryClick = {
                                    liveResultViewModel.retryConnection(electionId)
                                }
                            )
                        }

                        item {
                            // Data Update Notification
                            DataUpdateNotification(
                                isVisible = showUpdateNotification,
                                message = "Data updated successfully!",
                                onDismiss = { showUpdateNotification = false }
                            )
                        }

                        item {
                            // Real-time Stats Bar
                            RealTimeStatsBar(
                                votesPerSecond = rawLiveData?.stats?.votesPerSecond ?: 0.0,
                                activeConnections = if (connectionState == ConnectionState.CONNECTED) 1 else 0,
                                modifier = Modifier.fillMaxWidth()
                            )
                        }

                        // Statistics Summary Cards
                        if (aggregatedElectionStats != null) {
                            item {
                                ElectionStatsSummary(aggregatedStats = aggregatedElectionStats!!)
                            }
                        }

                        item {
                            // Aggregated Stats Card
                            AggregatedStatsCard(
                                aggregatedData = aggregatedData,
                                pulseAnimation = pulseAnimation,
                                electionStartTime = electionStartTime
                            )
                        }

                        item {
                            // Main Pie Chart Card - Shows distribution across ALL election pairs
                            when {
                                aggregatedData != null && aggregatedData!!.electionPairs.isNotEmpty() -> {
                                    Log.d("LiveResultScreen", "Rendering pie chart with ${aggregatedData!!.electionPairs.size} pairs")
                                    AggregatedPieChartCard(
                                        aggregatedData = aggregatedData!!,
                                        rotation = rotation
                                    )
                                }
                                aggregatedData != null && aggregatedData!!.electionPairs.isEmpty() -> {
                                    Card(
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Box(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .height(200.dp),
                                            contentAlignment = Alignment.Center
                                        ) {
                                            Text(
                                                text = "No election data available for chart",
                                                style = AppTypography.paragraphRegular
                                            )
                                        }
                                    }
                                }
                                else -> {
                                    Card(
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Box(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .height(200.dp),
                                            contentAlignment = Alignment.Center
                                        ) {
                                            Column(
                                                horizontalAlignment = Alignment.CenterHorizontally
                                            ) {
                                                CircularProgressIndicator()
                                                Spacer(modifier = Modifier.height(8.dp))
                                                Text(
                                                    text = "Loading chart data...",
                                                    style = AppTypography.paragraphRegular
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Participation Trend Chart
//                        if (allElectionsData.isNotEmpty() && electionPairs.isNotEmpty()) {
//                            item {
//                                ParticipationTrendChart(
//                                    electionsData = allElectionsData,
//                                    electionPairs = electionPairs
//                                )
//                            }
//                        }

                        // Regional Performance Map
                        if (allElectionsData.isNotEmpty() && electionPairs.isNotEmpty()) {
                            item {
                                RegionalPerformanceMap(
                                    electionsData = allElectionsData,
                                    electionPairs = electionPairs
                                )
                            }
                        }

                        // Detailed Election Pair Results
                        if (aggregatedData?.electionPairs?.isNotEmpty() == true) {
                            items(aggregatedData!!.electionPairs.sortedByDescending { it.votes }) { electionPairData ->
                                ElectionPairResultCard(
                                    electionPairData = electionPairData,
                                    rank = aggregatedData!!.electionPairs.sortedByDescending { it.votes }
                                        .indexOf(electionPairData) + 1
                                )
                            }
                        }

                        // Regional Breakdown untuk current election
                        if (rawLiveData?.regions?.isNotEmpty() == true) {
                            item {
                                RegionalBreakdownCard(regions = rawLiveData!!.regions)
                            }
                        }

                        // Top Cities untuk current election
                        if (rawLiveData?.topCities?.isNotEmpty() == true) {
                            item {
                                TopCitiesCard(cities = rawLiveData!!.topCities)
                            }
                        }

                        // Individual Election Results
                        if (allElectionsData.isNotEmpty()) {
                            item {
                                IndividualElectionResultsCard(
                                    allLiveData = allElectionsData,
                                    electionPairs = electionPairs
                                )
                            }
                        }

                        // Footer with last update info
                        item {
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(8.dp),
                                colors = CardDefaults.cardColors(
                                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                                )
                            ) {
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(16.dp),
                                    horizontalAlignment = Alignment.CenterHorizontally
                                ) {
                                    Text(
                                        text = "🔄 Data refreshes automatically every 30 seconds",
                                        style = AppTypography.paragraphRegular,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                    if (lastUpdateTime != null) {
                                        Text(
                                            text = "Last updated: ${
                                                java.text.SimpleDateFormat(
                                                    "HH:mm:ss",
                                                    java.util.Locale.getDefault()
                                                ).format(java.util.Date(lastUpdateTime!!))
                                            }",
                                            style = AppTypography.paragraphRegular,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }
                        }

                        // Bottom padding untuk scrolling yang nyaman
                        item {
                            Spacer(modifier = Modifier.height(80.dp))
                        }
                    }
                }
            }
        }
    }

// PERBAIKAN 9: Improved fallback data creation
fun createFallbackAggregatedData(data: LiveElectionData): AggregatedElectionData {
    Log.d("LiveResultScreen", "Creating fallback aggregated data")

    return TODO("Provide the return value")
}

@Composable
fun AggregatedStatsCard(
    aggregatedData: AggregatedElectionData?,
    pulseAnimation: Float,
    electionStartTime: Long? = null
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .shadow(8.dp, RoundedCornerShape(16.dp)),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Overall Election Statistics",
                    style = AppTypography.heading5Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }

            // Stats Grid
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                StatItem(
                    title = "Election Duration",
                    value = calculateElectionDuration(electionStartTime),
                    modifier = Modifier.weight(1f)
                )
                StatItem(
                    title = "Total Votes",
                    value = NumberFormat.getNumberInstance(Locale.US)
                        .format(aggregatedData?.totalVotes ?: 0),
                    modifier = Modifier.weight(1f)
                )
                StatItem(
                    title = "Total Candidates",
                    value = "${aggregatedData?.electionPairs?.size ?: 0}",
                    modifier = Modifier.weight(1f)
                )
                StatItem(
                    title = "Participation",
                    value = "${String.format("%.1f", aggregatedData?.participationRate ?: 0.0)}%",
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}

private fun calculateElectionDuration(startTime: Long?): String {
    if (startTime == null) return "00:00"

    val currentTime = System.currentTimeMillis()
    val durationMs = currentTime - startTime
    val totalSeconds = durationMs / 1000

    val minutes = totalSeconds / 60
    val seconds = totalSeconds % 60

    return String.format("%02d:%02d", minutes, seconds)
}

// PERBAIKAN 10: Improved AggregatedPieChartCard dengan better error handling
@Composable
fun AggregatedPieChartCard(
    aggregatedData: AggregatedElectionData,
    rotation: Float
) {
    Log.d("AggregatedPieChartCard", "Rendering with ${aggregatedData.electionPairs.size} pairs")

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .shadow(8.dp, RoundedCornerShape(16.dp)),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "Vote Distribution",
                style = AppTypography.heading5Bold,
                color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(24.dp))

            // PERBAIKAN: Tambahkan kondisi check sebelum render pie chart
            if (aggregatedData.electionPairs.isNotEmpty()) {
                // Pie Chart
                Box(
                    modifier = Modifier
                        .size(240.dp)
                        .aspectRatio(1f), // Tambahan untuk memastikan rasio 1:1
                    contentAlignment = Alignment.Center
                ) {
                    AggregatedAnimatedPieChart(
                        electionPairs = aggregatedData.electionPairs,
                        modifier = Modifier.size(240.dp) // Ukuran fixed, bukan fillMaxSize()
                    )

                    // Center info
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "Leading",
                            style = AppTypography.paragraphRegular,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        aggregatedData.electionPairs.maxByOrNull { it.votes }?.let { leader ->
                            Text(
                                text = "${leader.percentage.toInt()}%",
                                style = AppTypography.heading3Bold,
                                color = leader.color
                            )
                            Text(
                                text = "#${leader.electionPair.election_no}",
                                style = AppTypography.paragraphMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(20.dp))

                // Legend
                aggregatedData.electionPairs.sortedByDescending { it.votes }.forEach { electionPairData ->
                    AggregatedLegendItem(
                        electionPairData = electionPairData,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                }
            } else {
                // TAMBAHAN: Fallback UI jika tidak ada data
                Box(
                    modifier = Modifier
                        .size(280.dp)
                        .background(
                            MaterialTheme.colorScheme.surfaceVariant,
                            RoundedCornerShape(16.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            painter = painterResource(R.drawable.back),
                            contentDescription = "No data",
                            modifier = Modifier.size(48.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "No chart data available",
                            style = AppTypography.paragraphRegular,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

// PERBAIKAN 11: Improved AggregatedAnimatedPieChart dengan safety checks
@Composable
fun AggregatedAnimatedPieChart(
    electionPairs: List<ElectionPairWithVotes>,
    modifier: Modifier = Modifier
) {
    // TAMBAHAN: Safety check untuk data kosong
    if (electionPairs.isEmpty()) {
        Log.w("AggregatedAnimatedPieChart", "No election pairs data to render")
        return
    }

    Log.d("AggregatedAnimatedPieChart", "Rendering pie chart for ${electionPairs.size} pairs")

    val animatedValues = electionPairs.map { electionPairData ->
        animateFloatAsState(
            targetValue = electionPairData.percentage,
            animationSpec = tween(durationMillis = 1500, easing = FastOutSlowInEasing),
            label = "pie_slice_${electionPairData.electionPair.id}"
        )
    }

    Canvas(
        modifier = modifier
            .size(280.dp) // Ukuran fixed untuk mencegah infinite constraints
            .aspectRatio(1f) // Pastikan berbentuk persegi
    ) {
        val canvasWidth = size.width
        val canvasHeight = size.height

        if (canvasWidth <= 0 || canvasHeight <= 0) {
            return@Canvas
        }

        val radius = minOf(canvasWidth, canvasHeight) / 2f * 0.85f
        val center = center

        var currentAngle = -90f
        val strokeWidth = 50.dp.toPx()

        electionPairs.forEachIndexed { index, electionPairData ->
            val animatedValue = animatedValues[index].value
            val sweepAngle = (animatedValue / 100f) * 360f

            Log.d("AggregatedAnimatedPieChart", "Drawing slice $index: ${electionPairData.percentage}% -> $sweepAngle°")

            if (sweepAngle > 0) {
                // Draw pie slice
                drawArc(
                    color = electionPairData.color,
                    startAngle = currentAngle,
                    sweepAngle = sweepAngle,
                    useCenter = false,
                    style = Stroke(width = strokeWidth, cap = StrokeCap.Round),
                    size = androidx.compose.ui.geometry.Size(radius * 2, radius * 2),
                    topLeft = androidx.compose.ui.geometry.Offset(
                        center.x - radius,
                        center.y - radius
                    )
                )

                currentAngle += sweepAngle
            }
        }
    }
}

// Function untuk mensimulasikan data dari multiple election_id
fun generateSimulatedElectionData(
    electionPairs: List<ElectionPair>,
    currentLiveData: LiveElectionData
): Map<String, LiveElectionData> {
    val simulatedData = mutableMapOf<String, LiveElectionData>()

    electionPairs.forEach { pair ->
        // Simulasi data untuk setiap election pair
        val baseVotes = currentLiveData.totalVotes
        val randomMultiplier = Random.nextDouble(0.5, 1.5)
        val simulatedVotes = (baseVotes * randomMultiplier).toInt()

        val simulatedElectionData = LiveElectionData(
            electionId = pair.id,
            totalVotes = simulatedVotes,
            totalVoters = currentLiveData.totalVoters,
            lastUpdated = currentLiveData.lastUpdated,
            overallPercentage = currentLiveData.overallPercentage * randomMultiplier,
            regions = currentLiveData.regions.map { region ->
                region.copy(votes = (region.votes * randomMultiplier).toInt())
            },
            topCities = currentLiveData.topCities.map { city ->
                city.copy(votes = (city.votes * randomMultiplier).toInt())
            },
            stats = currentLiveData.stats
        )

        simulatedData[pair.id] = simulatedElectionData
    }

    return simulatedData
}

// Function untuk agregasi data dari semua election_id
fun aggregateElectionData(
    electionPairs: List<ElectionPair>,
    allLiveData: Map<String, LiveElectionData>
): AggregatedElectionData {
    val totalVotes = allLiveData.values.sumOf { it.totalVotes }
    val totalVoters = allLiveData.values.firstOrNull()?.totalVoters ?: 0
    val participationRate = if (totalVoters > 0) (totalVotes.toDouble() / totalVoters) * 100 else 0.0

    val electionPairsWithVotes = electionPairs.mapIndexed { index, pair ->
        val liveData = allLiveData[pair.id]
        val votes = liveData?.totalVotes ?: 0
        val percentage = if (totalVotes > 0) (votes.toFloat() / totalVotes) * 100f else 0f

        ElectionPairWithVotes(
            electionPair = pair,
            electionId = pair.id,
            votes = votes,
            percentage = percentage,
            color = PieChartColors[index % PieChartColors.size]
        )
    }

    return AggregatedElectionData(
        totalVotes = totalVotes,
        totalVoters = totalVoters,
        participationRate = participationRate,
        electionPairs = electionPairsWithVotes
    )
}

// PERBAIKAN 8: Improved robust data creation dengan better fallback
fun createRobustAggregatedData(
    electionPairs: List<ElectionPair>,
    allElectionsData: Map<String, LiveElectionData>,
    rawLiveData: LiveElectionData?
): AggregatedElectionData? {
    return when {
        // Case 1: Ada election pairs dan live data
        electionPairs.isNotEmpty() && allElectionsData.isNotEmpty() -> {
            Log.d("LiveResultScreen", "Creating aggregated data from election pairs and live data")
            aggregateElectionData(electionPairs, allElectionsData)
        }

        // Case 2: Ada election pairs tapi tidak ada live data, gunakan rawLiveData
        electionPairs.isNotEmpty() && rawLiveData != null -> {
            Log.d("LiveResultScreen", "Creating aggregated data from election pairs and raw data")
            val simulatedData = generateSimulatedElectionData(electionPairs, rawLiveData)
            aggregateElectionData(electionPairs, simulatedData)
        }

        // Case 3: Tidak ada election pairs tapi ada rawLiveData, buat fallback
        electionPairs.isEmpty() && rawLiveData != null -> {
            Log.w("LiveResultScreen", "Creating fallback aggregated data")
            createFallbackAggregatedData(rawLiveData)
        }

        // Case 4: Ada election pairs tapi tidak ada data apapun, buat empty data
        electionPairs.isNotEmpty() -> {
            Log.w("LiveResultScreen", "Creating empty aggregated data from election pairs")
            createEmptyAggregatedData(electionPairs)
        }

        // Case 5: Tidak ada data sama sekali
        else -> {
            Log.w("LiveResultScreen", "No data available for aggregation")
            null
        }
    }
}

// TAMBAHAN: Function untuk membuat empty aggregated data
fun createEmptyAggregatedData(electionPairs: List<ElectionPair>): AggregatedElectionData {
    val electionPairsWithVotes = electionPairs.mapIndexed { index, pair ->
        ElectionPairWithVotes(
            electionPair = pair,
            electionId = pair.id,
            votes = 0,
            percentage = 0f,
            color = PieChartColors[index % PieChartColors.size]
        )
    }

    return AggregatedElectionData(
        totalVotes = 0,
        totalVoters = 0,
        participationRate = 0.0,
        electionPairs = electionPairsWithVotes
    )
}

@Composable
fun AggregatedLegendItem(
    electionPairData: ElectionPairWithVotes,
    modifier: Modifier = Modifier
) {
    Row(
        modifier = modifier,
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(16.dp)
                    .clip(CircleShape)
                    .background(electionPairData.color)
            )

            Spacer(modifier = Modifier.width(12.dp))

            Column {
                Text(
                    text = "#${electionPairData.electionPair.election_no} - ${electionPairData.electionPair.president.full_name} & ${electionPairData.electionPair.vice_president.full_name}",
                    style = AppTypography.heading6Medium,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(modifier = Modifier.width(8.dp))

                Text(
                    text = "${NumberFormat.getNumberInstance(Locale.US).format(electionPairData.votes)} votes",
                    style = AppTypography.paragraphRegular,
                    color = MaterialTheme.colorScheme.onPrimary
                )
            }
        }

        Text(
            text = "${electionPairData.percentage.toInt()}%",
            style = AppTypography.heading6Bold,
            color = electionPairData.color
        )
    }
}

@Composable
fun ElectionPairResultCard(
    electionPairData: ElectionPairWithVotes,
    rank: Int
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { /* Handle election pair detail */ },
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Rank badge
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(CircleShape)
                    .background(electionPairData.color),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = "$rank",
                    style = AppTypography.paragraphBold,
                    color = Color.White
                )
            }

            Spacer(modifier = Modifier.width(16.dp))

            Column(
                modifier = Modifier.weight(1f)
            ) {
                Text(
                    text = "#${electionPairData.electionPair.election_no}",
                    style = AppTypography.paragraphBold,
                    color = electionPairData.color
                )
                Text(
                    text = "${electionPairData.electionPair.president.full_name} & ${electionPairData.electionPair.vice_president.full_name}",
                    style = AppTypography.paragraphBold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "${NumberFormat.getNumberInstance(Locale.US).format(electionPairData.votes)} votes",
                    style = AppTypography.paragraphBold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Column(
                horizontalAlignment = Alignment.End
            ) {
                Text(
                    text = "${electionPairData.percentage.toInt()}%",
                    style = AppTypography.heading6Bold,
                    color = electionPairData.color
                )
                Text(
                    text = "of total",
                    style = AppTypography.paragraphRegular,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
fun IndividualElectionResultsCard(
    allLiveData: Map<String, LiveElectionData>,
    electionPairs: List<ElectionPair>
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .shadow(8.dp, RoundedCornerShape(16.dp)),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp)
        ) {
            Text(
                text = "Individual Election Results",
                style = AppTypography.heading5Bold,
                color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(16.dp))

            allLiveData.forEach { (electionId, liveData) ->
                val electionPair = electionPairs.find { it.id == electionId }
                if (electionPair != null) {
                    IndividualElectionItem(
                        electionPair = electionPair,
                        liveData = liveData
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                }
            }
        }
    }
}

@Composable
fun IndividualElectionItem(
    electionPair: ElectionPair,
    liveData: LiveElectionData
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column {
            Text(
                text = "#${electionPair.election_no} - ${electionPair.president.full_name}",
                style = AppTypography.paragraphMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = "Election ID: ${liveData.electionId}",
                style = AppTypography.paragraphRegular,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        Column(
            horizontalAlignment = Alignment.End
        ) {
            Text(
                text = "${NumberFormat.getNumberInstance(Locale.US).format(liveData.totalVotes)} votes",
                style = AppTypography.paragraphBold,
                color = MaterialTheme.colorScheme.primary
            )
            Text(
                text = "${String.format("%.3f", liveData.overallPercentage * 100)}% participation",
                style = AppTypography.paragraphRegular,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

// Reuse existing components
@Composable
fun RegionalBreakdownCard(regions: List<LiveRegionResult>) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .shadow(8.dp, RoundedCornerShape(16.dp)),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp)
        ) {
            Text(
                text = "Regional Breakdown",
                style = AppTypography.heading5Bold,
                color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(16.dp))

            regions.forEach { region ->
                RegionItem(region = region)
                Spacer(modifier = Modifier.height(12.dp))
            }
        }
    }
}

@Composable
fun RegionItem(region: LiveRegionResult) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = region.region,
            style = AppTypography.paragraphMedium,
            color = MaterialTheme.colorScheme.onSurface
        )

        Row(
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "${NumberFormat.getNumberInstance(Locale.US).format(region.votes)} votes",
                style = AppTypography.paragraphRegular,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = "${String.format("%.1f", region.percentage * 100)}%",
                style = AppTypography.paragraphBold,
                color = MaterialTheme.colorScheme.primary
            )
        }
    }
}

@Composable
fun TopCitiesCard(cities: List<LiveCityResult>) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .shadow(8.dp, RoundedCornerShape(16.dp)),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp)
        ) {
            Text(
                text = "Top Cities",
                style = AppTypography.heading5Bold,
                color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(16.dp))

            cities.take(5).forEach { city ->
                CityItem(city = city)
                Spacer(modifier = Modifier.height(12.dp))
            }
        }
    }
}

@Composable
fun ConnectionStatusCard(
    connectionState: ConnectionState,
    onRetryClick: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when (connectionState) {
                ConnectionState.CONNECTED -> SuccessColors.Success20
                ConnectionState.CONNECTING -> WarningColors.Warning20
                ConnectionState.FAILED, ConnectionState.DISCONNECTED -> DangerColors.Danger20
            }
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(
                            when (connectionState) {
                                ConnectionState.CONNECTED -> SuccessColors.Success60
                                ConnectionState.CONNECTING -> WarningColors.Warning60
                                ConnectionState.FAILED, ConnectionState.DISCONNECTED -> DangerColors.Danger60
                            }
                        )
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = when (connectionState) {
                        ConnectionState.CONNECTED -> "Live Connection Active"
                        ConnectionState.CONNECTING -> "Connecting..."
                        ConnectionState.FAILED -> "Connection Failed"
                        ConnectionState.DISCONNECTED -> "Disconnected"
                    },
                    style = AppTypography.paragraphMedium,
                    color = MaterialTheme.colorScheme.inverseSurface
                )
            }

            if (connectionState == ConnectionState.FAILED || connectionState == ConnectionState.DISCONNECTED) {
                TextButton(onClick = onRetryClick) {
                    Text("Retry")
                }
            }
        }
    }
}

@Composable
fun CityItem(city: LiveCityResult) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(24.dp)
                    .clip(CircleShape)
                    .background(MaterialTheme.colorScheme.primary),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = "${city.rank}",
                    style = AppTypography.paragraphBold,
                    color = Color.White
                )
            }

            Spacer(modifier = Modifier.width(12.dp))

            Column {
                Text(
                    text = city.city,
                    style = AppTypography.paragraphMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = "${NumberFormat.getNumberInstance(Locale.US).format(city.votes)}/${NumberFormat.getNumberInstance(Locale.US).format(city.voters)} voters",
                    style = AppTypography.paragraphRegular,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        Text(
            text = "${String.format("%.1f", city.percentage * 100)}%",
            style = AppTypography.paragraphBold,
            color = MaterialTheme.colorScheme.primary
        )
    }
}

@Composable
fun StatItem(
    title: String,
    value: String,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = title,
            style = AppTypography.paragraphRegular,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = value,
            style = AppTypography.heading6Bold,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}