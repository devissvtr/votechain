package com.nocturna.votechain.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.nocturna.votechain.data.model.ElectionPair
import com.nocturna.votechain.data.model.LiveElectionData
import com.nocturna.votechain.ui.theme.AppTypography
import com.nocturna.votechain.viewmodel.vote.AggregatedElectionStats
import com.nocturna.votechain.viewmodel.vote.ElectionComparison
import java.text.NumberFormat
import java.util.Locale
import kotlin.math.max
import kotlin.math.min

/**
 * Advanced analytics components untuk election results
 */

@Composable
fun ElectionComparisonCard(
    comparisons: List<ElectionComparison>,
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
                text = "Election Performance Comparison",
                style = AppTypography.heading5Bold,
                color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(16.dp))

            comparisons.forEachIndexed { index, comparison ->
                val electionPair = electionPairs.find { it.id == comparison.electionId }
                if (electionPair != null) {
                    ElectionComparisonItem(
                        comparison = comparison,
                        electionPair = electionPair,
                        rank = index + 1,
                        maxVotes = comparisons.maxOfOrNull { it.totalVotes } ?: 1
                    )
                    if (index < comparisons.size - 1) {
                        Spacer(modifier = Modifier.height(12.dp))
                        Divider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.2f))
                        Spacer(modifier = Modifier.height(12.dp))
                    }
                }
            }
        }
    }
}

@Composable
fun ElectionComparisonItem(
    comparison: ElectionComparison,
    electionPair: ElectionPair,
    rank: Int,
    maxVotes: Int
) {
    val progressPercentage = if (maxVotes > 0) {
        (comparison.totalVotes.toFloat() / maxVotes.toFloat())
    } else 0f

    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        // Rank indicator
        Box(
            modifier = Modifier
                .size(32.dp)
                .clip(CircleShape)
                .background(
                    when (rank) {
                        1 -> Color(0xFFFFD700) // Gold
                        2 -> Color(0xFFC0C0C0) // Silver
                        3 -> Color(0xFFCD7F32) // Bronze
                        else -> MaterialTheme.colorScheme.primary
                    }
                ),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = "$rank",
                style = AppTypography.paragraphBold,
                color = if (rank <= 3) Color.Black else Color.White,
                fontSize = 14.sp
            )
        }

        Spacer(modifier = Modifier.width(12.dp))

        Column(
            modifier = Modifier.weight(1f)
        ) {
            Text(
                text = "#${electionPair.election_no} - ${electionPair.president.full_name}",
                style = AppTypography.paragraphBold,
                color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(4.dp))

            // Progress bar
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(8.dp)
                    .clip(RoundedCornerShape(4.dp))
                    .background(MaterialTheme.colorScheme.outline.copy(alpha = 0.1f))
            ) {
                Box(
                    modifier = Modifier
                        .fillMaxHeight()
                        .fillMaxWidth(progressPercentage)
                        .clip(RoundedCornerShape(4.dp))
                        .background(MaterialTheme.colorScheme.primary)
                )
            }

            Spacer(modifier = Modifier.height(4.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = "Top: ${comparison.topRegion}",
                    style = AppTypography.paragraphRegular,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = "${String.format("%.1f", comparison.participationRate * 100)}%",
                    style = AppTypography.paragraphBold,
                    color = MaterialTheme.colorScheme.primary
                )
            }
        }

        Spacer(modifier = Modifier.width(12.dp))

        Column(
            horizontalAlignment = Alignment.End
        ) {
            Text(
                text = NumberFormat.getNumberInstance(Locale.US).format(comparison.totalVotes),
                style = AppTypography.paragraphBold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = "votes",
                style = AppTypography.paragraphRegular,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

//@Composable
//fun ParticipationTrendChart(
//    electionsData: Map<String, LiveElectionData>,
//    electionPairs: List<ElectionPair>
//) {
//    Card(
//        modifier = Modifier
//            .fillMaxWidth()
//            .shadow(8.dp, RoundedCornerShape(16.dp)),
//        shape = RoundedCornerShape(16.dp)
//    ) {
//        Column(
//            modifier = Modifier
//                .fillMaxWidth()
//                .padding(20.dp)
//        ) {
//            Text(
//                text = "Participation Rate Trend",
//                style = AppTypography.heading5Bold,
//                color = MaterialTheme.colorScheme.onSurface
//            )
//
//            Spacer(modifier = Modifier.height(16.dp))
//
//            // Chart area
//            Box(
//                modifier = Modifier
//                    .fillMaxWidth()
//                    .height(200.dp)
//            ) {
//                ParticipationLineChart(
//                    electionsData = electionsData,
//                    electionPairs = electionPairs
//                )
//            }
//
//            Spacer(modifier = Modifier.height(16.dp))
//
//            // Legend
//            LazyRow(
//                horizontalArrangement = Arrangement.spacedBy(16.dp)
//            ) {
//                items(electionsData.toList()) { (electionId, data) ->
//                    val electionPair = electionPairs.find { it.id == electionId }
//                    if (electionPair != null) {
//                        ParticipationLegendItem(
//                            electionPair = electionPair,
//                            participationRate = data.overallPercentage
//                        )
//                    }
//                }
//            }
//        }
//    }
//}

@Composable
fun ParticipationLineChart(
    electionsData: Map<String, LiveElectionData>,
    electionPairs: List<ElectionPair>
) {
    val data = electionsData.values.toList()
    if (data.isEmpty()) return

    val maxParticipation = data.maxOfOrNull { it.overallPercentage } ?: 1.0
    val minParticipation = data.minOfOrNull { it.overallPercentage } ?: 0.0
    val range = maxParticipation - minParticipation

    Canvas(
        modifier = Modifier.fillMaxSize()
    ) {
        val width = size.width
        val height = size.height
        val padding = 40.dp.toPx()

        val chartWidth = width - (padding * 2)
        val chartHeight = height - (padding * 2)

        // Draw grid lines
        val gridLines = 5
        for (i in 0..gridLines) {
            val y = padding + (chartHeight * i / gridLines)
            drawLine(
                color = Color.Gray.copy(alpha = 0.3f),
                start = androidx.compose.ui.geometry.Offset(padding, y),
                end = androidx.compose.ui.geometry.Offset(width - padding, y),
                strokeWidth = 1.dp.toPx()
            )
        }

        // Draw data points and lines
        if (data.size > 1) {
            val stepX = chartWidth / (data.size - 1)
            val path = Path()

            data.forEachIndexed { index, electionData ->
                val x = padding + (stepX * index)
                val normalizedValue = if (range > 0) {
                    ((electionData.overallPercentage - minParticipation) / range).toFloat()
                } else 0.5f
                val y = padding + chartHeight - (chartHeight * normalizedValue)

                if (index == 0) {
                    path.moveTo(x, y)
                } else {
                    path.lineTo(x, y)
                }

                // Draw data point
                drawCircle(
                    color = Color(0xFF3B82F6),
                    radius = 6.dp.toPx(),
                    center = androidx.compose.ui.geometry.Offset(x, y)
                )
            }

            // Draw line
            drawPath(
                path = path,
                color = Color(0xFF3B82F6),
                style = Stroke(width = 3.dp.toPx())
            )
        }
    }
}

@Composable
fun ParticipationLegendItem(
    electionPair: ElectionPair,
    participationRate: Double
) {
    Row(
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(12.dp)
                .clip(CircleShape)
                .background(Color(0xFF3B82F6))
        )

        Spacer(modifier = Modifier.width(8.dp))

        Column {
            Text(
                text = "#${electionPair.election_no}",
                style = AppTypography.paragraphBold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = "${String.format("%.1f", participationRate * 100)}%",
                style = AppTypography.paragraphRegular,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun RegionalPerformanceMap(
    electionsData: Map<String, LiveElectionData>,
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
                text = "Regional Performance Overview",
                style = AppTypography.heading5Bold,
                color = MaterialTheme.colorScheme.onSurface
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Aggregate regional data
            val aggregatedRegions = aggregateRegionalData(electionsData)

            LazyColumn(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(aggregatedRegions.entries.toList()) { (regionName, totalVotes) ->
                    RegionalPerformanceItem(
                        regionName = regionName,
                        totalVotes = totalVotes,
                        maxVotes = aggregatedRegions.values.maxOrNull() ?: 1
                    )
                }
            }
        }
    }
}

@Composable
fun RegionalPerformanceItem(
    regionName: String,
    totalVotes: Int,
    maxVotes: Int
) {
    val progressPercentage = if (maxVotes > 0) {
        (totalVotes.toFloat() / maxVotes.toFloat())
    } else 0f

    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = regionName,
            style = AppTypography.paragraphMedium,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(0.3f)
        )

        Spacer(modifier = Modifier.width(12.dp))

        Box(
            modifier = Modifier
                .weight(0.5f)
                .height(8.dp)
                .clip(RoundedCornerShape(4.dp))
                .background(MaterialTheme.colorScheme.outline.copy(alpha = 0.1f))
        ) {
            Box(
                modifier = Modifier
                    .fillMaxHeight()
                    .fillMaxWidth(progressPercentage)
                    .clip(RoundedCornerShape(4.dp))
                    .background(MaterialTheme.colorScheme.primary)
            )
        }

        Spacer(modifier = Modifier.width(12.dp))

        Text(
            text = NumberFormat.getNumberInstance(Locale.US).format(totalVotes),
            style = AppTypography.paragraphBold,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(0.2f)
        )
    }
}

@Composable
fun ElectionStatsSummary(
    aggregatedStats: AggregatedElectionStats
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Total Elections
        StatSummaryCard(
            title = "Total Elections",
            value = "${aggregatedStats.totalElections}",
            icon = "📊",
            modifier = Modifier.weight(1f)
        )

        // Total Votes
        StatSummaryCard(
            title = "Total Votes",
            value = NumberFormat.getNumberInstance(Locale.US).format(aggregatedStats.totalVotes),
            icon = "🗳️",
            modifier = Modifier.weight(1f)
        )

        // Average Participation
        StatSummaryCard(
            title = "Avg Participation",
            value = "${String.format("%.1f", aggregatedStats.averageParticipation * 100)}%",
            icon = "📈",
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
fun StatSummaryCard(
    title: String,
    value: String,
    icon: String,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.shadow(4.dp, RoundedCornerShape(12.dp)),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = icon,
                fontSize = 24.sp
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = value,
                style = AppTypography.heading6Bold,
                color = MaterialTheme.colorScheme.primary
            )

            Text(
                text = title,
                style = AppTypography.paragraphRegular,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

// Utility function untuk aggregate regional data
private fun aggregateRegionalData(electionsData: Map<String, LiveElectionData>): Map<String, Int> {
    val aggregatedRegions = mutableMapOf<String, Int>()

    electionsData.values.forEach { electionData ->
        electionData.regions.forEach { region ->
            aggregatedRegions[region.region] = (aggregatedRegions[region.region] ?: 0) + region.votes
        }
    }

    return aggregatedRegions.toMap().toList().sortedByDescending { it.second }.toMap()
}