package com.nocturna.votechain.ui.screens.votepage

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.nocturna.votechain.data.model.VotingCategory
import com.nocturna.votechain.ui.screens.BottomNavigation
import com.nocturna.votechain.ui.theme.AppTypography
import com.nocturna.votechain.ui.theme.MainColors
import com.nocturna.votechain.ui.theme.NeutralColors
import com.nocturna.votechain.viewmodel.vote.VotingViewModel
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.res.painterResource
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.ui.platform.LocalContext
import com.nocturna.votechain.R
import com.nocturna.votechain.ui.screens.LoadingScreen
import com.nocturna.votechain.utils.LanguageManager
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun VotingScreen(
    navController: NavController,
    onHomeClick: () -> Unit = { navController.navigate("home") },
    onVotesClick: () -> Unit = { /* Already on votes */ },
    onProfileClick: () -> Unit = { navController.navigate("profile") }
) {
    val context = LocalContext.current
    val strings = LanguageManager.getLocalizedStrings()

    // Create ViewModel with proper dependencies
    val viewModel: VotingViewModel = viewModel(
        factory = VotingViewModel.Factory(context)
    )

    val activeVotings by viewModel.activeVotings.collectAsState()
    val votingResults by viewModel.votingResults.collectAsState()
    val isLoading by viewModel.isLoading.collectAsState()
    val error by viewModel.error.collectAsState()
    val hasVoted by viewModel.hasVoted.collectAsState()

    val currentRoute = "votes"

    val pagerState = rememberPagerState(pageCount = { 2 })
    val coroutineScope = rememberCoroutineScope()

    val tabs = listOf(strings.activeVotesList, strings.results)

    Scaffold(
        bottomBar = {
            BottomNavigation(
                currentRoute = currentRoute,
                onNavigate = { route ->
                    when (route) {
                        "home" -> onHomeClick()
                        "votes" -> onVotesClick()
                        "profile" -> onProfileClick()
                    }
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(bottom = innerPadding.calculateBottomPadding())
        ) {
            // Tab Row
            TabRow(
                selectedTabIndex = pagerState.currentPage,
                indicator = { tabPositions ->
                    TabRowDefaults.Indicator(
                        modifier = Modifier
                            .tabIndicatorOffset(tabPositions[pagerState.currentPage])
                            .padding(horizontal = 24.dp),
                        color = MainColors.Primary1
                    )
                },
                divider = { Divider(color = NeutralColors.Neutral10, thickness = 1.dp) }
            ) {
                tabs.forEachIndexed { index, title ->
                    Tab(
                        selected = pagerState.currentPage == index,
                        onClick = {
                            coroutineScope.launch {
                                pagerState.animateScrollToPage(index)
                            }
                        },
                        text = {
                            Text(
                                text = title,
                                style = AppTypography.heading4Medium,
                                color = if (pagerState.currentPage == index) MainColors.Primary1 else NeutralColors.Neutral50
                            )
                        }
                    )
                }
            }

            // Page content
            HorizontalPager(
                state = pagerState,
                modifier = Modifier.fillMaxSize()
            ) { page ->
                when (page) {
                    0 -> ActiveVotingTab(
                        activeVotings = activeVotings,
                        isLoading = isLoading,
                        error = error,
                        hasVoted = hasVoted,
                        onVoteItemClick = { categoryId, title ->
                            // Check if it's the 2024 presidential election - Indonesia card
                            if (title.contains("2024 presidential election", ignoreCase = true) &&
                                title.contains("Indonesia", ignoreCase = true)) {
                                // Navigate directly to candidate selection screen
                                navController.navigate("candidate_selection/$categoryId")
                            } else {
                                // Navigate to the general voting detail screen for other elections
                                navController.navigate("voting_detail/$categoryId")
                            }
                        },
                        navController = navController
                    )
                    1 -> ResultsScreen(
                        navController = navController,
                        viewModel = viewModel
                    )
                }
            }

            // Load appropriate data based on selected tab
            LaunchedEffect(pagerState.currentPage) {
                when (pagerState.currentPage) {
                    0 -> viewModel.fetchActiveVotings()
                    1 -> viewModel.fetchVotingResults()
                }
            }
        }
    }
}

@Composable
fun ActiveVotingTab(
    activeVotings: List<VotingCategory>,
    isLoading: Boolean,
    error: String?,
    hasVoted: Boolean,
    onVoteItemClick: (String, String) -> Unit,
    navController: NavController
) {
    val strings = LanguageManager.getLocalizedStrings()

    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp)
    ) {
        if (isLoading) {
            LoadingScreen()
        } else if (error != null) {
            Column(
                modifier = Modifier.align(Alignment.Center),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = "Error loading votings",
                    style = AppTypography.heading5Medium,
                    color = NeutralColors.Neutral70
                )
                Text(
                    text = error,
                    style = AppTypography.paragraphRegular,
                    color = NeutralColors.Neutral50
                )
            }
        } else {
            // Always show at least the default presidential election card
            val votingsToShow = if (activeVotings.isEmpty()) {
                // Create default presidential election card when no data
                listOf(
                    VotingCategory(
                        id = "presidential_2024",
                        title = strings.cardTitle,
                        description = strings.cardSubtitle,
                        isActive = true
                    )
                )
            } else {
                activeVotings
            }

            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(top = 24.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(24.dp)
            ) {
                items(votingsToShow) { votingCategory ->
                    VotingCard(
                        votingCategory = votingCategory,
                        hasVoted = hasVoted,
                        onClick = { onVoteItemClick(votingCategory.id, votingCategory.title) },
                        navController = navController
                    )
                }
            }
        }
    }
}

@Composable
fun VotingCard(
    votingCategory: VotingCategory,
    hasVoted: Boolean,
    onClick: () -> Unit,
    navController: NavController,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 2.dp
        ),
        onClick = {
            navController.navigate("otp_verification/${votingCategory.id}")}
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(
                modifier = Modifier.weight(1f)
            ) {
                Text(
                    text = votingCategory.title,
                    style = AppTypography.heading5Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )

                Spacer(modifier = Modifier.height(4.dp))

                Text(
                    text = votingCategory.description,
                    style = AppTypography.heading6Medium,
                    color = MaterialTheme.colorScheme.onBackground,
                    maxLines = 1,
                    modifier = Modifier.width(270.dp),
                    overflow = TextOverflow.Ellipsis
                )
            }

            Icon(
                painter = painterResource(id = R.drawable.right2),
                contentDescription = "View Details",
                tint = MainColors.Primary1,
                modifier = Modifier.size(16.dp)
            )
        }
    }
}