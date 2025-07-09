package com.nocturna.votechain.ui.screens.votepage

import android.content.Context
import android.util.Log
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import coil.compose.AsyncImage
import coil.compose.SubcomposeAsyncImage
import coil.request.ImageRequest
import com.nocturna.votechain.R
import com.nocturna.votechain.data.model.ElectionPair
import com.nocturna.votechain.data.network.PartyPhotoHelper
import com.nocturna.votechain.ui.screens.LoadingScreen
import com.nocturna.votechain.ui.theme.AppTypography
import com.nocturna.votechain.ui.theme.DangerColors
import com.nocturna.votechain.ui.theme.MainColors
import com.nocturna.votechain.ui.theme.NeutralColors
import com.nocturna.votechain.ui.theme.PrimaryColors
import com.nocturna.votechain.ui.theme.SuccessColors
import com.nocturna.votechain.utils.CandidatePhotoHelper
import com.nocturna.votechain.utils.CoilAuthHelper
import com.nocturna.votechain.utils.LanguageManager
import com.nocturna.votechain.utils.VoteErrorHandler
import com.nocturna.votechain.viewmodel.candidate.ElectionViewModel
import com.nocturna.votechain.viewmodel.vote.EnhancedVoteConfirmationUiState
import com.nocturna.votechain.viewmodel.vote.VoteConfirmationViewModel
import com.nocturna.votechain.viewmodel.vote.VoteStep
import com.nocturna.votechain.viewmodel.vote.VotingViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VoteConfirmationScreen(
    navController: NavController,
    electionPairId: String,
    categoryId: String = "",
    modifier: Modifier = Modifier
) {
    val strings = LanguageManager.getLocalizedStrings()
    val context = LocalContext.current

    // Create enhanced ViewModel
    val viewModel: VoteConfirmationViewModel = viewModel(
        factory = VoteConfirmationViewModel.Factory(
            context = context,
            categoryId = categoryId,
            electionPairId = electionPairId
        )
    )

    val uiState by viewModel.uiState.collectAsState()

    // Handle navigation on success
    LaunchedEffect(uiState.isVoteSuccess) {
        if (uiState.isVoteSuccess) {
            // Navigate to success screen after a short delay
            kotlinx.coroutines.delay(2000)
            navController.navigate("vote_success/${uiState.voteId}") {
                popUpTo("candidate_selection") { inclusive = true }
            }
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color.White)
    ) {
        // Custom Top Bar
        EnhancedTopBar(
            title = "Confirm Your Vote",
            onBackClick = {
                if (!uiState.isLoading) {
                    navController.popBackStack()
                }
            },
            isBackEnabled = !uiState.isLoading
        )

        // Content
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(24.dp)
        ) {
            // Progress Indicator
            VoteProcessProgressIndicator(
                currentStep = uiState.step,
                isLoading = uiState.isLoading
            )

            // Election Pair Information Card
            ElectionPairConfirmationCard(
                electionPairId = electionPairId
            )

            // Security Information Card
            SecurityInfoCard()

            // Error Display
            uiState.error?.let { error ->
                ErrorCard(
                    error = error,
                    onRetry = { viewModel.retryVote() },
                    onDismiss = { viewModel.clearError() }
                )
            }

            // Success Display
            if (uiState.isVoteSuccess) {
                SuccessCard(
                    transactionHash = uiState.transactionHash,
                    voteId = uiState.voteId,
                    votedAt = uiState.votedAt
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Action Buttons
            VoteActionButtons(
                uiState = uiState,
                onConfirm = {
                    val sharedPrefs = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
                    val region = sharedPrefs.getString("user_region", "default") ?: "default"
                    val otpToken = sharedPrefs.getString("otp_token", "")

                    viewModel.castVoteWithSignedTransaction(electionPairId, region, otpToken)
                },
                onCancel = {
                    if (!uiState.isLoading) {
                        navController.popBackStack()
                    }
                }
            )
        }
    }
}

@Composable
private fun EnhancedTopBar(
    title: String,
    onBackClick: () -> Unit,
    isBackEnabled: Boolean
) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 24.dp, horizontal = 24.dp)
    ) {
        if (isBackEnabled) {
            Box(
                modifier = Modifier
                    .align(Alignment.CenterStart)
                    .clickable { onBackClick() }
                    .size(32.dp),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    painter = painterResource(id = R.drawable.back),
                    contentDescription = "Back",
                    tint = MainColors.Primary1,
                    modifier = Modifier.size(20.dp)
                )
            }
        }

        Text(
            text = title,
            style = AppTypography.heading4Regular,
            color = PrimaryColors.Primary80,
            modifier = Modifier.align(Alignment.Center)
        )
    }
}

@Composable
private fun VoteProcessProgressIndicator(
    currentStep: VoteStep,
    isLoading: Boolean
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = PrimaryColors.Primary50)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = "Vote Process",
                style = AppTypography.paragraphSemiBold,
                color = PrimaryColors.Primary70
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                // Step Indicator
                Box(
                    modifier = Modifier
                        .size(24.dp)
                        .background(
                            color = when {
                                currentStep == VoteStep.COMPLETED -> SuccessColors.Success50
                                currentStep == VoteStep.ERROR -> DangerColors.Danger50
                                isLoading -> MainColors.Primary1
                                else -> NeutralColors.Neutral30
                            },
                            shape = RoundedCornerShape(12.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    when {
                        currentStep == VoteStep.COMPLETED -> {
                            Icon(
                                painter = painterResource(id = R.drawable.ic_launcher_foreground), // Replace with check icon
                                contentDescription = "Success",
                                tint = Color.White,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                        currentStep == VoteStep.ERROR -> {
                            Icon(
                                painter = painterResource(id = R.drawable.ic_launcher_foreground), // Replace with error icon
                                contentDescription = "Error",
                                tint = Color.White,
                                modifier = Modifier.size(16.dp)
                            )
                        }
                        isLoading -> {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                color = Color.White,
                                strokeWidth = 2.dp
                            )
                        }
                        else -> {
                            Text(
                                text = "1",
                                style = AppTypography.paragraphRegular,
                                color = Color.White
                            )
                        }
                    }
                }

                // Step Description
                Text(
                    text = when (currentStep) {
                        VoteStep.READY -> "Ready to vote"
                        VoteStep.VALIDATING_PREREQUISITES -> "Validating credentials..."
                        VoteStep.GENERATING_TRANSACTION -> "Generating signed transaction..."
                        VoteStep.SUBMITTING_VOTE -> "Submitting vote..."
                        VoteStep.COMPLETED -> "Vote submitted successfully!"
                        VoteStep.ERROR -> "Error occurred"
                    },
                    style = AppTypography.paragraphRegular,
                    color = when (currentStep) {
                        VoteStep.COMPLETED -> SuccessColors.Success70
                        VoteStep.ERROR -> DangerColors.Danger70
                        else -> PrimaryColors.Primary70
                    }
                )
            }
        }
    }
}

@Composable
private fun SecurityInfoCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFFF0F8FF)) // Light blue
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    painter = painterResource(id = R.drawable.ic_launcher_foreground), // Replace with security icon
                    contentDescription = "Security",
                    tint = PrimaryColors.Primary60,
                    modifier = Modifier.size(20.dp)
                )
                Text(
                    text = "Secured with Blockchain",
                    style = AppTypography.paragraphSemiBold,
                    color = PrimaryColors.Primary70
                )
            }

            Text(
                text = "Your vote will be secured using your personal cryptographic keys and recorded on the blockchain. This ensures complete transparency and immutability.",
                style = AppTypography.paragraphRegular,
                color = PrimaryColors.Primary60
            )
        }
    }
}

@Composable
private fun ErrorCard(
    error: String,
    onRetry: () -> Unit,
    onDismiss: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = DangerColors.Danger50)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    painter = painterResource(id = R.drawable.ic_launcher_foreground), // Replace with error icon
                    contentDescription = "Error",
                    tint = DangerColors.Danger60,
                    modifier = Modifier.size(20.dp)
                )
                Text(
                    text = "Error",
                    style = AppTypography.paragraphSemiBold,
                    color = DangerColors.Danger70
                )
            }

            Text(
                text = error,
                style = AppTypography.paragraphRegular,
                color = DangerColors.Danger70
            )

            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = onRetry,
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = DangerColors.Danger60
                    )
                ) {
                    Text("Retry")
                }

                TextButton(onClick = onDismiss) {
                    Text(
                        text = "Dismiss",
                        color = DangerColors.Danger60
                    )
                }
            }
        }
    }
}

@Composable
private fun SuccessCard(
    transactionHash: String?,
    voteId: String?,
    votedAt: String?
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = SuccessColors.Success50)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(
                    painter = painterResource(id = R.drawable.ic_launcher_foreground), // Replace with success icon
                    contentDescription = "Success",
                    tint = SuccessColors.Success60,
                    modifier = Modifier.size(20.dp)
                )
                Text(
                    text = "Vote Submitted Successfully!",
                    style = AppTypography.paragraphSemiBold,
                    color = SuccessColors.Success70
                )
            }

            transactionHash?.let {
                Text(
                    text = "Transaction Hash: ${it.take(16)}...",
                    style = AppTypography.paragraphRegular,
                    color = SuccessColors.Success60
                )
            }

            voteId?.let {
                Text(
                    text = "Vote ID: $it",
                    style = AppTypography.paragraphRegular,
                    color = SuccessColors.Success60
                )
            }

            votedAt?.let {
                Text(
                    text = "Voted at: $it",
                    style = AppTypography.paragraphRegular,
                    color = SuccessColors.Success60
                )
            }
        }
    }
}

@Composable
private fun ElectionPairConfirmationCard(electionPairId: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Icon(
                painter = painterResource(id = R.drawable.ic_launcher_foreground), // Replace with vote icon
                contentDescription = "Vote",
                tint = PrimaryColors.Primary50,
                modifier = Modifier.size(48.dp)
            )

            Text(
                text = "You are about to vote for:",
                style = AppTypography.heading6Medium,
                color = PrimaryColors.Primary70,
                textAlign = TextAlign.Center
            )

            Text(
                text = "Election Pair #$electionPairId",
                style = AppTypography.paragraphSemiBold,
                color = PrimaryColors.Primary80,
                textAlign = TextAlign.Center
            )

            Text(
                text = "Once submitted, your vote cannot be changed. Please make sure this is your final choice.",
                style = AppTypography.paragraphRegular,
                color = NeutralColors.Neutral60,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
private fun VoteActionButtons(
    uiState: EnhancedVoteConfirmationUiState,
    onConfirm: () -> Unit,
    onCancel: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Confirm Vote Button
        Button(
            onClick = onConfirm,
            modifier = Modifier.fillMaxWidth(),
            enabled = !uiState.isLoading && !uiState.isVoteSuccess,
            colors = ButtonDefaults.buttonColors(
                containerColor = MainColors.Primary1,
                disabledContainerColor = MainColors.Primary1.copy(alpha = 0.5f)
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            if (uiState.isLoading) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        color = Color.White,
                        strokeWidth = 2.dp
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = when (uiState.step) {
                            VoteStep.VALIDATING_PREREQUISITES -> "Validating..."
                            VoteStep.GENERATING_TRANSACTION -> "Signing..."
                            VoteStep.SUBMITTING_VOTE -> "Submitting..."
                            else -> "Processing..."
                        },
                        style = AppTypography.paragraphSemiBold,
                        color = Color.White
                    )
                }
            } else {
                Text(
                    text = if (uiState.isVoteSuccess) "Vote Submitted" else "Confirm Vote",
                    style = AppTypography.paragraphSemiBold,
                    modifier = Modifier.padding(vertical = 8.dp),
                    color = Color.White
                )
            }
        }

        // Cancel Button
        if (!uiState.isVoteSuccess) {
            OutlinedButton(
                onClick = onCancel,
                modifier = Modifier.fillMaxWidth(),
                enabled = !uiState.isLoading,
                shape = RoundedCornerShape(12.dp)
            ) {
                Text(
                    text = "Cancel",
                    style = AppTypography.paragraphSemiBold,
                    modifier = Modifier.padding(vertical = 8.dp),
                    color = MainColors.Primary1
                )
            }
        }
    }
}