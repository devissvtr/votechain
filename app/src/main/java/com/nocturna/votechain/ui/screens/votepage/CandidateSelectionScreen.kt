package com.nocturna.votechain.ui.screens.votepage

import android.content.Context
import android.util.Log
import androidx.compose.runtime.collectAsState
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import coil.compose.AsyncImage
import coil.compose.SubcomposeAsyncImage
import coil.request.ImageRequest
import com.nocturna.votechain.R
import com.nocturna.votechain.data.model.ElectionPair
import com.nocturna.votechain.data.network.ElectionNetworkClient
import com.nocturna.votechain.data.network.PartyPhotoHelper
import com.nocturna.votechain.ui.screens.LoadingScreen
import com.nocturna.votechain.ui.theme.AppTypography
import com.nocturna.votechain.ui.theme.MainColors
import com.nocturna.votechain.ui.theme.NeutralColors
import com.nocturna.votechain.ui.theme.PrimaryColors
import com.nocturna.votechain.ui.theme.WarningColors
import com.nocturna.votechain.utils.CandidatePhotoHelper
import com.nocturna.votechain.utils.CoilAuthHelper
import com.nocturna.votechain.utils.LanguageManager
import com.nocturna.votechain.utils.VoteErrorHandler
import androidx.compose.runtime.collectAsState
import com.nocturna.votechain.data.repository.VoterRepository
import com.nocturna.votechain.viewmodel.candidate.ElectionViewModel
import com.nocturna.votechain.viewmodel.vote.VotingViewModel
import com.nocturna.votechain.viewmodel.vote.VotingViewModel.VoteState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CandidateSelectionScreen(
    navController: NavController,
    categoryId: String,
    votingViewModel: VotingViewModel,
    electionViewModel: ElectionViewModel = viewModel(factory = ElectionViewModel.Factory)
) {
    val strings = LanguageManager.getLocalizedStrings()
    val context = LocalContext.current
    val scrollState = rememberScrollState()

    // States for UI
    var selectedCandidateId by remember { mutableStateOf<String?>(null) }
    var selectedElectionPair by remember { mutableStateOf<ElectionPair?>(null) }
    var showConfirmationDialog by remember { mutableStateOf(false) }
    var isSubmittingVote by remember { mutableStateOf(false) }

    // Observe election pairs
    val electionPairs by electionViewModel.electionPairs.collectAsState()
    val isLoading by electionViewModel.isLoading.collectAsState()
    val error by electionViewModel.error.collectAsState()

    // Observe vote results
    val voteResult by votingViewModel.voteResult.collectAsState()
    val votingError by votingViewModel.error.collectAsState()
    val hasVoted by votingViewModel.hasVoted.collectAsState()

    LaunchedEffect(Unit) {
        Log.d("CandidateSelectionScreen", "Initializing screen with categoryId: $categoryId")

        // Ensure ElectionNetworkClient is properly initialized with the context
        val isNetworkClientReady = ElectionNetworkClient.ensureInitialized(context)
        Log.d("CandidateSelectionScreen", "ElectionNetworkClient initialization status: $isNetworkClientReady")

        if (!isNetworkClientReady) {
            Log.e("CandidateSelectionScreen", "Failed to initialize ElectionNetworkClient")
            return@LaunchedEffect
        }

        // Check if user has valid token
        val userToken = ElectionNetworkClient.getUserToken()
        Log.d("CandidateSelectionScreen", "User token status: ${if (userToken.isNotEmpty()) "Available" else "Missing"}")

        if (userToken.isEmpty()) {
            Log.e("CandidateSelectionScreen", "No authentication token found - redirecting to login")
            navController.navigate("login") {
                popUpTo(0) { inclusive = true }
            }
            return@LaunchedEffect
        }

        // Fetch election pairs after ensuring network client is ready
        Log.d("CandidateSelectionScreen", "Network client ready - fetching election pairs")
        electionViewModel.fetchElectionPairs()
    }

    // Handle successful vote submission
    LaunchedEffect(hasVoted) {
        if (hasVoted && isSubmittingVote) {
            isSubmittingVote = false
            Log.d("CandidateSelectionScreen", "Vote submitted successfully - navigating to vote success")
            // Navigate to vote success screen
            navController.navigate("vote_success") {
                popUpTo("candidate_selection/$categoryId") { inclusive = true }
            }
        }
    }

    // Handle vote submission errors
    LaunchedEffect(votingError) {
        if (votingError != null && isSubmittingVote) {
            isSubmittingVote = false
            Log.e("CandidateSelectionScreen", "Vote submission error: $votingError")
            // Handle error (show snackbar, etc.)
        }
    }

    suspend fun getUserRegion(): String {
        return try {
            Log.d("CandidateSelectionScreen", "🌍 Retrieving user region from VoterData...")

            // Step 1: Try to get region from VoterData (most reliable)
            val voterRepository = VoterRepository(context)
            val voterData = voterRepository.getVoterData()

            if (voterData != null && voterData.region.isNotBlank()) {
                Log.d("CandidateSelectionScreen", "✅ Region found in VoterData: ${voterData.region}")
                return voterData.region
            }

            // Step 2: If VoterData region is empty, try to fetch from API
            Log.w("CandidateSelectionScreen", "⚠️ VoterData region empty, fetching from API...")

            val token = ElectionNetworkClient.getUserToken()
            if (token.isNotEmpty()) {
                voterRepository.fetchVoterData(token).fold(
                    onSuccess = { fetchedVoterData ->
                        if (fetchedVoterData.region.isNotBlank()) {
                            Log.d("CandidateSelectionScreen", "✅ Region fetched from API: ${fetchedVoterData.region}")
                            return fetchedVoterData.region
                        }
                    },
                    onFailure = { error ->
                        Log.e("CandidateSelectionScreen", "❌ Failed to fetch voter data from API: ${error.message}")
                    }
                )
            }

            // Step 3: Fallback to SharedPreferences (legacy)
            Log.w("CandidateSelectionScreen", "⚠️ Using SharedPreferences fallback for region")
            val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
            val fallbackRegion = sharedPreferences.getString("user_region", null)
                ?: sharedPreferences.getString("region", null)
                ?: "default"

            Log.d("CandidateSelectionScreen", "📱 Fallback region from SharedPreferences: $fallbackRegion")
            fallbackRegion

        } catch (e: Exception) {
            Log.e("CandidateSelectionScreen", "❌ Exception getting user region: ${e.message}", e)

            // Ultimate fallback
            val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
            val ultimateFallback = sharedPreferences.getString("region", "default") ?: "default"

            Log.d("CandidateSelectionScreen", "🆘 Ultimate fallback region: $ultimateFallback")
            ultimateFallback
        }
    }

    fun getOTPToken(): String {
        val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
        val token = sharedPreferences.getString("otp_token", null) ?: ""
        val createdTime = sharedPreferences.getLong("otp_token_created", 0)

        Log.d("CandidateSelectionScreen", "Retrieving OTP token:")
        Log.d("CandidateSelectionScreen", "  - Token found: ${if (token.isNotEmpty()) "Yes (${token.length} chars)" else "No"}")

        if (token.isNotEmpty() && createdTime > 0) {
            val tokenAge = System.currentTimeMillis() - createdTime
            val maxAge = 5 * 60 * 1000L // 5 minutes

            Log.d("CandidateSelectionScreen", "  - Token age: ${tokenAge / 1000}s")
            Log.d("CandidateSelectionScreen", "  - Max age: ${maxAge / 1000}s")

            if (tokenAge > maxAge) {
                Log.w("CandidateSelectionScreen", "⚠️ OTP token is too old, clearing it")
                // Clear the expired token
                with(sharedPreferences.edit()) {
                    remove("otp_token")
                    remove("otp_token_created")
                    remove("otp_token_expiry")
                    apply()
                }
                return ""
            }
        }

        Log.d("CandidateSelectionScreen", "  - Returning token: ${if (token.isNotEmpty()) "Valid" else "Empty"}")
        return token
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = strings.candidateSelection,
                        style = AppTypography.heading4SemiBold,
                        color = NeutralColors.Neutral90
                    )
                },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(
                            painter = painterResource(id = R.drawable.back),
                            contentDescription = "Back",
                            tint = NeutralColors.Neutral90
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.White
                )
            )
        }
    ) { paddingValues ->
        when {
            isLoading -> {
                LoadingScreen()
            }
            error != null -> {
                // Error state
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(paddingValues)
                        .padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = error ?: "Unknown error occurred",
                        style = AppTypography.heading5Regular,
                        color = NeutralColors.Neutral70,
                        textAlign = TextAlign.Center
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    Button(
                        onClick = {
                            CoilAuthHelper.reset()
                            electionViewModel.fetchElectionPairs()
                        },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MainColors.Primary1
                        )
                    ) {
                        Text("Try Again")
                    }
                }
            }
            else -> {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(paddingValues)
                        .padding(horizontal = 16.dp)
                        .verticalScroll(scrollState)
                ) {
                    Spacer(modifier = Modifier.height(16.dp))

                    // Candidate cards
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        electionPairs.forEach { pair ->
                            CandidateCard(
                                electionPair = pair,
                                isSelected = selectedCandidateId == pair.id,
                                onSelect = {
                                    selectedCandidateId = pair.id
                                    selectedElectionPair = pair
                                }
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(24.dp))

                    // Vote Button - Show confirmation dialog first
                    Button(
                        onClick = {
                            selectedCandidateId?.let {
                                showConfirmationDialog = true
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(56.dp),
                        enabled = selectedCandidateId != null && !isSubmittingVote,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MainColors.Primary1,
                            disabledContainerColor = NeutralColors.Neutral30
                        ),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        if (isSubmittingVote) {
                            Row(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(20.dp),
                                    color = Color.White,
                                    strokeWidth = 2.dp
                                )
                                Text(
                                    text = "Mengirim...",
                                    style = AppTypography.heading5SemiBold,
                                    color = Color.White
                                )
                            }
                        } else {
                            Text(
                                text = strings.vote,
                                style = AppTypography.heading5SemiBold,
                                color = Color.White
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(24.dp))
                }
            }
        }
    }

    // Confirmation Dialog
    if (showConfirmationDialog) {
        var userRegion by remember { mutableStateOf("default") }

        LaunchedEffect(showConfirmationDialog) {
            if (showConfirmationDialog) {
                userRegion = getUserRegion()
                Log.d("CandidateSelectionScreen", "🌍 Dialog region loaded: $userRegion")
            }
        }

        VoteConfirmationDialog(
            onConfirm = {
                showConfirmationDialog = false
                selectedCandidateId?.let { electionPairId ->
                    val otpToken = getOTPToken()

                    Log.d("CandidateSelectionScreen", "Submitting vote:")
                    Log.d("CandidateSelectionScreen", "  - Election Pair ID: $electionPairId")
                    Log.d("CandidateSelectionScreen", "  - Region: $userRegion")
                    Log.d("CandidateSelectionScreen", "  - OTP Token: ${if (otpToken.isNotEmpty()) "Present" else "Missing"}")

                    // FIXED: Use proper parameters for vote submission
                    votingViewModel.castVote(
                        electionPairId = electionPairId,
                        region = userRegion,
                        otpToken = otpToken
                    )
                }
            },
            onDismiss = {
                showConfirmationDialog = false
            },
            candidateName = selectedElectionPair?.let { pair ->
                "${pair.president.full_name} & ${pair.vice_president.full_name}"
            } ?: ""
        )
    }
}

@Composable
private fun VoteConfirmationDialog(
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
    candidateName: String
) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(
            dismissOnBackPress = true,
            dismissOnClickOutside = true
        )
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = Color.White
            ),
            elevation = CardDefaults.cardElevation(
                defaultElevation = 8.dp
            )
        ) {
            Column(
                modifier = Modifier.padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // Warning Icon
                Icon(
                    painter = painterResource(id = R.drawable.dangercircle), // Anda perlu menambahkan icon ini
                    contentDescription = "Warning",
                    tint = WarningColors.Warning50,
                    modifier = Modifier.size(48.dp)
                )

                Spacer(modifier = Modifier.height(16.dp))

                // Title
                Text(
                    text = "Konfirmasi Pilihan",
                    style = AppTypography.heading4SemiBold,
                    color = NeutralColors.Neutral90,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(12.dp))

                // Main message
                Text(
                    text = "Are you sure about your choice? Once submitted, your vote cannot be changed.",
                    style = AppTypography.paragraphRegular,
                    color = NeutralColors.Neutral70,
                    textAlign = TextAlign.Center,
                    lineHeight = 20.sp
                )

                Spacer(modifier = Modifier.height(8.dp))

                // Selected candidate info
                if (candidateName.isNotEmpty()) {
                    Text(
                        text = "Anda memilih: $candidateName",
                        style = AppTypography.paragraphSemiBold,
                        color = MainColors.Primary1,
                        textAlign = TextAlign.Center
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                // Buttons
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    // No Button
                    OutlinedButton(
                        onClick = onDismiss,
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = MainColors.Primary1
                        ),
                        border = androidx.compose.foundation.BorderStroke(
                            1.dp,
                            MainColors.Primary1
                        ),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text(
                            text = "No",
                            style = AppTypography.heading6SemiBold,
                            color = MainColors.Primary1
                        )
                    }

                    // Yes Button
                    Button(
                        onClick = onConfirm,
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MainColors.Primary1
                        ),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Text(
                            text = "Yes",
                            style = AppTypography.heading6SemiBold,
                            color = Color.White
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun CandidateCard(
    electionPair: ElectionPair,
    isSelected: Boolean,
    onSelect: () -> Unit
) {
    val isUsingFallbackData = electionPair.id.startsWith("fallback-")
    val context = LocalContext.current
    val strings = LanguageManager.getLocalizedStrings()

    // Get the authenticated image loader
    val imageLoader = remember { CoilAuthHelper.getImageLoader(context) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onSelect() }
            .then(
                if (isSelected) {
                    Modifier.border(
                        width = 2.dp,
                        color = MainColors.Primary1,
                        shape = RoundedCornerShape(12.dp)
                    )
                } else {
                    Modifier.border(
                        width = 1.dp,
                        color = NeutralColors.Neutral30,
                        shape = RoundedCornerShape(12.dp)
                    )
                }
            ),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isSelected) MainColors.Primary1.copy(alpha = 0.05f) else Color.White
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = if (isSelected) 8.dp else 2.dp
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            // Candidate number
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(32.dp)
                        .background(
                            color = if (isSelected) MainColors.Primary1 else NeutralColors.Neutral20,
                            shape = RoundedCornerShape(8.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = electionPair.election_no.toString(),
                        style = AppTypography.heading6Bold,
                        color = if (isSelected) Color.White else NeutralColors.Neutral70
                    )
                }

                Spacer(modifier = Modifier.width(12.dp))

                Text(
                    text = "Pasangan Calon ${electionPair.election_no}",
                    style = AppTypography.heading6Medium,
                    color = NeutralColors.Neutral90
                )

                Spacer(modifier = Modifier.weight(1f))

                if (isSelected) {
                    Icon(
                        painter = painterResource(id = R.drawable.lock),
                        contentDescription = "Selected",
                        tint = MainColors.Primary1,
                        modifier = Modifier.size(24.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Candidates info
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Column(
                    modifier = Modifier.weight(1f),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    if (isUsingFallbackData) {
                        // Use local drawable for fallback data
                        Image(
                            painter = painterResource(id = R.drawable.ic_launcher_background),
                            contentDescription = "Candidate Pair Photo",
                            modifier = Modifier.fillMaxSize(),
                            contentScale = ContentScale.Fit
                        )
                    } else {
                        // For API data, use the /v1/election/pairs/{id}/photo endpoint
                        val pairPhotoUrl = CandidatePhotoHelper.getPairPhotoUrl(electionPair.id)

                        SubcomposeAsyncImage(
                            model = ImageRequest.Builder(context)
                                .data(pairPhotoUrl)
                                .crossfade(true)
                                .build(),
                            contentDescription = "Candidate Pair Photo",
                            imageLoader = imageLoader,
                            modifier = Modifier.fillMaxSize(),
                            contentScale = ContentScale.Crop,
                            loading = {
                                Box(
                                    modifier = Modifier.fillMaxSize(),
                                    contentAlignment = Alignment.Center
                                ) {
                                    CircularProgressIndicator(
                                        color = MainColors.Primary1,
                                        modifier = Modifier.size(40.dp)
                                    )
                                }
                            },
                            error = {
                                // On error, show fallback image
                                Image(
                                    painter = painterResource(id = R.drawable.ic_launcher_background),
                                    contentDescription = "Candidate Pair Photo (Fallback)",
                                    modifier = Modifier.fillMaxSize(),
                                    contentScale = ContentScale.Fit
                                )
                            }
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                // Combined candidate names
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceEvenly
                ) {
                    // President name
                    Column(
                        modifier = Modifier.weight(1f),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = strings.presidentialCandidate,
                            style = AppTypography.paragraphRegular,
                            color = NeutralColors.Neutral50
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        Text(
                            text = electionPair.president.full_name,
                            style = AppTypography.heading6SemiBold.copy(lineHeight = 22.sp),
                            color = PrimaryColors.Primary70,
                            textAlign = TextAlign.Center,
                            maxLines = 2
                        )
                    }

                    // Vice President name
                    Column(
                        modifier = Modifier.weight(1f),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = strings.vicePresidentialCandidate,
                            style = AppTypography.paragraphRegular,
                            color = NeutralColors.Neutral50
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        Text(
                            text = electionPair.vice_president.full_name,
                            style = AppTypography.heading6SemiBold.copy(lineHeight = 22.sp),
                            color = PrimaryColors.Primary70,
                            textAlign = TextAlign.Center,
                            maxLines = 2
                        )
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Supporting parties section
                if (!electionPair.supporting_parties.isNullOrEmpty()) {
                    Text(
                        text = strings.proposingParties,
                        style = AppTypography.paragraphRegular,
                        color = NeutralColors.Neutral50,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )

                    // Party logos in a horizontal scrollable row
                    LazyRow(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        contentPadding = PaddingValues(horizontal = 16.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .wrapContentWidth(Alignment.CenterHorizontally)
                    ) {
                        items(
                            items = electionPair.supporting_parties,
                            key = { it.id }
                        ) { supportingParty ->
                            val partyPhotoUrl =
                                PartyPhotoHelper.getPartyPhotoUrl(supportingParty.party.id)

                            Box(
                                modifier = Modifier
                                    .size(32.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                AsyncImage(
                                    model = ImageRequest.Builder(context)
                                        .data(partyPhotoUrl)
                                        .crossfade(true)
                                        .build(),
                                    contentDescription = "${supportingParty.party.name} Logo",
                                    imageLoader = imageLoader,
                                    modifier = Modifier
                                        .fillMaxSize(),
                                    contentScale = ContentScale.Fit,
                                    error = painterResource(id = R.drawable.ic_launcher_foreground),
                                    placeholder = painterResource(id = R.drawable.ic_launcher_foreground)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}