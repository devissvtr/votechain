package com.nocturna.votechain.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.nocturna.votechain.R
import com.nocturna.votechain.ui.theme.AppTypography
import com.nocturna.votechain.ui.theme.MainColors
import com.nocturna.votechain.ui.theme.NeutralColors
import com.nocturna.votechain.ui.theme.PrimaryColors
import com.nocturna.votechain.viewmodel.vote.OTPVerificationViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@Composable
fun OTPVerificationScreen(
    navController: NavController,
    categoryId: String,
    onBackClick: () -> Unit = { navController.popBackStack() },
    onVerificationComplete: () -> Unit = { navController.navigate("home") { popUpTo("login") { inclusive = true } } }
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    // Create ViewModel with proper factory
    val viewModel: OTPVerificationViewModel = viewModel(
        factory = OTPVerificationViewModel.Factory(context, categoryId)
    )

    val uiState by viewModel.uiState.collectAsState()

    // OTP input state
    var otpDigits by remember { mutableStateOf(listOf("", "", "", "")) }
    val focusRequesters = remember { List(4) { FocusRequester() } }
    val isOtpComplete = otpDigits.all { it.isNotEmpty() }

    // Timer state
    var remainingSeconds by remember { mutableStateOf(300) }
    var isTimerRunning by remember { mutableStateOf(true) }

    // Update timer from ViewModel state
    LaunchedEffect(uiState.timeRemainingSeconds) {
        remainingSeconds = uiState.timeRemainingSeconds
        isTimerRunning = true
    }

    // Timer effect
    LaunchedEffect(isTimerRunning) {
        if (isTimerRunning) {
            while (remainingSeconds > 0) {
                delay(1000L)
                remainingSeconds--
                viewModel.updateTimer(remainingSeconds)
            }
            isTimerRunning = false
        }
    }

    // Handle verification success
    LaunchedEffect(uiState.isVerificationSuccess) {
        if (uiState.isVerificationSuccess) {
            delay(1500)
            onVerificationComplete()
        }
    }

    // Format timer display
    val formattedTime = String.format("%02d:%02d", remainingSeconds / 60, remainingSeconds % 60)

    // Main screen content
    Column(modifier = Modifier.fillMaxSize()) {
        // Custom top bar with shadow
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 24.dp)
        ) {
            Box(
                modifier = Modifier
                    .align(Alignment.CenterStart)
                    .padding(start = 24.dp)
                    .size(24.dp),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    painter = painterResource(id = R.drawable.back),
                    contentDescription = "Back",
                    tint = MainColors.Primary1,
                    modifier = Modifier
                        .size(20.dp)
                        .align(Alignment.CenterStart)
                        .clickable(onClick = onBackClick)
                )
            }

            // Centered title
            Text(
                text = "OTP Verification",
                style = AppTypography.heading4Regular,
                color = PrimaryColors.Primary80,
                modifier = Modifier.align(Alignment.Center)
            )
        }

        // Center content with vertical spacing
        Spacer(modifier = Modifier.weight(0.3f))

        // OTP Verification title
        Text(
            text = "OTP Verification",
            style = AppTypography.heading2Bold,
            color = MainColors.Primary1,
            modifier = Modifier.padding(bottom = 12.dp).align(Alignment.CenterHorizontally)
        )

        // Instructions
        Text(
//            text = "Enter the OTP sent to your registered phone number${uiState.voterData?.telephone?.let { " (${it.takeLast(4).padStart(4, '*')})" } ?: ""} to verify your identity before voting",
            text = "Enter the OTP sent to your registered phone number to verify your identity before voting",
            style = AppTypography.heading5Regular,
            color = NeutralColors.Neutral70,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 24.dp)
        )

        // Countdown timer
        Text(
            text = formattedTime,
            style = AppTypography.heading6SemiBold,
            color = MainColors.Primary1,
            modifier = Modifier.padding(vertical = 24.dp).align(Alignment.CenterHorizontally)
        )

        // Remaining attempts display
        if (uiState.remainingAttempts > 0) {
            Text(
                text = "Remaining attempts: ${uiState.remainingAttempts}",
                style = AppTypography.heading6Regular,
                color = NeutralColors.Neutral60,
                modifier = Modifier
                    .padding(bottom = 16.dp)
                    .align(Alignment.CenterHorizontally)
            )
        }

        // Error message display
        uiState.error?.let { error ->
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp, vertical = 8.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFFFFF3F3)),
                shape = RoundedCornerShape(8.dp)
            ) {
                Text(
                    text = error,
                    style = AppTypography.heading6Regular,
                    color = Color(0xFFD32F2F),
                    modifier = Modifier.padding(12.dp),
                    textAlign = TextAlign.Center
                )
            }
        }

        // OTP Input Fields
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 32.dp),
            horizontalArrangement = Arrangement.Center
        ) {
            for (i in 0 until 4) {
                val isFocused = remember { mutableStateOf(false) }

                Box(
                    modifier = Modifier
                        .width(50.dp)
                        .padding(horizontal = 4.dp),
                    contentAlignment = Alignment.Center
                ) {
                    BasicTextField(
                        value = otpDigits[i],
                        onValueChange = { newValue ->
                            if (newValue.isEmpty() || (newValue.length == 1 && newValue.all { it.isDigit() })) {
                                val newDigits = otpDigits.toMutableList().apply {
                                    set(i, newValue)
                                }
                                otpDigits = newDigits

                                // Auto-move to next field if digit entered
                                if (newValue.isNotEmpty() && i < 3) {
                                    focusRequesters[i + 1].requestFocus()
                                }

                                if (newValue.isNotEmpty() && uiState.error != null) {
                                    viewModel.clearError()
                                }
                            }
                        },
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Number
                        ),
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .focusRequester(focusRequesters[i])
                            .onFocusChanged { isFocused.value = it.isFocused },
                        textStyle = AppTypography.heading5Regular.copy(
                            color = PrimaryColors.Primary70,
                            textAlign = TextAlign.Center
                        ),
                        decorationBox = { innerTextField ->
                            Column(
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                // Text field
                                Box(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(40.dp),
                                    contentAlignment = Alignment.Center
                                ) {
                                    innerTextField()
                                }

                                // Underline
                                Divider(
                                    color = if (isFocused.value) MainColors.Primary1 else NeutralColors.Neutral30,
                                    thickness = 1.dp,
                                    modifier = Modifier.fillMaxWidth()
                                )
                            }
                        }
                    )
                }
            }
        }

        // Resend OTP text and button
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 32.dp),
            horizontalArrangement = Arrangement.Center, // Center the row contents
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Didn't you receive the OTP? ",
                style = AppTypography.heading5Medium,
                color = NeutralColors.Neutral70
            )
            Text(
                text = "Resend OTP",
                style = AppTypography.heading5Medium,
                color = if (remainingSeconds > 0) NeutralColors.Neutral40 else MainColors.Primary1,
                modifier = Modifier.clickable(enabled = remainingSeconds == 0 && !uiState.isResending) {
                    if (remainingSeconds == 0) {
                        viewModel.resendOTP()
                        remainingSeconds = 300
                        isTimerRunning = true
                    }
                }
            )
        }

        // Verify Button
        Button(
            onClick = { onVerificationComplete() },
            modifier = Modifier
                .fillMaxWidth()
                .height(46.dp)
                .padding(horizontal = 24.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = MainColors.Primary1,
                contentColor = NeutralColors.Neutral10,
                disabledContainerColor = NeutralColors.Neutral30,
                disabledContentColor = NeutralColors.Neutral50
            ),
            shape = RoundedCornerShape(22.dp),
            enabled = isOtpComplete && !uiState.isVerifying && !uiState.isVerificationSuccess
        )
        {
            Text("Verify", style = AppTypography.heading4SemiBold, color = NeutralColors.Neutral10)
        }

        Spacer(modifier = Modifier.weight(0.5f))
    }

    // Request focus to first digit field when screen loads
    LaunchedEffect(Unit) {
        focusRequesters[0].requestFocus()
    }
}