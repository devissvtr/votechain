package com.nocturna.votechain.ui.screens.auth

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import com.nocturna.votechain.R
import com.nocturna.votechain.ui.theme.AppTypography
import com.nocturna.votechain.ui.theme.MainColors
import com.nocturna.votechain.ui.theme.NeutralColors
import com.nocturna.votechain.ui.theme.PrimaryColors
import com.nocturna.votechain.utils.LanguageManager

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun EmailVerificationScreen(
    navController: NavController,
    onBackClick: () -> Unit,
    onSubmitEmail: (String) -> Unit
) {
    val strings = LanguageManager.getLocalizedStrings()
    var email by remember { mutableStateOf("") }
    var isEmailValid by remember { mutableStateOf(true) }
    var isProcessing by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    val emailFocusRequester = remember { FocusRequester() }
    val focusManager = LocalFocusManager.current
    val keyboardController = LocalSoftwareKeyboardController.current

    val validateEmail: (String) -> Boolean = { input ->
        input.isEmpty() || android.util.Patterns.EMAIL_ADDRESS.matcher(input).matches()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(NeutralColors.Neutral10)
            .padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Custom top bar
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 24.dp)
        ) {
            Box(
                modifier = Modifier
                    .align(Alignment.CenterStart)
                    .padding(start = 4.dp)
                    .size(24.dp),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    painter = painterResource(id = R.drawable.back),
                    contentDescription = "Back",
                    tint = MainColors.Primary1,
                    modifier = Modifier
                        .size(20.dp)
                        .clickable(onClick = onBackClick)
                )
            }

            // Centered title
            Text(
                text = "Forgot Password",
                style = AppTypography.heading4Regular,
                color = PrimaryColors.Primary80,
                modifier = Modifier.align(Alignment.Center)
            )
        }

        Spacer(modifier = Modifier.weight(0.15f))

        // Header section
        Text(
            text = "Email Verification",
            style = AppTypography.heading2Bold,
            color = MainColors.Primary1,
            modifier = Modifier.padding(bottom = 12.dp)
        )

        Text(
            text = "Enter your email address to receive an OTP verification code",
            style = AppTypography.heading5Regular,
            color = NeutralColors.Neutral70,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp)
        )

        Spacer(modifier = Modifier.height(32.dp))

        // Display error message if any
        AnimatedVisibility(
            visible = errorMessage != null
        ) {
            errorMessage?.let {
                Text(
                    text = it,
                    style = AppTypography.paragraphRegular,
                    color = MaterialTheme.colorScheme.error,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 8.dp)
                )
            }
        }

        // Email field
        OutlinedTextField(
            value = email,
            onValueChange = {
                email = it
                isEmailValid = validateEmail(it)
                errorMessage = null // Clear error when user types
            },
            label = { Text("Email") },
            singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .focusRequester(emailFocusRequester),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = MainColors.Primary1,
                unfocusedBorderColor = NeutralColors.Neutral30,
                focusedTextColor = NeutralColors.Neutral70,
                unfocusedTextColor = NeutralColors.Neutral70,
                errorBorderColor = MaterialTheme.colorScheme.error,
                errorLabelColor = MaterialTheme.colorScheme.error
            ),
            keyboardOptions = KeyboardOptions(
                keyboardType = KeyboardType.Email,
                imeAction = ImeAction.Done
            ),
            keyboardActions = KeyboardActions(
                onDone = {
                    focusManager.clearFocus()
                    keyboardController?.hide()
                }
            ),
            isError = !isEmailValid,
            supportingText = {
                if (!isEmailValid) {
                    Text(
                        text = "Please enter a valid email address",
                        color = MaterialTheme.colorScheme.error,
                        style = AppTypography.paragraphRegular
                    )
                }
            }
        )

        Spacer(modifier = Modifier.height(32.dp))

        // Send OTP Button
        Button(
            onClick = {
                if (validateEmail(email) && email.isNotEmpty()) {
                    isProcessing = true
                    focusManager.clearFocus()
                    keyboardController?.hide()
                    onSubmitEmail(email)
                } else {
                    isEmailValid = validateEmail(email) && email.isNotEmpty()
                    if (email.isEmpty()) {
                        errorMessage = "Please enter your email address"
                    }
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = MainColors.Primary1,
                disabledContainerColor = MainColors.Primary1.copy(alpha = 0.6f)
            ),
            shape = RoundedCornerShape(12.dp),
            enabled = !isProcessing
        ) {
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (isProcessing) {
                    CircularProgressIndicator(
                        color = NeutralColors.Neutral10,
                        strokeWidth = 2.dp,
                        modifier = Modifier.size(24.dp)
                    )
                } else {
                    Text(
                        "Send OTP",
                        style = AppTypography.heading4SemiBold,
                        color = NeutralColors.Neutral10
                    )
                }
            }
        }

        Spacer(modifier = Modifier.weight(0.5f))
    }

    // Request focus when screen is first shown
    LaunchedEffect(Unit) {
        emailFocusRequester.requestFocus()
    }
}
