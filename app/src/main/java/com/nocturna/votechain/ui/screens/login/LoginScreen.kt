package com.nocturna.votechain.ui.screens.login

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.nocturna.votechain.R
import com.nocturna.votechain.ui.theme.AppTypography
import com.nocturna.votechain.ui.theme.MainColors
import com.nocturna.votechain.ui.theme.NeutralColors
import com.nocturna.votechain.utils.LanguageManager
import com.nocturna.votechain.viewmodel.login.LoginViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun LoginScreen(
    onRegisterClick: () -> Unit,
    onLoginClick: () -> Unit,
    onForgotPasswordClick: () -> Unit = {}
) {
    val strings = LanguageManager.getLocalizedStrings()

    val context = LocalContext.current
    val viewModel: LoginViewModel = viewModel(factory = LoginViewModel.Factory(context))
    val uiState by viewModel.uiState.collectAsState()

    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }
    var isEmailFocused by remember { mutableStateOf(false) }
    var isPasswordFocused by remember { mutableStateOf(false) }
    var isEmailValid by remember { mutableStateOf(true) }
    var isPasswordValid by remember { mutableStateOf(true) }
    var isLoading by remember { mutableStateOf(false) }
    var showElements by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    val emailError = "Please enter a valid email address"
    val passwordError = "Password must be at least 8 characters"

    val emailFocusRequester = remember { FocusRequester() }
    val passwordFocusRequester = remember { FocusRequester() }
    val focusManager = LocalFocusManager.current
    val keyboardController = LocalSoftwareKeyboardController.current
    val scope = rememberCoroutineScope()

    // Animation values
    val titleAlpha = animateFloatAsState(
        targetValue = if (showElements) 1f else 0f,
        animationSpec = tween(700)
    )
    val formAlpha = animateFloatAsState(
        targetValue = if (showElements) 1f else 0f,
        animationSpec = tween(1000)
    )
    val buttonScale = animateFloatAsState(
        targetValue = if (showElements) 1f else 0.8f,
        animationSpec = tween(800)
    )

    // Validator functions
    val validateEmail: (String) -> Boolean = { input ->
        input.isEmpty() || android.util.Patterns.EMAIL_ADDRESS.matcher(input).matches()
    }

    val validatePassword: (String) -> Boolean = { input ->
        input.isEmpty() || input.length >= 8
    }

    // Handle UI state changes
    LaunchedEffect(uiState) {
        when (uiState) {
            is LoginViewModel.LoginUiState.Success -> {
                // Navigate to home screen on successful login
                onLoginClick()
            }
            is LoginViewModel.LoginUiState.Error -> {
                val message = (uiState as LoginViewModel.LoginUiState.Error).message
                errorMessage = message
            }
            is LoginViewModel.LoginUiState.Success -> {
                // User is already logged in, navigate to home
                onLoginClick()
            }
            else -> {
                // Handle other states
                errorMessage = null
            }
        }
    }

    // Check if user is already logged in when screen is first shown
    LaunchedEffect(Unit) {
        viewModel.checkLoginState()
        delay(100)
        showElements = true
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(NeutralColors.Neutral10)
    ) {
        // Background gradient overlay (subtle)
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            NeutralColors.Neutral10,
                            NeutralColors.Neutral10.copy(alpha = 0.95f),
                            NeutralColors.Neutral10
                        )
                    )
                )
        )
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            // Show loading indicator when processing login
            if (uiState is LoginViewModel.LoginUiState.Loading) {
                CircularProgressIndicator(
                    color = MainColors.Primary1,
                    modifier = Modifier.size(48.dp)
                )
            } else {
                // Header section with animations
                Box(
                    modifier = Modifier
                        .alpha(titleAlpha.value)
                        .padding(bottom = 44.dp)
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(
                            text = strings.loginAccount,
                            style = AppTypography.heading1Bold,
                            color = MainColors.Primary1
                        )

                        Spacer(modifier = Modifier.height(12.dp))

                        Text(
                            text = strings.loginDescription,
                            style = AppTypography.heading4Medium,
                            color = NeutralColors.Neutral70,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                }

                // Form section with animations
                Box(modifier = Modifier.alpha(formAlpha.value)) {
                    Column {
                        // Email field with enhanced feedback
                        OutlinedTextField(
                            value = email,
                            onValueChange = {
                                email = it
                                isEmailValid = validateEmail(it)
                            },
                            label = { Text(strings.email) },
                            singleLine = true,
                            modifier = Modifier
                                .fillMaxWidth()
                                .focusRequester(emailFocusRequester)
                                .onFocusChanged { isEmailFocused = it.isFocused },
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = MainColors.Primary1,
                                unfocusedBorderColor = NeutralColors.Neutral20,
                                focusedTextColor = NeutralColors.Neutral70,
                                unfocusedTextColor = NeutralColors.Neutral70,
//                                focusedLabelColor = MainColors.Primary1,
                                unfocusedLabelColor = NeutralColors.Neutral30,
                                errorBorderColor = MaterialTheme.colorScheme.error,
                                errorLabelColor = MaterialTheme.colorScheme.error
                            ),
                            keyboardOptions = KeyboardOptions(
                                keyboardType = KeyboardType.Email,
                                imeAction = ImeAction.Next
                            ),
                            keyboardActions = KeyboardActions(
                                onNext = { passwordFocusRequester.requestFocus() }
                            ),
                            isError = !isEmailValid,
                            supportingText = {
                                if (!isEmailValid) {
                                    Text(
                                        text = emailError,
                                        color = MaterialTheme.colorScheme.error,
                                        style = AppTypography.paragraphRegular
                                    )
                                }
                            }
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        // Password field with enhanced feedback
                        OutlinedTextField(
                            value = password,
                            onValueChange = {
                                password = it
                                isPasswordValid = validatePassword(it)
                                errorMessage = null  // Clear error when user types
                            },
                            label = { Text(strings.password) },
                            singleLine = true,
                            modifier = Modifier
                                .fillMaxWidth()
                                .focusRequester(passwordFocusRequester)
                                .onFocusChanged { isPasswordFocused = it.isFocused },
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedBorderColor = MainColors.Primary1,
                                unfocusedBorderColor = NeutralColors.Neutral20,
                                focusedTextColor = NeutralColors.Neutral70,
                                unfocusedTextColor = NeutralColors.Neutral70,
//                                focusedLabelColor = MainColors.Primary1,
                                unfocusedLabelColor = NeutralColors.Neutral30,
                                errorBorderColor = MaterialTheme.colorScheme.error,
                                errorLabelColor = MaterialTheme.colorScheme.error
                            ),
                            visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(
                                keyboardType = KeyboardType.Password,
                                imeAction = ImeAction.Done
                            ),
                            keyboardActions = KeyboardActions(
                                onDone = {
                                    focusManager.clearFocus()
                                    keyboardController?.hide()
                                }
                            ),
                            isError = !isPasswordValid,
                            supportingText = {
                                if (!isPasswordValid) {
                                    Text(
                                        text = passwordError,
                                        color = MaterialTheme.colorScheme.error,
                                        style = AppTypography.paragraphRegular
                                    )
                                }
                            },
                            trailingIcon = {
                                IconButton(onClick = { passwordVisible = !passwordVisible }) {
                                    Icon(
                                        painter = painterResource(
                                            id = if (passwordVisible) R.drawable.show else R.drawable.hide
                                        ),
                                        contentDescription = if (passwordVisible) "Hide password" else "Show password",
                                        tint = NeutralColors.Neutral30
                                    )
                                }
                            }
                        )

                        // Forgot password link
                        Box(
                            modifier = Modifier.fillMaxWidth(),
                            contentAlignment = Alignment.CenterEnd
                        ) {
                            Text(
                                text = strings.forgotPassword,
                                style = AppTypography.heading6Medium,
                                color = MainColors.Primary1,
                                modifier = Modifier
                                    .padding(top = 4.dp)
                                    .clickable { onForgotPasswordClick() }
                            )
                        }

                        Spacer(modifier = Modifier.height(44.dp))

                        // Login button with loading state
                        Button(
                            onClick = {
                                if (validateEmail(email) && validatePassword(password) && email.isNotEmpty() && password.isNotEmpty()) {
                                    focusManager.clearFocus()
                                    keyboardController?.hide()
                                    viewModel.loginUser(email, password)
                                } else {
                                    isEmailValid = validateEmail(email) && email.isNotEmpty()
                                    isPasswordValid = validatePassword(password) && password.isNotEmpty()

                                    if (email.isEmpty() || password.isEmpty()) {
                                        errorMessage = "Please enter both email and password"
                                    }
                                }
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(56.dp)
                                .scale(buttonScale.value),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MainColors.Primary1,
                                disabledContainerColor = MainColors.Primary1.copy(alpha = 0.6f)
                            ),
                            shape = RoundedCornerShape(12.dp),
                            enabled = !isLoading
                        ) {
                            Box(
                                contentAlignment = Alignment.Center,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                if (isLoading) {
                                    CircularProgressIndicator(
                                        color = NeutralColors.Neutral10,
                                        strokeWidth = 2.dp,
                                        modifier = Modifier.size(24.dp)
                                    )
                                } else {
                                    Text(
                                        strings.login,
                                        style = AppTypography.heading4SemiBold,
                                        color = NeutralColors.Neutral10
                                    )
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(32.dp))

                        // Register link
                        AnimatedVisibility(
                            visible = showElements,
                            enter = fadeIn(animationSpec = tween(1000)) +
                                    slideInVertically(
                                        animationSpec = tween(800),
                                        initialOffsetY = { it / 2 }
                                    )
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.Center
                            ) {
                                Text(
                                    text = strings.dontHaveAccount,
                                    color = NeutralColors.Neutral70,
                                    style = AppTypography.heading5Medium
                                )
                                Text(
                                    text = strings.register,
                                    color = MainColors.Primary1,
                                    style = AppTypography.heading5Medium,
                                    modifier = Modifier.clickable(onClick = onRegisterClick)
                                )
                            }
                        }

                        // Display error message at the bottom
                        Spacer(modifier = Modifier.height(80.dp))

                        AnimatedVisibility(
                            visible = errorMessage != null,
                            enter = fadeIn(tween(300)),
                            exit = fadeOut(tween(300))
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
                    }
                }
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun LoginScreenPreview() {
    MaterialTheme {
        LoginScreen({}, {})
    }
}