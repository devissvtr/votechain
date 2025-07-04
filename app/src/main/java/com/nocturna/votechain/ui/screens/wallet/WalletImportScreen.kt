package com.nocturna.votechain.ui.screens.wallet

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.nocturna.votechain.ui.theme.*
import com.nocturna.votechain.utils.LanguageManager
import com.nocturna.votechain.viewmodel.wallet.ImportStep
import com.nocturna.votechain.viewmodel.wallet.WalletImportUiState
import com.nocturna.votechain.viewmodel.wallet.WalletImportViewModel
import kotlinx.coroutines.delay
import com.nocturna.votechain.R
import com.nocturna.votechain.data.network.ElectionNetworkClient.initialize

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WalletImportScreen(
    onBackClick: () -> Unit = {},
    onSuccessClick: (String) -> Unit = {},
    viewModel: WalletImportViewModel = viewModel()
) {
    val context = LocalContext.current
    val actualViewModel = remember { viewModel.apply { initialize(context) } }

    val localizedStrings = LanguageManager.getLocalizedStrings()
    val uiState by viewModel.uiState.collectAsState()
    val currentStep by viewModel.currentStep.collectAsState()
    val privateKey by viewModel.privateKey.collectAsState()
    val password by viewModel.password.collectAsState()
    val confirmPassword by viewModel.confirmPassword.collectAsState()
    val isPrivateKeyVisible by viewModel.isPrivateKeyVisible.collectAsState()
    val isPasswordVisible by viewModel.isPasswordVisible.collectAsState()
    val privateKeyError by viewModel.privateKeyError.collectAsState()
    val passwordError by viewModel.passwordError.collectAsState()

    val focusManager = LocalFocusManager.current
    val privateKeyFocusRequester = remember { FocusRequester() }
    val passwordFocusRequester = remember { FocusRequester() }
    val confirmPasswordFocusRequester = remember { FocusRequester() }

    // Handle success state
    LaunchedEffect(uiState) {
        if (uiState is WalletImportUiState.Success) {
            delay(2000) // Show success message briefly
            onSuccessClick((uiState as WalletImportUiState.Success).walletAddress)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(color = ThemeColor.OnSurface)
    ) {
        // Top App Bar
        TopAppBar(
            title = {
                Text(
                    text = "Import Wallet",
                    style = AppTypography.heading6Medium,
                    color = NeutralColors.Neutral90
                )
            },
            navigationIcon = {
                IconButton(onClick = onBackClick) {
                    Icon(
                        imageVector = Icons.Default.ArrowBack,
                        contentDescription = "Back",
                        tint = NeutralColors.Neutral70
                    )
                }
            },
            actions = {
                if (uiState !is WalletImportUiState.Loading) {
                    IconButton(onClick = { viewModel.resetImport() }) {
                        Icon(
                            imageVector = Icons.Default.Close,
                            contentDescription = "Reset",
                            tint = NeutralColors.Neutral70
                        )
                    }
                }
            },
            colors = TopAppBarDefaults.topAppBarColors(
                containerColor = Color.Transparent
            )
        )

        // Progress Indicator
        LinearProgressIndicator(
            progress = when (currentStep) {
                ImportStep.PRIVATE_KEY_INPUT -> 0.25f
                ImportStep.PASSWORD_SETUP -> 0.5f
                ImportStep.CONFIRMATION -> 0.75f
                ImportStep.PROCESSING -> 1f
            },
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp),
            color = PrimaryColors.Primary50,
            trackColor = NeutralColors.Neutral20
        )

        // Main Content
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(24.dp)
        ) {
            AnimatedContent(
                targetState = currentStep,
                transitionSpec = {
                    slideInHorizontally(
                        animationSpec = tween(300),
                        initialOffsetX = { it }
                    ) togetherWith slideOutHorizontally(
                        animationSpec = tween(300),
                        targetOffsetX = { -it }
                    )
                },
                label = "step_transition"
            ) { step ->
                when (step) {
                    ImportStep.PRIVATE_KEY_INPUT -> {
                        PrivateKeyInputStep(
                            privateKey = privateKey,
                            isVisible = isPrivateKeyVisible,
                            error = privateKeyError,
                            onPrivateKeyChange = viewModel::updatePrivateKey,
                            onVisibilityToggle = viewModel::togglePrivateKeyVisibility,
                            onNextClick = viewModel::proceedToNextStep,
                            focusRequester = privateKeyFocusRequester
                        )
                    }
                    ImportStep.PASSWORD_SETUP -> {
                        PasswordSetupStep(
                            password = password,
                            confirmPassword = confirmPassword,
                            isVisible = isPasswordVisible,
                            error = passwordError,
                            onPasswordChange = viewModel::updatePassword,
                            onConfirmPasswordChange = viewModel::updateConfirmPassword,
                            onVisibilityToggle = viewModel::togglePasswordVisibility,
                            onBackClick = viewModel::goBackToPreviousStep,
                            onNextClick = viewModel::proceedToNextStep,
                            passwordFocusRequester = passwordFocusRequester,
                            confirmPasswordFocusRequester = confirmPasswordFocusRequester
                        )
                    }
                    ImportStep.CONFIRMATION -> {
                        ConfirmationStep(
                            walletAddress = "0x..." + privateKey.takeLast(8), // Preview only
                            onBackClick = viewModel::goBackToPreviousStep,
                            onConfirmClick = viewModel::proceedToNextStep
                        )
                    }
                    ImportStep.PROCESSING -> {
                        ProcessingStep(uiState = uiState)
                    }
                }
            }
        }
    }
}

@Composable
private fun PrivateKeyInputStep(
    privateKey: String,
    isVisible: Boolean,
    error: String?,
    onPrivateKeyChange: (String) -> Unit,
    onVisibilityToggle: () -> Unit,
    onNextClick: () -> Unit,
    focusRequester: FocusRequester
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(24.dp)
    ) {
        // Header
        Column(
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "Import Your Wallet",
                style = AppTypography.heading6Medium,
                color = NeutralColors.Neutral90
            )
            Text(
                text = "Enter your private key to import an existing wallet. Your private key will be encrypted and stored securely.",
                style = AppTypography.paragraphRegular,
                color = NeutralColors.Neutral60
            )
        }

        // Security Warning
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = WarningColors.Warning50
            ),
            border = BorderStroke(1.dp, WarningColors.Warning30)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.Top
            ) {
                Icon(
                    imageVector = Icons.Default.Warning,
                    contentDescription = null,
                    tint = WarningColors.Warning70,
                    modifier = Modifier.size(20.dp)
                )
                Column(
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Text(
                        text = "Security Notice",
                        style = AppTypography.heading6Medium,
                        color = WarningColors.Warning80,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "Never share your private key with anyone. VoteChain will never ask for your private key.",
                        style = AppTypography.paragraphRegular,
                        color = WarningColors.Warning70
                    )
                }
            }
        }

        // Private Key Input
        Column(
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "Private Key",
                style = AppTypography.heading5Bold,
                color = NeutralColors.Neutral70
            )

            OutlinedTextField(
                value = privateKey,
                onValueChange = onPrivateKeyChange,
                modifier = Modifier
                    .fillMaxWidth()
                    .focusRequester(focusRequester),
                placeholder = {
                    Text(
                        text = "Enter your private key (64 characters)",
                        color = NeutralColors.Neutral40
                    )
                },
                visualTransformation = if (isVisible) VisualTransformation.None else PasswordVisualTransformation(),
                trailingIcon = {
                    IconButton(onClick = onVisibilityToggle) {
                        Icon(
                            painter = painterResource(id = if (isVisible) R.drawable.hide else R.drawable.show),
                            contentDescription = if (isVisible) "Hide" else "Show"
                        )
                    }
                },
                isError = error != null,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Done
                ),
                keyboardActions = KeyboardActions(
                    onDone = { onNextClick() }
                ),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = PrimaryColors.Primary50,
                    errorBorderColor = DangerColors.Danger50
                )
            )

            AnimatedVisibility(visible = error != null) {
                Text(
                    text = error ?: "",
                    style = AppTypography.paragraphRegular,
                    color = DangerColors.Danger60,
                    modifier = Modifier.padding(start = 16.dp)
                )
            }
        }

        Spacer(modifier = Modifier.weight(1f))

        // Next Button
        Button(
            onClick = onNextClick,
            modifier = Modifier.fillMaxWidth(),
            enabled = privateKey.isNotBlank() && error == null,
            colors = ButtonDefaults.buttonColors(
                containerColor = PrimaryColors.Primary50,
                disabledContainerColor = NeutralColors.Neutral30
            )
        ) {
            Text(
                text = "Continue",
                style = AppTypography.paragraphRegular,
                modifier = Modifier.padding(vertical = 4.dp)
            )
        }
    }

    LaunchedEffect(Unit) {
        focusRequester.requestFocus()
    }
}

@Composable
private fun PasswordSetupStep(
    password: String,
    confirmPassword: String,
    isVisible: Boolean,
    error: String?,
    onPasswordChange: (String) -> Unit,
    onConfirmPasswordChange: (String) -> Unit,
    onVisibilityToggle: () -> Unit,
    onBackClick: () -> Unit,
    onNextClick: () -> Unit,
    passwordFocusRequester: FocusRequester,
    confirmPasswordFocusRequester: FocusRequester
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(24.dp)
    ) {
        // Header
        Column(
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "Secure Your Wallet",
                style = AppTypography.heading6Medium,
                color = NeutralColors.Neutral90
            )
            Text(
                text = "Create a strong password to encrypt your wallet. This password will be required to access your wallet.",
                style = AppTypography.paragraphRegular,
                color = NeutralColors.Neutral60
            )
        }

        // Password Fields
        Column(
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Password Input
            Column(
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = "Password",
                    style = AppTypography.paragraphRegular,
                    color = NeutralColors.Neutral60
                )

                OutlinedTextField(
                    value = password,
                    onValueChange = onPasswordChange,
                    modifier = Modifier
                        .fillMaxWidth()
                        .focusRequester(passwordFocusRequester),
                    placeholder = {
                        Text(
                            text = "Enter a strong password",
                            color = NeutralColors.Neutral40
                        )
                    },
                    visualTransformation = if (isVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = {
                        IconButton(onClick = onVisibilityToggle) {
                            Icon(
                                painter = painterResource(id = if (isVisible) R.drawable.hide else R.drawable.show),
                                contentDescription = if (isVisible) "Hide" else "Show"
                            )
                        }
                    },
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        imeAction = ImeAction.Next
                    ),
                    keyboardActions = KeyboardActions(
                        onNext = { confirmPasswordFocusRequester.requestFocus() }
                    ),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = PrimaryColors.Primary50
                    )
                )
            }

            // Confirm Password Input
            Column(
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = "Confirm Password",
                    style = AppTypography.heading6Medium,
                    color = NeutralColors.Neutral70
                )

                OutlinedTextField(
                    value = confirmPassword,
                    onValueChange = onConfirmPasswordChange,
                    modifier = Modifier
                        .fillMaxWidth()
                        .focusRequester(confirmPasswordFocusRequester),
                    placeholder = {
                        Text(
                            text = "Confirm your password",
                            color = NeutralColors.Neutral40
                        )
                    },
                    visualTransformation = if (isVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    isError = error != null,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Password,
                        imeAction = ImeAction.Done
                    ),
                    keyboardActions = KeyboardActions(
                        onDone = { onNextClick() }
                    ),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = PrimaryColors.Primary50,
                        errorBorderColor = DangerColors.Danger50
                    )
                )

                AnimatedVisibility(visible = error != null) {
                    Text(
                        text = error ?: "",
                        style = AppTypography.paragraphRegular,
                        color = DangerColors.Danger60,
                        modifier = Modifier.padding(start = 16.dp)
                    )
                }
            }
        }

        // Security Info
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = PrimaryColors.Primary50
            ),
            border = BorderStroke(1.dp, PrimaryColors.Primary20)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.Top
            ) {
//                Icon(
//                    imageVector = Icons.Default.Security,
//                    contentDescription = null,
//                    tint = PrimaryColors.primary600,
//                    modifier = Modifier.size(20.dp)
//                )
                Column(
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Text(
                        text = "Password Requirements",
                        style = AppTypography.heading6Medium,
                        color = PrimaryColors.Primary50,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "• At least 8 characters\n• Use a password you'll remember\n• Consider using a password manager",
                        style = AppTypography.paragraphRegular,
                        color = PrimaryColors.Primary70
                    )
                }
            }
        }

        Spacer(modifier = Modifier.weight(1f))

        // Action Buttons
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedButton(
                onClick = onBackClick,
                modifier = Modifier.weight(1f),
                border = BorderStroke(1.dp, NeutralColors.Neutral30)
            ) {
                Text(
                    text = "Back",
                    style = AppTypography.paragraphRegular,
                    color = NeutralColors.Neutral70,
                    modifier = Modifier.padding(vertical = 4.dp)
                )
            }

            Button(
                onClick = onNextClick,
                modifier = Modifier.weight(1f),
                enabled = password.length >= 8 && password == confirmPassword && error == null,
                colors = ButtonDefaults.buttonColors(
                    containerColor = PrimaryColors.Primary50,
                    disabledContainerColor = NeutralColors.Neutral30
                )
            ) {
                Text(
                    text = "Continue",
                    style = AppTypography.paragraphRegular,
                    modifier = Modifier.padding(vertical = 4.dp)
                )
            }
        }
    }

    LaunchedEffect(Unit) {
        passwordFocusRequester.requestFocus()
    }
}

@Composable
private fun ConfirmationStep(
    walletAddress: String,
    onBackClick: () -> Unit,
    onConfirmClick: () -> Unit
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(24.dp)
    ) {
        // Header
        Column(
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "Confirm Import",
                style = AppTypography.paragraphRegular,
                color = NeutralColors.Neutral90
            )
            Text(
                text = "Please review the information below before importing your wallet.",
                style = AppTypography.paragraphRegular,
                color = NeutralColors.Neutral60
            )
        }

        // Wallet Info
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = NeutralColors.Neutral50
            ),
            border = BorderStroke(1.dp, NeutralColors.Neutral20)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Text(
                    text = "Wallet Preview",
                    style = AppTypography.paragraphRegular,
                    color = NeutralColors.Neutral90,
                    fontWeight = FontWeight.SemiBold
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Address:",
                        style = AppTypography.paragraphRegular,
                        color = NeutralColors.Neutral60
                    )
                    Text(
                        text = walletAddress,
                        style = AppTypography.paragraphRegular,
                        color = NeutralColors.Neutral90,
                        fontWeight = FontWeight.Medium
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Encryption:",
                        style = AppTypography.paragraphRegular,
                        color = NeutralColors.Neutral60
                    )
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = SuccessColors.Success60,
                            modifier = Modifier.size(16.dp)
                        )
                        Text(
                            text = "Password Protected",
                            style = AppTypography.smallParagraphRegular,
                            color = SuccessColors.Success70,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
            }
        }

        // Important Notice
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = WarningColors.Warning70
            ),
            border = BorderStroke(1.dp, WarningColors.Warning30)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = "Important",
                    style = AppTypography.smallParagraphRegular,
                    color = WarningColors.Warning80,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = "• Your private key will be encrypted with your password\n• Make sure to remember your password\n• VoteChain cannot recover your password if lost",
                    style = AppTypography.smallParagraphRegular,
                    color = WarningColors.Warning70
                )
            }
        }

        Spacer(modifier = Modifier.weight(1f))

        // Action Buttons
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedButton(
                onClick = onBackClick,
                modifier = Modifier.weight(1f),
                border = BorderStroke(1.dp, NeutralColors.Neutral30)
            ) {
                Text(
                    text = "Back",
                    style = AppTypography.paragraphRegular,
                    color = NeutralColors.Neutral70,
                    modifier = Modifier.padding(vertical = 4.dp)
                )
            }

            Button(
                onClick = onConfirmClick,
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(
                    containerColor = PrimaryColors.Primary50
                )
            ) {
                Text(
                    text = "Import Wallet",
                    style = AppTypography.paragraphRegular,
                    modifier = Modifier.padding(vertical = 4.dp)
                )
            }
        }
    }
}

@Composable
private fun ProcessingStep(
    uiState: WalletImportUiState
) {
    Column(
        modifier = Modifier.fillMaxSize(),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        when (uiState) {
            is WalletImportUiState.Loading -> {
                CircularProgressIndicator(
                    modifier = Modifier.size(48.dp),
                    color = PrimaryColors.Primary50
                )
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = "Importing wallet...",
                    style = AppTypography.paragraphRegular,
                    color = NeutralColors.Neutral70
                )
                Text(
                    text = "Please wait while we securely import your wallet",
                    style = AppTypography.smallParagraphMedium,
                    color = NeutralColors.Neutral70,
                    textAlign = TextAlign.Center
                )
            }
            is WalletImportUiState.Success -> {
                Icon(
                    imageVector = Icons.Default.CheckCircle,
                    contentDescription = null,
                    tint = SuccessColors.Success60,
                    modifier = Modifier.size(48.dp)
                )
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = "Wallet Imported Successfully!",
                    style = AppTypography.heading6Medium,
                    color = SuccessColors.Success60
                )
                Text(
                    text = "Address: ${uiState.walletAddress}",
                    style = AppTypography.paragraphRegular,
                    color = NeutralColors.Neutral60,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 16.dp)
                )
            }
            is WalletImportUiState.Error -> {
                Icon(
                    imageVector = Icons.Default.Warning,
                    contentDescription = null,
                    tint = DangerColors.Danger60,
                    modifier = Modifier.size(48.dp)
                )
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = "Import Failed",
                    style = AppTypography.paragraphRegular,
                    color = DangerColors.Danger70
                )
                Text(
                    text = uiState.message,
                    style = AppTypography.smallParagraphMedium,
                    color = NeutralColors.Neutral60,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.padding(horizontal = 16.dp)
                )
            }
            else -> {
                // Should not reach here
            }
        }
    }
}