package com.nocturna.votechain.ui.screens.profilepage

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import kotlinx.coroutines.launch
import com.nocturna.votechain.data.repository.UserLoginRepository
import com.nocturna.votechain.data.repository.VoterRepository
import com.nocturna.votechain.ui.theme.*
import com.nocturna.votechain.utils.LocalizedStrings
import androidx.compose.ui.platform.LocalContext
import android.util.Log
import androidx.compose.ui.res.painterResource
import com.nocturna.votechain.utils.LanguageManager
import com.nocturna.votechain.R

@Composable
fun PasswordConfirmationDialog(
    isOpen: Boolean,
    onCancel: () -> Unit,
    onSubmit: (String) -> Unit,
    userLoginRepository: UserLoginRepository
) {
    val strings = LanguageManager.getLocalizedStrings()

    var password by remember { mutableStateOf("") }
    var isError by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf("") }
    var isLoading by remember { mutableStateOf(false) }
    var isPasswordVisible by remember { mutableStateOf(false) }

    val context = LocalContext.current
    val voterRepository = remember { VoterRepository(context) }
    val coroutineScope = rememberCoroutineScope()
    val focusRequester = remember { FocusRequester() }
    val focusManager = LocalFocusManager.current
    val keyboardController = LocalSoftwareKeyboardController.current

    // Reset state when dialog opens
    LaunchedEffect(isOpen) {
        if (isOpen) {
            password = ""
            isError = false
            errorMessage = ""
            isLoading = false
            focusRequester.requestFocus()
        }
    }

    if (isOpen) {
        Dialog(onDismissRequest = onCancel) {
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = NeutralColors.Neutral10
                )
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    // Title
                    Text(
                        text = strings.passwordConfirmationTitle,
                        style = AppTypography.heading4SemiBold,
                        color = NeutralColors.Neutral90,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )

                    // Subtitle
                    Text(
                        text = strings.passwordConfirmationSubtitle,
                        style = AppTypography.paragraphRegular,
                        color = NeutralColors.Neutral70,
                        modifier = Modifier.padding(bottom = 24.dp)
                    )

                    // Password field
                    OutlinedTextField(
                        value = password,
                        onValueChange = {
                            password = it
                            if (isError) {
                                isError = false
                                errorMessage = ""
                            }
                        },
                        label = {
                            Text(
                                text = strings.password,
                                style = AppTypography.paragraphRegular
                            )
                        },
                        visualTransformation = if (isPasswordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                        trailingIcon = {
                            IconButton(onClick = { isPasswordVisible = !isPasswordVisible }) {
                                Icon(
                                    painter = painterResource(
                                        id = if (isPasswordVisible) R.drawable.hide else R.drawable.show
                                    ),
                                    contentDescription = if (isPasswordVisible) "Hide password" else "Show password",
                                    tint = NeutralColors.Neutral50
                                )
                            }
                        },
                        isError = isError,
                        enabled = !isLoading,
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Done
                        ),
                        keyboardActions = KeyboardActions(
                            onDone = {
                                if (password.isNotEmpty() && !isLoading) {
                                    focusManager.clearFocus()
                                    keyboardController?.hide()
                                    coroutineScope.launch {
                                        handlePasswordSubmission(
                                            password = password,
                                            userLoginRepository = userLoginRepository,
                                            voterRepository = voterRepository,
                                            onSuccess = { validatedPassword ->
                                                password = ""
                                                isError = false
                                                errorMessage = ""
                                                onSubmit(validatedPassword)
                                            },
                                            onError = { error ->
                                                isError = true
                                                errorMessage = error
                                            },
                                            setLoading = { loading ->
                                                isLoading = loading
                                            }
                                        )
                                    }
                                }
                            }
                        ),
                        modifier = Modifier
                            .fillMaxWidth()
                            .focusRequester(focusRequester),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = MainColors.Primary1,
                            unfocusedBorderColor = NeutralColors.Neutral30,
                            errorBorderColor = MaterialTheme.colorScheme.error,
                            focusedLabelColor = MainColors.Primary1,
                            unfocusedLabelColor = NeutralColors.Neutral50,
                            cursorColor = MainColors.Primary1
                        ),
                        textStyle = AppTypography.paragraphRegular
                    )

                    // Error message
                    if (isError && errorMessage.isNotEmpty()) {
                        Text(
                            text = errorMessage,
                            style = AppTypography.paragraphRegular,
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 4.dp)
                        )
                    }

                    Spacer(modifier = Modifier.height(24.dp))

                    // Buttons
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        // Cancel button
                        OutlinedButton(
                            onClick = {
                                if (!isLoading) {
                                    password = ""
                                    isError = false
                                    errorMessage = ""
                                    onCancel()
                                }
                            },
                            modifier = Modifier.weight(1f),
                            enabled = !isLoading,
                            shape = RoundedCornerShape(8.dp),
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = MainColors.Primary1,
                                disabledContentColor = NeutralColors.Neutral50
                            )
                        ) {
                            Text(
                                text = strings.passwordConfirmationCancel,
                                style = AppTypography.paragraphMedium
                            )
                        }

                        // Submit button
                        Button(
                            onClick = {
                                if (password.isNotEmpty() && !isLoading) {
                                    focusManager.clearFocus()
                                    keyboardController?.hide()
                                    coroutineScope.launch {
                                        handlePasswordSubmission(
                                            password = password,
                                            userLoginRepository = userLoginRepository,
                                            voterRepository = voterRepository,
                                            onSuccess = { validatedPassword ->
                                                password = ""
                                                isError = false
                                                errorMessage = ""
                                                onSubmit(validatedPassword)
                                            },
                                            onError = { error ->
                                                isError = true
                                                errorMessage = error
                                            },
                                            setLoading = { loading ->
                                                isLoading = loading
                                            }
                                        )
                                    }
                                }
                            },
                            modifier = Modifier.weight(1f),
                            enabled = password.isNotEmpty() && !isLoading,
                            shape = RoundedCornerShape(8.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MainColors.Primary1,
                                disabledContainerColor = MainColors.Primary1.copy(alpha = 0.6f)
                            )
                        ) {
                            if (isLoading) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.Center
                                ) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(16.dp),
                                        color = NeutralColors.Neutral10,
                                        strokeWidth = 2.dp
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = "Verifying",
                                        style = AppTypography.paragraphMedium,
                                        color = NeutralColors.Neutral10
                                    )
                                }
                            } else {
                                Text(
                                    text = strings.passwordConfirmationSubmit,
                                    style = AppTypography.paragraphMedium,
                                    color = NeutralColors.Neutral10
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

/**
 * Handle password submission with automatic voter data fetching
 */
private suspend fun handlePasswordSubmission(
    password: String,
    userLoginRepository: UserLoginRepository,
    voterRepository: VoterRepository,
    onSuccess: (String) -> Unit,
    onError: (String) -> Unit,
    setLoading: (Boolean) -> Unit
) {
    if (password.isEmpty()) {
        onError("Password cannot be empty")
        return
    }

    try {
        setLoading(true)
        Log.d("PasswordDialog", "🔐 Starting password verification...")

        // Step 1: Verify password
        val isPasswordValid = userLoginRepository.verifyPassword(password)

        if (!isPasswordValid) {
            Log.w("PasswordDialog", "❌ Password verification failed")
            onError("Incorrect password. Please try again")
            return
        }

        Log.d("PasswordDialog", "✅ Password verification successful")

        // Step 2: Automatically fetch voter data after successful password verification
        Log.d("PasswordDialog", "🔄 Auto-fetching voter data...")

        try {
            val userToken = userLoginRepository.getUserToken()
            if (userToken.isNotEmpty()) {
                // Fetch fresh voter data from API
                val voterResult = voterRepository.fetchVoterData(userToken)

                voterResult.fold(
                    onSuccess = { voterData ->
                        Log.d("PasswordDialog", "✅ Voter data auto-fetch successful")
                        Log.d("PasswordDialog", "- Voter: ${voterData.full_name}")
                        Log.d("PasswordDialog", "- NIK: ${voterData.nik}")
                        Log.d("PasswordDialog", "- Has Voted: ${voterData.has_voted}")

                        // Save locally for immediate access
                        voterRepository.saveVoterDataLocally(voterData)

                        onSuccess(password)
                    },
                    onFailure = { error ->
                        Log.w("PasswordDialog", "⚠️ Voter data fetch failed: ${error.message}")
                        // Still allow access but with warning
                        onError("Password verified but failed to refresh data: ${error.message}")
                    }
                )
            } else {
                Log.w("PasswordDialog", "⚠️ No user token available for voter data fetch")
                // Still allow access but note the limitation
                onSuccess(password)
            }

        } catch (e: Exception) {
            Log.e("PasswordDialog", "❌ Exception during voter data fetch: ${e.message}")
            // Still allow access but with warning
            onError("Password verified but error refreshing data: ${e.message}")
        }

    } catch (e: Exception) {
        Log.e("PasswordDialog", "❌ Exception during password verification: ${e.message}")
        onError("Verification error: ${e.message}")
    } finally {
        setLoading(false)
    }
}