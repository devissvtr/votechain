package com.nocturna.votechain.ui.screens.profilepage

import com.nocturna.votechain.R
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import androidx.navigation.compose.rememberNavController
import com.nocturna.votechain.data.model.WalletInfo
import com.nocturna.votechain.data.repository.UserLoginRepository
import com.nocturna.votechain.data.repository.UserProfileRepository
import com.nocturna.votechain.data.repository.VoterRepository
import com.nocturna.votechain.ui.screens.BottomNavigation
import com.nocturna.votechain.ui.theme.AppTypography
import com.nocturna.votechain.ui.theme.MainColors
import com.nocturna.votechain.ui.theme.NeutralColors
import com.nocturna.votechain.ui.theme.PrimaryColors
import com.nocturna.votechain.utils.LanguageManager
import com.nocturna.votechain.utils.LanguageManager.currentLanguage
import com.nocturna.votechain.utils.ThemeManager
import com.nocturna.votechain.utils.getLocalizedStrings
import com.nocturna.votechain.viewmodel.UserProfileViewModel
import com.nocturna.votechain.viewmodel.UserProfileViewModelFactory
import com.nocturna.votechain.viewmodel.login.LoginViewModel

@Composable
fun ProfileScreen(
    onNavigateToFAQ: () -> Unit = {},
    navController: NavController,
    onHomeClick: () -> Unit = {},
    onVotesClick: () -> Unit = {},
    onLogout: () -> Unit = {}
) {
    var showLanguageDropdown by remember { mutableStateOf(false) }
    var showThemeDropdown by remember { mutableStateOf(false) }
    var showLogoutDialog by remember { mutableStateOf(false) }
    val currentRoute = "profile"
    var showPasswordDialog by remember { mutableStateOf(false) }

    val currentLanguage by LanguageManager.currentLanguage.collectAsState()
    val strings = LanguageManager.getLocalizedStrings()

    val context = LocalContext.current
    val currentTheme by ThemeManager.currentTheme.collectAsState()

    // Get LoginViewModel instance
    val loginViewModel: LoginViewModel = viewModel(factory = LoginViewModel.Factory(context))

    // Repository instances
    val userProfileRepository = remember { UserProfileRepository(context) }
    val userLoginRepository = remember { UserLoginRepository(context) }
    val voterRepository = remember { VoterRepository(context) }

    // State untuk profile data dengan real-time wallet info
    var completeUserProfile by remember { mutableStateOf(userProfileRepository.getSavedCompleteProfile()) }
    var fallbackVoterData by remember { mutableStateOf(voterRepository.getVoterDataLocally()) }
    var walletInfo by remember { mutableStateOf(WalletInfo()) }
    var dataLoadError by remember { mutableStateOf<String?>(null) }
    var isLoadingWallet by remember { mutableStateOf(true) }

// Refresh profile data dan wallet info saat screen dibuka
    LaunchedEffect(Unit) {
        // Load profile data
        userProfileRepository.fetchCompleteUserProfileWithFallback().fold(
            onSuccess = { profile ->
                completeUserProfile = profile
            },
            onFailure = { error ->
                completeUserProfile = userProfileRepository.getSavedCompleteProfile()
            }
        )

        // Load real-time wallet info
        try {
            isLoadingWallet = true
            walletInfo = voterRepository.getCompleteWalletInfo()
            dataLoadError = null
        } catch (e: Exception) {
            dataLoadError = "Failed to load wallet info: ${e.message}"
            // Use cached wallet info as fallback
            walletInfo = voterRepository.getWalletInfo()
        } finally {
            isLoadingWallet = false
        }
    }

    // Extract voter data dari complete profile
    val voterData = completeUserProfile?.voterProfile ?: fallbackVoterData
    val userEmail = completeUserProfile?.userProfile?.email ?: userLoginRepository.getUserEmail()

    val scrollState = rememberScrollState()

    // Logout Confirmation Dialog
    if (showLogoutDialog) {
        AlertDialog(
            onDismissRequest = { showLogoutDialog = false },
            title = {
                Text(
                    text = "Logout",
                    style = AppTypography.heading4Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
            },
            text = {
                Text(
                    text = "Are you sure you want to logout from your account?",
                    style = AppTypography.paragraphRegular,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showLogoutDialog = false
                        loginViewModel.logoutUser()
                        onLogout()
                    },
                    colors = ButtonDefaults.textButtonColors(
                        contentColor = NeutralColors.Neutral40
                    )
                ) {
                    Text("Logout")
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { showLogoutDialog = false },
                    colors = ButtonDefaults.textButtonColors(
                        contentColor = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                ) {
                    Text("Cancel")
                }
            }
        )
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(scrollState)
        ) {
            // Header with gradient teal background
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(104.dp)
            ) {
                Image(
                    painter = painterResource(id = R.drawable.background),
                    contentDescription = null,
                    contentScale = ContentScale.FillBounds,
                    modifier = Modifier.fillMaxSize()
                )
            }

            // Profile Card - positioned to overlap with the header
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp)
                    .offset(y = (-50).dp),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                elevation = CardDefaults.cardElevation(defaultElevation = 8.dp)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column {
                            // Display voter full name or fallback
                            val displayName = when {
                                voterData?.full_name?.isNotEmpty() == true -> voterData.full_name
                                userEmail.isNotEmpty() -> userEmail.split("@").firstOrNull() ?: "User"
                                else -> "User"
                            }

                            Text(
                                text = displayName,
                                style = AppTypography.heading4Bold,
                                color = MaterialTheme.colorScheme.onSurface
                            )

                            // Display voting status with appropriate icon
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.padding(top = 8.dp)
                            ) {
                                // Display appropriate status image based on has_voted
                                Image(
                                    painter = painterResource(
                                        id = if (voterData?.has_voted == true) {
                                            R.drawable.tag_complete
                                        } else {
                                            R.drawable.tag_incomplete
                                        }
                                    ),
                                    contentDescription = if (voterData?.has_voted == true) {
                                        "Vote Complete"
                                    } else {
                                        "Vote Incomplete"
                                    },
                                    modifier = Modifier.size(80.dp, 24.dp)
                                )
                            }

                            if (dataLoadError != null) {
                                Text(
                                    text = "Data may not be current",
                                    style = AppTypography.smallParagraphRegular,
                                    color = MaterialTheme.colorScheme.error,
                                    modifier = Modifier.padding(top = 4.dp)
                                )
                            }
                        }
                        Column {
                            Button(
                                onClick = {
                                    showPasswordDialog = true
                                },
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = MainColors.Primary1
                                ),
                                shape = RoundedCornerShape(12.dp),
                                contentPadding = PaddingValues(horizontal = 3.dp, vertical = 4.dp),
                                modifier = Modifier.height(26.dp),
                            ) {
                                Text(strings.view, style = AppTypography.heading6Regular, color = NeutralColors.Neutral10)
                                Icon(
                                    painter = painterResource(id = R.drawable.right2),
                                    contentDescription = null,
                                    tint = NeutralColors.Neutral10,
                                    modifier = Modifier
                                        .padding(start = 4.dp)
                                        .size(12.dp)
                                )
                            }
                        }
                    }
                }
            }

            // Account Section dengan real wallet info
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 16.dp),
                colors = CardDefaults.cardColors(containerColor = Color.White),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
            ) {
                Column(
                    modifier = Modifier.padding(20.dp)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(
                                text = strings.account,
                                style = AppTypography.heading5Bold,
                                color = NeutralColors.Neutral90
                            )

                            // Balance display dengan loading state
                            Text(
                                text = if (isLoadingWallet) {
                                    "Loading balance..."
                                } else if (walletInfo.hasError) {
                                    "Error loading balance"
                                } else {
                                    "${strings.balance}: ${walletInfo.balance} ETH"
                                },
                                style = AppTypography.paragraphRegular,
                                color = if (walletInfo.hasError) {
                                    Color.Red
                                } else {
                                    NeutralColors.Neutral70
                                },
                                modifier = Modifier.padding(top = 4.dp)
                            )

                            // Show last updated time
                            if (!isLoadingWallet && !walletInfo.hasError) {
                                val lastUpdated = remember(walletInfo.lastUpdated) {
                                    java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
                                        .format(java.util.Date(walletInfo.lastUpdated))
                                }
                                Text(
                                    text = "Updated: $lastUpdated",
                                    style = AppTypography.paragraphRegular,
                                    color = NeutralColors.Neutral50,
                                    modifier = Modifier.padding(top = 2.dp)
                                )
                            }
                        }

                        // View button dengan loading indicator
                        Button(
                            onClick = {
                                if (!isLoadingWallet) {
                                    showPasswordDialog = true
                                }
                            },
                            enabled = !isLoadingWallet,
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MainColors.Primary1
                            ),
                            shape = RoundedCornerShape(12.dp),
                            contentPadding = PaddingValues(horizontal = 3.dp, vertical = 4.dp),
                            modifier = Modifier.height(26.dp),
                        ) {
                            if (isLoadingWallet) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(12.dp),
                                    strokeWidth = 1.dp,
                                    color = NeutralColors.Neutral10
                                )
                            } else {
                                Text(strings.view, style = AppTypography.heading6Regular, color = NeutralColors.Neutral10)
                                Icon(
                                    painter = painterResource(id = R.drawable.right2),
                                    contentDescription = null,
                                    tint = NeutralColors.Neutral10,
                                    modifier = Modifier
                                        .padding(start = 4.dp)
                                        .size(12.dp)
                                )
                            }
                        }
                    }
                }
            }

            // Password Confirmation Dialog
            PasswordConfirmationDialog(
                isOpen = showPasswordDialog,
                userLoginRepository = userLoginRepository,
                onCancel = { showPasswordDialog = false },
                onSubmit = { password ->
                    // Password verification is handled inside the dialog
                    // If we reach here, password is correct
                    showPasswordDialog = false
                    navController.navigate("account_details")
                }
            )

            // Content area with padding
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp)
            ) {
                // Settings Section
                Text(
                    text = strings.settings,
                    style = AppTypography.heading4Bold,
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    modifier = Modifier.padding(bottom = 8.dp)
                )

//                // Accessibility Settings
//                Row(
//                    modifier = Modifier
//                        .fillMaxWidth()
//                        .clickable {
//                            if (isAccessibilityEnabled) {
//                                accessibilityManager.speakAction("Pengaturan bantuan suara")
//                            }
//                        }
//                        .padding(vertical = 12.dp),
//                    verticalAlignment = Alignment.CenterVertically,
//                    horizontalArrangement = Arrangement.SpaceBetween
//                ) {
//                    Column {
//                        Text(
//                            text = "Bantuan Suara",
//                            style = AppTypography.heading5Medium,
//                            color = NeutralColors.Neutral40
//                        )
//                        Text(
//                            text = "Untuk pengguna tunanetra",
//                            style = AppTypography.paragraphRegular,
//                            color = NeutralColors.Neutral50
//                        )
//                    }
//
//                    Switch(
//                        checked = isAccessibilityEnabled,
//                        onCheckedChange = { enabled ->
//                            if (enabled) {
//                                accessibilityManager.initialize()
//                            } else {
//                                accessibilityManager.setEnabled(false)
//                            }
//                        },
//                        colors = SwitchDefaults.colors(
//                            checkedThumbColor = MainColors.Primary1,
//                            checkedTrackColor = MainColors.Primary1.copy(alpha = 0.5f)
//                        )
//                    )
//                }
//
//                Divider(color = MaterialTheme.colorScheme.outlineVariant, thickness = 1.dp)

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { showThemeDropdown = true }
                        .padding(vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = strings.theme,
                        style = AppTypography.heading5Medium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Box {
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(12.dp))
                                .border(
                                    1.dp,
                                    MaterialTheme.colorScheme.outline,
                                    RoundedCornerShape(12.dp)
                                )
                                .clickable { showThemeDropdown = true }
                                .padding(horizontal = 12.dp, vertical = 6.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = currentTheme,
                                    style = AppTypography.paragraphRegular,
                                    color = NeutralColors.Neutral40
                                )
                                Icon(
                                    painter = painterResource(id = R.drawable.down2),
                                    contentDescription = null,
                                    tint = NeutralColors.Neutral40,
                                    modifier = Modifier
                                        .padding(start = 4.dp)
                                        .size(14.dp)
                                )
                            }
                        }

                        // Theme dropdown menu
                        DropdownMenu(
                            expanded = showThemeDropdown,
                            onDismissRequest = { showThemeDropdown = false },
                            modifier = Modifier
                                .background(MaterialTheme.colorScheme.surface)
                                .width(200.dp)
                        ) {
                            DropdownMenuItem(
                                text = {
                                    Text(
                                        text = ThemeManager.THEME_LIGHT,
                                        style = AppTypography.paragraphRegular,
                                        color = if (currentTheme == ThemeManager.THEME_LIGHT)
                                            MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                },
                                onClick = {
                                    ThemeManager.setTheme(context, ThemeManager.THEME_LIGHT)
                                    showThemeDropdown = false
                                }
                            )
                            DropdownMenuItem(
                                text = {
                                    Text(
                                        text = ThemeManager.THEME_DARK,
                                        style = AppTypography.paragraphRegular,
                                        color = if (currentTheme == ThemeManager.THEME_DARK)
                                            MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                },
                                onClick = {
                                    ThemeManager.setTheme(context, ThemeManager.THEME_DARK)
                                    showThemeDropdown = false
                                }
                            )
                            DropdownMenuItem(
                                text = {
                                    Text(
                                        text = ThemeManager.THEME_SYSTEM,
                                        style = AppTypography.paragraphRegular,
                                        color = if (currentTheme == ThemeManager.THEME_SYSTEM)
                                            MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                },
                                onClick = {
                                    ThemeManager.setTheme(context, ThemeManager.THEME_SYSTEM)
                                    showThemeDropdown = false
                                }
                            )
                        }
                    }
                }

                Divider(color = MaterialTheme.colorScheme.outlineVariant, thickness = 1.dp)

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = strings.language,
                        style = AppTypography.heading5Medium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Box {
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(12.dp))
                                .clickable { showLanguageDropdown = true }
                                .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(12.dp))
                                .padding(horizontal = 12.dp, vertical = 6.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = currentLanguage,
                                    style = AppTypography.paragraphRegular,
                                    color = NeutralColors.Neutral40
                                )
                                Icon(
                                    painter = painterResource(id = R.drawable.down2),
                                    contentDescription = null,
                                    tint = NeutralColors.Neutral40,
                                    modifier = Modifier
                                        .padding(start = 4.dp)
                                        .size(14.dp)
                                )
                            }
                        }

                        // Language dropdown menu
                        DropdownMenu(
                            expanded = showLanguageDropdown,
                            onDismissRequest = { showLanguageDropdown = false },
                            modifier = Modifier
                                .background(MaterialTheme.colorScheme.surface)
                                .width(150.dp)
                        ) {
                            DropdownMenuItem(
                                text = {
                                    Text(
                                        text = LanguageManager.LANGUAGE_ENGLISH,
                                        style = AppTypography.paragraphRegular,
                                        color = if (currentLanguage == LanguageManager.LANGUAGE_ENGLISH)
                                            MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                },
                                onClick = {
                                    LanguageManager.setLanguage(context, LanguageManager.LANGUAGE_ENGLISH)
                                    showLanguageDropdown = false
                                }
                            )
                            DropdownMenuItem(
                                text = {
                                    Text(
                                        text = LanguageManager.LANGUAGE_INDONESIAN,
                                        style = AppTypography.paragraphRegular,
                                        color = if (currentLanguage == LanguageManager.LANGUAGE_INDONESIAN)
                                            MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                },
                                onClick = {
                                    LanguageManager.setLanguage(context, LanguageManager.LANGUAGE_INDONESIAN)
                                    showLanguageDropdown = false
                                }
                            )
                        }
                    }
                }

                Divider(color =  MaterialTheme.colorScheme.outlineVariant, thickness = 1.dp)

                // Logout Option
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { showLogoutDialog = true }
                        .padding(vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = strings.logout,
                        style = AppTypography.heading5Medium,
                        color = NeutralColors.Neutral40,
                    )
                    Icon(
                        painter = painterResource(id = R.drawable.down2),
                        contentDescription = null,
                        tint = NeutralColors.Neutral40,
                        modifier = Modifier.size(16.dp),
                    )
                }

                // About Section
                Text(
                    text = strings.about,
                    style = AppTypography.heading4Bold,
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    modifier = Modifier.padding(top = 24.dp, bottom = 8.dp)
                )

                // FAQ Item - Updated to navigate to FAQ Screen
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onNavigateToFAQ() }
                        .padding(vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "FAQ",
                        style = AppTypography.heading5Medium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Icon(
                        painter = painterResource(id = R.drawable.right2),
                        contentDescription = "Navigate to FAQ",
                        tint = MaterialTheme.colorScheme.outline,
                        modifier = Modifier.size(16.dp),
                    )
                }

                Divider(color = MaterialTheme.colorScheme.outlineVariant, thickness = 1.dp)
            }
        }

        // Bottom Navigation Bar
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .height(60.dp)
                .align(Alignment.BottomCenter),
            color = MaterialTheme.colorScheme.surface,
        ) {
            BottomNavigation(
                currentRoute = currentRoute,
                onNavigate = { route ->
                    when (route) {
                        "home" -> onHomeClick()
                        "votes" -> onVotesClick()
                        "profile" -> { /* Already on profile */}
                    }
                }
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun ProfileScreenPreview() {
    MaterialTheme {
        ProfileScreen(
            navController = rememberNavController()
        )
    }
}