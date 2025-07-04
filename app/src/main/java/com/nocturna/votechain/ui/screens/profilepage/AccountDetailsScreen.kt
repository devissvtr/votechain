package com.nocturna.votechain.ui.screens.profilepage

import android.util.Log
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.ClipboardManager
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.nocturna.votechain.R
import com.nocturna.votechain.VoteChainApplication
import com.nocturna.votechain.data.model.AccountDisplayData
import com.nocturna.votechain.data.repository.UserLoginRepository
import com.nocturna.votechain.data.repository.UserProfileRepository
import com.nocturna.votechain.data.repository.VoterRepository
import com.nocturna.votechain.security.CryptoKeyManager
import com.nocturna.votechain.ui.screens.LoadingScreen
import com.nocturna.votechain.ui.screens.login.LoginScreen
import com.nocturna.votechain.ui.theme.AppTypography
import com.nocturna.votechain.ui.theme.DangerColors
import com.nocturna.votechain.ui.theme.MainColors
import com.nocturna.votechain.ui.theme.NeutralColors
import com.nocturna.votechain.ui.theme.SuccessColors
import com.nocturna.votechain.utils.LanguageManager
import com.nocturna.votechain.utils.WalletImportUtils
import com.nocturna.votechain.viewmodel.login.LoginViewModel
import com.nocturna.votechain.viewmodel.login.LoginViewModel.KeyIntegrityStatus
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AccountDetailsScreen(
    navController: NavController,
    modifier: Modifier = Modifier,
    onLogout: () -> Unit = {}
) {
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    val coroutineScope = rememberCoroutineScope()

    // Repositories
    val userProfileRepository = remember { UserProfileRepository(context) }
    val userLoginRepository = remember { UserLoginRepository(context) }
    val voterRepository = remember { VoterRepository(context) }

    // State variables
    var accountData by remember { mutableStateOf(AccountDisplayData()) }
    var isLoading by remember { mutableStateOf(true) }
    var showPrivateKey by remember { mutableStateOf(false) }
    var showPublicKey by remember { mutableStateOf(false) }
    var showPasswordDialog by remember { mutableStateOf(false) }
    var showImportWalletDialog by remember { mutableStateOf(false) }
    var showRestoreDialog by remember { mutableStateOf(false) }
    var walletRecoveryInfo by remember { mutableStateOf<WalletImportUtils.WalletRecoveryInfo?>(null) }

    // Load account data
    LaunchedEffect(Unit) {
        try {
            isLoading = true

            // Check wallet recovery info
            walletRecoveryInfo = WalletImportUtils.getWalletRecoveryInfo(context)

            // Get user email
            val userEmail = userLoginRepository.getUserEmail()

            // Attempt to repair keys if needed
            if (!walletRecoveryInfo!!.hasPrimaryKeys && walletRecoveryInfo!!.hasBackupKeys) {
                Log.d("AccountDetails", "🔧 Attempting to restore keys from backup...")
                try {
                    val restoreResult = WalletImportUtils.restoreFromBackup(context)
                    if (restoreResult.success) {
                        Log.d("AccountDetails", "✅ Keys restored from backup")
                        // Refresh recovery info
                        walletRecoveryInfo = WalletImportUtils.getWalletRecoveryInfo(context)
                    }
                } catch (e: Exception) {
                    Log.e("AccountDetails", "❌ Error during key restoration: ${e.message}")
                }
            }

            // Load profile data
            userProfileRepository.fetchCompleteUserProfile().fold(
                onSuccess = { profile ->
                    Log.d("AccountDetails", "✅ Profile data loaded")

                    // Get wallet info with enhanced verification
                    val walletInfo = voterRepository.getCompleteWalletInfo()

                    // Get crypto keys with verification
                    val cryptoKeyManager = CryptoKeyManager(context)
                    var privateKey = cryptoKeyManager.getPrivateKey()
                    var publicKey = cryptoKeyManager.getPublicKey()
                    var voterAddress = cryptoKeyManager.getVoterAddress()

                    // Fallback to backup storage if keys not available
                    if (privateKey.isNullOrEmpty() && userEmail != null) {
                        Log.w("AccountDetails", "🔧 Primary keys empty, checking backup storage...")

                        val backupPrivateKey = userLoginRepository.getPrivateKey(userEmail)
                        val backupPublicKey = userLoginRepository.getPublicKey(userEmail)

                        if (backupPrivateKey != null && backupPublicKey != null) {
                            Log.d("AccountDetails", "✅ Found keys in backup storage")
                            privateKey = backupPrivateKey
                            publicKey = backupPublicKey

                            // Try to restore to primary storage
                            try {
                                val keyPairInfo = CryptoKeyManager.KeyPairInfo(
                                    publicKey = backupPublicKey,
                                    privateKey = backupPrivateKey,
                                    voterAddress = "0x$backupPublicKey",
                                    generationMethod = "Profile_Backup_Restoration"
                                )
                                cryptoKeyManager.storeKeyPair(keyPairInfo)
                                voterAddress = "0x$backupPublicKey"
                                Log.d("AccountDetails", "✅ Keys restored to primary storage")
                            } catch (e: Exception) {
                                Log.e("AccountDetails", "❌ Failed to restore keys: ${e.message}")
                            }
                        } else {
                            Log.e("AccountDetails", "❌ No keys found in backup storage either")
                        }
                    }

                    // Update account data
                    accountData = AccountDisplayData(
                        fullName = profile.voterProfile?.full_name ?: "N/A",
                        nik = profile.voterProfile?.nik ?: "N/A",
                        email = profile.userProfile?.email ?: userEmail ?: "",
                        ethBalance = walletInfo.balance,
                        publicKey = publicKey ?: "",
                        privateKey = privateKey ?: "",
                        voterAddress = voterAddress ?: walletInfo.voterAddress,
                        hasVoted = profile.voterProfile?.has_voted ?: false,
                        isDataLoading = false,
                        errorMessage = if (walletInfo.hasError) walletInfo.errorMessage else null
                    )
                },
                onFailure = { error ->
                    Log.e("AccountDetails", "Error loading profile: ${error.message}")
                    accountData = AccountDisplayData(
                        isDataLoading = false,
                        errorMessage = "Failed to load account data: ${error.message}"
                    )
                }
            )
        } finally {
            isLoading = false
        }
    }

    if (isLoading) {
        LoadingScreen(onClose = { /* Do nothing during loading */ })
        return
    }

    if (accountData.errorMessage != null) {
        Column(
            modifier = Modifier.fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = "Error: ${accountData.errorMessage}",
                style = AppTypography.paragraphRegular,
                color = DangerColors.Danger50,
                textAlign = TextAlign.Center
            )
            Spacer(modifier = Modifier.height(16.dp))
            Button(
                onClick = { navController.popBackStack() }
            ) {
                Text("Go Back")
            }
        }
        return
    }

    val scrollState = rememberScrollState()

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .verticalScroll(scrollState)
    ) {
        // Top Bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(
                onClick = { navController.popBackStack() }
            ) {
                Icon(
                    painter = painterResource(R.drawable.back),
                    contentDescription = "Back",
                    tint = MaterialTheme.colorScheme.onBackground
                )
            }

            Spacer(modifier = Modifier.width(8.dp))

            Text(
                text = "Account Details",
                style = AppTypography.heading3Bold,
                color = MaterialTheme.colorScheme.onBackground
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // User Info Card
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surface
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Text(
                    text = "User Information",
                    style = AppTypography.heading4Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )

                Spacer(modifier = Modifier.height(16.dp))

                InfoRow("Full Name", accountData.fullName)
                InfoRow("NIK", accountData.nik)
                InfoRow("Email", accountData.email)
                InfoRow("Voting Status", if (accountData.hasVoted) "Voted" else "Not Voted")
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Wallet Status Card
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surface
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Wallet Status",
                        style = AppTypography.heading4Bold,
                        color = MaterialTheme.colorScheme.onSurface
                    )

                    Spacer(modifier = Modifier.weight(1f))

                    // Status indicator
                    val isWalletComplete = WalletImportUtils.isWalletDataComplete(context)
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = if (isWalletComplete) {
                                SuccessColors.Success10
                            } else {
                                DangerColors.Danger10
                            }
                        ),
                        shape = RoundedCornerShape(16.dp)
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                painter = painterResource(
                                    if (isWalletComplete) R.drawable.tickcircle
                                    else R.drawable.dangercircle
                                ),
                                contentDescription = null,
                                tint = if (isWalletComplete) {
                                    SuccessColors.Success50
                                } else {
                                    DangerColors.Danger50
                                },
                                modifier = Modifier.size(12.dp)
                            )
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                text = if (isWalletComplete) "Complete" else "Incomplete",
                                style = AppTypography.paragraphRegular,
                                color = if (isWalletComplete) {
                                    SuccessColors.Success70
                                } else {
                                    DangerColors.Danger70
                                }
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Balance
                InfoRow("Balance", "${accountData.ethBalance} ETH")

                // Voter Address
                InfoRowCopyable(
                    label = "Voter Address",
                    value = accountData.voterAddress,
                    onCopy = {
                        clipboardManager.setText(AnnotatedString(accountData.voterAddress))
                        Toast.makeText(context, "Voter address copied!", Toast.LENGTH_SHORT).show()
                    }
                )

                // Public Key
                InfoRowCopyable(
                    label = "Public Key",
                    value = accountData.publicKey,
                    isSecret = !showPublicKey,
                    onToggleVisibility = { showPublicKey = !showPublicKey },
                    onCopy = {
                        clipboardManager.setText(AnnotatedString(accountData.publicKey))
                        Toast.makeText(context, "Public key copied!", Toast.LENGTH_SHORT).show()
                    }
                )

                // Private Key
                InfoRowCopyable(
                    label = "Private Key",
                    value = accountData.privateKey,
                    isSecret = !showPrivateKey,
                    onToggleVisibility = { showPasswordDialog = true },
                    onCopy = {
                        if (showPrivateKey) {
                            clipboardManager.setText(AnnotatedString(accountData.privateKey))
                            Toast.makeText(context, "Private key copied!", Toast.LENGTH_SHORT).show()
                        }
                    },
                    isPrivateKey = true
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Wallet Management Section
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surface
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Text(
                    text = "Wallet Management",
                    style = AppTypography.heading4Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "Kelola wallet Anda dengan aman. Jika data wallet hilang setelah reinstall, gunakan fitur import wallet.",
                    style = AppTypography.paragraphRegular,
                    color = NeutralColors.Neutral60
                )

                Spacer(modifier = Modifier.height(16.dp))

                // Check if wallet data is missing
                val isWalletDataMissing = accountData.privateKey.isEmpty() ||
                        accountData.publicKey.isEmpty() ||
                        !WalletImportUtils.isWalletDataComplete(context)

                if (isWalletDataMissing) {
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = DangerColors.Danger10
                        ),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                painter = painterResource(R.drawable.dangercircle),
                                contentDescription = "Warning",
                                tint = DangerColors.Danger50,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "Data wallet tidak lengkap. Import wallet untuk memulihkan data.",
                                style = AppTypography.paragraphMedium,
                                color = DangerColors.Danger70
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    // Import Wallet Button
                    OutlinedButton(
                        onClick = {
                            navController.navigate("import_wallet")
                        },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.outlinedButtonColors(
                            containerColor = Color.Transparent,
                            contentColor = MainColors.Primary1
                        ),
                        border = BorderStroke(1.dp, MainColors.Primary1),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Text(
                            text = "Import Wallet",
                            style = AppTypography.paragraphBold
                        )
                    }

                    // Auto Restore Button (if backup available)
                    if (walletRecoveryInfo?.hasBackupKeys == true && !walletRecoveryInfo!!.hasPrimaryKeys) {
                        OutlinedButton(
                            onClick = {
                                showRestoreDialog = true
                            },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.outlinedButtonColors(
                                containerColor = Color.Transparent,
                                contentColor = SuccessColors.Success50
                            ),
                            border = BorderStroke(1.dp, SuccessColors.Success50),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Text(
                                text = "Auto Restore",
                                style = AppTypography.paragraphBold
                            )
                        }
                    } else {
                        // Info Button
                        OutlinedButton(
                            onClick = { showImportWalletDialog = true },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.outlinedButtonColors(
                                containerColor = Color.Transparent,
                                contentColor = NeutralColors.Neutral60
                            ),
                            border = BorderStroke(1.dp, NeutralColors.Neutral30),
                            shape = RoundedCornerShape(8.dp)
                        ) {
                            Icon(
                                painter = painterResource(R.drawable.infosquare),
                                contentDescription = "Info",
                                tint = NeutralColors.Neutral60,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "Info Backup",
                                style = AppTypography.paragraphBold
                            )
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Logout Button
        Button(
            onClick = onLogout,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = DangerColors.Danger50
            ),
            shape = RoundedCornerShape(8.dp)
        ) {
            Text(
                text = "Logout",
                style = AppTypography.paragraphBold,
                color = Color.White
            )
        }

        Spacer(modifier = Modifier.height(32.dp))
    }

    if (showPasswordDialog) {
        PasswordConfirmationDialog(
            isOpen = showPasswordDialog,
            onCancel = { showPasswordDialog = false },
            onSubmit = {
                showPrivateKey = true
                showPasswordDialog = false
            },
            userLoginRepository = userLoginRepository
        )
    }

    // Import Wallet Info Dialog
    if (showImportWalletDialog) {
        AlertDialog(
            onDismissRequest = { showImportWalletDialog = false },
            title = {
                Text(
                    text = "Informasi Wallet Backup",
                    style = AppTypography.heading4Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
            },
            text = {
                Column {
                    Text(
                        text = "Untuk keamanan data wallet Anda:",
                        style = AppTypography.paragraphRegular,
                        color = MaterialTheme.colorScheme.onSurface
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    Text(
                        text = "• Simpan private key Anda di tempat yang aman\n" +
                                "• Jangan bagikan private key kepada siapapun\n" +
                                "• Gunakan fitur import wallet jika data hilang setelah reinstall\n" +
                                "• Private key dapat dilihat di section 'Private Key' di atas",
                        style = AppTypography.paragraphMedium,
                        color = NeutralColors.Neutral70
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = DangerColors.Danger10
                        ),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                painter = painterResource(R.drawable.infosquare),
                                contentDescription = "Warning",
                                tint = DangerColors.Danger50,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "Private key memberikan akses penuh ke wallet Anda. Jaga kerahasiaannya!",
                                style = AppTypography.paragraphMedium,
                                color = DangerColors.Danger70
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = { showImportWalletDialog = false }
                ) {
                    Text(
                        text = "Mengerti",
                        style = AppTypography.paragraphBold,
                        color = MainColors.Primary1
                    )
                }
            },
            containerColor = MaterialTheme.colorScheme.surface,
            shape = RoundedCornerShape(12.dp)
        )
    }

    // Auto Restore Confirmation Dialog
    if (showRestoreDialog) {
        AlertDialog(
            onDismissRequest = { showRestoreDialog = false },
            title = {
                Text(
                    text = "Auto Restore Wallet",
                    style = AppTypography.heading4Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
            },
            text = {
                Column {
                    Text(
                        text = "Ditemukan backup wallet di sistem. Apakah Anda ingin memulihkan wallet dari backup?",
                        style = AppTypography.paragraphMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = SuccessColors.Success10
                        ),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                painter = painterResource(R.drawable.infosquare),
                                contentDescription = "Info",
                                tint = SuccessColors.Success50,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "Proses ini akan memulihkan wallet dari backup yang tersimpan di akun Anda.",
                                style = AppTypography.paragraphRegular,
                                color = SuccessColors.Success70
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        coroutineScope.launch {
                            try {
                                val result = WalletImportUtils.restoreFromBackup(context)
                                if (result.success) {
                                    Toast.makeText(context, "Wallet berhasil dipulihkan!", Toast.LENGTH_SHORT).show()
                                    // Refresh the screen
                                    walletRecoveryInfo = WalletImportUtils.getWalletRecoveryInfo(context)
                                    // Reload account data
                                    val walletInfo = voterRepository.getCompleteWalletInfo()
                                    accountData = accountData.copy(
                                        ethBalance = walletInfo.balance,
                                        privateKey = result.publicKey ?: "",
                                        publicKey = result.publicKey ?: "",
                                        voterAddress = result.voterAddress ?: ""
                                    )
                                } else {
                                    Toast.makeText(context, "Gagal memulihkan wallet: ${result.message}", Toast.LENGTH_LONG).show()
                                }
                            } catch (e: Exception) {
                                Toast.makeText(context, "Error: ${e.localizedMessage}", Toast.LENGTH_LONG).show()
                            }
                        }
                        showRestoreDialog = false
                    }
                ) {
                    Text(
                        text = "Restore",
                        style = AppTypography.paragraphBold,
                        color = SuccessColors.Success50
                    )
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { showRestoreDialog = false }
                ) {
                    Text(
                        text = "Batal",
                        style = AppTypography.paragraphBold,
                        color = NeutralColors.Neutral60
                    )
                }
            },
            containerColor = MaterialTheme.colorScheme.surface,
            shape = RoundedCornerShape(12.dp)
        )
    }
}

@Composable
private fun InfoRow(
    label: String,
    value: String
) {
    Column(
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(
            text = label,
            style = AppTypography.paragraphMedium,
            color = NeutralColors.Neutral50
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = value,
            style = AppTypography.paragraphMedium,
            color = MaterialTheme.colorScheme.onSurface
        )
        Spacer(modifier = Modifier.height(12.dp))
    }
}

@Composable
private fun InfoRowCopyable(
    label: String,
    value: String,
    isSecret: Boolean = false,
    onToggleVisibility: (() -> Unit)? = null,
    onCopy: () -> Unit,
    isPrivateKey: Boolean = false
) {
    Column(
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(
            text = label,
            style = AppTypography.paragraphRegular,
            color = NeutralColors.Neutral50
        )
        Spacer(modifier = Modifier.height(4.dp))

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = if (isSecret) "••••••••••••••••" else value,
                style = AppTypography.paragraphMedium,
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.weight(1f)
            )

            if (onToggleVisibility != null) {
                IconButton(
                    onClick = onToggleVisibility,
                    modifier = Modifier.size(24.dp)
                ) {
                    Icon(
                        painter = painterResource(
                            if (isSecret) R.drawable.show else R.drawable.hide
                        ),
                        contentDescription = if (isSecret) "Show" else "Hide",
                        tint = NeutralColors.Neutral50,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }

            if (!isSecret || !isPrivateKey) {
                IconButton(
                    onClick = onCopy,
                    modifier = Modifier.size(24.dp)
                ) {
                    Icon(
                        painter = painterResource(R.drawable.copy),
                        contentDescription = "Copy",
                        tint = MainColors.Primary1,
                        modifier = Modifier.size(16.dp)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))
    }
}