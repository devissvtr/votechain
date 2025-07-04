package com.nocturna.votechain.ui.screens.profilepage

import android.util.Log
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import com.nocturna.votechain.R
import com.nocturna.votechain.blockchain.BlockchainManager
import com.nocturna.votechain.data.repository.UserLoginRepository
import com.nocturna.votechain.security.CryptoKeyManager
import com.nocturna.votechain.ui.theme.AppTypography
import com.nocturna.votechain.ui.theme.DangerColors
import com.nocturna.votechain.ui.theme.MainColors
import com.nocturna.votechain.ui.theme.NeutralColors
import com.nocturna.votechain.ui.theme.SuccessColors
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.web3j.crypto.ECKeyPair
import org.web3j.crypto.Keys
import java.math.BigInteger

// Data class untuk validasi result
data class WalletValidationResult(
    val isValid: Boolean,
    val publicKey: String?,
    val voterAddress: String?,
    val errorMessage: String?
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImportWalletScreen(
    navController: NavController,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val userLoginRepository = remember { UserLoginRepository(context) }
    val cryptoKeyManager = remember { CryptoKeyManager(context) }
    val coroutineScope = rememberCoroutineScope()

    // State variables
    var privateKeyInput by remember { mutableStateOf("") }
    var showPrivateKey by remember { mutableStateOf(false) }
    var isImporting by remember { mutableStateOf(false) }
    var importSuccess by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var showValidationInfo by remember { mutableStateOf(false) }
    var validationResults by remember { mutableStateOf<WalletValidationResult?>(null) }

    // Scroll state
    val scrollState = rememberScrollState()

    // Function untuk validasi private key
    fun validatePrivateKey(privateKey: String): WalletValidationResult {
        return try {
            // Remove whitespace and common prefixes
            val cleanedKey = privateKey.trim()
                .removePrefix("0x")
                .removePrefix("0X")

            // Check if it's a valid hex string with correct length
            if (cleanedKey.length != 64) {
                return WalletValidationResult(
                    isValid = false,
                    publicKey = null,
                    voterAddress = null,
                    errorMessage = "Private key harus 64 karakter (32 bytes)"
                )
            }

            if (!cleanedKey.matches(Regex("^[0-9a-fA-F]+$"))) {
                return WalletValidationResult(
                    isValid = false,
                    publicKey = null,
                    voterAddress = null,
                    errorMessage = "Private key hanya boleh mengandung karakter hex (0-9, a-f)"
                )
            }

            // Convert to BigInteger and validate range
            val privateKeyBigInt = BigInteger(cleanedKey, 16)
            val maxValidKey = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 16)

            if (privateKeyBigInt <= BigInteger.ZERO || privateKeyBigInt >= maxValidKey) {
                return WalletValidationResult(
                    isValid = false,
                    publicKey = null,
                    voterAddress = null,
                    errorMessage = "Private key berada di luar range yang valid"
                )
            }

            // Generate ECKeyPair and derive public key and address
            val ecKeyPair = ECKeyPair.create(privateKeyBigInt)
            val publicKey = Keys.getAddress(ecKeyPair.publicKey)
            val voterAddress = "0x$publicKey"

            WalletValidationResult(
                isValid = true,
                publicKey = publicKey,
                voterAddress = voterAddress,
                errorMessage = null
            )
        } catch (e: Exception) {
            Log.e("ImportWallet", "Error validating private key", e)
            WalletValidationResult(
                isValid = false,
                publicKey = null,
                voterAddress = null,
                errorMessage = "Format private key tidak valid: ${e.message}"
            )
        }
    }

    // Function untuk import wallet
    fun importWallet() {
        coroutineScope.launch {
            try {
                isImporting = true
                errorMessage = null

                // Validate private key
                val validation = validatePrivateKey(privateKeyInput)
                if (!validation.isValid) {
                    errorMessage = validation.errorMessage
                    return@launch
                }

                val cleanedPrivateKey = privateKeyInput.trim().removePrefix("0x").removePrefix("0X")
                val publicKey = validation.publicKey!!
                val voterAddress = validation.voterAddress!!

                // Store in CryptoKeyManager
                val keyPairInfo = CryptoKeyManager.KeyPairInfo(
                    publicKey = publicKey,
                    privateKey = cleanedPrivateKey,
                    voterAddress = voterAddress,
                    generationMethod = "Manual_Import"
                )

                cryptoKeyManager.storeKeyPair(keyPairInfo)

                // Store backup in UserLoginRepository
                val userEmail = userLoginRepository.getUserEmail()
                if (userEmail != null) {
                    userLoginRepository.storePrivateKey(userEmail, cleanedPrivateKey)
                    userLoginRepository.storePublicKey(userEmail, publicKey)
                }

                // Store locally untuk quick access
                val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", android.content.Context.MODE_PRIVATE)
                with(sharedPreferences.edit()) {
                    putString("voter_address", voterAddress)
                    putString("voter_public_key", publicKey)
                    putLong("wallet_import_timestamp", System.currentTimeMillis())
                    apply()
                }

                // Try to get balance
                try {
                    val balance = BlockchainManager.getAccountBalance(voterAddress)
                    with(sharedPreferences.edit()) {
                        putString("cached_balance", balance)
                        putLong("last_balance_update", System.currentTimeMillis())
                        apply()
                    }
                } catch (e: Exception) {
                    Log.w("ImportWallet", "Failed to fetch balance: ${e.message}")
                    // Set default balance
                    with(sharedPreferences.edit()) {
                        putString("cached_balance", "0.00000000")
                        putLong("last_balance_update", System.currentTimeMillis())
                        apply()
                    }
                }

                Log.d("ImportWallet", "✅ Wallet imported successfully")
                Log.d("ImportWallet", "Public Key: $publicKey")
                Log.d("ImportWallet", "Voter Address: $voterAddress")

                importSuccess = true

                // Show success message
                Toast.makeText(
                    context,
                    "Wallet berhasil diimpor!",
                    Toast.LENGTH_SHORT
                ).show()

                // Navigate back after a short delay
                delay(1500)
                navController.popBackStack()

            } catch (e: Exception) {
                Log.e("ImportWallet", "Error importing wallet", e)
                errorMessage = "Gagal mengimpor wallet: ${e.message}"
            } finally {
                isImporting = false
            }
        }
    }

    // Validate on input change
    LaunchedEffect(privateKeyInput) {
        if (privateKeyInput.isNotBlank()) {
            validationResults = validatePrivateKey(privateKeyInput)
            showValidationInfo = true
        } else {
            validationResults = null
            showValidationInfo = false
        }
    }

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
                text = "Import Wallet",
                style = AppTypography.heading3Bold,
                color = MaterialTheme.colorScheme.onBackground
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Warning Card
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            colors = CardDefaults.cardColors(
                containerColor = DangerColors.Danger10
            ),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(
                modifier = Modifier.padding(16.dp)
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        painter = painterResource(R.drawable.infosquare),
                        contentDescription = "Warning",
                        tint = DangerColors.Danger50,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Peringatan Keamanan",
                        style = AppTypography.paragraphBold,
                        color = DangerColors.Danger50
                    )
                }

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "• Jangan pernah membagikan private key Anda kepada siapapun\n" +
                            "• Pastikan Anda berada di tempat yang aman dan privat\n" +
                            "• Private key akan disimpan dengan enkripsi tingkat tinggi\n" +
                            "• Backup private key Anda di tempat yang aman",
                    style = AppTypography.smallParagraphRegular,
                    color = DangerColors.Danger70
                )
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Import Form
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
                    text = "Import dengan Private Key",
                    style = AppTypography.heading4Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )

                Spacer(modifier = Modifier.height(16.dp))

                // Private Key Input
                OutlinedTextField(
                    value = privateKeyInput,
                    onValueChange = { privateKeyInput = it },
                    label = {
                        Text(
                            "Private Key",
                            style = AppTypography.paragraphMedium
                        )
                    },
                    placeholder = {
                        Text(
                            "Masukkan 64-digit private key",
                            style = AppTypography.paragraphMedium,
                            color = NeutralColors.Neutral40
                        )
                    },
                    visualTransformation = if (showPrivateKey) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    },
                    trailingIcon = {
                        IconButton(
                            onClick = { showPrivateKey = !showPrivateKey }
                        ) {
                            Icon(
                                painter = painterResource(
                                    if (showPrivateKey) R.drawable.hide
                                    else R.drawable.show
                                ),
                                contentDescription = if (showPrivateKey) "Hide" else "Show",
                                tint = NeutralColors.Neutral50
                            )
                        }
                    },
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Text
                    ),
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MainColors.Primary1,
                        unfocusedBorderColor = NeutralColors.Neutral30
                    ),
                    singleLine = false,
                    maxLines = 3
                )

                Spacer(modifier = Modifier.height(12.dp))

                // Format Help
                Text(
                    text = "Format: 64 karakter hex (0-9, a-f) tanpa atau dengan prefix 0x",
                    style = AppTypography.paragraphMedium,
                    color = NeutralColors.Neutral50
                )

                // Validation Results
                if (showValidationInfo && validationResults != null) {
                    Spacer(modifier = Modifier.height(16.dp))

                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = if (validationResults!!.isValid) {
                                SuccessColors.Success10
                            } else {
                                DangerColors.Danger10
                            }
                        ),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = if (validationResults!!.isValid) {
                                        "Private key valid"
                                    } else {
                                        "Private key tidak valid"
                                    },
                                    style = AppTypography.paragraphRegular,
                                    color = if (validationResults!!.isValid) {
                                        SuccessColors.Success70
                                    } else {
                                        DangerColors.Danger70
                                    }
                                )
                            }

                            if (!validationResults!!.isValid && validationResults!!.errorMessage != null) {
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(
                                    text = validationResults!!.errorMessage!!,
                                    style = AppTypography.paragraphRegular,
                                    color = DangerColors.Danger60
                                )
                            }

                            if (validationResults!!.isValid) {
                                Spacer(modifier = Modifier.height(8.dp))
                                Text(
                                    text = "Alamat wallet: ${validationResults!!.voterAddress}",
                                    style = AppTypography.paragraphRegular,
                                    color = SuccessColors.Success70
                                )
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                // Import Button
                Button(
                    onClick = { importWallet() },
                    enabled = !isImporting &&
                            privateKeyInput.isNotBlank() &&
                            validationResults?.isValid == true,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MainColors.Primary1,
                        disabledContainerColor = NeutralColors.Neutral30
                    ),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    if (isImporting) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                color = Color.White,
                                strokeWidth = 2.dp
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                "Mengimpor...",
                                style = AppTypography.paragraphRegular,
                                color = Color.White
                            )
                        }
                    } else {
                        Text(
                            "Import Wallet",
                            style = AppTypography.paragraphRegular,
                            color = Color.White
                        )
                    }
                }

                // Error Message
                if (errorMessage != null) {
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
                            Text(
                                text = errorMessage!!,
                                style = AppTypography.paragraphRegular,
                                color = DangerColors.Danger70
                            )
                        }
                    }
                }

                // Success Message
                if (importSuccess) {
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
                            Text(
                                text = "Wallet berhasil diimpor! Mengarahkan kembali...",
                                style = AppTypography.paragraphRegular,
                                color = SuccessColors.Success70
                            )
                        }
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        // Instructions Card
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
                    text = "Petunjuk Import Wallet",
                    style = AppTypography.heading4Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )

                Spacer(modifier = Modifier.height(12.dp))

                Column(
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    InstructionItem(
                        number = "1",
                        text = "Pastikan private key Anda memiliki format yang benar (64 karakter hex)"
                    )
                    InstructionItem(
                        number = "2",
                        text = "Private key dapat dimulai dengan '0x' atau tanpa prefix"
                    )
                    InstructionItem(
                        number = "3",
                        text = "Aplikasi akan memverifikasi dan menampilkan alamat wallet yang sesuai"
                    )
                    InstructionItem(
                        number = "4",
                        text = "Setelah berhasil, data wallet akan tersimpan dengan aman di device Anda"
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(32.dp))
    }
}

@Composable
private fun InstructionItem(
    number: String,
    text: String
) {
    Row(
        modifier = Modifier.fillMaxWidth()
    ) {
        Box(
            modifier = Modifier
                .size(24.dp)
                .background(
                    MainColors.Primary1,
                    shape = RoundedCornerShape(12.dp)
                ),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = number,
                style = AppTypography.paragraphBold,
                color = Color.White
            )
        }

        Spacer(modifier = Modifier.width(12.dp))

        Text(
            text = text,
            style = AppTypography.paragraphBold,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.weight(1f)
        )
    }
}