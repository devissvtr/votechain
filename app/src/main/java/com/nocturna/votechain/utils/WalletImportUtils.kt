package com.nocturna.votechain.utils

import android.content.Context
import android.util.Log
import com.nocturna.votechain.blockchain.BlockchainManager
import com.nocturna.votechain.data.repository.UserLoginRepository
import com.nocturna.votechain.security.CryptoKeyManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.web3j.crypto.ECKeyPair
import org.web3j.crypto.Keys
import org.web3j.utils.Numeric
import java.math.BigInteger

/**
 * Utility class untuk menangani import wallet dan validasi private key
 */
object WalletImportUtils {
    private const val TAG = "WalletImportUtils"

    data class ImportResult(
        val success: Boolean,
        val message: String,
        val publicKey: String? = null,
        val voterAddress: String? = null,
        val balance: String? = null
    )

    data class ValidationResult(
        val isValid: Boolean,
        val publicKey: String? = null,
        val voterAddress: String? = null,
        val errorMessage: String? = null
    )

    /**
     * Validasi private key dan derive public key & address
     */
    fun validatePrivateKey(privateKey: String): ValidationResult {
        return try {
            val cleanedKey = cleanPrivateKey(privateKey)

            // Validasi format dan panjang
            if (cleanedKey.length != 64) {
                return ValidationResult(
                    false,
                    errorMessage = "Private key harus 64 karakter (32 bytes)"
                )
            }

            if (!cleanedKey.matches(Regex("^[0-9a-fA-F]+$"))) {
                return ValidationResult(
                    false,
                    errorMessage = "Private key hanya boleh mengandung karakter hex (0-9, a-f)"
                )
            }

            // Validasi range
            val privateKeyBigInt = BigInteger(cleanedKey, 16)
            val maxValidKey = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 16)

            if (privateKeyBigInt <= BigInteger.ZERO || privateKeyBigInt >= maxValidKey) {
                return ValidationResult(
                    false,
                    errorMessage = "Private key berada di luar range yang valid"
                )
            }

            // Generate key pair dan derive address
            val ecKeyPair = ECKeyPair.create(privateKeyBigInt)
            val publicKey = Keys.getAddress(ecKeyPair.publicKey)
            val voterAddress = "0x$publicKey"

            ValidationResult(
                isValid = true,
                publicKey = publicKey,
                voterAddress = voterAddress
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error validating private key", e)
            ValidationResult(
                false,
                errorMessage = "Format private key tidak valid: ${e.localizedMessage}"
            )
        }
    }

    /**
     * Import wallet dengan private key
     */
    suspend fun importWallet(
        context: Context,
        privateKey: String,
        userEmail: String? = null
    ): ImportResult = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Starting wallet import process")

            // Validasi private key
            val validation = validatePrivateKey(privateKey)
            if (!validation.isValid) {
                return@withContext ImportResult(
                    success = false,
                    message = validation.errorMessage ?: "Validasi gagal"
                )
            }

            val cleanedPrivateKey = cleanPrivateKey(privateKey)
            val publicKey = validation.publicKey!!
            val voterAddress = validation.voterAddress!!

            // Initialize repositories
            val cryptoKeyManager = CryptoKeyManager(context)
            val userLoginRepository = UserLoginRepository(context)

            // Store di CryptoKeyManager (primary storage)
            val keyPairInfo = CryptoKeyManager.KeyPairInfo(
                publicKey = publicKey,
                privateKey = cleanedPrivateKey,
                voterAddress = voterAddress,
                generationMethod = "Manual_Import_${System.currentTimeMillis()}"
            )

            cryptoKeyManager.storeKeyPair(keyPairInfo)
            Log.d(TAG, "✅ Keys stored in CryptoKeyManager")

            // Store backup di UserLoginRepository
            val emailForBackup = userEmail ?: userLoginRepository.getUserEmail()
            if (emailForBackup != null) {
                userLoginRepository.storePrivateKey(emailForBackup, cleanedPrivateKey)
                userLoginRepository.storePublicKey(emailForBackup, publicKey)
                Log.d(TAG, "✅ Keys backed up in UserLoginRepository")
            } else {
                Log.w(TAG, "⚠️ No email available for backup storage")
            }

            // Get balance dari blockchain
            val balance = try {
                BlockchainManager.getAccountBalance(voterAddress)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to fetch balance: ${e.message}")
                "0.00000000"
            }

            // Store di SharedPreferences untuk quick access
            storeWalletDataLocally(context, voterAddress, publicKey, balance)

            Log.d(TAG, "✅ Wallet import completed successfully")
            Log.d(TAG, "Public Key: $publicKey")
            Log.d(TAG, "Voter Address: $voterAddress")
            Log.d(TAG, "Balance: $balance ETH")

            ImportResult(
                success = true,
                message = "Wallet berhasil diimpor",
                publicKey = publicKey,
                voterAddress = voterAddress,
                balance = balance
            )

        } catch (e: Exception) {
            Log.e(TAG, "Error importing wallet", e)
            ImportResult(
                success = false,
                message = "Gagal mengimpor wallet: ${e.localizedMessage}"
            )
        }
    }

    /**
     * Check apakah wallet data ada dan lengkap
     */
    fun isWalletDataComplete(context: Context): Boolean {
        return try {
            val cryptoKeyManager = CryptoKeyManager(context)
            val privateKey = cryptoKeyManager.getPrivateKey()
            val publicKey = cryptoKeyManager.getPublicKey()
            val voterAddress = cryptoKeyManager.getVoterAddress()

            !privateKey.isNullOrEmpty() &&
                    !publicKey.isNullOrEmpty() &&
                    !voterAddress.isNullOrEmpty()
        } catch (e: Exception) {
            Log.e(TAG, "Error checking wallet data completeness", e)
            false
        }
    }

    /**
     * Get wallet recovery info untuk user
     */
    fun getWalletRecoveryInfo(context: Context): WalletRecoveryInfo {
        val cryptoKeyManager = CryptoKeyManager(context)
        val userLoginRepository = UserLoginRepository(context)

        return WalletRecoveryInfo(
            hasPrimaryKeys = !cryptoKeyManager.getPrivateKey().isNullOrEmpty(),
            hasBackupKeys = run {
                val email = userLoginRepository.getUserEmail()
                email != null && !userLoginRepository.getPrivateKey(email).isNullOrEmpty()
            },
            lastKeyGeneration = getLastKeyGenerationTime(context),
            voterAddress = cryptoKeyManager.getVoterAddress()
        )
    }

    /**
     * Restore wallet dari backup jika primary keys hilang
     */
    suspend fun restoreFromBackup(context: Context): ImportResult = withContext(Dispatchers.IO) {
        try {
            val userLoginRepository = UserLoginRepository(context)
            val email = userLoginRepository.getUserEmail()

            if (email == null) {
                return@withContext ImportResult(
                    success = false,
                    message = "Email pengguna tidak ditemukan"
                )
            }

            val backupPrivateKey = userLoginRepository.getPrivateKey(email)
            val backupPublicKey = userLoginRepository.getPublicKey(email)

            if (backupPrivateKey == null || backupPublicKey == null) {
                return@withContext ImportResult(
                    success = false,
                    message = "Backup keys tidak ditemukan"
                )
            }

            // Import dari backup
            importWallet(context, backupPrivateKey, email)
        } catch (e: Exception) {
            Log.e(TAG, "Error restoring from backup", e)
            ImportResult(
                success = false,
                message = "Gagal memulihkan dari backup: ${e.localizedMessage}"
            )
        }
    }

    /**
     * Clean private key dari whitespace dan prefix
     */
    private fun cleanPrivateKey(privateKey: String): String {
        return privateKey.trim()
            .removePrefix("0x")
            .removePrefix("0X")
            .lowercase()
    }

    /**
     * Store wallet data locally untuk quick access
     */
    private fun storeWalletDataLocally(
        context: Context,
        voterAddress: String,
        publicKey: String,
        balance: String
    ) {
        try {
            val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
            with(sharedPreferences.edit()) {
                putString("voter_address", voterAddress)
                putString("voter_public_key", publicKey)
                putString("cached_balance", balance)
                putLong("last_balance_update", System.currentTimeMillis())
                putLong("wallet_import_timestamp", System.currentTimeMillis())
                apply()
            }
            Log.d(TAG, "✅ Wallet data stored locally")
        } catch (e: Exception) {
            Log.e(TAG, "Error storing wallet data locally", e)
        }
    }

    /**
     * Get timestamp dari last key generation
     */
    private fun getLastKeyGenerationTime(context: Context): Long {
        return try {
            val sharedPreferences = context.getSharedPreferences("VoteChainPrefs", Context.MODE_PRIVATE)
            sharedPreferences.getLong("wallet_import_timestamp", 0)
        } catch (e: Exception) {
            0L
        }
    }

    data class WalletRecoveryInfo(
        val hasPrimaryKeys: Boolean,
        val hasBackupKeys: Boolean,
        val lastKeyGeneration: Long,
        val voterAddress: String?
    )
}