package com.nocturna.votechain

import StartupInitializer
import android.app.Application
import android.content.ContentValues.TAG
import android.util.Log
import com.nocturna.votechain.blockchain.BlockchainManager
import com.nocturna.votechain.data.network.ElectionNetworkClient
import com.nocturna.votechain.data.network.NetworkClient
import com.nocturna.votechain.security.CryptoKeyManager
import com.nocturna.votechain.utils.CoilAuthHelper
import com.nocturna.votechain.utils.LanguageManager
import com.nocturna.votechain.utils.ThemeManager
import com.nocturna.votechain.utils.TokenManager
import com.nocturna.votechain.utils.TokenSyncUtil
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

/**
 * Custom Application class to initialize blockchain connection and language manager
 * Make sure to add this to AndroidManifest.xml with android:name=".VoteChainApplication"
 */
class VoteChainApplication : Application() {
    companion object {
        private const val TAG = "VoteChainApplication"

        lateinit var instance: VoteChainApplication
            private set
    }

    // Application scope untuk background operations
    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    // Startup initializer untuk key management
    private lateinit var startupInitializer: StartupInitializer

    override fun onCreate() {
        super.onCreate()

        scheduleKeyHealthChecks()

        instance = this

        Log.d(TAG, "🚀 VoteChain Application starting with enhanced key management...")

        // Initialize CryptoKeyManager BouncyCastle provider
        try {
            // Step 1: Initialize BouncyCastle provider
            initializeBouncyCastle()

            // Step 2: Initialize core components
            initializeCoreComponents()
            initializeLanguageManager()
            initializeThemeManager()

            // Step 3: Initialize network clients
            initializeNetworkClients()

            // Step 4: Initialize startup manager untuk crypto keys
            initializeStartupManager()

            Log.d(TAG, "✅ VoteChain Application initialized successfully")

        } catch (e: Exception) {
            Log.e(TAG, "❌ Error during application initialization: ${e.message}", e)
        }
    }

    /**
     * Initialize language manager
     */
    private fun initializeLanguageManager() {
        // Initialize with saved language preference (defaults to Indonesian)
        LanguageManager.initialize(this)
        Log.d(TAG, "✅ Language initialized to: ${LanguageManager.getLanguage(this)}")
    }

    /**
     * Initialize theme manager
     */
    private fun initializeThemeManager() {
        // Initialize with saved theme preference (defaults to Light Mode)
        ThemeManager.initialize(this)
        Log.d(TAG, "✅ Theme initialized to: ${ThemeManager.getTheme(this)}")
    }

    /**
     * Initialize BouncyCastle provider for cryptographic operations
     */
    private fun initializeBouncyCastle() {
        try {
            // Initialize CryptoKeyManager BouncyCastle provider
            CryptoKeyManager.initializeBouncyCastle()

            // Register BouncyCastle provider
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProvider())
                Log.d(TAG, "✅ BouncyCastle provider registered")
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Failed to initialize BouncyCastle", e)
        }
    }

    /**
     * Initialize core application components
     */
    private fun initializeCoreComponents() {
        try {
            // Initialize language manager
            LanguageManager.initialize(this)
            Log.d(TAG, "✅ Language initialized to: ${LanguageManager.getLanguage(this)}")

            // Initialize theme manager
            ThemeManager.initialize(this)
            Log.d(TAG, "✅ Theme initialized to: ${ThemeManager.getTheme(this)}")

        } catch (e: Exception) {
            Log.e(TAG, "❌ Error initializing core components: ${e.message}", e)
        }
    }

    /**
     * Initialize network clients
     */
    private fun initializeNetworkClients() {
        try {
            // Initialize NetworkClient with application context
            NetworkClient.initialize(this)
            Log.d(TAG, "✅ NetworkClient initialized")

            // Initialize the ElectionNetworkClient
            initializeElectionNetworkClient()

        } catch (e: Exception) {
            Log.e(TAG, "❌ Error initializing network clients: ${e.message}", e)
        }
    }

    /**
     * Initialize startup manager untuk auto-loading crypto keys
     */
    private fun initializeStartupManager() {
        try {
            // Initialize startup manager
            startupInitializer = StartupInitializer.getInstance(this)

            // Start key initialization in background
            applicationScope.launch {
                try {
                    Log.d(TAG, "🔐 Starting crypto key initialization...")
                    startupInitializer.initializeApp()
                    Log.d(TAG, "✅ Crypto key initialization completed")
                } catch (e: Exception) {
                    Log.e(TAG, "❌ Error during crypto key initialization: ${e.message}", e)
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "❌ Error initializing startup manager: ${e.message}", e)
        }
    }

    /**
     * Initialize ElectionNetworkClient dengan token handling
     */
    private fun initializeElectionNetworkClient() {
        try {
            // First initialize with application context
            ElectionNetworkClient.initialize(this)

            // Check if there's a token already stored
            val hasToken = ElectionNetworkClient.hasValidToken()
            Log.i(TAG, "ElectionNetworkClient initialized with token status: ${if (hasToken) "Token available" else "No token"}")

            // If there's no token and you have a default/demo token, you can set it here
            if (!hasToken) {
                val demoToken = getDemoTokenIfAvailable()
                if (demoToken.isNotEmpty()) {
                    Log.i(TAG, "Setting demo token for ElectionNetworkClient")
                    ElectionNetworkClient.saveUserToken(demoToken)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error initializing ElectionNetworkClient: ${e.message}", e)
        }
    }

    /**
     * Get a demo token if available (for testing purposes)
     */
    private fun getDemoTokenIfAvailable(): String {
        // This is where you could provide a demo/default token for testing
        // For security reasons, don't hard-code real tokens in production code
        return "" // Return empty string for now
    }

    /**
     * Get startup initializer instance
     */
    fun getStartupInitializer(): StartupInitializer {
        return if (::startupInitializer.isInitialized) {
            startupInitializer
        } else {
            Log.w(TAG, "StartupInitializer not yet initialized, creating new instance")
            StartupInitializer.getInstance(this)
        }
    }

    /**
     * Force reload all keys (untuk debugging atau recovery)
     */
    suspend fun forceReloadAllKeys(): Boolean {
        return try {
            Log.d(TAG, "🔄 Force reloading all keys from Application level...")
            getStartupInitializer().forceReloadAllKeys()
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error during force reload: ${e.message}", e)
            false
        }
    }

    /**
     * Clear keys that need attention flag
     */
    fun clearKeysNeedAttention(userEmail: String) {
        try {
            getStartupInitializer().clearKeysNeedAttention(userEmail)
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error clearing keys need attention: ${e.message}", e)
        }
    }

    private fun scheduleKeyHealthChecks() {
        // Check key health every time the app starts
        val cryptoKeyManager = CryptoKeyManager.getInstance(this)

        // Perform health check in background
        Thread {
            try {
                val isHealthy = cryptoKeyManager.performKeyHealthCheck()
                Log.d("VoteChain", "Key health check result: $isHealthy")

                if (!isHealthy) {
                    Log.w("VoteChain", "Key health check failed - user may need to re-register")
                }
            } catch (e: Exception) {
                Log.e("VoteChain", "Key health check error", e)
            }
        }.start()
    }
}