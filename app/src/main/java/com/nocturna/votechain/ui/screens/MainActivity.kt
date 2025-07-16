package com.nocturna.votechain.ui.screens

import android.content.ContentValues.TAG
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.rememberNavController
import com.nocturna.votechain.data.repository.RegistrationStateManager
import com.nocturna.votechain.data.repository.UserLoginRepository
import com.nocturna.votechain.navigation.VotechainNavGraph
import com.nocturna.votechain.ui.theme.VotechainTheme
import com.nocturna.votechain.utils.RegistrationStatusChecker
import com.nocturna.votechain.utils.TokenManager
import com.nocturna.votechain.utils.TokenSyncUtil
import com.nocturna.votechain.utils.openUrlInBrowser
import com.nocturna.votechain.viewmodel.candidate.ElectionViewModel

class MainActivity : ComponentActivity() {
    private val TAG = "MainActivity"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Create repository instances
        val userLoginRepository = UserLoginRepository(this)
        val registrationStateManager = RegistrationStateManager(this)
        val registrationStatusChecker = RegistrationStatusChecker(this)

        // Determine the appropriate start destination with enhanced logic
        val startDestination = determineStartDestination(
            userLoginRepository,
            registrationStateManager,
            registrationStatusChecker
        )

        Log.d(TAG, "Determined start destination: $startDestination")

        setContent {
            VotechainTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    val navController = rememberNavController()
                    val context = LocalContext.current
                    val tokenManager = TokenManager(this)
                    val isAuthenticated = TokenSyncUtil.isUserAuthenticated(this, tokenManager)

                    if (isAuthenticated) {
                        // Sync tokens jika perlu
                        TokenSyncUtil.validateAndSyncTokens(this, tokenManager)
                    }

                    VotechainNavGraph(
                        navController = navController,
                        startDestination = startDestination,
                        onNewsClick = { newsItem ->
                            // Open the news in the browser with the correct URL format:
                            // https://www.kpu.go.id/berita/baca/id/post_slug
                            val newsUrl = "https://www.kpu.go.id/berita/baca/${newsItem.id}/${newsItem.post_slug}"
                            openUrlInBrowser(context, newsUrl)
                        }
                    )
                }
            }
        }
    }
}

/**
 * Determine the appropriate start destination based on user state
 * Priority order:
 * 1. If user is logged in -> Home screen
 * 2. If user has pending registration -> Appropriate registration screen
 * 3. Default -> Splash screen
 */
private fun determineStartDestination(
    userLoginRepository: UserLoginRepository,
    registrationStateManager: RegistrationStateManager,
    registrationStatusChecker: RegistrationStatusChecker
): String {

    // First check if user is logged in
    if (userLoginRepository.isUserLoggedIn()) {
        Log.d(TAG, "User is logged in, going to home screen")
        // If user is logged in, clear any lingering registration states
        val currentRegState = registrationStateManager.getRegistrationState()
        if (currentRegState != RegistrationStateManager.STATE_NONE) {
            Log.d(TAG, "Clearing registration state for logged in user: $currentRegState")
            registrationStateManager.clearRegistrationState()
        }
        return "home"
    }

    // Check for registration states
    val registrationState = registrationStateManager.getRegistrationState()
    Log.d(TAG, "Registration state: $registrationState")

    return when (registrationState) {
        RegistrationStateManager.STATE_WAITING -> {
            Log.d(TAG, "User has pending registration, going to waiting screen")
            "waiting"
        }

        RegistrationStateManager.STATE_APPROVED -> {
            Log.d(TAG, "User has approved registration, going to accepted screen")
            "accepted"
        }

        RegistrationStateManager.STATE_REJECTED -> {
            Log.d(TAG, "User has rejected registration, clearing state and going to splash")
            // Clear rejected state automatically so user can register again
            registrationStateManager.clearRegistrationState()
            "splash"
        }

        RegistrationStateManager.STATE_NONE -> {
            Log.d(TAG, "No registration state, going to splash screen")
            "splash"
        }

        else -> {
            Log.d(TAG, "Unknown registration state: $registrationState, going to splash")
            "splash"
        }
    }
}