package com.nocturna.votechain.navigation

import android.util.Log
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.nocturna.votechain.data.repository.RegistrationStateManager
import com.nocturna.votechain.ui.screens.register.RegisterScreen
import com.nocturna.votechain.viewmodel.register.RegisterViewModel

/**
 * A wrapper component that handles the registration flow based on the persisted state
 * This component determines which screen to show based on the current registration state
 */
@Composable
fun RegistrationFlowController(
    navController: NavController,
) {
    val TAG = "RegistrationFlowController"
    val context = LocalContext.current
    val viewModel: RegisterViewModel = viewModel(factory = RegisterViewModel.Factory(context))
    val uiState by viewModel.uiState.collectAsState()

    Log.d(TAG, "RegistrationFlowController - Current UI State: $uiState")

    // Handle navigation based on UI state changes
    LaunchedEffect(uiState) {
        Log.d(TAG, "LaunchedEffect triggered with uiState: $uiState")

        when (uiState) {
            RegisterViewModel.RegisterUiState.Waiting -> {
                Log.d(TAG, "Navigating to waiting screen")
                navController.navigate("waiting") {
                    // Don't clear the back stack - allow returning to register
                }
            }
            RegisterViewModel.RegisterUiState.Approved -> {
                Log.d(TAG, "Navigating to accepted screen")
                navController.navigate("accepted") {
                    popUpTo("register") { inclusive = true }
                }
            }
            RegisterViewModel.RegisterUiState.Rejected -> {
                Log.d(TAG, "Navigating to rejected screen")
                navController.navigate("rejected") {
                    popUpTo("register") { inclusive = true }
                }
            }
            RegisterViewModel.RegisterUiState.NavigateToLogin -> {
                Log.d(TAG, "Navigating to login screen")
                navController.navigate("login") {
                    popUpTo("register") { inclusive = true }
                }
            }
            is RegisterViewModel.RegisterUiState.Success -> {
                Log.d(TAG, "Registration success, handling based on verification status")
                // The ViewModel will automatically update the state based on verification status
                // No navigation needed here as it will be handled by other state changes
            }
            is RegisterViewModel.RegisterUiState.Error -> {
                Log.e(TAG, "Registration error: ${(uiState as RegisterViewModel.RegisterUiState.Error).message}")
                // Stay on register screen to show error
            }
            RegisterViewModel.RegisterUiState.Loading -> {
                Log.d(TAG, "Registration in progress")
                // Stay on register screen to show loading
            }
            RegisterViewModel.RegisterUiState.Initial -> {
                Log.d(TAG, "Initial state - showing register screen")
                // Show register screen
            }
        }
    }

    // Check initial registration state when component loads
    LaunchedEffect(Unit) {
        Log.d(TAG, "Checking initial registration state")
        val currentState = viewModel.getCurrentRegistrationState()
        Log.d(TAG, "Current registration state: $currentState")

        // If there's an existing state, update the UI accordingly
        when (currentState) {
            RegistrationStateManager.STATE_WAITING -> {
                Log.d(TAG, "User has waiting registration, navigating to waiting screen")
                // Don't auto-navigate here - let user choose to continue or start new registration
            }
            RegistrationStateManager.STATE_APPROVED -> {
                Log.d(TAG, "User has approved registration, navigating to accepted screen")
                navController.navigate("accepted") {
                    popUpTo("register") { inclusive = true }
                }
            }
            RegistrationStateManager.STATE_REJECTED -> {
                Log.d(TAG, "User has rejected registration, staying on register to allow new registration")
                // Stay on register screen but could show a message
            }
            else -> {
                Log.d(TAG, "No active registration state, showing register form")
            }
        }
    }

    // Always render the RegisterScreen - navigation is handled above
    RegisterScreen(
        onRegisterClick = {
            Log.d(TAG, "Register button clicked")
            // The RegisterScreen will handle the registration internally through the ViewModel
        },
        onLoginClick = {
            Log.d(TAG, "Login clicked, navigating to login")
            navController.navigate("login") {
                popUpTo("register") { inclusive = true }
            }
        },
        onWaitingScreen = {
            Log.d(TAG, "Navigating to waiting screen from register")
            navController.navigate("waiting")
        },
        navigateToAccepted = {
            Log.d(TAG, "Navigating to accepted screen from register")
            navController.navigate("accepted") {
                popUpTo("register") { inclusive = true }
            }
        },
        navigateToRejected = {
            Log.d(TAG, "Navigating to rejected screen from register")
            navController.navigate("rejected") {
                popUpTo("register") { inclusive = true }
            }
        },
        viewModel = viewModel
    )
}