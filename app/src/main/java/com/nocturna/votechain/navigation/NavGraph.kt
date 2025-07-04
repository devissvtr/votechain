package com.nocturna.votechain.navigation

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.viewmodel.compose.viewModel
import com.nocturna.votechain.ui.screens.login.LoginScreen
import com.nocturna.votechain.ui.screens.homepage.CandidatePresidentScreen
import com.nocturna.votechain.ui.screens.homepage.DetailCandidateScreen
import com.nocturna.votechain.ui.screens.homepage.HomeScreen
import com.nocturna.votechain.ui.screens.homepage.VisionMissionScreen
import com.nocturna.votechain.ui.screens.register.AcceptedScreen
import com.nocturna.votechain.ui.screens.register.RejectedScreen
import com.nocturna.votechain.ui.screens.register.WaitingScreen
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.nocturna.votechain.data.model.NewsItem
import com.nocturna.votechain.ui.screens.LoadingScreen
import com.nocturna.votechain.ui.screens.OTPVerificationScreen
import com.nocturna.votechain.ui.screens.SplashScreen
import com.nocturna.votechain.ui.screens.auth.EmailVerificationScreen
import com.nocturna.votechain.ui.screens.forgotpassword.ResetPasswordScreen
import com.nocturna.votechain.ui.screens.votepage.CandidateSelectionScreen
import com.nocturna.votechain.ui.screens.homepage.NotificationScreen
import com.nocturna.votechain.ui.screens.profilepage.AccountDetailsScreen
import com.nocturna.votechain.ui.screens.profilepage.FAQScreen
import com.nocturna.votechain.ui.screens.profilepage.ProfileScreen
import com.nocturna.votechain.ui.screens.register.RegistrationFlowController
import com.nocturna.votechain.ui.screens.votepage.LiveResultScreen
import com.nocturna.votechain.ui.screens.votepage.OTPVotingVerificationScreen
import com.nocturna.votechain.ui.screens.votepage.ResultsScreen
import com.nocturna.votechain.ui.screens.votepage.VoteConfirmationScreen
import com.nocturna.votechain.ui.screens.votepage.VoteSuccessScreen
import com.nocturna.votechain.ui.screens.votepage.VotingScreen
import com.nocturna.votechain.ui.screens.wallet.WalletImportScreen
import com.nocturna.votechain.viewmodel.candidate.ElectionViewModel
import com.nocturna.votechain.viewmodel.login.LoginViewModel
import com.nocturna.votechain.viewmodel.register.RegisterViewModel
import com.nocturna.votechain.viewmodel.vote.VotingViewModel

@Composable
fun VotechainNavGraph(
    navController: NavHostController,
    startDestination: String = "splash",
    modifier: Modifier = Modifier,
    electionViewModel: ElectionViewModel,
    onNewsClick: (NewsItem) -> Unit = {}
) {
    // Get context for ViewModel factories
    val context = LocalContext.current

    // Create ViewModels with proper factories
    val votingViewModel: VotingViewModel = viewModel(
        factory = VotingViewModel.Factory(context)
    )
    val electionViewModel: ElectionViewModel = viewModel(
        factory = ElectionViewModel.Factory
    )

    NavHost(
        navController = navController,
        startDestination = startDestination
    ) {
        // Splash screen - shows when app first opens
        composable("splash") {
            SplashScreen(
                onSplashComplete = {
                    // Navigate to login and remove splash from back stack
                    navController.navigate("login") {
                        popUpTo("splash") { inclusive = true }
                    }
                }
            )
        }

        // Loading screen - shows during data processing
        composable("loading") {
            LoadingScreen(
                onClose = { navController.popBackStack() }
            )
        }

        // Authentication routes
        composable("login") {
            val loginViewModel: LoginViewModel = viewModel(factory = LoginViewModel.Factory(context))
            val loginState = loginViewModel.uiState.collectAsState().value

            // Handle navigation based on login result
            LaunchedEffect(loginState) {
                when (loginState) {
                    LoginViewModel.LoginUiState.NavigateToHome -> {
                        navController.navigate("home") {
                            popUpTo("login") { inclusive = true }
                        }
                    }
                    LoginViewModel.LoginUiState.NavigateToWaiting -> {
                        navController.navigate("waiting_from_login") {
                            popUpTo("login") { inclusive = true }
                        }
                    }
                    LoginViewModel.LoginUiState.NavigateToAccepted -> {
                        navController.navigate("accepted_from_login") {
                            popUpTo("login") { inclusive = true }
                        }
                    }
                    LoginViewModel.LoginUiState.NavigateToRejected -> {
                        navController.navigate("rejected_from_login") {
                            popUpTo("login") { inclusive = true }
                        }
                    }
                    else -> {
                        // Stay on login screen
                    }
                }
            }
            LoginScreen(
                onRegisterClick = {
                    navController.navigate("register")
                },
                onLoginClick = {
                    // Login handled by ViewModel
                },
                onForgotPasswordClick = {
                    navController.navigate("forgot_password")
                }
            )
        }

        // Email Verification screen for forgot password
        composable("email_verification") {
            EmailVerificationScreen(
                navController = navController,
                onBackClick = { navController.popBackStack() },
                onSubmitEmail = { email ->
                    // Navigate to OTP verification with the email as parameter
                    navController.navigate("otp_verification_reset?email=${email}")
                }
            )
        }

        // OTP Verification screen for forgot password
        composable(
            "otp_verification_reset?email={email}",
            arguments = listOf(navArgument("email") {
                type = NavType.StringType
                defaultValue = ""
            })
        ) { backStackEntry ->
            val email = backStackEntry.arguments?.getString("email") ?: ""
            com.nocturna.votechain.ui.screens.forgotpassword.OTPVerificationScreen(
                navController = navController,
                email = email,
                onBackClick = { navController.popBackStack() },
                onVerificationComplete = { verifiedEmail, otp ->
                    // Navigate to reset password screen
                    navController.navigate("reset_password?email=${verifiedEmail}&otp=${otp}")
                }
            )
        }

        // Reset Password screen
        composable(
            "reset_password?email={email}&otp={otp}",
            arguments = listOf(
                navArgument("email") {
                    type = NavType.StringType
                    defaultValue = ""
                },
                navArgument("otp") {
                    type = NavType.StringType
                    defaultValue = ""
                }
            )
        ) { backStackEntry ->
            val email = backStackEntry.arguments?.getString("email") ?: ""
            val otp = backStackEntry.arguments?.getString("otp") ?: ""
            ResetPasswordScreen(
                navController = navController,
                email = email,
                otp = otp,
                onBackClick = { navController.popBackStack() },
                onResetSuccess = {
                    // Navigate back to login after successful password reset
                    navController.navigate("login") {
                        popUpTo("email_verification") { inclusive = true }
                    }
                }
            )
        }

        // Registration flow - now using the controller
        composable("register") {
            RegistrationFlowController(
                navController = navController
            )
        }

        composable("waiting") {
            val registerViewModel: RegisterViewModel = viewModel(factory = RegisterViewModel.Factory(context))
            val registerState = registerViewModel.uiState.collectAsState().value

            // Observe UI state changes for navigation
            LaunchedEffect(registerState) {
                if (registerState == RegisterViewModel.RegisterUiState.NavigateToLogin) {
                    navController.navigate("login") {
                        popUpTo("register") { inclusive = true }
                    }
                }
            }

            WaitingScreen(
                source = "register",
                viewModel = registerViewModel,
                onClose = {
                    // As a fallback, also provide direct navigation
                    navController.navigate("login") {
                        popUpTo("register") { inclusive = true }
                    }
                }
            )
        }

        composable("waiting_from_login") {
            WaitingScreen(
                source = "login",
                onClose = {
                    // Return to login page
                    navController.navigate("login") {
                        popUpTo("login") { inclusive = true }
                    }
                }
            )
        }

        // Accepted Screen from Register Flow
        composable("accepted") {
            val registerViewModel: RegisterViewModel = viewModel(factory = RegisterViewModel.Factory(context))

            AcceptedScreen(
                onLoginClick = {
                    navController.navigate("login") {
                        popUpTo("register") { inclusive = true }
                    }
                },
                viewModel = registerViewModel
            )
        }

        // Accepted Screen from Login Flow
        composable("accepted_from_login") {
            AcceptedScreen(
                onLoginClick = {
                    navController.navigate("login") {
                        popUpTo("login") { inclusive = true }
                    }
                }
            )
        }

        // Rejected Screen from Register Flow
        composable("rejected") {
            val registerViewModel: RegisterViewModel = viewModel(factory = RegisterViewModel.Factory(context))

            RejectedScreen(
                onRegisterAgainClick = {
                    // Clear registration state and start new registration
                    registerViewModel.clearRegistrationState()
                    navController.navigate("register") {
                        popUpTo("register") { inclusive = true }
                    }
                }
            )
        }

        // Rejected Screen from Login Flow
        composable("rejected_from_login") {
            RejectedScreen(
                onRegisterAgainClick = {
                    navController.navigate("register") {
                        popUpTo("login") { inclusive = true }
                    }
                }
            )
        }

        // Main application routes
        composable("home") {
            HomeScreen(
                onVoteItemClick = { voteId ->
                    navController.navigate("candidate_president/$voteId")
                },
                onHomeClick = { /* Already on home */ },
                onVotesClick = {
                    navController.navigate("votes") {
                        popUpTo("home") { inclusive = false }
                        launchSingleTop = true
                    }
                },
                onProfileClick = {
                    navController.navigate("profile") {
                        popUpTo("home") { inclusive = false }
                        launchSingleTop = true
                    }
                },
                onNotificationClick = { navController.navigate("notification") },
                onNewsClick = onNewsClick
            )
        }

        composable("notification") {
            NotificationScreen(
                onBackClick = { navController.popBackStack() }
            )
        }

        composable("votes") {
            VotingScreen(
                navController = navController,
                onHomeClick = {
                    navController.navigate("home") {
                        popUpTo("votes") { inclusive = true }
                        launchSingleTop = true
                    }
                },
                onProfileClick = {
                    navController.navigate("profile") {
                        popUpTo("votes") { inclusive = true }
                        launchSingleTop = true
                    }
                }
            )
        }

        // Vote Success screen - Fixed implementation
        composable("vote_success") {
            VoteSuccessScreen(
                onBackToHome = {
                    navController.navigate("home") {
                        popUpTo("vote_success") { inclusive = true }
                    }
                }
            )
        }

        composable(
            "candidate_president/{voteId}",
            arguments = listOf(navArgument("voteId") { type = NavType.StringType })
        ) {
            val voteId = it.arguments?.getString("voteId") ?: ""
            CandidatePresidentScreen(
                onBackClick = { navController.popBackStack() },
                onViewProfileClick = { candidateId ->
                    navController.navigate("candidate_detail/$candidateId")
                },
                navController = navController
            )
        }

        composable(
            "candidate_detail_api/{candidateId}",
            arguments = listOf(navArgument("candidateId") { type = NavType.StringType })
        ) {
            val candidateId = it.arguments?.getString("candidateId") ?: ""
            DetailCandidateScreen(
                candidateId = candidateId,
                onBackClick = { navController.popBackStack() },
                viewModel = electionViewModel
            )
        }

        composable(
            route = "vision_mission/{pairId}",
            arguments = listOf(navArgument("pairId") { type = NavType.StringType })
        ) { backStackEntry ->
            val pairId = backStackEntry.arguments?.getString("pairId") ?: ""
            VisionMissionScreen(
                navController = navController,
                pairId = pairId
            )
        }

        // OTP Voting Verification screen
        composable(
            "otp_verification/{categoryId}",
            arguments = listOf(navArgument("categoryId") { type = NavType.StringType })
        ) { backStackEntry ->
            val categoryId = backStackEntry.arguments?.getString("categoryId") ?: ""

            OTPVotingVerificationScreen(
                navController = navController,
                categoryId = categoryId,
                onBackClick = {
                    navController.popBackStack()
                },
                onVerificationComplete = {
                    // Navigate to candidate selection after successful OTP verification
                    navController.navigate("candidate_selection/$categoryId") {
                        popUpTo("otp_verification/$categoryId") { inclusive = true }
                    }
                }
            )
        }

        // FIXED: Candidate Selection screen with proper parameters and ViewModel
        composable(
            "candidate_selection/{categoryId}",
            arguments = listOf(navArgument("categoryId") { type = NavType.StringType })
        ) { backStackEntry ->
            val categoryId = backStackEntry.arguments?.getString("categoryId") ?: ""

            CandidateSelectionScreen(
                categoryId = categoryId,
                votingViewModel = votingViewModel,
                navController = navController
            )
        }

        // Vote Confirmation Screen
        composable(
            route = "vote_confirmation/{electionPairId}",
            arguments = listOf(navArgument("electionPairId") { type = NavType.StringType })
        ) { backStackEntry ->
            val electionPairId = backStackEntry.arguments?.getString("electionPairId") ?: ""
            VoteConfirmationScreen(
                navController = navController,
                electionPairId = electionPairId,
                viewModel = votingViewModel // Pass your existing VotingViewModel
            )
        }

        // FIXED: Voting Detail screen implementation
//        composable(
//            "voting_detail/{categoryId}",
//            arguments = listOf(navArgument("categoryId") { type = NavType.StringType })
//        ) {
//            val categoryId = it.arguments?.getString("categoryId") ?: ""
//            VotingDetailScreen(
//                categoryId = categoryId,
//                navController = navController,
//                viewModel = votingViewModel // Use the ViewModel with proper factory
//            )
//        }

        composable("results") {
            ResultsScreen(navController, votingViewModel)
        }

        composable(
            "live_result/{electionId}",
            arguments = listOf(navArgument("electionId") { type = NavType.StringType })
        ) { backStackEntry ->
            val electionId = backStackEntry.arguments?.getString("electionId") ?: ""
            LiveResultScreen(
                electionId = electionId,
                navController = navController,
                electionViewModel = electionViewModel
            )
        }

        // FAQ Screen - Updated implementation
        composable("faq") {
            FAQScreen(
                navController = navController
            )
        }

        composable("profile") {
            ProfileScreen(
                onNavigateToFAQ = {
                    navController.navigate("faq")
                },
                navController = navController,
                onHomeClick = {
                    navController.navigate("home") {
                        popUpTo("profile") { inclusive = true }
                        launchSingleTop = true
                    }
                },
                onVotesClick = {
                    navController.navigate("votes") {
                        popUpTo("profile") { inclusive = true }
                        launchSingleTop = true
                    }
                }
//                onLogout = {
//                    // Navigate to login screen and clear all previous screens from back stack
//                    navController.navigate("login") {
//                        popUpTo(0) { inclusive = true }
//                    }
//                }
            )
        }

        composable("account_details") {
            AccountDetailsScreen(
                navController = navController,
                onLogout = {
                    // Navigate to login screen and clear all previous screens from back stack
                    navController.navigate("login") {
                        popUpTo(0) { inclusive = true }
                    }
                }
            )
        }

        composable("wallet_import") {
            WalletImportScreen(
                onBackClick = { navController.popBackStack() },
                onSuccessClick = { walletAddress ->
                    // Navigate to wallet or profile screen
                    navController.navigate("profile") {
                        popUpTo("wallet_import") { inclusive = true }
                    }
                }
            )
        }
    }
}