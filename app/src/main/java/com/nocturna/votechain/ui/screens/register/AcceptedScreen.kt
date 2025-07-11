package com.nocturna.votechain.ui.screens.register

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.nocturna.votechain.R
import com.nocturna.votechain.ui.theme.AppTypography
import com.nocturna.votechain.ui.theme.MainColors
import com.nocturna.votechain.ui.theme.NeutralColors
import com.nocturna.votechain.ui.theme.VotechainTheme
import com.nocturna.votechain.viewmodel.register.RegisterViewModel
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.compose.ui.platform.LocalContext
import com.nocturna.votechain.utils.LanguageManager

@Composable
fun AcceptedScreen(
    onLoginClick: () -> Unit = {},
    viewModel: RegisterViewModel = viewModel(factory = RegisterViewModel.Factory(LocalContext.current))
) {
    val strings = LanguageManager.getLocalizedStrings()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Image(
            painter = painterResource(id = R.drawable.approve),
            contentDescription = strings.verificationApproved,
            modifier = Modifier.size(224.dp)
        )

        Spacer(modifier = Modifier.height(32.dp))

        // Title text
        Text(
            text = strings.verificationApproved,
            style = AppTypography.heading1Bold,
            color = MainColors.Primary1,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(16.dp))

        // Description text
        Text(
            text = strings.verificationApprovedDescription,
            style = AppTypography.heading4Medium,
            color = NeutralColors.Neutral70,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(40.dp))

        // Login button
        Button(
            onClick = {
                viewModel.clearRegistrationState()
                onLoginClick()
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = MainColors.Primary1
            ),
            shape = RoundedCornerShape(28.dp)
        ) {
            Text(
                text = strings.login,
                style = AppTypography.heading4SemiBold,
                color = NeutralColors.Neutral10
            )
        }
    }
}