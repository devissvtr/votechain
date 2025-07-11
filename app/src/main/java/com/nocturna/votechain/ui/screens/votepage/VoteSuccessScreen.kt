package com.nocturna.votechain.ui.screens.votepage

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import com.nocturna.votechain.R
import com.nocturna.votechain.ui.theme.*
import com.nocturna.votechain.utils.LanguageManager

@Composable
fun VoteSuccessScreen(
    navController: NavController
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
            painter = painterResource(id = R.drawable.successful),
            contentDescription = strings.votingSuccess,
            modifier = Modifier.size(224.dp)
        )

        Spacer(modifier = Modifier.height(32.dp))

        // Title text
        Text(
            text = strings.votingSuccess,
            style = AppTypography.heading1Bold,
            color = MainColors.Primary1,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(16.dp))

        // Description text
        Text(
            text = strings.votingSuccessDesc,
            style = AppTypography.heading4Medium,
            color = NeutralColors.Neutral70,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(40.dp))

        // Login button
        Button(
            onClick = {
                navController.navigate("main") {
                    popUpTo(0) { inclusive = true }
                }
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
                text = strings.backHome,
                style = AppTypography.heading4SemiBold,
                color = NeutralColors.Neutral10
            )
        }
    }
}