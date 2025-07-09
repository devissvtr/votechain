package com.nocturna.votechain.ui.screens.votepage

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

@Composable
fun VoteSuccessScreen(
    navController: NavController,
    voteId: String,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .background(SuccessColors.Success50)
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        // Success Icon
        Icon(
            painter = painterResource(id = R.drawable.ic_launcher_foreground), // Replace with success icon
            contentDescription = "Success",
            tint = SuccessColors.Success50,
            modifier = Modifier.size(80.dp)
        )

        Spacer(modifier = Modifier.height(24.dp))

        // Success Title
        Text(
            text = "Vote Submitted Successfully!",
            style = AppTypography.heading4Regular,
            color = SuccessColors.Success70,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(16.dp))

        // Success Message
        Text(
            text = "Your vote has been securely recorded on the blockchain. Thank you for participating in the democratic process.",
            style = AppTypography.paragraphRegular,
            color = SuccessColors.Success60,
            textAlign = TextAlign.Center
        )

        Spacer(modifier = Modifier.height(24.dp))

        // Vote ID Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = Color.White)
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    text = "Vote ID",
                    style = AppTypography.paragraphSemiBold,
                    color = PrimaryColors.Primary70
                )

                Text(
                    text = voteId,
                    style = AppTypography.heading6Medium,
                    color = PrimaryColors.Primary80
                )
            }
        }

        Spacer(modifier = Modifier.height(32.dp))

        // Action Buttons
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Button(
                onClick = {
                    navController.navigate("main") {
                        popUpTo(0) { inclusive = true }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = MainColors.Primary1),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text(
                    text = "Back to Home",
                    style = AppTypography.paragraphSemiBold,
                    color = Color.White,
                    modifier = Modifier.padding(vertical = 8.dp)
                )
            }

            OutlinedButton(
                onClick = {
                    navController.navigate("results") {
                        popUpTo("main")
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text(
                    text = "View Results",
                    style = AppTypography.paragraphSemiBold,
                    color = MainColors.Primary1,
                    modifier = Modifier.padding(vertical = 8.dp)
                )
            }
        }
    }
}