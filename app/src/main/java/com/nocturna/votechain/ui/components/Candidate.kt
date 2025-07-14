package com.nocturna.votechain.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Divider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.nocturna.votechain.data.model.EducationEntry
import com.nocturna.votechain.data.model.WorkEntry
import com.nocturna.votechain.ui.theme.AppTypography
import com.nocturna.votechain.ui.theme.NeutralColors
import com.nocturna.votechain.utils.LanguageManager

/**
 * Displays a table row with label and value
 */
@Composable
fun TableRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 1.dp)
    ) {
        Text(
            text = label,
            style = AppTypography.paragraphRegular,
            color = NeutralColors.Neutral70,
            modifier = Modifier
                .weight(1f)
                .background(color = NeutralColors.Neutral10)
                .padding(vertical = 12.dp, horizontal = 8.dp)
        )

        Text(
            text = value,
            style = AppTypography.paragraphRegular,
            color = NeutralColors.Neutral90,
            modifier = Modifier
                .weight(1f)
                .background(color = NeutralColors.Neutral10)
                .padding(vertical = 12.dp, horizontal = 8.dp)
        )
    }

    Divider(
        color = NeutralColors.Neutral20,
        thickness = 1.dp
    )
}

/**
 * Displays a table for education history
 */
@Composable
fun EducationHistoryTable(educationHistory: List<EducationEntry>) {
    val strings = LanguageManager.getLocalizedStrings()

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(6.dp))
            .background(NeutralColors.Neutral20)
    ) {
        // Table header
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(NeutralColors.Neutral20)
                .padding(vertical = 8.dp)
        ) {
            Text(
                text = strings.institution,
                style = AppTypography.paragraphSemiBold,
                color = NeutralColors.Neutral80,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .weight(1.5f)
                    .padding(horizontal = 8.dp)
            )

            Text(
                text = strings.year,
                style = AppTypography.paragraphSemiBold,
                color = NeutralColors.Neutral80,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .weight(0.8f)
                    .padding(horizontal = 8.dp)
            )
        }

        // Dynamic education entries
        educationHistory.forEach { entry ->
            EducationRow(entry.institution, entry.period)
        }
    }
}

/**
 * Displays a row for education entry
 */
@Composable
fun EducationRow(institution: String, years: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(NeutralColors.Neutral10)
            .padding(vertical = 8.dp)
    ) {
        Text(
            text = institution,
            style = AppTypography.paragraphRegular.copy(lineHeight = 18.sp),
            color = NeutralColors.Neutral90,
            modifier = Modifier
                .weight(1.5f)
                .padding(horizontal = 8.dp)
        )

        Text(
            text = years,
            style = AppTypography.paragraphRegular,
            color = NeutralColors.Neutral90,
            textAlign = TextAlign.Center,
            modifier = Modifier
                .weight(0.8f)
                .padding(horizontal = 8.dp)
        )
    }

    Divider(
        color = NeutralColors.Neutral20,
        thickness = 1.dp
    )
}

/**
 * Displays a table for work history
 */
@Composable
fun WorkHistoryTable(workHistory: List<WorkEntry>) {
    val strings = LanguageManager.getLocalizedStrings()

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(6.dp))
            .background(NeutralColors.Neutral20)
    ) {
        // Table header
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(NeutralColors.Neutral20)
                .padding(vertical = 8.dp)
        ) {
            Text(
                text = strings.institution,
                style = AppTypography.paragraphSemiBold,
                color = NeutralColors.Neutral80,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .weight(1.5f)
                    .padding(horizontal = 8.dp)
            )

            Text(
                text = strings.position,
                style = AppTypography.paragraphSemiBold,
                color = NeutralColors.Neutral80,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 8.dp)
            )

            Text(
                text = strings.year,
                style = AppTypography.paragraphSemiBold,
                color = NeutralColors.Neutral80,
                textAlign = TextAlign.Center,
                modifier = Modifier
                    .weight(0.8f)
                    .padding(horizontal = 8.dp)
            )
        }

        // Dynamic work experience entries
        workHistory.forEach { entry ->
            WorkRow(entry.institution, entry.position, entry.period)
        }
    }
}

/**
 * Displays a row for work entry
 */
@Composable
fun WorkRow(institution: String, position: String, years: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(NeutralColors.Neutral10)
            .padding(vertical = 8.dp)
    ) {
        Text(
            text = institution,
            style = AppTypography.paragraphRegular.copy(lineHeight = 18.sp),
            color = NeutralColors.Neutral90,
            modifier = Modifier
                .weight(1.5f)
                .padding(horizontal = 8.dp)
        )

        Text(
            text = position,
            style = AppTypography.paragraphRegular.copy(lineHeight = 18.sp),
            color = NeutralColors.Neutral90,
            textAlign = TextAlign.Center,
            modifier = Modifier
                .weight(1f)
                .padding(horizontal = 8.dp)
        )

        Text(
            text = years,
            style = AppTypography.paragraphRegular,
            color = NeutralColors.Neutral90,
            textAlign = TextAlign.Center,
            modifier = Modifier
                .weight(0.8f)
                .padding(horizontal = 8.dp)
        )
    }

    Divider(
        color = NeutralColors.Neutral20,
        thickness = 1.dp
    )
}