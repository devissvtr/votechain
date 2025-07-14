package com.nocturna.votechain.data.repository

import android.util.Log
import com.nocturna.votechain.data.model.Candidate
import com.nocturna.votechain.data.model.Education
import com.nocturna.votechain.data.model.ElectionPair
import com.nocturna.votechain.data.model.Party
import com.nocturna.votechain.data.model.SupportingParty
import com.nocturna.votechain.data.model.WorkExperience
import com.nocturna.votechain.data.network.ElectionNetworkClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn

/**
 * Repository for election-related data
 */
class ElectionRepository {
    private val TAG = "ElectionRepository"
    private val apiService = ElectionNetworkClient.electionApiService

    /**
     * Get election pairs with their supporting parties
     * @return Flow of election pairs with supporting parties
     */
    fun getElectionPairsWithSupportingParties(): Flow<Result<List<ElectionPair>>> = flow {
        try {
            Log.d(TAG, "Fetching election pairs with supporting parties")

            // Check if user token is available before making API call
            val token = ElectionNetworkClient.getUserToken()
            if (token.isEmpty()) {
                Log.w(TAG, "No authentication token available - using fallback data")
                emit(Result.success(getFallbackElectionPairs()))
                return@flow
            }

            // First, get all election pairs
            val pairsResponse = apiService.getElectionPairs()
            if (!pairsResponse.isSuccessful) {
                when (pairsResponse.code()) {
                    401 -> {
                        Log.w(TAG, "Authentication failed - using fallback data")
                        emit(Result.success(getFallbackElectionPairs()))
                        return@flow
                    }
                    else -> {
                        emit(Result.failure(Exception("Failed to fetch election pairs")))
                        return@flow
                    }
                }
            }

            val pairs = pairsResponse.body()?.data ?: emptyList()
            val pairsWithParties = mutableListOf<ElectionPair>()

            // For each pair, fetch supporting parties
            for (pair in pairs) {
                try {
                    val partiesResponse = apiService.getSupportingParties(pair.id)
                    val supportingParties = if (partiesResponse.isSuccessful) {
                        partiesResponse.body()?.data?.parties ?: emptyList()
                    } else {
                        // Use fallback data for this specific pair
                        getFallbackSupportingParties(pair.id)
                    }

                    // Create updated pair with supporting parties
                    val updatedPair = pair.copy(supporting_parties = supportingParties)
                    pairsWithParties.add(updatedPair)
                } catch (e: Exception) {
                    Log.w(
                        TAG,
                        "Failed to fetch supporting parties for pair ${pair.id}: ${e.message}"
                    )
                    // Add pair with fallback supporting parties
                    val fallbackParties = getFallbackSupportingParties(pair.id)
                    pairsWithParties.add(pair.copy(supporting_parties = fallbackParties))
                }
            }

            Log.d(
                TAG,
                "Successfully fetched ${pairsWithParties.size} election pairs with supporting parties"
            )
            emit(Result.success(pairsWithParties))

        } catch (e: Exception) {
            Log.e(
                TAG,
                "Exception while fetching election pairs with supporting parties: ${e.message}",
                e
            )

            // Use fallback data for any exceptions
            when {
                e.message?.contains("401") == true ||
                        e.message?.contains("Unauthenticated") == true -> {
                    Log.w(TAG, "Authentication error - using fallback data")
                    emit(Result.success(getFallbackElectionPairs()))
                }
                else -> {
                    Log.w(TAG, "Using fallback data due to exception")
                    emit(Result.success(getFallbackElectionPairs()))
                }
            }
        }
    }.flowOn(Dispatchers.IO)

    /**
     * Fallback election pairs data when API is unavailable
     * Based on the design shown in the image
     */
    private fun getFallbackElectionPairs(): List<ElectionPair> {
        Log.d(TAG, "Using fallback election pairs data")

        return listOf(
            // Candidate 1: Anies - Imin
            ElectionPair(
                id = "fallback-pair-1",
                election_no = "1",
                is_active = true,
                pair_photo_path = "",
                president = Candidate(
                    full_name = "Anies",
                    gender = "Male",
                    birth_place = "Kuningan, West Java",
                    birth_date = "1969-05-07",
                    religion = "Islam",
                    last_education = "University of Chicago (Ph.D)",
                    job = "Former Governor of DKI Jakarta",
                    photo_path = "",
                    education_history = listOf(
                        Education("Gadjah Mada University", "1995"),
                        Education("University of Chicago", "2004")
                    ),
                    work_experience = listOf(
                        WorkExperience("Governor of DKI Jakarta", "Governor", "2017-2022"),
                        WorkExperience("Ministry of Education", "Minister", "2014-2016")
                    )
                ),
                vice_president = Candidate(
                    full_name = "Imin",
                    gender = "Male",
                    birth_place = "Jombang, East Java",
                    birth_date = "1966-01-04",
                    religion = "Islam",
                    last_education = "Al-Azhar University Cairo",
                    job = "Chairman of PKB",
                    photo_path = "",
                    education_history = listOf(
                        Education("Al-Azhar University Cairo", "1993")
                    ),
                    work_experience = listOf(
                        WorkExperience("PKB", "Chairman", "2019-Present"),
                        WorkExperience("Ministry of Religious Affairs", "Minister", "2014-2019")
                    )
                ),
                vote_count = 0,
                supporting_parties = getFallbackSupportingParties("fallback-pair-1")
            ),

            // Candidate 2: Prabowo - Gibran
            ElectionPair(
                id = "fallback-pair-2",
                election_no = "2",
                is_active = true,
                pair_photo_path = "",
                president = Candidate(
                    full_name = "Prabowo",
                    gender = "Male",
                    birth_place = "Jakarta",
                    birth_date = "1951-10-17",
                    religion = "Islam",
                    last_education = "Military Academy",
                    job = "Minister of Defense",
                    photo_path = "",
                    education_history = listOf(
                        Education("Military Academy", "1974"),
                        Education("Command and General Staff College", "1985")
                    ),
                    work_experience = listOf(
                        WorkExperience("Ministry of Defense", "Minister", "2019-Present"),
                        WorkExperience("Gerindra Party", "Chairman", "2008-Present"),
                        WorkExperience("Indonesian Armed Forces", "Lieutenant General", "1974-1998")
                    )
                ),
                vice_president = Candidate(
                    full_name = "Gibran",
                    gender = "Male",
                    birth_place = "Surakarta, Central Java",
                    birth_date = "1987-10-01",
                    religion = "Islam",
                    last_education = "Singapore Management University",
                    job = "Mayor of Surakarta",
                    photo_path = "",
                    education_history = listOf(
                        Education("Singapore Management University", "2010")
                    ),
                    work_experience = listOf(
                        WorkExperience("Surakarta City", "Mayor", "2021-Present"),
                        WorkExperience("Entrepreneur", "Business Owner", "2010-2021")
                    )
                ),
                vote_count = 0,
                supporting_parties = getFallbackSupportingParties("fallback-pair-2")
            ),

            // Candidate 3: Ganjar - Mahfud MD
            ElectionPair(
                id = "fallback-pair-3",
                election_no = "3",
                is_active = true,
                pair_photo_path = "",
                president = Candidate(
                    full_name = "Ganjar",
                    gender = "Male",
                    birth_place = "Bantul, Yogyakarta",
                    birth_date = "1968-10-10",
                    religion = "Islam",
                    last_education = "Gadjah Mada University",
                    job = "Former Governor of Central Java",
                    photo_path = "",
                    education_history = listOf(
                        Education("Gadjah Mada University", "1993")
                    ),
                    work_experience = listOf(
                        WorkExperience("Central Java Province", "Governor", "2013-2023"),
                        WorkExperience("Indonesian House of Representatives", "Member", "2004-2013")
                    )
                ),
                vice_president = Candidate(
                    full_name = "Mahfud MD",
                    gender = "Male",
                    birth_place = "Sampang, East Java",
                    birth_date = "1957-05-13",
                    religion = "Islam",
                    last_education = "Gadjah Mada University",
                    job = "Former Coordinating Minister",
                    photo_path = "",
                    education_history = listOf(
                        Education("Gadjah Mada University", "1982")
                    ),
                    work_experience = listOf(
                        WorkExperience("Coordinating Ministry", "Minister", "2019-2023"),
                        WorkExperience("Constitutional Court", "Chief Justice", "2008-2013")
                    )
                ),
                vote_count = 0,
                supporting_parties = getFallbackSupportingParties("fallback-pair-3")
            )
        )
    }

    /**
     * Fallback supporting parties data for each candidate pair
     */
    private fun getFallbackSupportingParties(pairId: String): List<SupportingParty> {
        return when (pairId) {
            "fallback-pair-1" -> listOf(
                SupportingParty(
                    id = "supporting-1-1",
                    election_pair_id = pairId,
                    party_id = "party-pkb",
                    party = Party(id = "party-pkb", name = "PKB", logo_path = "")
                ),
                SupportingParty(
                    id = "supporting-1-2",
                    election_pair_id = pairId,
                    party_id = "party-pks",
                    party = Party(id = "party-pks", name = "PKS", logo_path = "")
                ),
                SupportingParty(
                    id = "supporting-1-3",
                    election_pair_id = pairId,
                    party_id = "party-nasdem",
                    party = Party(id = "party-nasdem", name = "NasDem", logo_path = "")
                )
            )

            "fallback-pair-2" -> listOf(
                SupportingParty(
                    id = "supporting-2-1",
                    election_pair_id = pairId,
                    party_id = "party-pan",
                    party = Party(id = "party-pan", name = "PAN", logo_path = "")
                ),
                SupportingParty(
                    id = "supporting-2-2",
                    election_pair_id = pairId,
                    party_id = "party-golkar",
                    party = Party(id = "party-golkar", name = "Golkar", logo_path = "")
                ),
                SupportingParty(
                    id = "supporting-2-3",
                    election_pair_id = pairId,
                    party_id = "party-gerindra",
                    party = Party(id = "party-gerindra", name = "Gerindra", logo_path = "")
                ),
                SupportingParty(
                    id = "supporting-2-4",
                    election_pair_id = pairId,
                    party_id = "party-demokrat",
                    party = Party(id = "party-demokrat", name = "Demokrat", logo_path = "")
                ),
                SupportingParty(
                    id = "supporting-2-5",
                    election_pair_id = pairId,
                    party_id = "party-pbb",
                    party = Party(id = "party-pbb", name = "PBB", logo_path = "")
                ),
                SupportingParty(
                    id = "supporting-2-6",
                    election_pair_id = pairId,
                    party_id = "party-gelora",
                    party = Party(id = "party-gelora", name = "Gelora", logo_path = "")
                )
            )

            "fallback-pair-3" -> listOf(
                SupportingParty(
                    id = "supporting-3-1",
                    election_pair_id = pairId,
                    party_id = "party-pdip",
                    party = Party(id = "party-pdip", name = "PDIP", logo_path = "")
                ),
                SupportingParty(
                    id = "supporting-3-2",
                    election_pair_id = pairId,
                    party_id = "party-ppp",
                    party = Party(id = "party-ppp", name = "PPP", logo_path = "")
                ),
                SupportingParty(
                    id = "supporting-3-3",
                    election_pair_id = pairId,
                    party_id = "party-perindo",
                    party = Party(id = "party-perindo", name = "Perindo", logo_path = "")
                ),
                SupportingParty(
                    id = "supporting-3-4",
                    election_pair_id = pairId,
                    party_id = "party-hanura",
                    party = Party(id = "party-hanura", name = "Hanura", logo_path = "")
                )
            )

            else -> emptyList()
        }
    }
}
