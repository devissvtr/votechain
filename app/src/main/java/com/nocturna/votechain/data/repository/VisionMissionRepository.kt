package com.nocturna.votechain.data.repository

import android.util.Log
import com.nocturna.votechain.data.model.VisionMissionDetailModel
import com.nocturna.votechain.data.model.VisionMissionModel
import com.nocturna.votechain.data.model.WorkProgram
import com.nocturna.votechain.data.network.ElectionNetworkClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.ResponseBody

/**
 * Repository interface for Vision Mission data
 */
interface VisionMissionRepository {
    suspend fun getVisionMission(candidateNumber: Int): VisionMissionModel // Keep for backward compatibility
    suspend fun getVisionMissionFromAPI(pairId: String): VisionMissionDetailModel // New method for API integration
    suspend fun getProgramDocsFromAPI(pairId: String): Result<ResponseBody> {
        return try {
            val response = ElectionNetworkClient.electionApiService.getProgramDocs(pairId)

            if (response.isSuccessful) {
                response.body()?.let { responseBody ->
                    Result.success(responseBody)
                } ?: Result.failure(Exception("Empty response body"))
            } else {
                Result.failure(Exception("Failed to download PDF: ${response.code()} ${response.message()}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

/**
 * Implementation of Vision Mission Repository
 */
class VisionMissionRepositoryImpl : VisionMissionRepository {

    private val TAG = "VisionMissionRepository"
    private val apiService = ElectionNetworkClient.electionApiService

    /**
     * Get vision mission from API using pair ID
     * @param pairId The election pair ID
     * @return VisionMissionDetailModel containing vision, mission, and work programs
     */
    override suspend fun getVisionMissionFromAPI(pairId: String): VisionMissionDetailModel = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Fetching vision mission detail for pair ID: $pairId")

            val response = apiService.getElectionPairDetail(pairId)

            if (response.isSuccessful) {
                val responseBody = response.body()
                if (responseBody != null && responseBody.code == 200) {
                    val data = responseBody.data

                    if (data != null) {
                        Log.d(TAG, "Successfully fetched vision mission detail")

                        // Check if vision is empty or null, use "data tidak tersedia" as fallback
                        val vision = if (data.vision.isBlank()) {
                            "Data tidak tersedia"
                        } else {
                            data.vision
                        }

                        // Check if mission is empty or null, use "data tidak tersedia" as fallback
                        val mission = if (data.mission.isBlank()) {
                            "Data tidak tersedia"
                        } else {
                            data.mission
                        }

                        // Convert API work programs to UI work programs
                        // If work_program is null or empty, create empty list
                        val workPrograms = if (data.work_program.isEmpty()) {
                            emptyList()
                        } else {
                            data.work_program.map { workProgramResponse ->
                                WorkProgram(
                                    programName = workProgramResponse.program_name.ifBlank { "Data tidak tersedia" },
                                    programPhoto = workProgramResponse.program_photo?.takeIf { it.isNotBlank() }?.let {
                                        // Build full URL for program photo if available
                                        if (it.startsWith("http")) it else "${ElectionNetworkClient.BASE_URL}/$it"
                                    },
                                    programDesc = if (workProgramResponse.program_desc.isEmpty()) {
                                        listOf("Data tidak tersedia")
                                    } else {
                                        workProgramResponse.program_desc
                                    }
                                )
                            }
                        }

                        // Build full URL for program docs if available
                        val programDocsUrl = data.program_docs?.let { docPath ->
                            if (docPath.isNotBlank()) {
                                // Handle Windows-style paths and normalize them
                                val normalizedPath = docPath.replace("\\", "/")
                                if (normalizedPath.startsWith("http")) {
                                    normalizedPath
                                } else {
                                    "${ElectionNetworkClient.BASE_URL}/$normalizedPath"
                                }
                            } else null
                        }

                        return@withContext VisionMissionDetailModel(
                            id = data.id,
                            electionPairId = data.election_pair_id,
                            vision = vision,
                            mission = mission,
                            workPrograms = workPrograms,
                            programDocs = programDocsUrl
                        )
                    } else {
                        Log.e(TAG, "API returned null data")
                        // Return model with "data tidak tersedia" instead of throwing exception
                        return@withContext VisionMissionDetailModel(
                            id = pairId,
                            electionPairId = pairId,
                            vision = "Data tidak tersedia",
                            mission = "Data tidak tersedia",
                            workPrograms = emptyList(),
                            programDocs = null
                        )
                    }
                } else {
                    val errorMsg = responseBody?.error?.error_message ?: "Unknown error occurred"
                    Log.e(TAG, "API returned error: $errorMsg")
                    // Return model with "data tidak tersedia" instead of throwing exception
                    return@withContext VisionMissionDetailModel(
                        id = pairId,
                        electionPairId = pairId,
                        vision = "Data tidak tersedia",
                        mission = "Data tidak tersedia",
                        workPrograms = emptyList(),
                        programDocs = null
                    )
                }
            } else {
                Log.e(TAG, "API call failed with code: ${response.code()}")
                // Return model with "data tidak tersedia" instead of using fallback hardcoded data
                return@withContext VisionMissionDetailModel(
                    id = pairId,
                    electionPairId = pairId,
                    vision = "Data tidak tersedia",
                    mission = "Data tidak tersedia",
                    workPrograms = emptyList(),
                    programDocs = null
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception while fetching vision mission detail: ${e.message}", e)
            // Return model with "data tidak tersedia" instead of using fallback hardcoded data
            return@withContext VisionMissionDetailModel(
                id = pairId,
                electionPairId = pairId,
                vision = "Data tidak tersedia",
                mission = "Data tidak tersedia",
                workPrograms = emptyList(),
                programDocs = null
            )
        }
    }

    /**
     * Legacy method - keep for backward compatibility
     * @param candidateNumber The candidate number (1, 2, 3)
     * @return VisionMissionModel with hardcoded data
     */
    override suspend fun getVisionMission(candidateNumber: Int): VisionMissionModel = withContext(Dispatchers.IO) {
        // Simulate network delay
        kotlinx.coroutines.delay(500)

        return@withContext when(candidateNumber) {
            1 -> VisionMissionModel(
                candidateNumber = 1,
                vision = "Indonesia Adil Makmur Untuk Semua",
                missions = listOf(
                    "Memastikan Ketersediaan Kebutuhan Pokok dan Biaya Hidup Murah melalui Kemandirian Pangan, Ketahanan Energi, dan Kedaulatan Air.",
                    "Mengentaskan Kemiskinan dengan Memperluas Kesempatan Berusaha dan Menciptakan Lapangan Kerja, Mewujudkan Upah Berkeadilan, Menjamin Kemajuan Ekonomi Berbasis Kemandirian dan Pemerataan, serta Mendukung Korporasi Indonesia Berhasil di Negeri Sendiri dan Bertumbuh di Kancah Global.",
                    "Memperkuat Sistem Perlindungan Sosial, Kesehatan, Pendidikan yang Berkualitas, serta Perluasan Akses Ekonomi untuk Kelompok Rentan, Disabilitas, dan Wilayah Terpencil.",
                    "Melanjutkan Transformasi Digital, Hilirisasi Industri, dan Penciptaan Rantai Nilai (Value Chain) untuk Memperkuat Kedaulatan di Bidang Pangan, Energi, Air, Ekonomi Digital, Ekonomi Hijau, dan Ekonomi Biru.",
                    "Memperkuat Reformasi Politik, Hukum, dan Birokrasi guna Mewujudkan Pemerintahan Bersih, Efektif, Demokratis, Terpercaya, dan Berorientasi pada Pelayanan Rakyat."
                )
            )
            2 -> VisionMissionModel(
                candidateNumber = 2,
                vision = "Bersama Indonesia Maju Menuju Indonesia Emas 2045",
                missions = listOf(
                    "Memperkuat Kedaulatan Politik dan Demokrasi Pancasila",
                    "Memperkuat Sistem Pertahanan-Keamanan Negara dan Mendorong Kemandirian Bangsa melalui Swasembada Pangan, Energi, Air, Ekonomi Syariah, Ekonomi Digital, Ekonomi Hijau dan Ekonomi Biru",
                    "Meningkatkan SDM yang Unggul dan Pembangunan yang Berkelanjutan"
                )
            )
            3 -> VisionMissionModel(
                candidateNumber = 3,
                vision = "Menuju Indonesia yang Adil dan Makmur",
                missions = listOf(
                    "Mewujudkan Keadilan Sosial bagi Seluruh Rakyat Indonesia",
                    "Membangun Ekonomi yang Kuat dan Berkelanjutan",
                    "Menciptakan Pemerintahan yang Bersih dan Amanah"
                )
            )
            else -> VisionMissionModel(
                candidateNumber = candidateNumber,
                vision = "Vision not available",
                missions = listOf("Mission not available")
            )
        }
    }

    /**
     * Get program docs PDF files from API
     * @param pairId The election pair ID
     * @return Result containing okhttp3.ResponseBody for the PDF file
     */
    override suspend fun getProgramDocsFromAPI(pairId: String): Result<ResponseBody> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Fetching program docs for pair ID: $pairId")

            val response = apiService.getProgramDocs(pairId)

            if (response.isSuccessful) {
                val responseBody = response.body()
                if (responseBody != null) {
                    Log.d(TAG, "Successfully fetched program docs")
                    return@withContext Result.success(responseBody)
                } else {
                    Log.e(TAG, "API returned null body for program docs")
                    return@withContext Result.failure(Exception("No data available for program docs"))
                }
            } else {
                Log.e(TAG, "API call for program docs failed with code: ${response.code()}")
                return@withContext Result.failure(Exception("Failed to fetch program docs"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception while fetching program docs: ${e.message}", e)
            return@withContext Result.failure(e)
        }
    }
}