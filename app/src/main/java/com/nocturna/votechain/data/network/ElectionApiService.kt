package com.nocturna.votechain.data.network

import com.nocturna.votechain.data.model.ElectionPairsResponse
import com.nocturna.votechain.data.model.PartyResponse
import com.nocturna.votechain.data.model.SupportingPartiesResponse
import com.nocturna.votechain.data.model.VisionMissionApiResponse
import com.nocturna.votechain.data.model.VisionMissionDetailResponse
import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.Headers
import retrofit2.http.Path
import retrofit2.http.Streaming

/**
 * API Service interface for election-related endpoints
 */
interface ElectionApiService {
    /**
     * Get all election candidate pairs
     * Endpoint: /v1/election/pairs
     */
    @GET("v1/election/pairs")
    suspend fun getElectionPairs(): Response<ElectionPairsResponse>

    /**
     * Get detail for a specific election pair (includes vision, mission, work programs)
     * Endpoint: /v1/election/pairs/{pairId}/detail
     */
    @GET("v1/election/pairs/{pairId}/detail")
    suspend fun getElectionPairDetail(@Path("pairId") pairId: String): Response<VisionMissionDetailResponse>
    /**
     * Get supporting parties for a specific election pair
     * Endpoint: /v1/election/pairs/{pairID}/supporting-parties
     */
    @GET("v1/election/pairs/{pairID}/supporting-parties")
    suspend fun getSupportingParties(@Path("pairID") pairId: String): Response<SupportingPartiesResponse>

    /**
     * Get all political parties
     * Endpoint: /v1/party
     */
    @GET("v1/party")
    suspend fun getParties(): Response<PartyResponse>

    /**
     * Download program docs PDF
     * @Streaming annotation penting untuk download file besar
     * agar tidak di-load semua ke memory sekaligus
     */
    @Streaming
    @GET("v1/election/pairs/{id}/detail/program-docs")
    suspend fun getProgramDocs(
        @Path("id") pairId: String
    ): Response<ResponseBody>
}