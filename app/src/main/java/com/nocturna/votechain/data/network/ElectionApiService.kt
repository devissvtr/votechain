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
     * Get pair photo by pair ID (Combined photo of president and vice president)
     * Endpoint: /v1/election/pairs/{id}/photo
     */
    @GET("v1/election/pairs/{id}/photo")
    suspend fun getPairPhoto(
        @Path("id") pairId: String
    ): Response<ResponseBody>

    /**
     * Get president photo by pair ID
     * Endpoint: /v1/election/pairs/{id}/photo/president
     */
    @GET("v1/election/pairs/{id}/photo/president")
    suspend fun getPresidentPhoto(
        @Path("id") pairId: String
    ): Response<ResponseBody>

    /**
     * Get vice president photo by pair ID
     * Endpoint: /v1/election/pairs/{id}/photo/vice-president
     */
    @GET("v1/election/pairs/{id}/photo/vice-president")
    suspend fun getVicePresidentPhoto(
        @Path("id") pairId: String
    ): Response<ResponseBody>

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
     * Get party photo by party ID
     * Endpoint: /v1/party/{id}/photo
     */
    @GET("v1/party/{id}/photo")
    suspend fun getPartyPhoto(
        @Path("id") partyId: String
    ): Response<ResponseBody>

    /**
     * Get program docs PDF by pair ID
     * Endpoint: /v1/election/pairs/{id}/detail/program-docs
     * Returns PDF document with application/pdf content type
     */
//    @GET("v1/election/pairs/{id}/detail/program-docs")
//    suspend fun getProgramDocs(
//        @Path("id") pairId: String
//    ): Response<ResponseBody>

    /**
     * Get vision mission detail
     */
    @GET("v1/election/pairs/{id}/detail")
    suspend fun getVisionMissionDetail(
        @Path("id") pairId: String
    ): Response<VisionMissionApiResponse>

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

    /**
     * Alternative: Jika API memerlukan header khusus
     */
    @Streaming
    @GET("v1/election/pairs/{id}/detail/program-docs")
    @Headers("Accept: application/pdf")
    suspend fun getProgramDocsWithHeaders(
        @Path("id") pairId: String,
        @Header("Authorization") token: String? = null
    ): Response<ResponseBody>
}