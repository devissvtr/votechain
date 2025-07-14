package com.nocturna.votechain.data.repository

import android.content.Context
import android.net.Uri
import android.util.Log
import android.webkit.MimeTypeMap
import com.google.gson.Gson
import com.nocturna.votechain.data.model.ApiResponse
import com.nocturna.votechain.data.model.RegisterRequest
import com.nocturna.votechain.data.model.UserRegistrationData
import com.nocturna.votechain.data.network.NetworkClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import retrofit2.Response
import java.io.File
import java.io.FileOutputStream

/**
 * Repository class to handle user-related operations
 */
class UserRepository(private val context: Context) {

    private val apiService = NetworkClient.registrationApiService

    /**
     * Register a new user with or without KTP file
     * @param ktpFileUri Optional KTP file URI - if provided, form data approach will be used
     * @param voterAddress Ethereum address to use as voter_address
     */
    suspend fun registerUser(
        email: String,
        password: String,
        nik: String,
        fullName: String,
        gender: String,
        birthPlace: String,
        birthDate: String,
        residentialAddress: String,
        region: String,
        role: String = "voter",
        voterAddress: String = "",
        telephone: String,
        ktpFileUri: Uri? = null
    ): Result<ApiResponse<UserRegistrationData>> = withContext(Dispatchers.IO) {
        try {
            // Determine which API approach to use based on KTP file presence
            val response = if (ktpFileUri != null) {
                // Use multipart form data approach with file upload
                registerWithFormData(
                    email, password, role, nik, fullName, gender,
                    birthPlace, birthDate, residentialAddress, region,
                    voterAddress, telephone, ktpFileUri
                )
            } else {
                // Use JSON request approach without file
                registerWithJson(
                    email, password, role, nik, fullName, gender,
                    birthPlace, birthDate, residentialAddress, region,
                    voterAddress, telephone
                )
            }

            // Enhanced logging for both success and error cases
            if (response.isSuccessful) {
                response.body()?.let {
                    Log.d("UserRepository", "Registration successful: ${it.message}")
                    Result.success(it)
                } ?: run {
                    Log.e("UserRepository", "Empty response body with success code: ${response.code()}")
                    Result.failure(Exception("Empty response body"))
                }
            } else {
                val errorBody = response.errorBody()?.string()
                Log.e("UserRepository", "Registration failed with code: ${response.code()}")
                Log.e("UserRepository", "Error body: $errorBody")

                // Try to parse the error body as JSON for more detailed logging
                try {
                    val gson = Gson()
                    val errorJson = gson.fromJson(errorBody, ApiResponse::class.java)
                    Log.e("UserRepository", "Parsed error: ${errorJson.message}, code: ${errorJson.code}")
                    if (errorJson.error != null) {
                        Log.e("UserRepository", "Error details: ${errorJson.error.error_message}")
                    }
                } catch (e: Exception) {
                    Log.e("UserRepository", "Could not parse error JSON: ${e.message}")
                }

                Result.failure(Exception("Error: ${response.code()} - $errorBody"))
            }
        } catch (e: Exception) {
            Log.e("UserRepository", "Exception during registration", e)
            Result.failure(e)
        }
    }

    /**
     * Register with JSON request (no file upload)
     */
    private suspend fun registerWithJson(
        email: String,
        password: String,
        role: String,
        nik: String,
        fullName: String,
        gender: String,
        birthPlace: String,
        birthDate: String,
        residentialAddress: String,
        region: String,
        voterAddress: String,
        telephone: String
    ): Response<ApiResponse<UserRegistrationData>> {
        val request = RegisterRequest(
            email = email,
            password = password,
            role = role,
            address = voterAddress,
            nik = nik,
            full_name = fullName,
            gender = gender,
            birth_place = birthPlace,
            birth_date = birthDate,
            residential_address = residentialAddress,
            region = region,
            telephone = telephone
        )
        Log.d("UserRepository", "Sending registration request with voter_address: $voterAddress")
        return apiService.registerUser(request)
    }

    /**
     * Get file extension from Uri
     */
    private fun getFileExtension(uri: Uri): String {
        val mimeType = context.contentResolver.getType(uri)
        return MimeTypeMap.getSingleton().getExtensionFromMimeType(mimeType) ?: "jpg"
    }

    /**
     * Register with form data approach (with file upload)
     */
    private suspend fun registerWithFormData(
        email: String,
        password: String,
        role: String,
        nik: String,
        fullName: String,
        gender: String,
        birthPlace: String,
        birthDate: String,
        residentialAddress: String,
        region: String,
        voterAddress: String,
        telephone: String,
        ktpFileUri: Uri
    ): Response<ApiResponse<UserRegistrationData>> {
        // Get the file extension from the actual URI
        val fileExtension = getFileExtension(ktpFileUri)

        // Convert Uri to File with the appropriate extension
        val ktpFile = uriToFile(ktpFileUri, "ktp_${System.currentTimeMillis()}.$fileExtension")

        // Create user data object
        val userRequest = RegisterRequest(
            email = email,
            password = password,
            role = role,
            address = voterAddress,
            nik = nik,
            full_name = fullName,
            gender = gender,
            birth_place = birthPlace,
            birth_date = birthDate,
            residential_address = residentialAddress,
            region = region,
            telephone = telephone
        )

        // Convert user data to JSON
        val gson = Gson()
        val userJson = gson.toJson(userRequest)
        Log.d("UserRepository", "User JSON: $userJson")
        val userPart = userJson.toRequestBody("application/json".toMediaTypeOrNull())

        // Get MIME type from Uri
        val mimeType = context.contentResolver.getType(ktpFileUri) ?: "image/jpeg"

        // Create file part with the appropriate MIME type
        val requestFile = ktpFile.asRequestBody(mimeType.toMediaTypeOrNull())
        val ktpFilePart = MultipartBody.Part.createFormData("ktp_photo", ktpFile.name, requestFile)


        // Make API call with the updated parameters
        return apiService.registerUserWithFormData(
            user = userPart,
            ktp_photo = ktpFilePart
        )
    }

    /**
     * Convert Uri to File
     * @param uri URI of the file
     * @param fileName Name of the file
     * @return File object
     */
    private fun uriToFile(uri: Uri, fileName: String): File {
        val inputStream = context.contentResolver.openInputStream(uri)
        val outputFile = File(context.cacheDir, fileName)

        inputStream?.use { input ->
            FileOutputStream(outputFile).use { output ->
                input.copyTo(output)
            }
        }

        return outputFile
    }
}