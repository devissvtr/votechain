package com.nocturna.votechain.data.repository

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit

/**
 * Class to manage and persist registration state
 */
class RegistrationStateManager(context: Context) {

    companion object {
        private const val PREFERENCES_NAME = "registration_prefs"
        private const val KEY_REGISTRATION_STATE = "registration_state"
        private const val KEY_EMAIL = "email"
        private const val KEY_NIK = "nik"

        // Registration states
        const val STATE_NONE = 0
        const val STATE_WAITING = 1
        const val STATE_APPROVED = 2
        const val STATE_REJECTED = 3
    }

    private val preferences: SharedPreferences = context.getSharedPreferences(
        PREFERENCES_NAME, Context.MODE_PRIVATE
    )

    /**
     * Save the registration state along with identification data
     */
    fun saveRegistrationState(state: Int, email: String, nik: String) {
        preferences.edit {
            putInt(KEY_REGISTRATION_STATE, state)
            putString(KEY_EMAIL, email)
            putString(KEY_NIK, nik)
        }
    }

    /**
     * Clear all registration state data
     */
    fun clearRegistrationState() {
        preferences.edit {
            remove(KEY_REGISTRATION_STATE)
            remove(KEY_EMAIL)
            remove(KEY_NIK)
        }
    }

    /**
     * Get the current registration state
     */
    fun getRegistrationState(): Int {
        return preferences.getInt(KEY_REGISTRATION_STATE, STATE_NONE)
    }

    /**
     * Get the saved email
     */
    fun getSavedEmail(): String {
        return preferences.getString(KEY_EMAIL, "") ?: ""
    }
}