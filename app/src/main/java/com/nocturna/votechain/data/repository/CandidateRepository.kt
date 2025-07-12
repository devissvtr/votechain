package com.nocturna.votechain.data.repository

import com.nocturna.votechain.R
import com.nocturna.votechain.data.model.CandidateDetailData
import com.nocturna.votechain.data.model.CandidatePersonalInfo
import com.nocturna.votechain.data.model.EducationEntry
import com.nocturna.votechain.data.model.WorkEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

class CandidateRepository {

    suspend fun getCandidateById(candidateId: String): CandidateDetailData =
        withContext(Dispatchers.IO) {
            // Simulate network delay
            delay(500)

            // For now, return dummy data
            // In real implementation, the data would come from a database or API
            return@withContext when (candidateId) {
                "anies" -> getDummyAniesData()
                "prabowo" -> getDummyPrabowoData()
                "ganjar" -> getDummyGanjarData()
                "imin" -> getDummyIminData()
                "gibran" -> getDummyGibranData()
                "mahfud" -> getDummyMahfudData()
                else -> getDummyAniesData() // Default to Anies data for now
            }
        }

    // Dummy data methods
    private fun getDummyAniesData(): CandidateDetailData {
        return CandidateDetailData(
            personalInfo = CandidatePersonalInfo(
                id = "anies",
                fullName = "H. Anies Rasyid Baswedan, Ph. D.",
                position = "Presidential Candidate",
                gender = "Laki-laki",
                birthInfo = "Kuningan, 7 Mei 1969",
                religion = "Islam",
                education = "S3",
                occupation = "Karyawan Swasta",
                photoResId = R.drawable.ic_launcher_background
            ),
            educationHistory = listOf(
                EducationEntry("SD Negeri Laboratori 2 Yogyakarta", "1976 - 1982"),
                EducationEntry("SMP Negeri 5 Yogyakarta", "1982 - 1985"),
                EducationEntry("SMA Negeri 2 Yogyakarta", "1985 - 1989"),
                EducationEntry(
                    "Fakultas Ekonomi, Universitas Gadjah Mada, Yogyakarta",
                    "1989 - 1995"
                ),
                EducationEntry(
                    "Departemen Kebijakan Publik, University of Maryland, College Park, AS",
                    "1996 - 1998"
                ),
                EducationEntry(
                    "Departemen Ilmu Politik, Northern Illinois University, AS",
                    "1999 - 2007"
                )
            ),
            workHistory = listOf(
                WorkEntry("The Indonesian Institute", "Direktur Riset", "2005 - 2009"),
                WorkEntry(
                    "Kemitraan-Partnership for Governance Reform",
                    "Direktur Riset",
                    "2006 - 2007"
                ),
                WorkEntry("Universitas Paramadina", "Rektor", "2007 - 2014"),
                WorkEntry("Kementerian Pendidikan dan Kebudayaan", "Menteri", "2014 - 2016"),
                WorkEntry("Pemerintah Provinsi DKI Jakarta", "Gubernur", "2017 - 2022")
            )
        )
    }

    private fun getDummyPrabowoData(): CandidateDetailData {
        return CandidateDetailData(
            personalInfo = CandidatePersonalInfo(
                id = "prabowo",
                fullName = "H. Prabowo Subianto",
                position = "Presidential Candidate",
                gender = "Laki-laki",
                birthInfo = "Jakarta, 17 Oktober 1951",
                religion = "Islam",
                education = "S1",
                occupation = "Pengusaha",
                photoResId = R.drawable.ic_launcher_background
            ),
            educationHistory = listOf(
                EducationEntry("Akademi Militer", "1970 - 1974"),
                EducationEntry("Sekolah Staf Komando Angkatan Darat", "1985 - 1986")
            ),
            workHistory = listOf(
                WorkEntry("TNI", "Komandan Kopassus", "1995 - 1998"),
                WorkEntry("Partai Gerindra", "Ketua Umum", "2008 - Sekarang")
            )
        )
    }

    private fun getDummyGanjarData(): CandidateDetailData {
        return CandidateDetailData(
            personalInfo = CandidatePersonalInfo(
                id = "ganjar",
                fullName = "H. Ganjar Pranowo",
                position = "Presidential Candidate",
                gender = "Laki-laki",
                birthInfo = "Karanganyar, 28 Oktober 1968",
                religion = "Islam",
                education = "S1",
                occupation = "Politisi",
                photoResId = R.drawable.ic_launcher_background
            ),
            educationHistory = listOf(
                EducationEntry("SDN Manahan 1 Surakarta", "1976 - 1982"),
                EducationEntry("SMP Negeri 1 Surakarta", "1982 - 1985"),
                EducationEntry("SMA Negeri 1 Surakarta", "1985 - 1988"),
                EducationEntry("Fakultas Hukum, Universitas Gadjah Mada", "1988 - 1995")
            ),
            workHistory = listOf(
                WorkEntry("DPRD Jawa Tengah", "Anggota", "2004 - 2009"),
                WorkEntry("DPR RI", "Anggota", "2009 - 2013"),
                WorkEntry("Pemerintah Provinsi Jawa Tengah", "Gubernur", "2013 - 2023")
            )
        )
    }

    // Vice Presidential candidates data

    private fun getDummyIminData(): CandidateDetailData {
        return CandidateDetailData(
            personalInfo = CandidatePersonalInfo(
                id = "imin",
                fullName = "KH. Abdul Muhaimin Iskandar",
                position = "Vice Presidential Candidate",
                gender = "Laki-laki",
                birthInfo = "Jombang, 24 Agustus 1966",
                religion = "Islam",
                education = "S1",
                occupation = "Politisi",
                photoResId = R.drawable.ic_launcher_background
            ),
            educationHistory = listOf(
                EducationEntry("Pondok Pesantren Tebuireng, Jombang", "1978 - 1984"),
                EducationEntry("Al-Azhar University, Kairo", "1985 - 1989"),
                EducationEntry(
                    "Fakultas Ilmu Sosial dan Ilmu Politik, Universitas Indonesia",
                    "1989 - 1993"
                )
            ),
            workHistory = listOf(
                WorkEntry("DPR RI", "Anggota", "1999 - 2004"),
                WorkEntry("DPR RI", "Anggota", "2004 - 2009"),
                WorkEntry("Kementerian Tenaga Kerja dan Transmigrasi", "Menteri", "2009 - 2014"),
                WorkEntry("PKB (Partai Kebangkitan Bangsa)", "Ketua Umum", "2005 - Sekarang"),
                WorkEntry("DPR RI", "Wakil Ketua", "2019 - 2024")
            )
        )
    }

    private fun getDummyGibranData(): CandidateDetailData {
        return CandidateDetailData(
            personalInfo = CandidatePersonalInfo(
                id = "gibran",
                fullName = "Gibran Rakabuming Raka",
                position = "Vice Presidential Candidate",
                gender = "Laki-laki",
                birthInfo = "Solo, 1 Oktober 1987",
                religion = "Islam",
                education = "S2",
                occupation = "Walikota Solo",
                photoResId = R.drawable.ic_launcher_background
            ),
            educationHistory = listOf(
                EducationEntry("Singapore Management University", "2005 - 2007"),
                EducationEntry("University of Technology, Sydney, Australia", "2007 - 2010"),
                EducationEntry("Management Development Institute of Singapore", "2010 - 2012")
            ),
            workHistory = listOf(
                WorkEntry("Chilli Pari Catering", "Pendiri & CEO", "2010 - 2021"),
                WorkEntry("Markobar (Martabak Kota Baru)", "Pendiri", "2015 - 2021"),
                WorkEntry("Pemerintah Kota Solo", "Walikota", "2021 - 2024")
            )
        )
    }

    private fun getDummyMahfudData(): CandidateDetailData {
        return CandidateDetailData(
            personalInfo = CandidatePersonalInfo(
                id = "mahfud",
                fullName = "Prof. Dr. H. Mahfud MD",
                position = "Vice Presidential Candidate",
                gender = "Laki-laki",
                birthInfo = "Sampang, Madura, 13 Mei 1957",
                religion = "Islam",
                education = "S3",
                occupation = "Menteri Koordinator Bidang Politik, Hukum, dan Keamanan",
                photoResId = R.drawable.ic_launcher_background
            ),
            educationHistory = listOf(
                EducationEntry(
                    "Fakultas Hukum, Universitas Islam Indonesia, Yogyakarta",
                    "1979 - 1983"
                ),
                EducationEntry("Magister Ilmu Hukum, Universitas Islam Indonesia", "1987 - 1989"),
                EducationEntry("Program Doktor Ilmu Hukum, Universitas Gadjah Mada", "1991 - 1993")
            ),
            workHistory = listOf(
                WorkEntry("Universitas Islam Indonesia", "Dosen/Guru Besar", "1984 - Sekarang"),
                WorkEntry("Mahkamah Konstitusi Republik Indonesia", "Ketua", "2008 - 2013"),
                WorkEntry("Kementerian Pertahanan", "Menteri", "2000 - 2001"),
                WorkEntry("Kementerian Kehakiman dan HAM", "Menteri", "2001 - 2004"),
                WorkEntry("Pemerintah Indonesia", "Menko Polhukam", "2019 - 2024")
            )
        )
    }
}