package com.nocturna.votechain.utils

/**
 * Data class containing all localized strings used in the application
 */
data class LocalizedStrings(
    // Common
    val appName: String,
    val loading: String,
    val error: String,
    val retry: String,
    val submit: String,
    val cancel: String,
    val close: String,
    val next: String,
    val back: String,
    val done: String,

    // Settings
    val settings: String,
    val theme: String,
    val language: String,
    val about: String,
    val faq: String,
    val logout: String,
    val textToSpeech: String,

    // Navigation
    val homeNav: String,
    val votesNav: String,
    val profileNav: String,

    // Login & Registration
    val login: String,
    val loginAccount: String,
    val loginDescription: String,
    val email: String,
    val password: String,
    val forgotPassword: String,
    val register: String,
    val registerAccount: String,
    val registerDescription: String,
    val dontHaveAccount: String,
    val alreadyHaveAccount: String,

    // Registration Form
    val nationalId: String,
    val fullName: String,
    val birthPlace: String,
    val birthDate: String,
    val address: String,
    val province: String,
    val region: String,
    val gender: String,
    val male: String,
    val female: String,
    val setPassword: String,
    val uploadKtp: String,
    val uploadKtpDescription: String,
    val browseFiles: String,

    // Registration States
    val verifyingData: String,
    val verifyingDataDescription: String,
    val verificationApproved: String,
    val verificationApprovedDescription: String,
    val verificationDenied: String,
    val verificationDeniedDescription: String,
    val retryRegistration: String,

    // Home
    val empoweringDemocracy: String,
    val oneVoteAtATime: String,
    val latestNews: String,
    val activeVotesList: String,
    val moreDetails: String,

    // Voting
    val candidatePresident: String,
    val allCandidates: String,
    val candidateSelection: String,
    val selectCandidate: String,
    val presidentialCandidate: String,
    val vicePresidentialCandidate: String,
    val proposingParties: String,
    val visionMission: String,
    val vision: String,
    val mission: String,
    val workProgram: String,
    val vote: String,
    val voteComplete: String,
    val voteIncomplete: String,
    val votingVerification: String,
    val otpVerification: String,
    val otpDescription: String,
    val didntReceiveOtp: String,
    val resendOtp: String,
    val verify: String,
    val verifyToVote: String,
    val votingSuccess: String,
    val votingSuccessDesc: String,
    val backHome: String,

    // Candidate Details
    val detailCandidate: String,
    val personalInfo: String,
    val genderCandidate: String,
    val birthInfo: String,
    val religion: String,
    val education: String,
    val occupation: String,
    val educationHistory: String,
    val workHistory: String,
    val institution: String,
    val position: String,
    val period: String,
    val candidate: String,
    val viewProfile: String,
    val year: String,
    val candidateVisionMission: String,
    val noneSupportingParties: String,

    // Results
    val results: String,
    val totalVotes: String,
    val votes: String,
    val noResultsAvailable: String,
    val noResultsDescription: String,

    // Profile
    val account: String,
    val balance: String,
    val nik: String,
    val privateKey: String,
    val publicKey: String,
    val view: String,
    val moreInformation: String,

    // Notifications
    val notification: String,
    val noNotifications: String,

    //Card
    val cardTitle: String,
    val cardSubtitle: String,
    val cardDescription: String,

    // FAQ Questions
    val faq_question_1: String,
    val faq_question_2: String,
    val faq_question_3: String,
    val faq_question_4: String,
    val faq_question_5: String,

    // FAQ Answer 1
    val faq_answer_1: String,

    // FAQ Answer 2
    val faq_answer_2_intro: String,
    val faq_answer_2_step1_title: String,
    val faq_answer_2_step1_desc: String,
    val faq_answer_2_step2_title: String,
    val faq_answer_2_step2_desc: String,
    val faq_answer_2_step3_title: String,
    val faq_answer_2_step3_desc: String,
    val faq_answer_2_step4_title: String,
    val faq_answer_2_step4_desc: String,
    val faq_answer_2_step5_title: String,
    val faq_answer_2_step5_desc: String,
    val faq_answer_2_step6_title: String,
    val faq_answer_2_step6_desc: String,

    // FAQ Answer 3
    val faq_answer_3_intro: String,
    val faq_answer_3_point1_title: String,
    val faq_answer_3_point1_desc: String,
    val faq_answer_3_point2_title: String,
    val faq_answer_3_point2_desc: String,
    val faq_answer_3_point3_title: String,
    val faq_answer_3_point3_desc: String,

    // FAQ Answer 4
    val faq_answer_4_intro: String,
    val faq_answer_4_point1_title: String,
    val faq_answer_4_point1_desc: String,
    val faq_answer_4_point2_title: String,
    val faq_answer_4_point2_desc: String,

    // FAQ Answer 5
    val faq_answer_5_intro: String,
    val faq_answer_5_point1_title: String,
    val faq_answer_5_point1_desc: String,
    val faq_answer_5_point2_title: String,
    val faq_answer_5_point2_desc: String,

    // Password Confirmation Dialog
    val passwordConfirmationTitle: String,
    val passwordConfirmationSubtitle: String,
    val passwordConfirmationCancel: String,
    val passwordConfirmationSubmit: String,
    val passwordIncorrect: String,
    val passwordEmpty: String,

    // Data availability
    val dataNotAvailable: String,
    val visionNotAvailable: String,
    val missionNotAvailable: String,
    val workProgramNotAvailable: String,
)

/**
 * Get localized strings based on the selected language
 */
fun getLocalizedStrings(language: String): LocalizedStrings {
    return when (language) {
        "Indonesia" -> getIndonesianStrings()
        else -> getEnglishStrings()
    }
}

/**
 * Get strings in Indonesian language
 */
private fun getIndonesianStrings(): LocalizedStrings {
    return LocalizedStrings(
        // Common
        appName = "VoteChain",
        loading = "Memuat",
        error = "Error",
        retry = "Coba Lagi",
        submit = "Kirim",
        cancel = "Batal",
        close = "Tutup",
        next = "Lanjut",
        back = "Kembali",
        done = "Selesai",

        // Settings
        settings = "Pengaturan",
        theme = "Tema",
        language = "Bahasa",
        about = "Tentang",
        faq = "Pertanyaan Umum",
        logout = "Keluar",
        textToSpeech = "Teks ke Suara",

        // Navigation
        homeNav = "Beranda",
        votesNav = "Voting",
        profileNav = "Profil",

        // Login & Registration
        login = "Masuk",
        loginAccount = "Masuk ke Akun",
        loginDescription = "Akses akun Anda untuk dapat berpartisipasi dan mengelola aktivitas pemungutan suara",
        email = "Email",
        password = "Kata Sandi",
        forgotPassword = "Lupa Kata Sandi?",
        register = "Daftar",
        registerAccount = "Buat Akun",
        registerDescription = "Buat akun untuk mengakses dan menjelajahi semua kesempatan pemungutan suara yang tersedia",
        dontHaveAccount = "Belum punya akun? ",
        alreadyHaveAccount = "Sudah punya akun? ",

        // Registration Form
        nationalId = "Nomor Induk Kependudukan",
        fullName = "Nama Lengkap",
        birthPlace = "Tempat Lahir",
        birthDate = "Tanggal Lahir",
        address = "Alamat",
        province = "Provinsi",
        region = "Kabupaten/Kota",
        gender = "Jenis Kelamin",
        male = "Laki-laki",
        female = "Perempuan",
        setPassword = "Buat Kata Sandi",
        uploadKtp = "Unggah Kartu Tanda Penduduk (KTP) Anda",
        uploadKtpDescription = "Format file yang diterima: JPG, JPEG, dan PNG",
        browseFiles = "Pilih File",

        // Registration States
        verifyingData = "Memverifikasi Data Anda",
        verifyingDataDescription = "Kami sedang memeriksa data Anda dengan Daftar Pemilih. Proses ini akan selesai dalam waktu singkat",
        verificationApproved = "Verifikasi Disetujui",
        verificationApprovedDescription = "Selamat! Akun Anda telah berhasil dibuat. Silakan masuk untuk mengakses akun Anda dan berpartisipasi dalam pemilihan",
        verificationDenied = "Verifikasi Ditolak",
        verificationDeniedDescription = "Data Anda tidak dapat diverifikasi dalam Daftar Pemilih. Harap periksa kembali detail Anda dan coba lagi",
        retryRegistration = "Coba Pendaftaran Lagi",

        // Home
        empoweringDemocracy = "Pemberdayaan Demokrasi",
        oneVoteAtATime = "Satu Suara Setiap Kali",
        latestNews = "Berita Terbaru",
        activeVotesList = "Daftar Voting Aktif",
        moreDetails = "Detail lebih lanjut",

        // Voting
        candidatePresident = "Kandidat Presiden",
        allCandidates = "Semua Kandidat",
        candidateSelection = "Pemilihan Kandidat",
        selectCandidate = "Pilih Kandidat",
        presidentialCandidate = "Kandidat Presiden",
        vicePresidentialCandidate = "Kandidat Wakil Presiden",
        proposingParties = "Partai Pengusung",
        visionMission = "Visi & Misi",
        vision = "Visi:",
        mission = "Misi:",
        workProgram = "Program Kerja:",
        vote = "Voting",
        voteComplete = "Sudah Memilih",
        voteIncomplete = "Belum Memilih",
        votingVerification = "Verifikasi Voting",
        otpVerification = "Verifikasi OTP",
        otpDescription = "Masukkan OTP yang dikirim ke nomor telepon terdaftar Anda untuk memverifikasi identitas Anda sebelum memilih",
        didntReceiveOtp = "Tidak menerima OTP? ",
        resendOtp = "Kirim Ulang OTP",
        verify = "Verifikasi",
        verifyToVote = "Verifikasi untuk Memilih",
        votingSuccess = "Voting Berhasil Submit!",
        votingSuccessDesc = "Terima kasih telah memberikan suara Anda. Suara Anda telah berhasil tercatat",
        backHome = "Kembali ke Beranda",

        // Candidate Details
        detailCandidate = "Detail Kandidat",
        personalInfo = "Informasi Pribadi",
        genderCandidate = "Jenis Kelamin",
        birthInfo = "Tempat/Tanggal Lahir",
        religion = "Agama",
        education = "Pendidikan Terakhir",
        occupation = "Pekerjaan",
        educationHistory = "Riwayat Pendidikan",
        workHistory = "Riwayat Pekerjaan",
        institution = "Nama Institusi",
        position = "Jabatan",
        period = "Periode",
        candidate = "Kandidat",
        viewProfile = "Lihat Profil",
        year = "Tahun",
        candidateVisionMission = "Visi & Misi Kandidat",
        noneSupportingParties = "Data partai tidak tersedia",

        // Results
        results = "Hasil Pemilihan Langsung",
        totalVotes = "Total Suara",
        votes = "suara",
        noResultsAvailable = "Tidak ada hasil voting tersedia",
        noResultsDescription = "Hasil akan muncul di sini setelah periode voting berakhir",

        // Profile
        account = "Akun",
        balance = "Saldo",
        nik = "Nomor Induk Kependudukan",
        privateKey = "Private Key",
        publicKey = "Public Key",
        view = "Lihat",
        moreInformation = "Informasi Lebih Lanjut",

        // Notifications
        notification = "Notifikasi",
        noNotifications = "Tidak ada notifikasi",

        // Card
        cardTitle = "Pemilihan Presiden 2024 - Indonesia",
        cardSubtitle = "Pilihlah pemimpin yang Anda percayai untuk memajukan Indonesia",
        cardDescription = "Klik di sini untuk mengakses informasi detail tentang visi, misi, dan program kerja lengkap pasangan calon ini",

        // FAQ Questions
        faq_question_1 = "Apa keunggulan VoteChain dibandingkan metode voting tradisional?",
        faq_question_2 = "Bagaimana cara menggunakan VoteChain?",
        faq_question_3 = "Apakah vote saya tetap privat di VoteChain?",
        faq_question_4 = "Apakah saya bisa melakukan vote di luar periode voting yang ditentukan?",
        faq_question_5 = "Mengapa Public Key dan Private Key penting dalam VoteChain?",

        // FAQ Answer 1
        faq_answer_1 = "VoteChain menawarkan banyak keunggulan dibandingkan metode voting tradisional. Menggunakan teknologi blockchain, VoteChain memastikan keamanan tinggi dimana data vote tidak dapat diubah, dan identitas pemilih tetap terlindungi. Semua vote tercatat secara transparan, memungkinkan hasil untuk diverifikasi tanpa mengorbankan privasi pemilih.\n\nProsesnya juga lebih cepat dan efisien biaya, karena penghitungan vote dilakukan secara otomatis. Pemilih dapat memberikan suara dari mana saja menggunakan perangkat yang terhubung internet, membuatnya lebih nyaman dan dapat diakses. Selain itu, VoteChain mendukung keberlanjutan lingkungan dengan mengurangi penggunaan kertas dan kebutuhan logistik skala besar. Dengan fitur-fitur ini, VoteChain menyediakan sistem voting yang lebih aman, transparan, dan efisien untuk semua orang.",

        // FAQ Answer 2
        faq_answer_2_intro = "Berikut adalah langkah-langkah menggunakan aplikasi VoteChain:",
        faq_answer_2_step1_title = "Daftar Akun",
        faq_answer_2_step1_desc = "Daftar dengan memasukkan nomor KTP (NIK) dan data diri. Setelah diverifikasi, akun Anda aktif dan dapat mengatur password.",
        faq_answer_2_step2_title = "Masuk ke Akun Anda",
        faq_answer_2_step2_desc = "Login dengan NIK dan password, dan Anda akan diarahkan ke Menu Voting.",
        faq_answer_2_step3_title = "Pilih Kategori Pemilihan",
        faq_answer_2_step3_desc = "Di tab Vote, pilih kategori pemilihan yang sedang aktif.",
        faq_answer_2_step4_title = "Verifikasi Identitas Anda",
        faq_answer_2_step4_desc = "Sistem akan meminta Anda untuk Scan KTP untuk mencocokkan data Anda dengan sistem.",
        faq_answer_2_step5_title = "Berikan Suara Anda",
        faq_answer_2_step5_desc = "Setelah verifikasi, pilih kandidat atau opsi yang Anda inginkan dan konfirmasi. Sistem akan memberi tahu Anda setelah vote berhasil tercatat.",
        faq_answer_2_step6_title = "Cek Status Voting",
        faq_answer_2_step6_desc = "Anda dapat mengecek status voting di Settings > Account > Voting Status. Jika sudah vote akan muncul Vote Complete, jika belum akan muncul Vote Incomplete.",

        // FAQ Answer 3
        faq_answer_3_intro = "Ya, vote Anda tetap sepenuhnya privat di VoteChain. Platform ini menggunakan teknologi blockchain dan enkripsi tingkat tinggi untuk memastikan privasi vote Anda.",
        faq_answer_3_point1_title = "Anonimitas Terjamin",
        faq_answer_3_point1_desc = "Identitas pemilih dipisahkan dari data voting, sehingga tidak ada yang dapat menghubungkan vote Anda dengan informasi pribadi Anda.",
        faq_answer_3_point2_title = "Keamanan Data",
        faq_answer_3_point2_desc = "Semua data voting dienkripsi dan hanya dapat diakses oleh sistem untuk keperluan penghitungan, tanpa melibatkan pihak ketiga.",
        faq_answer_3_point3_title = "Verifikasi Transparan",
        faq_answer_3_point3_desc = "Meskipun prosesnya transparan dan dapat diaudit, identitas pemilih tetap sepenuhnya rahasia.",

        // FAQ Answer 4
        faq_answer_4_intro = "Tidak, VoteChain hanya mengizinkan pengguna untuk memberikan suara selama periode pemilihan yang ditentukan. Sistem secara otomatis mengaktifkan dan menonaktifkan akses voting berdasarkan jadwal resmi yang ditetapkan penyelenggara pemilihan.",
        faq_answer_4_point1_title = "Jangka Waktu Terbatas",
        faq_answer_4_point1_desc = "Anda hanya dapat vote selama periode voting aktif. Setelah periode berakhir, sistem tidak akan menerima vote lagi.",
        faq_answer_4_point2_title = "Notifikasi Pengingat",
        faq_answer_4_point2_desc = "VoteChain menyediakan notifikasi untuk mengingatkan Anda tentang jadwal pemilihan agar tidak melewatkan kesempatan vote.",

        // FAQ Answer 5
        faq_answer_5_intro = "Public Key dan Private Key sangat penting dalam VoteChain karena mereka memastikan keamanan, privasi, dan integritas proses voting:",
        faq_answer_5_point1_title = "Public Key",
        faq_answer_5_point1_desc = "Berfungsi sebagai identitas digital Anda di jaringan blockchain. Memungkinkan Anda menerima data atau diverifikasi sebagai pemilih tanpa mengungkapkan informasi pribadi.",
        faq_answer_5_point2_title = "Private Key",
        faq_answer_5_point2_desc = "Mengamankan akun Anda dan mengotorisasi setiap transaksi yang Anda lakukan. Dengan Private Key, hanya Anda yang dapat mengakses dan memvalidasi vote Anda dalam sistem.",

        // Password Confirmation Dialog
        passwordConfirmationTitle = "Masukkan Kata Sandi",
        passwordConfirmationSubtitle = "Masukkan kata sandi Anda untuk melihat detail akun",
        passwordConfirmationCancel = "Batal",
        passwordConfirmationSubmit = "Kirim",
        passwordIncorrect = "Kata sandi salah. Silahkan coba lagi",
        passwordEmpty = "Kata sandi tidak boleh kosong",

        // Data availability
        dataNotAvailable = "Data tidak tersedia",
        visionNotAvailable = "Visi tidak tersedia",
        missionNotAvailable = "Misi tidak tersedia",
        workProgramNotAvailable = "Program kerja tidak tersedia",
    )
}

/**
 * Get strings in English language
 */
private fun getEnglishStrings(): LocalizedStrings {
    return LocalizedStrings(
        // Common
        appName = "VoteChain",
        loading = "Loading",
        error = "Error",
        retry = "Retry",
        submit = "Submit",
        cancel = "Cancel",
        close = "Close",
        next = "Next",
        back = "Back",
        done = "Done",

        // Settings
        settings = "Settings",
        theme = "Theme",
        language = "Language",
        about = "About",
        faq = "FAQ",
        logout = "Logout",
        textToSpeech = "Text to Speech",

        // Navigation
        homeNav = "Home",
        votesNav = "Votes",
        profileNav = "Profile",

        // Login & Registration
        login = "Login",
        loginAccount = "Login Account",
        loginDescription = "Access your account to participate in and manage your voting activities",
        email = "Email",
        password = "Password",
        forgotPassword = "Forgot Password?",
        register = "Register",
        registerAccount = "Create Account",
        registerDescription = "Create an account to access and explore all available voting opportunities",
        dontHaveAccount = "Don't have an account? ",
        alreadyHaveAccount = "Already have an account? ",

        // Registration Form
        nationalId = "National Identification Number",
        fullName = "Full Name",
        birthPlace = "Birth Place",
        birthDate = "Birth Date",
        address = "Address",
        province = "Province",
        region = "Region",
        gender = "Gender",
        male = "Male",
        female = "Female",
        setPassword = "Set Password",
        uploadKtp = "Upload your ID card (KTP)",
        uploadKtpDescription = "Accepted file formats: JPG, JPEG, and PNG",
        browseFiles = "Browse files",

        // Registration States
        verifyingData = "Verifying Your Data",
        verifyingDataDescription = "We're cross-checking your data with the Voter List. This process will be completed shortly",
        verificationApproved = "Verification Approved",
        verificationApprovedDescription = "Congratulations! Your account has been created successfully. Please log in to access your account and participate in the election",
        verificationDenied = "Verification Denied",
        verificationDeniedDescription = "Your data could not be verified in the Voter List. Please review your details and try again",
        retryRegistration = "Retry Registration",

        // Home
        empoweringDemocracy = "Empowering Democracy",
        oneVoteAtATime = "One Vote at a Time",
        latestNews = "Latest News",
        activeVotesList = "Active Votes List",
        moreDetails = "More details",

        // Voting
        candidatePresident = "Candidate President",
        allCandidates = "All Candidates",
        candidateSelection = "Candidate Selection",
        selectCandidate = "Select Candidate",
        presidentialCandidate = "Presidential Candidate",
        vicePresidentialCandidate = "Vice Presidential Candidate",
        proposingParties = "Proposing Parties",
        visionMission = "Vision & Mission",
        vision = "Vision:",
        mission = "Mission:",
        workProgram = "Work Program:",
        vote = "Vote",
        voteComplete = "Vote Complete",
        voteIncomplete = "Vote Incomplete",
        votingVerification = "Voting Verification",
        otpVerification = "OTP Verification",
        otpDescription = "Enter the OTP sent to your registered phone number to verify your identity before voting",
        didntReceiveOtp = "Didn't you receive the OTP? ",
        resendOtp = "Resend OTP",
        verify = "Verify",
        verifyToVote = "Verify to Vote",
        votingSuccess = "Vote Successfully Submitted!",
        votingSuccessDesc = "Thank you for providing your vote. Your vote has been successfully recorded",
        backHome = "Back to Home",

        // Candidate Details
        detailCandidate = "Detail Candidate",
        personalInfo = "Personal Information",
        genderCandidate = "Gender",
        birthInfo = "Birth Place/Date",
        religion = "Religion",
        education = "Last Education",
        occupation = "Occupation",
        educationHistory = "Education History",
        workHistory = "Work History",
        institution = "Institution",
        position = "Position",
        period = "Period",
        candidate = "Candidate",
        viewProfile = "View Profile",
        year = "Year",
        candidateVisionMission = "Candidate Vision & Mission",
        noneSupportingParties = "Party data not available",

        // Results
        results = "Live Election Results",
        totalVotes = "Total Votes",
        votes = "votes",
        noResultsAvailable = "No voting results available",
        noResultsDescription = "Results will appear here after voting periods end",

        // Profile
        account = "Account",
        balance = "Balance",
        nik = "National Identification Number",
        privateKey = "Private Key",
        publicKey = "Public Key",
        view = "View",
        moreInformation = "More Information",

        // Notifications
        notification = "Notification",
        noNotifications = "No notifications",

        // Card
        cardTitle = "Presidential Election 2024 - Indonesia",
        cardSubtitle = "Choose the leaders you trust to guide Indonesia forward",
        cardDescription = "Click here to access detailed information about the vision, mission, and complete work program of this candidate pair",

        // FAQ Questions
        faq_question_1 = "What are the advantages of VoteChain over traditional voting methods?",
        faq_question_2 = "How can I use VoteChain?",
        faq_question_3 = "Does my vote remain private on VoteChain?",
        faq_question_4 = "Can I vote outside the scheduled voting period?",
        faq_question_5 = "Why are Public Key and Private Key important in VoteChain?",

        // FAQ Answer 1
        faq_answer_1 = "VoteChain offers many advantages compared to traditional voting methods. Using blockchain technology, VoteChain ensures high security where vote data cannot be altered, and voter identities remain protected. All votes are transparently recorded, allowing results to be verified without compromising voter privacy.\n\nThe process is also faster and more cost-efficient, as vote counting is automated. Voters can cast their votes from anywhere using an internet-connected device, making it more convenient and accessible. Additionally, VoteChain supports environmental sustainability by reducing paper use and the need for large-scale logistics. With these features, VoteChain provides a safer, more transparent, and efficient voting system for everyone.",

        // FAQ Answer 2
        faq_answer_2_intro = "Here are the steps to use the VoteChain app:",
        faq_answer_2_step1_title = "Register an Account",
        faq_answer_2_step1_desc = "Sign up by entering your ID number (NIK) and personal details. Once verified, your account is activated, and you can set a password.",
        faq_answer_2_step2_title = "Log In to Your Account",
        faq_answer_2_step2_desc = "Log in with your NIK and password, and you'll be directed to the Voting Menu.",
        faq_answer_2_step3_title = "Select an Election Category",
        faq_answer_2_step3_desc = "In the Vote tab, choose an active election category.",
        faq_answer_2_step4_title = "Verify Your Identity",
        faq_answer_2_step4_desc = "The system will ask you to Scan Your ID to match your data with the system.",
        faq_answer_2_step5_title = "Cast Your Vote",
        faq_answer_2_step5_desc = "After verification, select your preferred candidate or option and confirm. The system will notify you once your vote is successfully recorded.",
        faq_answer_2_step6_title = "Check Voting Status",
        faq_answer_2_step6_desc = "You can check your voting status in Settings > Account > Voting Status. If you've voted, it will show Vote Complete; if not, it will show Vote Incomplete.",

        // FAQ Answer 3
        faq_answer_3_intro = "Yes, your vote remains completely private on VoteChain. The platform uses blockchain technology and high-level encryption to ensure the privacy of your vote.",
        faq_answer_3_point1_title = "Guaranteed Anonymity",
        faq_answer_3_point1_desc = "Voter identities are separated from voting data, so no one can link your vote to your personal information.",
        faq_answer_3_point2_title = "Data Security",
        faq_answer_3_point2_desc = "All voting data is encrypted and can only be accessed by the system for tallying purposes, without involving third parties.",
        faq_answer_3_point3_title = "Transparent Verification",
        faq_answer_3_point3_desc = "While the process is transparent and auditable, voter identities remain entirely confidential.",

        // FAQ Answer 4
        faq_answer_4_intro = "No, VoteChain only allows users to cast their votes during the specified election period. The system automatically enables and disables voting access based on the official schedule set by the election organizers.",
        faq_answer_4_point1_title = "Limited Timeframe",
        faq_answer_4_point1_desc = "You can only vote while the voting period is active. Once the period ends, the system will no longer accept votes.",
        faq_answer_4_point2_title = "Reminder Notifications",
        faq_answer_4_point2_desc = "VoteChain provides notifications to remind you of the election schedule so you don't miss your chance to vote.",

        // FAQ Answer 5
        faq_answer_5_intro = "Public Key and Private Key are crucial in VoteChain because they ensure the security, privacy, and integrity of the voting process:",
        faq_answer_5_point1_title = "Public Key",
        faq_answer_5_point1_desc = "Serves as your digital identity on the blockchain network. It allows you to receive data or be verified as a voter without revealing personal information.",
        faq_answer_5_point2_title = "Private Key",
        faq_answer_5_point2_desc = "Secures your account and authorizes every transaction you make. With the Private Key, only you can access and validate your vote within the system.",

        // Password Confirmation Dialog
        passwordConfirmationTitle = "Enter Password",
        passwordConfirmationSubtitle = "Enter your password to view account details",
        passwordConfirmationCancel = "Cancel",
        passwordConfirmationSubmit = "Submit",
        passwordIncorrect = "Incorrect password. Please try again",
        passwordEmpty = "Password cannot be empty",

        // Data availability
        dataNotAvailable = "Data not available",
        visionNotAvailable = "Vision not available",
        missionNotAvailable = "Mission not available",
        workProgramNotAvailable = "Work program not available",
    )
}