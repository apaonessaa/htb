<?php
session_start();

// Include configuration
require_once '../config/config.php';
require_once '../src/Models/User.php';

// Check if user is logged in
requireLogin();

// Redirect admin to dashboard
if (isAdmin()) {
    header('Location: dashboard.php');
    exit();
}

// Initialize database
$database = new Database();
$userModel = new User($database->getConnection());

$success = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $uploadedFile = '';
    
    // Handle file upload
    if (isset($_FILES['profile_pic']) && $_FILES['profile_pic']['error'] === UPLOAD_ERR_OK) {
        $uploadDir = 'assets/images/profiles/';
        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0755, true);
        }

        $fileExtension = pathinfo($_FILES['profile_pic']['name'], PATHINFO_EXTENSION);
        $allowedTypes = ['jpg', 'jpeg', 'png', 'gif'];

        if (in_array(strtolower($fileExtension), $allowedTypes)) {
            $fileName = $_SESSION['user_id'] . '_' . time() . '.' . $fileExtension;
            $uploadPath = $uploadDir . $fileName;

            if (move_uploaded_file($_FILES['profile_pic']['tmp_name'], $uploadPath)) {
                $uploadedFile = $fileName;
            }
        }
    }

    $currentUser = $userModel->findById($_SESSION['user_id']);
    $profilePic = $uploadedFile ?: $currentUser['profile_pic'];

    $data = [
        'name' => $_POST['name'] ?? '',
        'bio' => $_POST['bio'] ?? '',
        'interests' => $_POST['interests'] ?? '',
        'phone' => $_POST['phone'] ?? '',
        'profile_pic' => $profilePic
    ];

    if ($userModel->updateProfile($_SESSION['user_id'], $data)) {
        $success = 'Profile updated successfully!';
    } else {
        $error = 'Failed to update profile.';
    }
}

$user = $userModel->findById($_SESSION['user_id']);
$title = 'Profile - Soulmate';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $title ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link rel="stylesheet" href="/assets/css/style.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-white shadow-sm fixed-top">
        <div class="container">
            <div class="navbar-brand">
                <a href="/" class="brand-link">
                    <div class="brand-logo">
                        <i class="fas fa-heart"></i>
                        <i class="fas fa-bolt"></i>
                    </div>
                    <span class="brand-text">Soulmate</span>
                </a>
            </div>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="/">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/#about">About</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/#testimonials">Stories</a>
                    </li>
                <?php if (isLoggedIn()): ?>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user-circle me-1"></i><?= htmlspecialchars($_SESSION['username']) ?>
                        </a>
                        <ul class="dropdown-menu">
                            <?php if (isAdmin()): ?>
                                <li><a class="dropdown-item" href="dashboard.php"><i class="fas fa-chart-bar me-2"></i>Dashboard</a></li>
                            <?php else: ?>
                                <li><a class="dropdown-item" href="profile.php"><i class="fas fa-user me-2"></i>Profile</a></li>
                            <?php endif; ?>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item text-danger" href="logout.php"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
                        </ul>
                    </li>
                <?php else: ?>
                    <li class="nav-item">
                        <a class="nav-link" href="login.php">Login</a>
                    </li>
                    <li class="nav-item">
                        <a href="register.php" class="btn btn-pink ms-2">Get Started</a>
                    </li>
                <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>
    <main class="main-content pt-5">

<div class="profile-container">
    <div class="container">
        <div class="profile-header">
            <h1 class="profile-title display-4 fw-bold">My <span class="text-pink">Profile</span></h1>
            <p class="profile-subtitle lead">Update your information and make yourself shine</p>
        </div>

        <?php if (!empty($success)): ?>
            <div class="alert alert-success" role="alert">
                <i class="fas fa-check-circle me-2"></i>
                <?= htmlspecialchars($success) ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($error)): ?>
            <div class="alert alert-danger" role="alert">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>

        <div class="row g-4">
            <div class="col-lg-4">
                <div class="card border-0 shadow-sm">
                    <div class="card-body text-center p-4">
                        <div class="profile-picture mb-3">
                            <?php if (!empty($user['profile_pic'])): ?>
                                <img src="/assets/images/profiles/<?= htmlspecialchars($user['profile_pic']) ?>" alt="Profile Picture" class="profile-img">
                            <?php else: ?>
                                <div class="profile-placeholder">
                                    <i class="fas fa-camera fa-2x text-muted mb-2"></i>
                                    <p class="text-muted mb-0">No photo uploaded</p>
                                </div>
                            <?php endif; ?>
                        </div>
                        
                        <h3 class="profile-name"><?= htmlspecialchars($user['name'] ?: $user['username']) ?></h3>
                        <p class="profile-username">@<?= htmlspecialchars($user['username']) ?></p>
                        <p class="profile-joined">
                            <i class="fas fa-calendar-alt text-pink me-1"></i>
                            Member since <?= date('M Y', strtotime($user['created_at'])) ?>
                        </p>
                    </div>
                </div>
            </div>

            <div class="col-lg-8">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white border-0 py-3">
                        <h3 class="card-title mb-0">
                            <i class="fas fa-edit text-pink me-2"></i>Edit Profile
                        </h3>
                    </div>
                    <div class="card-body p-4">
                        <form method="POST" action="profile.php" enctype="multipart/form-data">
                            <div class="row g-4">
                                <div class="col-12">
                                    <h5 class="text-pink mb-3">
                                        <i class="fas fa-user me-2"></i>Basic Information
                                    </h5>
                                </div>
                                
                                <div class="col-md-6">
                                    <label for="name" class="form-label fw-semibold">Full Name</label>
                                    <input 
                                        type="text" 
                                        id="name" 
                                        name="name" 
                                        class="form-control"
                                        value="<?= htmlspecialchars($user['name']) ?>"
                                        placeholder="Enter your full name"
                                    >
                                </div>

                                <div class="col-md-6">
                                    <label for="phone" class="form-label fw-semibold">Phone Number</label>
                                    <input 
                                        type="tel" 
                                        id="phone" 
                                        name="phone" 
                                        class="form-control"
                                        value="<?= htmlspecialchars($user['phone']) ?>"
                                        placeholder="+1 (555) 123-4567"
                                    >
                                </div>

                                <div class="col-12">
                                    <label for="bio" class="form-label fw-semibold">Bio</label>
                                    <textarea 
                                        id="bio" 
                                        name="bio" 
                                        class="form-control"
                                        rows="4"
                                        placeholder="Tell us about yourself..."
                                    ><?= htmlspecialchars($user['bio']) ?></textarea>
                                </div>

                                <div class="col-12">
                                    <label for="interests" class="form-label fw-semibold">Interests</label>
                                    <input 
                                        type="text" 
                                        id="interests" 
                                        name="interests" 
                                        class="form-control"
                                        value="<?= htmlspecialchars($user['interests']) ?>"
                                        placeholder="e.g., Music, Travel, Cooking, Photography"
                                    >
                                    <div class="form-text">Separate interests with commas</div>
                                </div>

                                <div class="col-12">
                                    <h5 class="text-pink mb-3 mt-3">
                                        <i class="fas fa-camera me-2"></i>Profile Picture
                                    </h5>
                                </div>

                                <div class="col-12">
                                    <label for="profile_pic" class="form-label fw-semibold">Upload New Picture</label>
                                    <input 
                                        type="file" 
                                        id="profile_pic" 
                                        name="profile_pic" 
                                        class="form-control"
                                        accept="image/*"
                                    >
                                    <div class="form-text">Max file size: 5MB. Formats: JPG, PNG, GIF</div>
                                </div>

                                <div class="col-12">
                                    <button type="submit" class="btn btn-pink btn-lg">
                                        <i class="fas fa-save me-2"></i>Update Profile
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

    </main>
    <footer class="footer bg-dark text-white py-5">
        <div class="container">
            <div class="row">
                <div class="col-lg-4 col-md-6 mb-4">
                    <div class="footer-brand mb-3">
                        <div class="brand-logo me-2">
                            <i class="fas fa-heart text-pink"></i>
                            <i class="fas fa-bolt text-pink"></i>
                        </div>
                        <span class="brand-text fs-4 fw-bold">Soulmate</span>
                    </div>
                    <p class="text-muted">Find your perfect match on Soulmate - where meaningful connections happen naturally. Join thousands of singles finding love every day.</p>
                    <div class="social-links">
                        <a href="#" class="text-pink me-3"><i class="fab fa-facebook-f"></i></a>
                        <a href="#" class="text-pink me-3"><i class="fab fa-twitter"></i></a>
                        <a href="#" class="text-pink me-3"><i class="fab fa-instagram"></i></a>
                        <a href="#" class="text-pink me-3"><i class="fab fa-linkedin-in"></i></a>
                    </div>
                </div>
                <div class="col-lg-2 col-md-6 mb-4">
                    <h5 class="text-pink mb-3">Quick Links</h5>
                    <ul class="list-unstyled">
                        <li><a href="/" class="text-white text-decoration-none">Home</a></li>
                        <li><a href="/#about" class="text-white text-decoration-none">About Us</a></li>
                        <li><a href="/#testimonials" class="text-white text-decoration-none">Success Stories</a></li>
                        <li><a href="login.php" class="text-white text-decoration-none">Sign In</a></li>
                    </ul>
                </div>
                <div class="col-lg-2 col-md-6 mb-4">
                    <h5 class="text-pink mb-3">Support</h5>
                    <ul class="list-unstyled">
                        <li><a href="#" class="text-white text-decoration-none">Help Center</a></li>
                        <li><a href="#" class="text-white text-decoration-none">Safety Tips</a></li>
                        <li><a href="#" class="text-white text-decoration-none">Privacy Policy</a></li>
                        <li><a href="#" class="text-white text-decoration-none">Terms of Service</a></li>
                    </ul>
                </div>
                <div class="col-lg-4 col-md-6 mb-4">
                    <h5 class="text-pink mb-3">Contact Us</h5>
                    <div class="contact-info">
                        <div class="d-flex align-items-center mb-2">
                            <i class="fas fa-map-marker-alt text-pink me-3"></i>
                            <span class="text-white">123 Love Street, Romance City, RC 12345</span>
                        </div>
                        <div class="d-flex align-items-center mb-2">
                            <i class="fas fa-phone text-pink me-3"></i>
                            <span class="text-white">+1 (555) 123-LOVE</span>
                        </div>
                        <div class="d-flex align-items-center mb-2">
                            <i class="fas fa-envelope text-pink me-3"></i>
                            <span class="text-white">hello@soulmate.htb</span>
                        </div>
                        <div class="d-flex align-items-center">
                            <i class="fas fa-clock text-pink me-3"></i>
                            <span class="text-white">24/7 Customer Support</span>
                        </div>
                    </div>
                </div>
            </div>
            <hr class="my-4 border-secondary">
            <div class="row align-items-center">
                <div class="col-md-6">
                    <p class="mb-0 text-white">&copy; <?= date('Y') ?> Soulmate Dating. All rights reserved.</p>
                </div>
                <div class="col-md-6 text-md-end">
                    <p class="mb-0 text-white">Made with <i class="fas fa-heart text-pink"></i> for finding love</p>
                </div>
            </div>
        </div>
    </footer>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>