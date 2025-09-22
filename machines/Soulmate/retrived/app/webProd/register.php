<?php
session_start();

// Include configuration
require_once '../config/config.php';
require_once '../src/Models/User.php';

// Initialize database
$database = new Database();
$userModel = new User($database->getConnection());

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $confirmPassword = $_POST['confirm_password'] ?? '';
    $bio = $_POST['bio'] ?? '';
    $name = $_POST['name'] ?? '';

    // Validation
    if (empty($username) || empty($password) || empty($confirmPassword)) {
        $error = 'Username, password, and password confirmation are required';
    } elseif ($password !== $confirmPassword) {
        $error = 'Passwords do not match';
    } elseif (strlen($password) < 6) {
        $error = 'Password must be at least 6 characters long';
    } elseif ($userModel->findByUsername($username)) {
        $error = 'Username already exists';
    } else {
        // Handle profile picture upload
        $profilePic = '';
        if (isset($_FILES['profile_pic']) && $_FILES['profile_pic']['error'] === UPLOAD_ERR_OK) {
            $uploadDir = 'assets/images/profiles/';
            if (!is_dir($uploadDir)) {
                mkdir($uploadDir, 0755, true);
            }

            $fileExtension = pathinfo($_FILES['profile_pic']['name'], PATHINFO_EXTENSION);
            $allowedTypes = ['jpg', 'jpeg', 'png', 'gif'];

            if (in_array(strtolower($fileExtension), $allowedTypes)) {
                $fileName = $username . '_' . time() . '.' . $fileExtension;
                $uploadPath = $uploadDir . $fileName;

                if (move_uploaded_file($_FILES['profile_pic']['tmp_name'], $uploadPath)) {
                    $profilePic = $fileName;
                }
            }
        }

        // Create user
        if ($userModel->createWithDetails($username, $password, $name, $bio, $profilePic)) {
            $_SESSION['success'] = 'Account created successfully! Please log in.';
            header('Location: login.php');
            exit();
        } else {
            $error = 'Failed to create account. Please try again.';
        }
    }
}

$title = 'Register - Soulmate';
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

<div class="auth-container">
    <div class="auth-card">
        <div class="text-center mb-4">
            <div class="brand-logo d-inline-flex align-items-center justify-content-center mb-3">
                <i class="fas fa-heart text-pink"></i>
                <i class="fas fa-bolt text-pink"></i>
            </div>
            <h1 class="auth-title h2">Join <span class="text-pink">Soulmate</span></h1>
            <p class="auth-subtitle text-muted">Create your account and start your love journey</p>
        </div>
        
        <?php if (!empty($error)): ?>
            <div class="alert alert-danger" role="alert">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <?= htmlspecialchars($error) ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="register.php" enctype="multipart/form-data">
            <div class="row g-3">
                <div class="col-md-6">
                    <label for="username" class="form-label fw-semibold">
                        <i class="fas fa-user me-2 text-pink"></i>Username
                    </label>
                    <input 
                        type="text" 
                        id="username" 
                        name="username" 
                        class="form-control"
                        placeholder="Choose a username"
                        required
                        value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
                    >
                </div>
                
                <div class="col-md-6">
                    <label for="name" class="form-label fw-semibold">
                        <i class="fas fa-id-card me-2 text-pink"></i>Full Name
                    </label>
                    <input 
                        type="text" 
                        id="name" 
                        name="name" 
                        class="form-control"
                        placeholder="Your full name"
                        value="<?= htmlspecialchars($_POST['name'] ?? '') ?>"
                    >
                </div>
            </div>
            
            <div class="row g-3 mt-2">
                <div class="col-md-6">
                    <label for="password" class="form-label fw-semibold">
                        <i class="fas fa-lock me-2 text-pink"></i>Password
                    </label>
                    <input 
                        type="password" 
                        id="password" 
                        name="password" 
                        class="form-control"
                        placeholder="Create a password"
                        required
                        minlength="6"
                    >
                </div>
                
                <div class="col-md-6">
                    <label for="confirm_password" class="form-label fw-semibold">
                        <i class="fas fa-lock me-2 text-pink"></i>Confirm Password
                    </label>
                    <input 
                        type="password" 
                        id="confirm_password" 
                        name="confirm_password" 
                        class="form-control"
                        placeholder="Confirm your password"
                        required
                        minlength="6"
                    >
                </div>
            </div>
            
            <div class="mt-3">
                <label for="bio" class="form-label fw-semibold">
                    <i class="fas fa-pen me-2 text-pink"></i>Tell us about yourself
                </label>
                <textarea 
                    id="bio" 
                    name="bio" 
                    class="form-control"
                    rows="3"
                    placeholder="Write a little bit about yourself, your interests, what you're looking for..."
                ><?= htmlspecialchars($_POST['bio'] ?? '') ?></textarea>
            </div>
            
            <div class="mt-3">
                <label for="profile_pic" class="form-label fw-semibold">
                    <i class="fas fa-camera me-2 text-pink"></i>Profile Picture (Optional)
                </label>
                <input 
                    type="file" 
                    id="profile_pic" 
                    name="profile_pic" 
                    class="form-control"
                    accept="image/*"
                >
                <div class="form-text">Upload a photo to make your profile stand out!</div>
            </div>
            
            <button type="submit" class="btn btn-pink w-100 btn-lg mt-4 mb-3">
                <i class="fas fa-user-plus me-2"></i>Create Account
            </button>
        </form>

        <div class="text-center">
            <p class="text-muted">
                Already have an account? <a href="login.php" class="text-pink text-decoration-none fw-semibold">Sign in here!</a>
            </p>
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