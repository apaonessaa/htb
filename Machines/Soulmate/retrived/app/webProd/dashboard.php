<?php
session_start();

// Include configuration
require_once '../config/config.php';
require_once '../src/Models/User.php';

// Check if user is admin
requireAdmin();

// Initialize database
$database = new Database();
$userModel = new User($database->getConnection());

$totalUsers = $userModel->getTotalUsers();
$recentLogins = $userModel->getRecentLogins();
$adminCount = $userModel->getAdminCount();
$regularUsers = $totalUsers - $adminCount;

$title = 'Admin Dashboard - Soulmate';
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

<div class="dashboard-container">
    <div class="container">
        <div class="dashboard-header">
            <h1 class="dashboard-title display-4 fw-bold">Admin <span class="text-pink">Dashboard</span></h1>
            <p class="dashboard-subtitle lead">Monitor your dating site statistics and user activity</p>
        </div>

        <div class="row g-4 mb-5">
            <div class="col-lg-3 col-md-6">
                <div class="stat-card card border-0 shadow-sm">
                    <div class="card-body text-center">
                        <div class="stat-icon">
                            <i class="fas fa-users"></i>
                        </div>
                        <h3 class="stat-number"><?= $totalUsers ?></h3>
                        <p class="stat-label mb-0">Total Users</p>
                    </div>
                </div>
            </div>

            <div class="col-lg-3 col-md-6">
                <div class="stat-card card border-0 shadow-sm">
                    <div class="card-body text-center">
                        <div class="stat-icon">
                            <i class="fas fa-fire"></i>
                        </div>
                        <h3 class="stat-number"><?= $recentLogins ?></h3>
                        <p class="stat-label mb-0">Active Today</p>
                    </div>
                </div>
            </div>

            <div class="col-lg-3 col-md-6">
                <div class="stat-card card border-0 shadow-sm">
                    <div class="card-body text-center">
                        <div class="stat-icon">
                            <i class="fas fa-user"></i>
                        </div>
                        <h3 class="stat-number"><?= $regularUsers ?></h3>
                        <p class="stat-label mb-0">Regular Users</p>
                    </div>
                </div>
            </div>

            <div class="col-lg-3 col-md-6">
                <div class="stat-card card border-0 shadow-sm">
                    <div class="card-body text-center">
                        <div class="stat-icon">
                            <i class="fas fa-user-shield"></i>
                        </div>
                        <h3 class="stat-number"><?= $adminCount ?></h3>
                        <p class="stat-label mb-0">Admin Users</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="row g-4">
            <div class="col-lg-8">
                <div class="card border-0 shadow-sm">
                    <div class="card-header bg-white border-0 py-3">
                        <h3 class="card-title mb-0">
                            <i class="fas fa-chart-line text-pink me-2"></i>Site Overview
                        </h3>
                    </div>
                    <div class="card-body">
                        <div class="row g-3">
                            <div class="col-md-4">
                                <div class="d-flex align-items-center p-3 bg-light rounded">
                                    <div class="me-3">
                                        <i class="fas fa-arrow-up text-success fa-2x"></i>
                                    </div>
                                    <div>
                                        <h5 class="mb-0 text-success">+12%</h5>
                                        <small class="text-muted">User Growth Rate</small>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="d-flex align-items-center p-3 bg-light rounded">
                                    <div class="me-3">
                                        <i class="fas fa-users text-pink fa-2x"></i>
                                    </div>
                                    <div>
                                        <h5 class="mb-0"><?= $recentLogins ?></h5>
                                        <small class="text-muted">Daily Active Users</small>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="d-flex align-items-center p-3 bg-light rounded">
                                    <div class="me-3">
                                        <i class="fas fa-heart text-danger fa-2x"></i>
                                    </div>
                                    <div>
                                        <h5 class="mb-0 text-success">85%</h5>
                                        <small class="text-muted">Success Rate</small>
                                    </div>
                                </div>
                            </div>
                        </div>
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