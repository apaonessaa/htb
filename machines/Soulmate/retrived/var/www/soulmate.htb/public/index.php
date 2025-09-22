<?php
session_start();

// Include configuration
require_once '../config/config.php';
require_once '../src/Models/User.php';

// Initialize database
$database = new Database();
$userModel = new User($database->getConnection());

// Home page content
$title = 'Soulmate - Find Your Perfect Match';
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
                        <a class="nav-link" href="#about">About</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#testimonials">Stories</a>
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

<!-- Hero Section -->
<section class="hero-section py-5">
    <div class="container">
        <div class="row align-items-center min-vh-100">
            <div class="col-lg-6">
                <div class="hero-content">
                    <h1 class="hero-title display-2 fw-bold mb-4">Find Your Perfect <span class="text-pink">Match</span></h1>
                    <p class="hero-subtitle lead mb-4">Connect with like-minded people and discover meaningful relationships. Join over 10,000 singles who found love on Soulmate.</p>
                    <div class="hero-actions">
                        <?php if (!isLoggedIn()): ?>
                            <a href="register.php" class="btn btn-pink btn-lg me-3">Start Your Journey</a>
                            <a href="#about" class="btn btn-outline-pink btn-lg">Learn More</a>
                        <?php else: ?>
                            <?php if (isAdmin()): ?>
                                <a href="dashboard.php" class="btn btn-pink btn-lg">Go to Dashboard</a>
                            <?php else: ?>
                                <a href="profile.php" class="btn btn-pink btn-lg">View Profile</a>
                            <?php endif; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
            <div class="col-lg-6">
                <div class="hero-image text-center">
                    <img src="https://images.pexels.com/photos/1024993/pexels-photo-1024993.jpeg?auto=compress&cs=tinysrgb&w=600" alt="Happy Couple" class="img-fluid rounded-4 shadow-lg">
                </div>
            </div>
        </div>
    </div>
</section>

<!-- Features Section -->
<section class="features-section py-5 bg-light">
    <div class="container">
        <div class="text-center mb-5">
            <h2 class="section-title display-4 fw-bold mb-3">Why Choose <span class="text-pink">Soulmate?</span></h2>
            <p class="lead text-muted">Discover what makes us the perfect platform for finding love</p>
        </div>
        <div class="row g-4">
            <div class="col-lg-4 col-md-6">
                <div class="feature-card card h-100 border-0 shadow-sm">
                    <div class="card-body text-center p-4">
                        <div class="feature-icon mb-3">
                            <i class="fas fa-heart fa-3x text-pink"></i>
                        </div>
                        <h3 class="feature-title h4 fw-bold mb-3">Smart Matching</h3>
                        <p class="feature-text text-muted">Our advanced algorithm helps you find compatible matches based on your interests, values, and preferences.</p>
                    </div>
                </div>
            </div>
            <div class="col-lg-4 col-md-6">
                <div class="feature-card card h-100 border-0 shadow-sm">
                    <div class="card-body text-center p-4">
                        <div class="feature-icon mb-3">
                            <i class="fas fa-shield-alt fa-3x text-pink"></i>
                        </div>
                        <h3 class="feature-title h4 fw-bold mb-3">Safe & Secure</h3>
                        <p class="feature-text text-muted">Your privacy and security are our top priorities. All profiles are verified and your data is protected.</p>
                    </div>
                </div>
            </div>
            <div class="col-lg-4 col-md-6">
                <div class="feature-card card h-100 border-0 shadow-sm">
                    <div class="card-body text-center p-4">
                        <div class="feature-icon mb-3">
                            <i class="fas fa-comments fa-3x text-pink"></i>
                        </div>
                        <h3 class="feature-title h4 fw-bold mb-3">Easy Communication</h3>
                        <p class="feature-text text-muted">Connect and chat with your matches through our intuitive messaging system designed for meaningful conversations.</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- About Section -->
<section id="about" class="about-section py-5">
    <div class="container">
        <div class="row align-items-center">
            <div class="col-lg-6 mb-4 mb-lg-0">
                <img src="https://images.pexels.com/photos/3184291/pexels-photo-3184291.jpeg?auto=compress&cs=tinysrgb&w=600" alt="About Soulmate" class="img-fluid rounded-4 shadow">
            </div>
            <div class="col-lg-6">
                <div class="about-content ps-lg-4">
                    <h2 class="display-5 fw-bold mb-4">About <span class="text-pink">Soulmate</span></h2>
                    <p class="lead mb-4">Founded in 2020, Soulmate has been bringing people together through meaningful connections and authentic relationships.</p>
                    <p class="mb-4">We believe that everyone deserves to find their perfect match. Our platform combines cutting-edge technology with a human touch to create an environment where genuine connections flourish.</p>
                    <div class="row g-3">
                        <div class="col-6">
                            <div class="stat-item text-center">
                                <h3 class="text-pink fw-bold">10K+</h3>
                                <p class="text-muted mb-0">Happy Couples</p>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="stat-item text-center">
                                <h3 class="text-pink fw-bold">50K+</h3>
                                <p class="text-muted mb-0">Active Users</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- Testimonials Section -->
<section id="testimonials" class="testimonials-section py-5 bg-light">
    <div class="container">
        <div class="text-center mb-5">
            <h2 class="display-4 fw-bold mb-3">Success <span class="text-pink">Stories</span></h2>
            <p class="lead text-muted">Real couples, real love stories</p>
        </div>
        <div class="row g-4">
            <div class="col-lg-4 col-md-6">
                <div class="testimonial-card card border-0 shadow-sm h-100">
                    <div class="card-body p-4">
                        <div class="d-flex align-items-center mb-3">
                            <img src="https://images.pexels.com/photos/1239291/pexels-photo-1239291.jpeg?auto=compress&cs=tinysrgb&w=100" alt="Sarah" class="rounded-circle me-3" width="50" height="50">
                            <div>
                                <h5 class="mb-0">Sarah & Mike</h5>
                                <small class="text-muted">Married 2 years</small>
                            </div>
                        </div>
                        <p class="text-muted">"We met on Soulmate and instantly connected over our love for hiking. Two years later, we're happily married and still exploring trails together!"</p>
                        <div class="text-warning">
                            <i class="fas fa-star"></i>
                            <i class="fas fa-star"></i>
                            <i class="fas fa-star"></i>
                            <i class="fas fa-star"></i>
                            <i class="fas fa-star"></i>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-4 col-md-6">
                <div class="testimonial-card card border-0 shadow-sm h-100">
                    <div class="card-body p-4">
                        <div class="d-flex align-items-center mb-3">
                            <img src="https://images.pexels.com/photos/1043471/pexels-photo-1043471.jpeg?auto=compress&cs=tinysrgb&w=100" alt="James" class="rounded-circle me-3" width="50" height="50">
                            <div>
                                <h5 class="mb-0">James & Emma</h5>
                                <small class="text-muted">Together 3 years</small>
                            </div>
                        </div>
                        <p class="text-muted">"Soulmate's matching algorithm is incredible! It paired me with Emma, who shares my passion for cooking. We now run a food blog together!"</p>
                        <div class="text-warning">
                            <i class="fas fa-star"></i>
                            <i class="fas fa-star"></i>
                            <i class="fas fa-star"></i>
                            <i class="fas fa-star"></i>
                            <i class="fas fa-star"></i>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-4 col-md-6">
                <div class="testimonial-card card border-0 shadow-sm h-100">
                    <div class="card-body p-4">
                        <div class="d-flex align-items-center mb-3">
                            <img src="https://images.pexels.com/photos/1181690/pexels-photo-1181690.jpeg?auto=compress&cs=tinysrgb&w=100" alt="Lisa" class="rounded-circle me-3" width="50" height="50">
                            <div>
                                <h5 class="mb-0">Lisa & David</h5>
                                <small class="text-muted">Engaged</small>
                            </div>
                        </div>
                        <p class="text-muted">"After trying many dating apps, Soulmate was different. The quality of matches was amazing, and I found my soulmate within a month!"</p>
                        <div class="text-warning">
                            <i class="fas fa-star"></i>
                            <i class="fas fa-star"></i>
                            <i class="fas fa-star"></i>
                            <i class="fas fa-star"></i>
                            <i class="fas fa-star"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- CTA Section -->
<section class="cta-section py-5 bg-pink text-white">
    <div class="container text-center">
        <h2 class="display-5 fw-bold mb-3">Ready to Find Your Match?</h2>
        <p class="lead mb-4">Join thousands of singles who have found love on Soulmate</p>
        <?php if (!isLoggedIn()): ?>
            <a href="register.php" class="btn btn-light btn-lg">Get Started</a>
        <?php else: ?>
            <a href="profile.php" class="btn btn-light btn-lg">Complete Your Profile</a>
        <?php endif; ?>
    </div>
</section>

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
                        <li><a href="#about" class="text-white text-decoration-none">About Us</a></li>
                        <li><a href="#testimonials" class="text-white text-decoration-none">Success Stories</a></li>
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