<?php
class User {
    private $pdo;

    public function __construct($pdo) {
        $this->pdo = $pdo;
    }

    public function findByUsername($username) {
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->execute([$username]);
        return $stmt->fetch();
    }

    public function findById($id) {
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$id]);
        return $stmt->fetch();
    }

    public function updateLastLogin($id) {
        $stmt = $this->pdo->prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?");
        $stmt->execute([$id]);
    }

    public function getTotalUsers() {
        $stmt = $this->pdo->query("SELECT COUNT(*) FROM users");
        return $stmt->fetchColumn();
    }

    public function getRecentLogins() {
        $stmt = $this->pdo->query("
            SELECT COUNT(*) FROM users 
            WHERE last_login >= datetime('now', '-1 day')
        ");
        return $stmt->fetchColumn();
    }

    public function getAdminCount() {
        $stmt = $this->pdo->query("SELECT COUNT(*) FROM users WHERE is_admin = 1");
        return $stmt->fetchColumn();
    }

    public function updateProfile($id, $data) {
        $stmt = $this->pdo->prepare("
            UPDATE users 
            SET name = ?, bio = ?, interests = ?, phone = ?, profile_pic = ?
            WHERE id = ?
        ");
        return $stmt->execute([
            $data['name'],
            $data['bio'],
            $data['interests'],
            $data['phone'],
            $data['profile_pic'],
            $id
        ]);
    }

    public function create($username, $password, $name = '') {
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $this->pdo->prepare("
            INSERT INTO users (username, password, name) 
            VALUES (?, ?, ?)
        ");
        return $stmt->execute([$username, $hashedPassword, $name]);
    }

    public function createWithDetails($username, $password, $name, $bio, $profilePic) {
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $this->pdo->prepare("
            INSERT INTO users (username, password, name, bio, profile_pic) 
            VALUES (?, ?, ?, ?, ?)
        ");
        return $stmt->execute([$username, $hashedPassword, $name, $bio, $profilePic]);
    }
}
?>