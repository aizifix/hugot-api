<?php
session_start();
require_once 'db-connect.inc.php';
header('Content-Type: application/json');
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: PUT, GET, POST");
header("Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept");


$response = [];
$input = json_decode(file_get_contents('php://input'), true);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['operation']) && $_POST['operation'] === 'update_user_settings') {
    $userId = $_SESSION['user']['user_id'];
    $username = isset($_POST['username']) ? $_POST['username'] : null;
    $password = isset($_POST['password']) ? $_POST['password'] : null;
    $profilePhotoFile = isset($_FILES['profile_photo']) ? $_FILES['profile_photo'] : null;
    $coverPhotoFile = isset($_FILES['cover_photo']) ? $_FILES['cover_photo'] : null;

    try {
        $conn->beginTransaction();

        // Handle profile photo upload and update
        if ($profilePhotoFile && $profilePhotoFile['tmp_name']) {
            $profilePhotoPath = 'public/' . basename($profilePhotoFile['name']);
            if (move_uploaded_file($profilePhotoFile['tmp_name'], $profilePhotoPath)) {
                $profilePhotoSql = "UPDATE tbl_user SET profile_picture = :profile_photo WHERE user_id = :user_id";
                $stmt = $conn->prepare($profilePhotoSql);
                $stmt->execute([':profile_photo' => $profilePhotoPath, ':user_id' => $userId]);
                $_SESSION['user']['profile_photo'] = $profilePhotoPath;
                $response['profile_photo'] = $profilePhotoPath;
            } else {
                throw new Exception("Failed to upload profile photo.");
            }
        }

        // Handle cover photo upload and update
        if ($coverPhotoFile && $coverPhotoFile['tmp_name']) {
            $coverPhotoPath = 'public/' . basename($coverPhotoFile['name']);
            if (move_uploaded_file($coverPhotoFile['tmp_name'], $coverPhotoPath)) {
                $coverPhotoSql = "UPDATE tbl_user SET coverphoto = :cover_photo WHERE user_id = :user_id";
                $stmt = $conn->prepare($coverPhotoSql);
                $stmt->execute([':cover_photo' => $coverPhotoPath, ':user_id' => $userId]);
                $_SESSION['user']['cover_photo'] = $coverPhotoPath;
                $response['cover_photo'] = $coverPhotoPath;
            } else {
                throw new Exception("Failed to upload cover photo.");
            }
        }

        // Handle username update
        if ($username) {
            $usernameSql = "UPDATE tbl_user SET username = :username WHERE user_id = :user_id";
            $stmt = $conn->prepare($usernameSql);
            $stmt->execute([':username' => $username, ':user_id' => $userId]);
            $_SESSION['user']['username'] = $username;
            $response['username'] = $username;
        }

        // Handle password update
        if ($password) {
            $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
            $passwordSql = "UPDATE tbl_user SET pwd = :password WHERE user_id = :user_id";
            $stmt = $conn->prepare($passwordSql);
            $stmt->execute([':password' => $hashedPassword, ':user_id' => $userId]);
        }

        $conn->commit();

        $response['success'] = true;
        echo json_encode($response);
        exit;

    } catch (Exception $e) {
        $conn->rollBack();
        error_log("Update failed: " . $e->getMessage());
        $response['error'] = 'Failed to update settings: ' . $e->getMessage();
        echo json_encode($response);
        exit;
    }
}

if (!$input) {
    $response['error'] = 'No input received';
    echo json_encode($response);
    exit;
}

$operation = isset($input["operation"]) ? $input["operation"] : "0";
$data = isset($input["data"]) ? $input["data"] : [];

class User {
    private $conn;

    public function __construct($dbConnection) {
        $this->conn = $dbConnection;
    }

    public function signup($data) {
        $username = filter_var($data['username'], FILTER_SANITIZE_STRING);
        $email = filter_var($data['email'], FILTER_SANITIZE_EMAIL);
        $password = $data['password'];

        if (empty($username) || empty($email) || empty($password)) {
            return ['error' => 'All fields are required.'];
        }

        $stmt = $this->conn->prepare("SELECT * FROM tbl_user WHERE username = :username OR email = :email");
        $stmt->execute([':username' => $username, ':email' => $email]);
        if ($stmt->rowCount() > 0) {
            return ['error' => 'Username or email already exists.'];
        }

        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

        $stmt = $this->conn->prepare("INSERT INTO tbl_user (username, email, pwd) VALUES (:username, :email, :pwd)");
        if ($stmt->execute([':username' => $username, ':email' => $email, ':pwd' => $hashedPassword])) {
            return ['success' => 'User registered successfully.'];
        } else {
            $errorInfo = $stmt->errorInfo();
            return ['error' => 'Error registering user: ' . $errorInfo[2]];
        }
    }

    public function login($data) {
        $username = filter_var($data['username'], FILTER_SANITIZE_STRING);
        $password = $data['password'];
    
        if (empty($username) || empty($password)) {
            return ['error' => 'All fields are required.'];
        }
    
        $stmt = $this->conn->prepare("SELECT user_id, username, followers_count, following_count, pwd FROM tbl_user WHERE username = :username");
        $stmt->execute([':username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
        if ($user && password_verify($password, $user['pwd'])) {
            $_SESSION['user'] = [
                'username' => $user['username'],
                'user_id' => $user['user_id'],
                'followers_count' => $user['followers_count'], 
                'following_count' => $user['following_count']
            ];
            return ['success' => 'Login successful.', 'user' => $_SESSION['user']];
        } else {
            return ['error' => 'Invalid username or password.'];
        }
    }

    public function logout() {
        $_SESSION = [];
    
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
    
        session_destroy();
    
        return ['success' => 'Logged out successfully.'];
    }

    public function postHugot($data) {


        $user = $data['user'];
        $text = filter_var($data['text'], FILTER_SANITIZE_STRING);
        $theme_id = filter_var($data['theme'], FILTER_SANITIZE_NUMBER_INT);

        $stmt = $this->conn->prepare("SELECT * FROM tbl_theme WHERE theme_id = :theme_id");
        $stmt->execute([':theme_id' => $theme_id]);
        if ($stmt->rowCount() == 0) {
            return ['error' => 'Invalid theme selected.'];
        }

        $stmt = $this->conn->prepare("
            INSERT INTO tbl_post (user_id, hugot_post, date_created) 
            VALUES (:user_id, :hugot_post, NOW())
        ");
        $stmt->execute([
            ':user_id' => $user['user_id'],
            ':hugot_post' => $text,
        ]);

        $post_id = $this->conn->lastInsertId();

        $stmt = $this->conn->prepare("
            INSERT INTO tbl_timeline (post_id, theme_id, date_created) 
            VALUES (:post_id, :theme_id, NOW())
        ");
        $stmt->execute([
            ':post_id' => $post_id,
            ':theme_id' => $theme_id,
        ]);

        return ['success' => true];
    }

    public function getTimelinePosts() {
        
        $sql = "
            SELECT p.hugot_post AS post_content, p.heart_count, t.theme_type, u.username, p.post_id, u.user_id 
            FROM tbl_timeline tl
            JOIN tbl_post p ON tl.post_id = p.post_id
            JOIN tbl_user u ON p.user_id = u.user_id
            JOIN tbl_theme t ON tl.theme_id = t.theme_id
            ORDER BY tl.date_created DESC
        ";
        $stmt = $this->conn->prepare($sql);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getUserPosts($data) {
        $userId = $data['user_id'];
    
        $sql = "
            SELECT p.post_id, p.hugot_post, p.heart_count, p.comment_count, t.theme_type, p.user_id
            FROM tbl_post p
            JOIN tbl_timeline tl ON p.post_id = tl.post_id
            JOIN tbl_theme t ON tl.theme_id = t.theme_id
            WHERE p.user_id = :user_id
            ORDER BY p.date_created DESC
        ";
        $stmt = $this->conn->prepare($sql);
        $stmt->execute([':user_id' => $userId]);
        $posts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
        return ['posts' => $posts]; 
    }
    
    public function getThemes() {
        $stmt = $this->conn->prepare("SELECT theme_id, theme_type FROM tbl_theme");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function addComment($data) {
        $postId = $data['post_id'];
        $userId = $data['user_id'];
        $comment = filter_var($data['comment'], FILTER_SANITIZE_STRING);
    
        try {
            // Insert the comment
            $stmt = $this->conn->prepare("
                INSERT INTO tbl_comments (post_id, user_id, comment, date_created) 
                VALUES (:post_id, :user_id, :comment, NOW())
            ");
            $stmt->execute([
                ':post_id' => $postId,
                ':user_id' => $userId,
                ':comment' => $comment,
            ]);
    
            // Update the comment count
            $stmt = $this->conn->prepare("
                UPDATE tbl_post
                SET comment_count = comment_count + 1
                WHERE post_id = :post_id
            ");
            $stmt->execute([':post_id' => $postId]);
    
            return ['success' => true];
        } catch (Exception $e) {
            return ['error' => 'An error occurred while adding the comment: ' . $e->getMessage()];
        }
    }

    public function deleteComment($commentId, $postId) {
        try {
            // Delete the comment from the `tbl_comments` table
            $stmt = $this->conn->prepare("
                DELETE FROM tbl_comments
                WHERE comment_id = :comment_id
            ");
            $stmt->execute([':comment_id' => $commentId]);
    
            // Decrement the comment_count in `tbl_post`
            $stmt = $this->conn->prepare("
                UPDATE tbl_post
                SET comment_count = comment_count - 1
                WHERE post_id = :post_id
            ");
            $stmt->execute([':post_id' => $postId]);
    
            return ['success' => true];
        } catch (Exception $e) {
            return ['error' => 'An error occurred while deleting the comment: ' . $e->getMessage()];
        }
    }
    
    

    public function getComments($data) {
        $postId = $data['post_id'];

        $stmt = $this->conn->prepare("
            SELECT c.comment, c.date_created, u.username 
            FROM tbl_comments c 
            JOIN tbl_user u ON c.user_id = u.user_id
            WHERE c.post_id = :post_id
            ORDER BY c.date_created DESC
        ");
        $stmt->execute([':post_id' => $postId]);

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
     
    public function likePost($data) {
        $userId = $data['user_id'];
        $postId = $data['post_id'];
    
        $stmt = $this->conn->prepare("SELECT react_id FROM tbl_hearts WHERE user_id = :user_id AND post_id = :post_id");
        $stmt->execute([':user_id' => $userId, ':post_id' => $postId]);
    
        if ($stmt->rowCount() == 0) {
            $stmt = $this->conn->prepare("INSERT INTO tbl_hearts (user_id, post_id, heart_reacts) VALUES (:user_id, :post_id, 1)");
            $stmt->execute([':user_id' => $userId, ':post_id' => $postId]);
    
            $stmt = $this->conn->prepare("UPDATE tbl_post SET heart_count = heart_count + 1 WHERE post_id = :post_id");
            $stmt->execute([':post_id' => $postId]);
    
            return ['success' => true];
        } else {
            return ['error' => 'Post already liked by this user.'];
        }
    }
    
    public function unlikePost($data) {
        $userId = $data['user_id'];
        $postId = $data['post_id'];
    
        $stmt = $this->conn->prepare("SELECT react_id FROM tbl_hearts WHERE user_id = :user_id AND post_id = :post_id");
        $stmt->execute([':user_id' => $userId, ':post_id' => $postId]);
    
        if ($stmt->rowCount() > 0) {
            $stmt = $this->conn->prepare("DELETE FROM tbl_hearts WHERE user_id = :user_id AND post_id = :post_id");
            $stmt->execute([':user_id' => $userId, ':post_id' => $postId]);
    
            $stmt = $this->conn->prepare("UPDATE tbl_post SET heart_count = heart_count - 1 WHERE post_id = :post_id");
            $stmt->execute([':post_id' => $postId]);
    
            return ['success' => true];
        } else {
            return ['error' => 'Post not liked by this user.'];
        }
    }
    
    public function getLikeStatus($data) {
        $userId = $data['user_id'];
        $postId = $data['post_id'];
    
        $stmt = $this->conn->prepare("SELECT react_id FROM tbl_hearts WHERE user_id = :user_id AND post_id = :post_id");
        $stmt->execute([':user_id' => $userId, ':post_id' => $postId]);
    
        if ($stmt->rowCount() > 0) {
            return ['liked' => true];
        } else {
            return ['liked' => false];
        }
    }
    
    public function deletePost($data) {
        $postId = $data['post_id'];
    
        try {
            $this->conn->beginTransaction();
    
            $stmt = $this->conn->prepare("DELETE FROM tbl_hearts WHERE post_id = :post_id");
            $stmt->execute([':post_id' => $postId]);
    
            $stmt = $this->conn->prepare("DELETE FROM tbl_timeline WHERE post_id = :post_id");
            $stmt->execute([':post_id' => $postId]);
    
            $stmt = $this->conn->prepare("DELETE FROM tbl_post WHERE post_id = :post_id");
            $stmt->execute([':post_id' => $postId]);
    
            $this->conn->commit();
    
            if ($stmt->rowCount() > 0) {
                return ['success' => true];
            } else {
                return ['error' => 'Post not found or already deleted.'];
            }
        } catch (Exception $e) {
            $this->conn->rollBack();
            return ['error' => 'An error occurred: ' . $e->getMessage()];
        }
    }
    
    public function editPost($data) {
        $postId = $data['post_id'];
        $newContent = filter_var($data['new_content'], FILTER_SANITIZE_STRING);
    
        $stmt = $this->conn->prepare("UPDATE tbl_post SET hugot_post = :new_content WHERE post_id = :post_id");
        $stmt->execute([':new_content' => $newContent, ':post_id' => $postId]);
    
        return ['success' => true];
    }
    
    public function getLatestUsers() {
        $stmt = $this->conn->prepare("
            SELECT user_id, username 
            FROM tbl_user 
            ORDER BY date_created DESC 
            LIMIT 8
        ");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getRecentHugots() {
        $stmt = $this->conn->prepare("
            SELECT p.post_id, p.hugot_post, p.heart_count, t.theme_type, u.username, p.user_id
            FROM tbl_post p
            JOIN tbl_timeline tl ON p.post_id = tl.post_id
            JOIN tbl_user u ON p.user_id = u.user_id
            JOIN tbl_theme t ON tl.theme_id = t.theme_id
            ORDER BY p.date_created DESC
            LIMIT 5
        ");
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}

$user = new User($conn);

switch ($operation) {
    case "signup":
        $response = $user->signup($data);
        break;
    case "login":
        $response = $user->login($data);
        break;
    case "logout":
        $response = $user->logout();
        break;
    case "get_latest_users":
        $response = $user->getLatestUsers();
        break;
    case "delete_post":
        $response = $user->deletePost($data);
        break;
    case "edit_post":
        $response = $user->editPost($data);
        break;
    case "post_hugot":
        $response = $user->postHugot($data);
        break;
    case "get_timeline_posts":
        $response = $user->getTimelinePosts();
        break;
    case "get_user_posts":
        $response = $user->getUserPosts($data);
        break;
    case "get_themes":
        $response = $user->getThemes();
        break;
    case "like_post":
        $response = $user->likePost($data);
        break;
    case "unlike_post":
        $response = $user->unlikePost($data);
        break;
    case "get_like_status":
        $response = $user->getLikeStatus($data);
        break;
    case "add_comment":
            $response = $user->addComment($data);
            break;
    case "delete_comment":
            $response = $user->addComment($data);
            break;
    case "get_comments":
            $response = $user->getComments($data);
            break;
    case "get_recent_hugots":
        $response = $user->getRecentHugots($data);
        break;
    default:
        $response['error'] = 'Invalid operation.';
        http_response_code(400); 
        break;
}

echo json_encode($response);
?>
