<?php
session_start();
/** For smaller websites this method is okay, but if you have a lot of users you would use a more RESTful method */
if ($_POST['token'] == $_SESSION['token']) {
    switch ($_POST['action']) {
        case "login":
            loggingIn($_POST['email'], $_POST['password']);
            break;
        case "postcomment":
            if (isLoggedIn($_SESSION['email'], $_SESSION['hash'])) {
                postComment($_SESSION['email'], $_POST['msg'], $_POST['blog_id']);
            } else {
                error("You are not logged in", "index.php");
            }
            break;
        case "createblog":
            if (isLoggedIn($_SESSION['email'], $_SESSION['hash'])) {
                createBlog($_SESSION['email'], $_POST['blog_name']);
            } else {
                error("You are not logged in", "index.php");
            }
            break;
        case "register":
            registerAccount($_POST['email'], $_POST['username'], $_POST['password']);
            break;
        default:
            break;
    }
} else {
    error("Oopsie something went wrong", "404.php");
}

/** 
 * Tries to make a connection do the db
 * @return connection $conn returns the connection to the database
 */
function connect()
{
    $config = parse_ini_file('../db.ini');
    $conn = new PDO(`mysql:host=localhost;dbname=` . $config['db'], $config['username'], $config['password'], $config["options"]);
    return $conn;
}


/** 
 * Posts the comment that an user posted
 * @param email $email is the email that was given to the check.
 * @param message $msg the comment you'll be posting
 * @param post $post in which post you're gonna post it
 * @return boolean returns a bool answer depending on if the user was logged in
 */
function postComment($email, $msg, $post)
{
    $conn = connect();
    if (!$conn) {
        die("couldn't connect to the database");
    }
    try {
        $sql = $conn->prepare("INSERT INTO comments (user_id, msg, post_id) VALUES (u.user_id, :msg, :post)
        JOIN users u ON email=:email");
        $sql->bindParam(":email", $email, PDO::PARAM_STR, 60);
        $sql->bindParam(":msg", $msg, PDO::PARAM_STR, 512);
        $sql->bindParam(":post", $post, PDO::PARAM_STR, 16);
        $sql->execute();
        $sql = $sql->fetchAll()[0];
    } catch (PDOException $e) {
        echo "Connection fail ed: " . $e->getMessage();
    }
    if ($sql) {
        return true;
    }
    return false;
}

/** 
 * Posts the comment that an user posted
 * @param email $email is the email that was given to the check.
 * @param message $msg the comment you'll be posting
 * @param post $post in which post you're gonna post it
 * @return boolean returns a bool answer depending on if the user was logged in
 */
function createBlog($email, $name)
{
    $conn = connect();
    if (!$conn) {
        die("couldn't connect to the database");
    }
    $hash = bin2hex(openssl_random_pseudo_bytes(3, true));
    try {
        $sql = $conn->prepare("INSERT INTO blog (user_id, name, hash) VALUES (u.user_id, :blog, :hash)
        JOIN users u ON email=:email");
        $sql->bindParam(":email", $email, PDO::PARAM_STR, 60);
        $sql->bindParam(":blog", $name, PDO::PARAM_STR, 16);
        $sql->bindParam(":hash", $hash, PDO::PARAM_STR, 6);
        $sql->execute();
        $sql = $sql->fetchAll()[0];
    } catch (PDOException $e) {
        echo "Connection fail ed: " . $e->getMessage();
    }
    if ($sql) {
        return true;
    }
    return false;
}

/** 
 * Checks if the email exists in the database
 * @param email $email is the email that was given to the check.
 * @param hash $hash is a random hash that was given to the user and saved in the DB.
 * @return boolean returns a bool answer depending on if the user was logged in
 */
function isLoggedIn($email, $hash)
{
    $conn = connect();
    if (!$conn) {
        die("couldn't connect to the database");
    }
    try {
        $sql = $conn->prepare("SELECT email FROM users WHERE email=:email AND hash=:hash");
        $sql->bindParam(":email", $email, PDO::PARAM_STR, 50);
        $sql->bindParam(":hash", $hash, PDO::PARAM_STR, 32);
        $sql->execute();
        $sql = $sql->fetchAll()[0];
    } catch (PDOException $e) {
        echo "Connection failed: " . $e->getMessage();
    }
    if ($sql) {
        return true;
    }
    return false;
}

/**
 * Send an error and sends you back to a certain page
 * @param message $msg is the error message that the user will receive 
 * @param link $link is the link you will be send back too
 */
function error($msg, $link)
{
    $_SESSION['error'] = $msg;
    header("Location: " . $link);
    exit(1);
}

function loggingIn($email, $pwd)
{
    $conn = connect();
    if (!$conn) {
        die("couldn't connect to the database");
    }
    try {
        $sql = $conn->prepare("SELECT password FROM users WHERE email=:email");
        $sql->bindParam(":email", $email, PDO::PARAM_STR, 50);
        $sql->bindParam(":pwd", $pwd, PDO::PARAM_STR, 64);
        $sql->execute();
    } catch (PDOException $e) {
        echo "Connection failed: " . $e->getMessage();
    }
    if (password_verify($pwd, $sql->fetchAll()[0])) {
        $pwd = password_needs_rehash($pwd, PASSWORD_DEFAULT);
        $token = bin2hex(openssl_random_pseudo_bytes(16, true));
        $sql = $conn->prepare("UPDATE hash=:hash, pwd=:pwd FROM users WHERE email=:email");
        $sql->bindParam(":hash", $token, PDO::PARAM_STR, 32);
        $sql->bindParam(":email", $email, PDO::PARAM_STR, 64);
        $sql->bindParam(":pwd", $pwd, PDO::PARAM_STR, 64);
        $sql->execute();
        $_SESSION['hash'] = $token;
        $_SESSION['email'] = $email;
        return true;
    }
    return false;
}

function registerAccount($email, $user, $pwd)
{
    $conn = connect();
    if (!$conn) {
        die("couldn't connect to the database");
    }
    $token = bin2hex(openssl_random_pseudo_bytes(16, true));
    $pwd = password_hash($pwd, PASSWORD_DEFAULT);
    try {
        $sql = $conn->prepare("INSERT INTO users (email, password, hash, username) VALUES (:email, :pwd, :hash, :user)");
        $sql->bindParam(":email", $email, PDO::PARAM_STR, 64);
        $sql->bindParam(":user", $user, PDO::PARAM_STR, 64);
        $sql->bindParam(":hash", $token, PDO::PARAM_STR, 32);
        $sql->bindParam(":pwd", $pwd, PDO::PARAM_STR, 64);
        $sql->execute();
        $sql = $sql->fetchAll()[0];
    } catch (PDOException $e) {
        echo "Connection failed: " . $e->getMessage();
    }
    if ($sql) {
        return true;
    }
    return false;
}
