<?php
session_start();    
$token = bin2hex(openssl_random_pseudo_bytes(32, true));
$_SESSION['token'] = $token;
?>  
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
    <form action="handler.php" method="post">
        <label for="email"><input type="email" id="email" name="email"></label>
        <label for="password"><input type="password" id="password" name="password"></label>
        <input type="hidden" name="token" value="<?php echo $token; ?>">
        <input type="hidden" name="action" value="login">
        <input type="submit" name="submit" value="Submit">
    </form>
    
    <p><a href="#">Register</a></p>
</body>
</html>