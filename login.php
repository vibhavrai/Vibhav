<?php

//This script will handle login
session_start();

// check if the user is already logged in
if(isset($_SESSION['username']))
{
    header("location: welcome.php");
    exit;
}
require_once "config.php";

$username = $password = "";
$err = "";

// if request method is post
if ($_SERVER['REQUEST_METHOD'] == "POST"){
    if(empty(trim($_POST['username'])) || empty(trim($_POST['password'])))
    {
        $err = "Invalid username/password";
    }
    else{
        $username = trim($_POST['username']);
        $password = trim($_POST['password']);
    }


if(empty($err))
{
    $sql = "SELECT id, username, password FROM users WHERE username = ?";
    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param($stmt, "s", $param_username);
    $param_username = $username;
    
    
    // Try to execute this statement
    if(mysqli_stmt_execute($stmt)){
        mysqli_stmt_store_result($stmt);
        if(mysqli_stmt_num_rows($stmt) == 1)
                {
                    mysqli_stmt_bind_result($stmt, $id, $username, $hashed_password);
                    if(mysqli_stmt_fetch($stmt))
                    {
                        if(password_verify($password, $hashed_password))
                        {
                            // this means the password is corrct. Allow user to login
                            session_start();
                            $_SESSION["username"] = $username;
                            $_SESSION["id"] = $id;
                            $_SESSION["loggedin"] = true;

                            //Redirect user to welcome page
                            header("location: welcome.php");
                            
                        }
                    }

                }

    }
}    


}


?>



<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <link rel="stylesheet" href="login.css">
</head>
<body>
    <div class="main">  	
        <input type="checkbox" id="chk" aria-hidden="true">
    
            <div class="login">
                <form class="form" action="" method="post">
                    <label for="chk" aria-hidden="true">Log in</label>
                    <input class="input" type="text" name="username" placeholder="Username" required="">
                    <input class="input" type="password" name="password" placeholder="Password" required="">
                    <button>Log in</button>
                </form>
            </div>
    
      <div class="register">
                <form class="form" action="" method="post">
                    <label for="chk" aria-hidden="true">Register</label>
                    
                    
                    <input class="input" type="text" name="username" placeholder="Username" id="inputusername" required="">
                    
                    
                    <input class="input" type="email" name="email" placeholder="Email" id="inputemail"  required="">
                    
                    
                    <input class="input" type="password" name="password" placeholder="Password" id="inputpass" required="">
                    
                    
                    <input class="input" type="password" name="confirm_password" placeholder="Confirm Password" id="cnfpass" required="">
                    <button>Register</button>
                </form>
            </div>
    </div>
</body>
</html>