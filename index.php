<?php

include 'functions.php';
front('Homepage');

$user = new user();

if( !isset( $_POST['submit'] ) ) { ?>
    
    <section class="login">
        <form action="index.php" method="POST" enctype="multipart/form-data">            
            <input type="text" class="basic" name="username" placeholder="Username or Email*" required><br/>
            <input type="password" class="basic" name="pwd1" id="pwd1" placeholder="Password*" required><br/>
            <input type="submit" class="submit" value='Login' name="submit">
        </form>
    </section>
    
    
    
<?php } else {
    
    if ( $_POST['username'] != "" ) {
        
        $res = $user->userLogin( $_REQUEST['username'], $_REQUEST['password'] );
        
        if($res == true) {
            echo "Login Successful!";
        } else {
            echo "Username/Email or Password is incorrect!";
        }
        
    }
    
}

?>

<?php

back();

?>