<?php
class user {
    
    /*========================================================== Definitions =====================================================================*/
    
    define("ALGORITHM", "sha256");  // Define Algorithm Type
    define("ITERATIONS", 1000);
    define("SALT_BYTE_SIZE", 24);
    define("HASH_BYTE_SIZE", 24);
    
    //-- Define number of sections within the hash and each index --
    define("HASH_SECTIONS", 4);
    define("HASH_ALGORITHM_INDEX", 0);
    define("HASH_ITERATION_INDEX", 1);
    define("HASH_SALT_INDEX", 2);
    define("HASH_PBKDF2_INDEX", 3);

    define("DB_HOST", "localhost");     // Define MySQL hostname (usually localhost)
	define("DB_NAME", "dbName");        // Define the database name
	define("DB_USER", "dbUsername");    // Define the username to access the database
	define("DB_PASS", "cbPassword");    // Define the password to access the database

    $conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    /*============================================================================================================================================*/
    
    /*========================================================== User Login ======================================================================*/
    
	function userLogin($uname, $password) {
						
		$sql = "SELECT * FROM users WHERE (email='$uname' OR username='$uname')";  // Look for user by username or password (can login with both)
		$result = mysqli_query($conn, $sql);
        $row = mysqli_fetch_assoc($result);
        
		$username = $row['username'];
		$id = $row['ref_id'];
		
		if ( $row['type'] == "employee" ) {  // Current login types defined in database are employee and customer (seperate tables)
            
			$sql2 = "SELECT * FROM employee WHERE employee_username='$username'"; //-- Fetch user information if type is employee --
			$result2 = mysqli_query($conn, $sql2);
            $row2 = mysqli_fetch_assoc($result2);
            
		} else { 
			//-- Fetch user information if type is customer -- (incomplete)
		}		

        //-- Set session variables (for later permission checking and greeting purposes) -- 
		$_SESSION['user_username']=$username;
		$_SESSION['user_role']=$row['role'];
		$_SESSION['user_type']=$row['type'];
		$_SESSION['user_id']=$id;
		$_SESSION['user_fullname']=$fetch2['employee_fname'];

        //--  User found and session variables set - Validate Password --
		$validate = validate_password( $password, $row['password'] );
		
		if( $validate == true )
			return true;	
		else
			return false;		

		return false;
	}	

    /*============================================================================================================================================*/
    
    /*==============================================PASSWORD FUNCTIONS!!!----Using PBKDF2 function================================================*/

    
    
    function hashPassword($password) {
        
        //-- Create hash from password provided in the following format (algorithm:iterations:salt:hash) --        
        $salt = base64_encode(mcrypt_create_iv(SALT_BYTE_SIZE, MCRYPT_DEV_URANDOM));
        return ALGORITHM . ":" . ITERATIONS . ":" .  $salt . ":" . base64_encode( pbkdf2( ALGORITHM, $password, $salt, ITERATIONS, HASH_BYTE_SIZE, true ) );
    
    }
    
    function validate($password, $correctHash) {
        
        $params = explode(":", $correctHash);
        if(count($params) < HASH_SECTIONS)
           return false;
        $pbkdf2 = base64_decode($params[HASH_PBKDF2_INDEX]);
        return compare( $pbkdf2, pbkdf2( $params[HASH_ALGORITHM_INDEX], $password, $params[HASH_SALT_INDEX], (int)$params[HASH_ITERATION_INDEX], strlen($pbkdf2), true ) );
    
    }
    
    //-- Compares two String Lengths --------------------------------------------------------------------------
    function compare($a, $b) {
        $diff = strlen($a) ^ strlen($b);
        for($i = 0; $i < strlen($a) && $i < strlen($b); $i++)
        {
            $diff |= ord($a[$i]) ^ ord($b[$i]);
        }
        return $diff === 0;
    
    }
    
    function pbkdf2($algorithm, $password, $salt, $count, $keyLength, $rawOutput = false) {
        
        $algorithm = strtolower($algorithm);
        if(!in_array($algorithm, hash_algos(), true))
            trigger_error('PBKDF2 ERROR: Invalid hash algorithm.', E_USER_ERROR);
            
        if($count <= 0 || $keyLength <= 0)
            trigger_error('PBKDF2 ERROR: Invalid parameters.', E_USER_ERROR);
    
        if (function_exists("hash_pbkdf2")) {            
            if (!$rawOutput) {
                $keyLength = $keyLength * 2;
            }
            return hash_pbkdf2($algorithm, $password, $salt, $count, $keyLength, $rawOutput);
        }
    
        $hashLength = strlen(hash($algorithm, "", true));
        $block_count = ceil($keyLength / $hashLength);    
        $output = "";
        
        for($i = 1; $i <= $block_count; $i++) {
           
            $last = $salt . pack("N", $i);            
            $last = $xorsum = hash_hmac($algorithm, $last, $password, true);
           
            for ($j = 1; $j < $count; $j++) {
                $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
            }
            
            $output .= $xorsum;
            
        }
    
        if($rawOutput)
            return substr($output, 0, $keyLength);
        
        else
            return bin2hex(substr($output, 0, $keyLength));
        
    }
    
    /*============================================================================================================================================*/
    
}