<?php 
	
	if(isset($_POST['foget_password_button'])){
		
		require_once '../connection/connection.php';

		$selector=bin2hex(random_bytes(8));
		$token=random_bytes(32);

		$url="http://localhost/sample-site/views/auth/reset_password.php?selector=".$selector."&validator=".bin2hex($token);

		$expirate=date('U')+1800;

		$email=$_POST['email'];

		if(empty($email)){

			header("Location:../../views/auth/foget_password.php?error=emptyfields");
			exit(); 
		}
		else if(!filter_var($email,FILTER_VALIDATE_EMAIL)){
			header("Location:../../views/auth/foget_password.php?error=invalidemail");
			exit();
		}
		else{

			//check user exixtancy
			$sql="SELECT email FROM uses WHERE email = ?";
			$stmt=$conn->prepare($sql);

			$stmt->bind_param("s",$email);
			$stmt->execute();

			$result=$stmt->get_result(); 

			if($result->num_rows>0){

				//delete exixting token perticular user
				$sql_delete="DELETE FROM pwd_reset WHERE email=?";	

				$stmt_delete=$conn->prepare($sql_delete);

				$stmt_delete->bind_param("s",$email);
				$stmt_delete->execute();

				//inset new token
				$sql_insert="INSERT INTO pwd_reset(email,selector,token,expires) VALUES(?,?,?,?)";

				$stmt_insert=$conn->prepare($sql_insert);

				//encrypt token
				$hash_token=password_hash($token, PASSWORD_DEFAULT);

				$stmt_insert->bind_param("ssss",$email,$selector,$hash_token,$expirate);

				$stmt_insert->execute();	

				$to=$email;
				$subject="password reset request";		


				$message = '<p> We receive your paswword reset request. The link toreset your password is below. if you did not request, please ignore this message.</p>';
				$message .= '<p>Here is your password reset link <br>';
				$message .= '<a href="' . $url . '">Click Here</a></p>';

				$headers = "From: Authentication <vipunsanjana34@gmail.com>";
				$headers .= "Replty-to: vipunsanjana34@gmail.com";
				$headers .= "Content-type: text/html\n";

				mail($to, $subject, $message, $headers);

				header("Location:../../views/auth/foget_password.php?reset=successful&url=".$url);
				

				$stmt->close();
				$stmt_delete->close();
				$stmt_insert->close();
				$conn->close();

			}
			else{
				header("Location:../../views/auth/foget_password.php?error=usernotfound");
			} 
		}
	}
	else{
		header("Location:../../views/auth/foget_password.php");
		exit(); 
	}

?>