<?php
	
	if(isset($_POST['register'])){

		require_once '../connection/connection.php';

		$first_name=$_POST['firstname'];
		$last_name=$_POST['lastname'];
		$email=$_POST['email'];
		$password=$_POST['password'];
		$conformpassword=$_POST['conformpassword'];
		$upload_image_name="";


		//check image availability
		if(isset($_FILES['image'])){

			$file_name=$_FILES['image']['name'];
			$file_tmp_name=$_FILES['image']['tmp_name'];
			$file_size=$_FILES['image']['size'];
			$file_error=$_FILES['image']['error'];
			$file_type=$_FILES['image']['type'];

			$upload_image_name=profileImageUpload($file_name,$file_error,$file_size,$file_tmp_name);

		}

		if(empty($first_name) || empty($last_name) || empty($email) || empty($password) || empty($conformpassword)){

			header("Location: ../../views/auth/register.php?error=emptyfields&first_name=".$first_name."&last_name=".$last_name."&email=".$email);
			exit();
		}
		else if(!filter_var($email,FILTER_VALIDATE_EMAIL)){
			header("Location: ../../views/auth/register.php?error=emailerror&first_name=".$first_name."&last_name=".$last_name);
			exit();
		}
		else if($password != $conformpassword){
			header("Location: ../../views/auth/register.php?error=passwordmistakes&first_name=".$first_name."&last_name=".$last_name."&email=".$email);
			exit();
		}
		else{

			try{
				$sql="SELECT email FROM uses WHERE email = ?";
				$stmt=$conn->prepare($sql);

				$stmt->bind_param("s",$email);
				$stmt->execute();

				$result=$stmt->get_result(); 

				if($result->num_rows > 0){
					$stmt->close();
					$conn->close();

					header("Location: ../../views/auth/register.php?error=emailalreadyexits&first_name=".$first_name."&last_name=".$last_name."&email=".$email);
					exit();
				}
				else{
					
					$insert_sql="INSERT INTO uses (firstname,lastname,email,password,image) VALUES (?,?,?,?,?)";

					$insert_stmt=$conn->prepare($insert_sql);

					$hash_password=password_hash($password,PASSWORD_DEFAULT);


					$insert_stmt->bind_param("sssss",$first_name,$last_name,$email,$hash_password,$upload_image_name);
					$result=$insert_stmt->execute();

					if(!$result){
						echo $stmt->error;
					}

					$stmt->close();
					$conn->close();

					header("Location: ../../index.php?register=successfull");
					exit();
				} 
			}
			catch(mysqli_sql_exception $e){
				echo $e->getMessage();
			}	
		}
	}

	else{
		header("Location: ../../views/auth/register.php");
		exit();
	}
	function profileImageUpload($file_name,$file_error,$file_size,$file_tmp_name){

		$file_ext=explode('.', $file_name);

		$file_actual_ext=strtolower(end($file_ext));

		$allowed=array('jpg','jpeg','png');

		if(in_array($file_actual_ext, $allowed)){

			if($file_error===0){
				if($file_size <= 5000000){

					//create unique id
					$file_new_name=uniqid('',true).".".$file_actual_ext;

					//define image destination
					$file_destination = '../../assets/uploads/profile_images/'.$file_new_name;

					//move image to the destiation
					move_uploaded_file($file_tmp_name, $file_destination);

					return $file_new_name;
				}

				else{
					header("Location: ../../views/auth/register.php?error=filetoolarge&first_name=".$first_name."&last_name=".$last_name."&email=".$email);
					exit();
				}
			}

			else{
				header("Location: ../../views/auth/register.php?error=fileerrors&first_name=".$first_name."&last_name=".$last_name."&email=".$email);
				exit();
			}
		}

		else{

			
			header("Location: ../../views/auth/register.php?error=filetypenotallowed&first_name=".$first_name."&last_name=".$last_name."&email=".$email);
			exit();
		}

	}

?>