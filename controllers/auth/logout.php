<?php

	session_start();
	if(isset($_SESSION['user_email'])){
		session_unset();
		session_destroy();
		header("Location:../../index.php?success=logout");
		exit();

	}

?>
