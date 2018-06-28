<?PHP

  set_include_path ('../');
  error_reporting (E_ALL);
  
  require_once ('qcEvents/Base.php');
  require_once ('qcEvents/Socket/Server.php');
  require_once ('TLS/Context.php');
  require_once ('TLS/Handshake.php');
  
  $pKey = openssl_pkey_new (array (
    'private_key_bits' => 1024,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
  ));
  
  $csr = openssl_csr_new (array ('commonName' => 'test.example'), $pKey, array ('digest_alg' => 'sha256'));
  $x509 = openssl_csr_sign ($csr, null, $pKey, 5, array ('digest_alg' => 'sha256'));
  openssl_x509_export ($x509, $pem);
  $der = base64_decode (substr ($pem, strpos ($pem, "\n") + 1, strpos ($pem, "\n--") - strpos ($pem, "\n")));
  
  $Base = qcEvents_Base::singleton ();
  $Pool = new qcEvents_Socket_Server ($Base);
  $Pool->setChildClass ('TLS_Context', true);
  $Pool->listen ($Pool::TYPE_TCP, 443);
  $Pool->addHook ('serverClientNew', function ($Pool, $Socket, $Context) use ($der, $pKey) {
    $Context->setCertificates (array ($der), $pKey);
  });
  
  $Base->loop ();

?>