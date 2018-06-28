<?PHP

  require_once ('qcEvents/Hookable.php');
  require_once ('qcEvents/Interface/Stream/Consumer.php');
  require_once ('TLS/Handshake.php');
  
  class TLS_Context extends qcEvents_Hookable implements qcEvents_Interface_Stream_Consumer {
    /* Our most supported TLS-Version */
    const TLS_VERSION_MAX = 0x0303;
    
    /* Well-known TLS-Record-Types */
    const RECORD_TYPE_CHANGE_CIPHER = 0x14;
    const RECORD_TYPE_ALERT         = 0x15;
    const RECORD_TYPE_HANDSHAKE     = 0x16;
    const RECORD_TYPE_APPLICATION   = 0x17;
    
    /* Well-known TLS-Alerts */
    const ALERT_LEVEL_WARNING = 0x01;
    const ALERT_LEVEL_FATAL = 0x02;
    
    const ALERT_CLOSE_NOTIFY = 0x00;
    const ALERT_UNEXPECTED_MESSAGE = 0x0A;
    const ALERT_BAD_RECORD_MAC = 0x14;
    const ALERT_DECRYPT_FAILED_X = 0x15;
    const ALERT_RECORD_OVERFLOW = 0x16;
    const ALERT_DECOMPRESSION_FAILURE = 0x1E;
    const ALERT_HANDSHAKE_FAILURE = 0x28;
    const ALERT_NO_CERTIFICATE_X = 0x29;
    const ALERT_BAD_CERTIFICATE = 0x2A;
    const ALERT_UNSUPPORTED_CERTIFICATE = 0x2B;
    const ALERT_CERTIFICATE_REVOKED = 0x2C;
    const ALERT_CERTIFICATE_EXPIRED = 0x2D;
    const ALERT_CERTIFICATE_UNKNOWN = 0x2E;
    const ALERT_ILLEGAL_PARAMETER = 0x2F;
    const ALERT_UNKNOWN_CA = 0x30;
    const ALERT_ACCESS_DENIED = 0x31;
    const ALERT_DECODE_ERROR = 0x32;
    const ALERT_DECRYPT_ERROR = 0x33;
    const ALERT_EXPORT_RESTRICTION_X = 0x3C;
    const ALERT_PROTOCOL_VERSION = 0x46;
    const ALERT_INSUFFICIENT_SECURITY = 0x47;
    const ALERT_INTERNAL_ERROR = 0x50;
    const ALERT_USER_CANCELED = 0x5A;
    const ALERT_NO_RENEGOTIATION = 0x64;
    const ALERT_UNSUPPORTED_EXTENSION = 0x6E;
    
    /* Well-known TLS-Roles */
    const ROLE_AUTODETECT = 0x00;
    const ROLE_SERVER = 0x01;
    const ROLE_CLIENT = 0x02;
    
    private $Role = TLS_Context::ROLE_AUTODETECT;
    
    /* Cipher-suites */
    const KEY_EXCHANGE_RSA         = 0x00;
    const KEY_EXCHANGE_DH_ANON     = 0x01; // Unsupported
    const KEY_EXCHANGE_DH_RSA      = 0x02; // Unsupported
    const KEY_EXCHANGE_DH_DSS      = 0x03; // Unsupported
    const KEY_EXCHANGE_DHE_RSA     = 0x04; // Unsupported
    const KEY_EXCHANGE_DHE_DSS     = 0x05; // Unsupported
    const KEY_EXCHANGE_ECDH_ANON   = 0x06; // Unsupported
    const KEY_EXCHANGE_ECDH_RSA    = 0x07; // Unsupported
    const KEY_EXCHANGE_ECDH_ECDSA  = 0x08; // Unsupported
    const KEY_EXCHANGE_ECDHE_RSA   = 0x09; // Unsupported
    const KEY_EXCHANGE_ECDHE_ECDSA = 0x0A; // Unsupported
    
    const CIPHER_AES      = 0x01;
    const CIPHER_RC4      = 0x02;
    const CIPHER_3DES     = 0x03; // Unsupported
    const CIPHER_CHACHA20 = 0x03;
    
    const BLOCK_CBC = 0x01;
    const BLOCK_GCM = 0x02; // Unsupported
    
    const MAC_MD5    = 0x01;
    const MAC_SHA1   = 0x02;
    const MAC_SHA256 = 0x03;
    const MAC_SHA384 = 0x04;
    const MAC_SHA512 = 0x05;
    
    private static $blockSize = array (
      TLS_Context::CIPHER_RC4      => null,
      TLS_Context::CIPHER_CHACHA20 => null,
      TLS_Context::CIPHER_3DES     => 8,
      TLS_Context::CIPHER_AES      => 16,
    );
    
    private static $macLength = array (
      TLS_Context::MAC_MD5    => 16,
      TLS_Context::MAC_SHA1   => 20,
      TLS_Context::MAC_SHA256 => 32,
      TLS_Context::MAC_SHA384 => 48,
      TLS_Context::MAC_SHA512 => 64,
    );
    
    private static $cipherSuites = array (
      // Format:       0: Key-Exchange,  1: Cipher,  2: Key-Size,  3: Block-Mode,  4: MAC-Algorithm
      0x002F => array (TLS_Context::KEY_EXCHANGE_RSA, TLS_Context::CIPHER_AES, 16, TLS_Context::BLOCK_CBC, TLS_Context::MAC_SHA1),
      0x0035 => array (TLS_Context::KEY_EXCHANGE_RSA, TLS_Context::CIPHER_AES, 32, TLS_Context::BLOCK_CBC, TLS_Context::MAC_SHA1),
      0x003C => array (TLS_Context::KEY_EXCHANGE_RSA, TLS_Context::CIPHER_AES, 16, TLS_Context::BLOCK_CBC, TLS_Context::MAC_SHA256),
      0x003D => array (TLS_Context::KEY_EXCHANGE_RSA, TLS_Context::CIPHER_AES, 32, TLS_Context::BLOCK_CBC, TLS_Context::MAC_SHA256),
    );
    
    private $cipherSuitesPreference = array (
      0x003D,
      #0x003C,
      0x0035,
      #0x002F,
    );
    
    private $cipherSuite = null;
    private $cipherSuiteNext = null;
    private $cipherSpec = null;
    
    /* Compression-Method */
    const COMPRESSION_NONE = 0x00;
    
    private $compressionMethods = array (
      TLS_Context::COMPRESSION_NONE,
    );
    
    private $compressionMethod = null;
    private $compressionMethodNext = null;
    
    /* Stream we are working on */
    private $Stream = null;
    
    /* Buffer for incoming TLS-Records */
    private $recordBuffer = '';
    
    /* Buffer for incoming TLS-Handshake-Messages */
    private $handshakeBuffer = '';
    private $handshakeBufferLength = 0;
    
    /* Digest of handshake */
    private $handshakeHash = null;
    
    /* Negotiated TLS-Version */
    private $tlsVersion = null;
    
    /* Maximum supported TLS-Version at client-side */
    private $tlsVersionMax = null;
    
    /* Private key */
    private $Key = null;
    
    /* Server-Certificates */
    private $Certificates = array ();
    
    /* Master-Key for this connection */
    private $MasterKey = '';
    
    /* Key-Material */
    private $remoteMAC = '';
    private $localMAC  = '';
    private $remoteKey = '';
    private $localKey  = '';
    private $remoteIV  = '';
    private $localIV   = '';
    
    /* Random values */
    private $randomClient = '';
    private $randomServer = '';
    
    /* Sequences (for MAC) */
    private $readSequence = 0;
    private $writeSequence = 0;
    
    // {{{ setCertificates
    /**
     * @param array $Certificates
     * @param resource $Key
     * 
     * @access public
     * @return void
     **/
    public function setCertificates (array $Certificates, $Key) {
      $this->Key = $Key;
      $this->Certificates = $Certificates;
    }
    // }}}
    
    // {{{ getCipherSuite
    /**
     * Retrive the negotiated cipher-suite
     * 
     * @param bool $Next (optional)
     * 
     * @access public
     * @return int
     **/
    public function getCipherSuite ($Next = false) {
      return ($Next ? $this->cipherSuiteNext : $this->cipherSuite);
    }
    // }}}
    
    // {{{ getCipherSuiteInfo
    /**
     * Retrive information about a well-known cipher
     * 
     * @param int $CipherSuite
     * 
     * @access public
     * @return array
     **/
    public function getCipherSuiteInfo ($CipherSuite) {
      if (isset ($this::$cipherSuites [$CipherSuite]))
        return $this::$cipherSuites [$CipherSuite];
    }
    // }}}
    
    // {{{ privateDecrypt
    /**
     * Decrypt data using our private key
     * 
     * @param string $Data
     * 
     * @access public
     * @return string
     **/
    public function privateDecrypt ($Data) {
      // Try to decrypt
      if (openssl_private_decrypt ($Data, $Plaintext, $this->Key, OPENSSL_SSLV23_PADDING) !== true)
        return false;
      
      return $Plaintext;
    }
    // }}}
    
    // {{{ deriveKey
    /**
     * Generate keying-material from secret, label and seed
     * 
     * @param string $Secret
     * @param string $Label
     * @param string $Seed
     * @param int $Length
     * @param string $PRNG (optional)
     * 
     * @access private
     * @return string
     **/
    private function deriveKey ($Secret, $Label, $Seed, $Length, $PRNG = 'sha256') {
      $Seed = $Label . $Seed;
      $A = hash_hmac ($PRNG, $Seed, $Secret, true);
      $Key = '';
      
      while (strlen ($Key) < $Length) {
        $Key .= hash_hmac ($PRNG, $A . $Seed, $Secret, true);
        $A = hash_hmac ($PRNG, $A, $Secret, true);
      }
      
      return substr ($Key, 0, $Length);
    }
    // }}}
    
    // {{{ consume
    /**
     * Consume a set of data
     * 
     * @param mixed $Data
     * @param qcEvents_Interface_Source $Source
     * 
     * @access public
     * @return void
     **/
    public function consume ($Data, qcEvents_Interface_Source $Source) {
      // Append data to local buffer
      $this->recordBuffer .= $Data;
      unset ($Data);
      
      // Try to read records from the buffer
      $Length = strlen ($this->recordBuffer);
      $Offset = 0;
      
      while ($Offset + 5 < $Length) {
        // Read the length of the record
        $recordLength = (ord ($this->recordBuffer [$Offset + 3]) << 8) | ord ($this->recordBuffer [$Offset + 4]);
        
        // Make sure we have the entire record
        if ($Offset + $recordLength + 5 > $Length)
          break;
        
        // Read the entire record
        $Type = ord ($this->recordBuffer [$Offset++]);
        $Version = (ord ($this->recordBuffer [$Offset++]) << 8) | ord ($this->recordBuffer [$Offset++]);
        $Payload = substr ($this->recordBuffer, $Offset + 2, $recordLength);
        $Offset += $recordLength + 2;
        
        // Check the version
        if (($this->tlsVersion !== null) && ($Version != $this->tlsVersion))
          return $this->sendAlert ($this::ALERT_LEVEL_FATAL, $this::ALERT_PROTOCOL_VERSION);
        
        // Check wheter to decipher the payload
        if ($this->cipherSuite !== null) {
          // Get Information about the current cipher
          $Info = $this->getCipherSuiteInfo ($this->cipherSuite);
          
          // Try to decrypt and dump
          $Payload = openssl_decrypt ($Payload, $this->cipherSpec, $this->remoteKey, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $this->remoteIV);
          
          // Extract IV from payload
          $IV = substr ($Payload, 0, $this::$blockSize [$Info [1]]);
          $Payload = substr ($Payload, $this::$blockSize [$Info [1]]);
          
          // Strip off padding
          $pLength = ord (substr ($Payload, -1, 1));
          $Payload = substr ($Payload, 0, -($pLength + 1));
          
          // Strip off MAC
          $MAC = substr ($Payload, -$this::$macLength [$Info [4]], $this::$macLength [$Info [4]]);
          $Payload = substr ($Payload, 0, -$this::$macLength [$Info [4]]);
          $recordLength = strlen ($Payload);
          
          // Check the MAC
          static $hMap = array (
            self::MAC_MD5 => 'md5',
            self::MAC_SHA1 => 'sha1',
            self::MAC_SHA256 => 'sha256',
            self::MAC_SHA384 => 'sha384',
            self::MAC_SHA512 => 'sha512',
          );
          
          $cMAC = hash_hmac ($hMap [$Info [4]], pack ('JCnn', $this->readSequence++, $Type, $Version, $recordLength) . $Payload, $this->remoteMAC, true);
          
          if (strcmp ($cMAC, $MAC) != 0) {
            trigger_error ('Incoming MAC invalid');
            
            return $this->sendAlert ($this::ALERT_LEVEL_FATAL, $this::ALERT_BAD_RECORD_MAC);
          }
          
          // Update the IV
          $this->removeIV = $IV;
        }
        
        // Check wheter to decompress the payload
        if ($this->compressionMethod > 0) {
          # TODO
        }
        
        // Push the record to the protocol-handler
        switch ($Type) {
          case $this::RECORD_TYPE_ALERT:
            if (!$this->processAlert ($Payload, $recordLength))
              return false;
            
            break;
          case $this::RECORD_TYPE_HANDSHAKE:
            if (!$this->processHandshake ($Payload, $recordLength))
              return false;
            
            break;
          case $this::RECORD_TYPE_CHANGE_CIPHER:
            // We expect only one byte
            if ($recordLength != 1)
              return $this->sendAlert ($this::ALERT_LEVEL_FATAL, $this::ALERT_DECODE_ERROR);
            
            // There is only one legal value
            if (ord ($Payload [0]) != 0x01)
              return $this->sendAlert ($this::ALERT_LEVEL_FATAL, $this::ALERT_DECODE_ERROR);
            
            // Check if there is a pending cipher-change
            if ($this->cipherSuiteNext === null)
              return;
            
            // Ack to the peer
            $this->writeRecord ($this::RECORD_TYPE_CHANGE_CIPHER, "\x01");
            
            // Switch states
            $Info = $this->getCipherSuiteInfo ($this->cipherSuiteNext);
            
            $this->cipherSuite = $this->cipherSuiteNext;
            $this->cipherSuiteNext = null;
            
            $this->compressionMethod = $this->compressionMethodNext;
            $this->compressionMethodNext = null;
            
            if ($Info [1] == $this::CIPHER_AES)
              $this->cipherSpec = 'aes-' . ($Info [2] * 8);
            elseif ($Info [1] == $this::CIPHER_RC4)
              $this->cipherSpec = 'RC4';
            elseif ($Info [1] == $this::CIPHER_CHACHA20)
              $this->cipherSpec = 'ChaCha20';
            
            if ($this::$blockSize [$Info [1]] !== null) {
              if ($Info [3] == $this::BLOCK_CBC)
                $this->cipherSpec .= '-cbc';
              elseif ($Info [3] == $this::BLOCK_GCM)
                $this->cipherSpec .= '-gcm';
            }
            
            // Generate new keys
            $bLength = ($this::$blockSize [$Info [1]] + $Info [2] + $this::$macLength [$Info [4]]) * 2;
            
            $Block = $this->deriveKey ($this->MasterKey, 'key expansion', $this->randomServer . $this->randomClient, $bLength);
            $bOffset = 0;
            
            if ($this->Role == $this::ROLE_CLIENT) {
              $this->localMAC  = substr ($Block, $bOffset, $this::$macLength [$Info [4]]); $bOffset += $this::$macLength [$Info [4]]; 
              $this->remoteMAC = substr ($Block, $bOffset, $this::$macLength [$Info [4]]); $bOffset += $this::$macLength [$Info [4]];
              $this->localKey  = substr ($Block, $bOffset, $Info [2]); $bOffset += $Info [2];
              $this->remoteKey = substr ($Block, $bOffset, $Info [2]); $bOffset += $Info [2];
              $this->localIV   = substr ($Block, $bOffset, $this::$blockSize [$Info [1]]); $bOffset += $this::$blockSize [$Info [1]];
              $this->remoteIV  = substr ($Block, $bOffset, $this::$blockSize [$Info [1]]);
            } else {
              $this->remoteMAC = substr ($Block, $bOffset, $this::$macLength [$Info [4]]); $bOffset += $this::$macLength [$Info [4]];
              $this->localMAC  = substr ($Block, $bOffset, $this::$macLength [$Info [4]]); $bOffset += $this::$macLength [$Info [4]];
              $this->remoteKey = substr ($Block, $bOffset, $Info [2]); $bOffset += $Info [2];
              $this->localKey  = substr ($Block, $bOffset, $Info [2]); $bOffset += $Info [2];
              $this->remoteIV  = substr ($Block, $bOffset, $this::$blockSize [$Info [1]]); $bOffset += $this::$blockSize [$Info [1]];
              $this->localIV   = substr ($Block, $bOffset, $this::$blockSize [$Info [1]]);
            }
            
            break;
          case $this::RECORD_TYPE_APPLICATION:
            trigger_error ('Application-Protocol still unimplemented');
            
            $this->writeRecord ($this::RECORD_TYPE_APPLICATION, 'PONG!' . "\n");
            
            break;
          default:
            return $this->sendAlert ($this::ALERT_LEVEL_FATAL, $this::ALERT_UNEXPECTED_MESSAGE);
        }
      }
      
      // Remove all processed records from the buffer
      if ($Offset > 0)
        $this->recordBuffer = substr ($this->recordBuffer, $Offset);
    }
    // }}}
    
    // {{{ processAlert
    /**
     * Process an incoming alert-message
     * 
     * @param string $Data
     * @param int $Length
     * 
     * @access private
     * @return bool
     **/
    private function processAlert ($Data, $Length) {
      // Check the length of the message
      if ($Length != 2)
        return $this->sendAlert ($this::ALERT_LEVEL_FATAL, $this::ALERT_DECODE_ERROR);
      
      // Unpack the message
      $Alert = unpack ('Clevel/Cmessage', $Data);
      
      # TODO
      trigger_error (sprintf ('TLS-Alert Level 0x%02X Message 0x%02X', $Alert ['level'], $Alert ['message']));
      
      return true;
    }
    // }}}
    
    // {{{ processHandshake
    /**
     * Process an incoming record for the handshake-protocol
     * 
     * @param string $Data
     * @param int $Length
     * 
     * @access private
     * @return bool
     **/
    private function processHandshake ($Data, $Length) {
      // Push the data to our buffer
      $this->handshakeBuffer .= $Data;
      $this->handshakeBufferLength += $Length;
      unset ($Data);
      
      // Try to read messages from the buffer
      $Handshake = new TLS_Handshake ($this);
      $Offset = 0;
      
      while ($Offset < $this->handshakeBufferLength) {
        // Try to parse a message from the buffer
        $Result = $Handshake->parse ($this->handshakeBuffer, $Offset, $this->handshakeBufferLength);
        
        if ($Result === false)
          return $this->sendAlert ($this::ALERT_LEVEL_FATAL, $this::ALERT_DECODE_ERROR);
        
        if ($Result === null)
          break;
        
        // Update handshake-digest
        if ($this->handshakeHash === null)
          $this->handshakeHash = hash_init ('sha256');
        
        if (!($Handshake->getMessage () instanceof TLS_Handshake_Finished))
          hash_update ($this->handshakeHash, $Handshake->toBinary ());
        
        // Forward the message
        if (!$this->processHandshakeMessage ($Handshake->getMessage ()))
          return false;
      }
      
      // Truncate processed messages from the buffer
      if ($Offset > 0) {
        $this->handshakeBuffer = substr ($this->handshakeBuffer, $Offset);
        $this->handshakeBufferLength -= $Offset;
      }
      
      return true;
    }
    // }}}
    
    // {{{ processHandshakeMessage
    /**
     * Process an incoming handshake-message
     * 
     * @access private
     * @return bool
     **/
    private function processHandshakeMessage (TLS_Handshake_Message $Message) {
      // Process an incoming client-hello
      if ($Message instanceof TLS_Handshake_ClientHello) {
        // Check if this message is allowed
        if ($this->Role != $this::ROLE_SERVER)
          return $this->sendAlert ($this::ALERT_LEVEL_FATAL, $this::ALERT_UNEXPECTED_MESSAGE);
        
        // Check if we are expecting a ClientHello
        if ($this->tlsVersion !== null)
          return $this->sendAlert ($this::ALERT_LEVEL_FATAL, $this::ALERT_UNEXPECTED_MESSAGE);
        
        // We only support TLS 1.2 at the moment
        # TODO: Change this
        if ($Message->getVersion () < 0x0303)
          return $this->sendAlert ($this::ALERT_LEVEL_FATAL, $this::ALERT_PROTOCOL_VERSION);
        
        $this->tlsVersion = 0x0303;
        $this->tlsVersionMax = $Message->getVersion ();
        $this->randomClient = $Message->getRandom (true);
        
        // Find a supported cipher-suite
        $this->cipherSuiteNext = null;
        $Suites = $Message->getSuites ();
        
        foreach ($this->cipherSuitesPreference as $Suite)
          if (in_array ($Suite, $Suites)) {
            $this->cipherSuiteNext = $Suite;
            break;
          }
          
        if ($this->cipherSuiteNext === null)
          return $this->sendAlert ($this::ALERT_LEVEL_FATAL, $this::ALERT_HANDSHAKE_FAILURE);
        
        // Find a supported compression-method
        $this->compressionMethodNext = null;
        $CompressionMethods = $Message->getCompressionMethods ();
        
        foreach ($this->compressionMethods as $Method)
          if (in_array ($Method, $CompressionMethods)) {
            $this->compressionMethodNext = $Method;
            break;
          }
        
        if ($this->compressionMethodNext === null)
          return $this->sendAlert ($this::ALERT_LEVEL_FATAL, $this::ALERT_HANDSHAKE_FAILURE);
        
        // Generate a reply
        $Response = new TLS_Handshake_ServerHello ($this);
        $Response->setVersion ($this->tlsVersion);
        $Response->setRandom ();
        $Response->setSuite ($this->cipherSuiteNext);
        $Response->setCompressionMethod ($this->compressionMethodNext);
        
        $this->randomServer = $Response->getRandom (true);
        $this->sendHandshake ($Response);
        
        // Send out server-certificates
        if ($this->Key && (count ($this->Certificates) > 0)) {
          $Response = new TLS_Handshake_Certificate ($this);
          $Response->setCertificates ($this->Certificates);
          
          $this->sendHandshake ($Response);
        }
        # TODO: ... and/or ServerKeyExchange
        
        # Optional: CertificateRequest
        
        $this->sendHandshake (new TLS_Handshake_ServerHelloDone ($this));
        
        return true;
      } elseif ($Message instanceof TLS_Handshake_ClientKeyExchange) {
        // Check if the latest supported version of the client was mitigated
        if ($this->tlsVersionMax != $Message->getLatestVersion ()) {
          # TODO
          trigger_error ('Version-Attack');
          
          return $this->sendAlert ($this::ALERT_LEVEL_FATAL, $this::ALERT_UNEXPECTED_MESSAGE);
        }
        
        // Generate master-secret
        $this->MasterKey = $this->deriveKey ($Message->getRandom (true), 'master secret', $this->randomClient . $this->randomServer, 48);
        
        return true;
      } elseif ($Message instanceof TLS_Handshake_Finished) {
        // Verify the data sent by the client
        if (strcmp ($Message->getVerifyData (), $this->deriveKey ($this->MasterKey, 'client finished', hash_final (hash_copy ($this->handshakeHash), true), 12)) != 0) {
          # TODO
          trigger_error ('Verify-Data invalid');
          
          return $this->sendAlert ($this::ALERT_LEVEL_FATAL, $this::ALERT_HANDSHAKE_FAILURE);
        }
        
        // Push the client-message back to the digest-buffer
        $Handshake = new TLS_Handshake ($this);
        $Handshake->setMessage ($Message);
        
        hash_update ($this->handshakeHash, $Handshake->toBinary ());
        
        // Overwrite the verify-data
        $Message->setVerifyData ($this->deriveKey ($this->MasterKey, 'server finished', hash_final ($this->handshakeHash, true), 12));
        $this->handshakeHash = null;
        
        // Push back the message
        return $this->sendHandshake ($Message);
      }
      
      trigger_error ('Unhandled handshake-message');
      
      return $this->sendAlert ($this::ALERT_LEVEL_FATAL, $this::ALERT_UNEXPECTED_MESSAGE);
    }
    // }}}
    
    // {{{ sendHandshake
    /**
     * Send a handshake-message
     * 
     * @param TLS_Handshake_Message $Message
     * 
     * @access private
     * @return bool
     **/
    private function sendHandshake (TLS_Handshake_Message $Message) {
      // Prepare a new envelope
      $Envelope = new TLS_Handshake ($this);
      $Envelope->setMessage ($Message);
      
      // Update handshake-digest
      if ($this->handshakeHash === null)
        $this->handshakeHash = hash_init ('sha256');
      
      hash_update ($this->handshakeHash, $Envelope->toBinary ());
      
      // Send out to the wire
      return $this->writeRecord ($this::RECORD_TYPE_HANDSHAKE, $Envelope->toBinary ());
    }
    // }}}
    
    // {{{ sendAlert
    /**
     * Write out an alert to the wire, close the connection if it's a fatal one
     * 
     * @param int $Level
     * @param int $Message
     * 
     * @access public
     * @return bool
     **/
    public function sendAlert ($Level, $Message) {
      $this->writeRecord ($this::RECORD_TYPE_ALERT, pack ('CC', $Level, $Message));
      
      if ($Level == $this::ALERT_LEVEL_FATAL) {
        $this->Stream->close ();
        
        return false;
      }
      
      return true;
    }
    // }}}
    
    // {{{ writeRecord
    /**
     * Write out a TLS-Record
     * 
     * @param int $Type
     * @param string $Message
     * 
     * @access private
     * @return bool
     **/
    private function writeRecord ($Type, $Message) {
      // Make sure we have a stream
      if (!$this->Stream)
        return false;
      
      // Determine TLS-Version
      $tlsVersion = ($this->tlsVersion !== null ? $this->tlsVersion : 0x0301);
      
      if ($this->cipherSuite !== null) {
        // Get Information about the current cipher
        $Info = $this->getCipherSuiteInfo ($this->cipherSuite);
        
        // Generate IV
        $IV = openssl_random_pseudo_bytes ($this::$blockSize [$Info [1]]);
        
        // Generate MAC
        static $hMap = array (
          self::MAC_MD5 => 'md5',
          self::MAC_SHA1 => 'sha1',
          self::MAC_SHA256 => 'sha256',
          self::MAC_SHA384 => 'sha384',
          self::MAC_SHA512 => 'sha512',
        );
        
        $MAC = hash_hmac ($hMap [$Info [4]], pack ('JCnn', $this->writeSequence++, $Type, $tlsVersion, strlen ($Message)) . $Message, $this->localMAC, true);
        
        $Message =
          $IV .
          $Message .
          $MAC;
        
        // Add padding
        if (($Padd = $this::$blockSize [$Info [1]] - (strlen ($Message) % $this::$blockSize [$Info [1]])) == 0)
          $Padd = $this::$blockSize [$Info [1]];
        
        $Message .= str_repeat (chr ($Padd - 1), $Padd);
        
        // Apply encryption
        $Message = openssl_encrypt ($Message, $this->cipherSpec, $this->localKey, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING, $this->localIV);
      }
      
      $Length = strlen ($Message);
      $Offset = 0;
      
      while ($Offset < $Length)
        if (!$this->Stream->write (pack ('Cnn', $Type, $tlsVersion, min (0xFFFF, $Length - $Offset)) . substr ($Message, $Offset, 0xFFFF)))
          return false;
        else
          $Offset += 0xFFFF;
      
      return true;
    }
    // }}}
    
    // {{{ close
    /**
     * Close this event-interface
     * 
     * @param callable $Callback (optional) Callback to raise once the interface is closed
     * @param mixed $Private (optional) Private data to pass to the callback
     * 
     * @access public
     * @return void
     **/
    public function close (callable $Callback = null, $Private = null) {
      # TODO
    }
    // }}}
    
    // {{{ initStreamConsumer
    /**
     * Setup ourself to consume data from a stream
     * 
     * @param qcEvents_Interface_Source $Source
     * @param callable $Callback (optional) Callback to raise once the pipe is ready
     * @param mixed $Private (optional) Any private data to pass to the callback
     * 
     * The callback will be raised in the form of
     * 
     *   function (qcEvents_Interface_Stream_Consumer $Self, qcEvents_Interface_Stream $Stream, bool $Status, mixed $Private = null) { }
     * 
     * @access public
     * @return callable
     **/
    public function initStreamConsumer (qcEvents_Interface_Stream $Source, callable $Callback = null, $Private = null) {
      // Assign the stream
      $this->Stream = $Source;
      
      // Get our role
      if ($this->Role == $this::ROLE_AUTODETECT) {
        if ($Source instanceof qcEvents_Socket)
          $this->Role = ($Source->isServer () ? $this::ROLE_SERVER : $this::ROLE_CLIENT);
        else
          trigger_error ('Cannot auto-detect our role on non-socket');
          # TODO: Add timeout to wait for ClientHello
      }
      
      // Raise the initial callback
      # TODO: Move this to the final negotiation of the protocol
      $this->___raiseCallback ($Callback, $Source, true, $Private);
    }
    // }}}
    
    // {{{ deinitConsumer
    /**
     * Callback: A source was removed from this consumer
     * 
     * @param qcEvents_Interface_Source $Source
     * @param callable $Callback (optional) Callback to raise once the pipe is ready
     * @param mixed $Private (optional) Any private data to pass to the callback
     * 
     * The callback will be raised in the form of 
     * 
     *   function (qcEvents_Interface_Stream_Consumer $Self, bool $Status, mixed $Private = null) { }
     * 
     * @access public
     * @return void
     **/
    public function deinitConsumer (qcEvents_Interface_Source $Source, callable $Callback = null, $Private = null) {
      $this->___raiseCallback ($Callback, true, $Private);
    }
    // }}}
    
    protected function eventReadable () { }
    protected function eventClosed () { }
  }

?>