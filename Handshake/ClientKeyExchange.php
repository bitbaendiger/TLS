<?PHP

  require_once ('TLS/Handshake/Message.php');
  
  class TLS_Handshake_ClientKeyExchange extends TLS_Handshake_Message {
    /* Type of this message */
    const HANDSHAKE_TYPE = 0x10;
    
    /* Instance of our TLS-Context */
    private $Context = null;
    
    /* Original content as received from the wire */
    private $originalPayload = null;
    
    /* Version of encrypted payload */
    private $latestVersion = null;
    
    /* Random bytes */
    private $Random = null;
    
    // {{{ __construct
    /**
     * Create a new Client-Key-Exchange-Message
     * 
     * @param TLS_Context $Context
     * 
     * @access friendly
     * @return void
     **/
    function __construct (TLS_Context $Context) {
      $this->Context = $Context;
    }
    // }}}
    
    // {{{ __debugInfo
    /**
     * Prepare output for var_dump()
     * 
     * @access friendly
     * @return array
     **/
    function __debugInfo () {
      // Rerive the next negotiated cipher-suite
      $Suite = $this->Context->getCipherSuite (true);
      $SuiteInfo = $this->Context->getCipherSuiteInfo ($Suite);
      
      switch ($SuiteInfo [0]) {
        case TLS_Context::KEY_EXCHANGE_RSA:
          return array (
            'latestVersion' => sprintf ('0x%04X', $this->latestVersion),
            'Random' => bin2hex ($this->Random),
          );
      }
      
      return array ();
    }
    // }}}
    
    // {{{ getLatestVersion
    /**
     * Retrive the latest supported TLS-Version of the client
     * 
     * @access public
     * @return int
     **/
    public function getLatestVersion () {
      return $this->latestVersion;
    }
    // }}}
    
    // {{{ getRandom
    /**
     * Retrive the random provided with this message
     * 
     * @access public
     * @return string
     **/
    public function getRandom ($Full = false) {
      return ($Full ? pack ('n', $this->latestVersion) : '') . $this->Random;
    }
    // }}}
    
    // {{{ parse
    /**
     * Read binary data into this instance
     * 
     * @param string $Data
     * @param int &$Offset (optional)
     * 
     * @access public
     * @return bool
     **/
    public function parse ($Data, &$Offset = 0) {
      // Rerive the next negotiated cipher-suite
      $Suite = $this->Context->getCipherSuite (true);
      $SuiteInfo = $this->Context->getCipherSuiteInfo ($Suite);
      
      switch ($SuiteInfo [0]) {
        case TLS_Context::KEY_EXCHANGE_RSA:
          // Try to read the encrypted pre-master-secret from the data
          if (($EncryptedPreMasterSecret = $this::readCompactString ($Data, $Offset, 2)) === false)
            return false;
          
          // Try to decrypt
          if (($PreMasterSecret = $this->Context->privateDecrypt ($EncryptedPreMasterSecret)) === false)
            return false;
          
          // Check the length
          if (strlen ($PreMasterSecret) != 48)
            return false;
          
          // Unpack the structure
          $PreMasterSecret = unpack ('nversion/a46random', $PreMasterSecret);
          
          // Assign the values
          $this->originalPayload = $EncryptedPreMasterSecret;
          $this->latestVersion = $PreMasterSecret ['version'];
          $this->Random = $PreMasterSecret ['random'];
          
          return true;
        case TLS_Context::KEY_EXCHANGE_DH_ANON:
        case TLS_Context::KEY_EXCHANGE_DH_RSA:
        case TLS_Context::KEY_EXCHANGE_DH_DSS:
        case TLS_Context::KEY_EXCHANGE_DHE_RSA:
        case TLS_Context::KEY_EXCHANGE_DHE_DSS:
          # TODO
          # return true;
        case TLS_Context::KEY_EXCHANGE_ECDH_ANON:
        case TLS_Context::KEY_EXCHANGE_ECDH_RSA:
        case TLS_Context::KEY_EXCHANGE_ECDH_ECDSA:
        case TLS_Context::KEY_EXCHANGE_ECDHE_RSA:
        case TLS_Context::KEY_EXCHANGE_ECDHE_ECDSA:
          # TODO
          # return true;
        default:
          return false;
      }
      
      return true;
    }
    // }}}
    
    // {{{ toBinary
    /**
     * Convert this message to binary format
     * 
     * @access public
     * @return string
     **/
    public function toBinary () {
      // Rerive the next negotiated cipher-suite
      $Suite = $this->Context->getCipherSuite (true);
      $SuiteInfo = $this->Context->getCipherSuiteInfo ($Suite);
      
      switch ($SuiteInfo [0]) {
        case TLS_Context::KEY_EXCHANGE_RSA:
          if ($this->originalPayload !== null)
            return $this::writeCompactString ($this->originalPayload, 2);
          
          return $this::writeCompactString ($this->Context->publicEncrypt (pack ('na46', $this->latestVersion, $this->Random)), 2);
        
        case TLS_Context::KEY_EXCHANGE_DH_ANON:
        case TLS_Context::KEY_EXCHANGE_DH_RSA:
        case TLS_Context::KEY_EXCHANGE_DH_DSS:
        case TLS_Context::KEY_EXCHANGE_DHE_RSA:
        case TLS_Context::KEY_EXCHANGE_DHE_DSS:
          # TODO
          # return '';
        case TLS_Context::KEY_EXCHANGE_ECDH_ANON:
        case TLS_Context::KEY_EXCHANGE_ECDH_RSA:
        case TLS_Context::KEY_EXCHANGE_ECDH_ECDSA:
        case TLS_Context::KEY_EXCHANGE_ECDHE_RSA:
        case TLS_Context::KEY_EXCHANGE_ECDHE_ECDSA:
          # TODO
          # return '';
        default:
          return '';
      }
    }
    // }}}
  }

?>