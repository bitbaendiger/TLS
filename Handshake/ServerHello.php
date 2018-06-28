<?PHP

  require_once ('TLS/Handshake/Message.php');
  
  class TLS_Handshake_ServerHello extends TLS_Handshake_Message {
    /* Type of this message */
    const HANDSHAKE_TYPE = 0x02;
    
    /* TLS-Version to use on the connection */
    private $Version = 0x0303;
    
    /* UNIX-Time at server-side */
    private $Time = 0x00000000;
    
    /* Random string */
    private $Random = '';
    
    /* ID of the negotiated session */
    private $SessionID = '';
    
    /* Cipher-Suite used on the session */
    private $Suite = 0x0000;
    
    /* Compression-Method used on the session */
    private $CompressionMethod = 0x00;
    
    /* Negotiated Extensions */
    private $Extensions = array ();
    
    // {{{ __debugInfo
    /**
     * Prepare output for var_dump()
     * 
     * @access friendly
     * @return array
     **/
    function __debugInfo () {
      return array (
        'Version' => sprintf ('0x%04x', $this->Version),
        'Time' => sprintf ('0x%08x', $this->Time) . date (' (Y-m-d H:i:s)', $this->Time),
        'Random' => bin2hex ($this->Random),
        'Suite' => $this->Suite,
        'CompressMethod' => $this->CompressionMethod,
        'Extensions' => $this->Extensions,
      );
    }
    // }}}
    
    // {{{ getVersion
    /**
     * Retrive the max. supported version of the client
     * 
     * @access public
     * @return int
     **/
    public function getVersion () {
      return $this->Version;
    }
    // }}}
    
    // {{{ setVersion
    /**
     * Set the max. supported version of the client
     * 
     * @param int $Version
     * 
     * @access public
     * @return void
     **/
    public function setVersion ($Version) {
      $this->Version = (int)$Version;
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
      return ($Full ? pack ('N', $this->Time) : '') . $this->Random;
    }
    // }}}
    
    // {{{ setRandom
    /**
     * Set random value
     * 
     * @param string $Data (optional)
     * 
     * @access public
     * @return void
     **/
    public function setRandom ($Data = null) {
      if ($Data === null) {
        $this->Time = unpack ('N', openssl_random_pseudo_bytes (4));
        $this->Random = openssl_random_pseudo_bytes (28);
        
        return;
      }
      
      $Length = strlen ($Data);
      
      if ($Length >= 32) {
        $this->Time = unpack ('N', substr ($Data, 0, 4));
        $this->Random = substr ($Data, 4, 28);
        
        return;
      } elseif ($Length < 12)
        $Data .= md5 ($Data, true) . sha1 ($Data, true);
      elseif ($Length < 28)
        $Data .= md5 ($Data, true);
      
      $this->Random = substr ($Data, 0, 28);
    }
    // }}}
    
    // {{{ getSuite
    /**
     * Retrive the negotiated cipher-suite
     * 
     * @access public
     * @return int
     **/
    public function getSuite () {
      return $this->Suite;
    }
    // }}}
    
    // {{{ setSuite
    /**
     * Set the suite to use
     * 
     * @param int $Suite
     * 
     * @access public
     * @return void
     **/
    public function setSuite ($Suite) {
      $this->Suite = (int)$Suite;
    }
    // }}}
    
    // {{{ getCompressionMethod
    /**
     * Retrive the negotiated compression-method
     * 
     * @access public
     * @return int
     **/
    public function getCompressionMethod () {
      return $this->CompressionMethod;
    }
    // }}}
    
    // {{{ setCompressionMethod
    /**
     * Set the compression-method to be used
     * 
     * @param int $CompressionMethod
     * 
     * @access public
     * @return void
     **/
    public function setCompressionMethod ($CompressionMethod) {
      $this->CompressionMethod = (int)$CompressionMethod;
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
      // Retrive the available length of input
      $Length = strlen ($Data);
      
      // Read static header
      if ($Length - $Offset < 32) {
        trigger_error ('Input too short');
      
        return false;
      }
      
      $Version = (ord ($Data [$Offset++]) << 8) | ord ($Data [$Offset++]);
      $Time    = (ord ($Data [$Offset++]) << 24) | (ord ($Data [$Offset++]) << 16) | (ord ($Data [$Offset++]) << 8) | ord ($Data [$Offset++]);
      $Random  = substr ($Data, $Offset, 28);
      $Offset += 28;
      
      // Try to read session-id
      if (($SessionID = $this::readCompactString ($Data, $Offset, 1, $Length - $Offset)) === false) {
        trigger_error ('Failed to read session-id');
    
        return false;
      }
      
      // Try to read suite and compression-method
      if ($Length - $Offset < 3) {
        trigger_error ('Input too short');
    
        return false;
      }
      
      $Suite = (ord ($Data [$Offset++]) << 8) | ord ($Data [$Offset++]);
      $CompressionMethod = ord ($Data [$Offset++]);
      
      // Check for extensions
      if ($Offset < $Length) {
        // Try to read the extensions
        if (($ExtensionsData = $this::readCompactString ($Data, $Offset, 2, $Length - $Offset)) === false) {
          trigger_error ('Failed to read extensions');

          return false;
        }
        
        $Extensions = array ();
        $eLength = strlen ($ExtensionsData);
        $eOffset = 0;
      
        while ($eOffset < $eLength) {
          // Try to read the type
          if ($eOffset + 2 >= $eLength)
            return false;
          
          $eType = (ord ($ExtensionsData [$eOffset++]) << 8) | ord ($ExtensionsData [$eOffset++]);
          
          if (isset ($Extensions [$eType])) {
            trigger_error ('Extension may only appear ONCE');
            
            return false;
          }
          
          // Read data of extension
          if (($eData = $this::readCompactString ($ExtensionsData, $eOffset, 2, $eLength - $eOffset)) === false) {
            trigger_error ('Failed to read extension-data');
          
            return false;
          }
        
          $Extensions [$eType] = $eData;
        }
      } else
        $Extensions = array ();
      
      // Commit data to this instance
      $this->Version = $Version;
      $this->Time = $Time;
      $this->Random = $Random;
      $this->SessionID = $SessionID;
      $this->Suite = $Suite;
      $this->CompressionMethod = $CompressionMethod;
      $this->Extensions = $Extensions;
      
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
      $Extensions = '';
      
      foreach ($this->Extensions as $ID=>$Data)
        $Extensions = pack ('n', $ID) . $this::writeCompactString ($Data);
      
      return
        pack ('nNa28', $this->Version, $this->Time, $this->Random) .
        $this::writeCompactString ($this->SessionID, 1) .
        pack ('nC', $this->Suite, $this->CompressionMethod) .
        $this::writeCompactString ($Extensions, 2);
    }
    // }}}
  }

?>