<?PHP

  require_once ('TLS/Handshake/Message.php');
  
  class TLS_Handshake_ClientHello extends TLS_Handshake_Message {
    /* Type of this message */
    const HANDSHAKE_TYPE = 0x01;
    
    /* TLS-Version of the client saying hello */
    private $Version = 0x0301;
    
    /* Unix-Timestamp at the client */
    private $Time = 0x00000000;
    
    /* Random bytes */
    private $Random = '';
    
    /* Session the client is trying to resume */
    private $SessionID = '';
    
    /* Supported cipher-suites */
    private $Suites = array ();
    
    /* Supported compression-methods */
    private $CompressionMethods = array ();
    
    /* TLS-Extensions */
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
        'Suites' => $this->Suites,
        'CompressionMethods' => $this->CompressionMethods,
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
    
    // {{{ getSuites
    /**
     * Retrive the list of supported cipher-suites at the client
     * 
     * @access public
     * @return array
     **/
    public function getSuites () {
      return $this->Suites;
    }
    // }}}
    
    // {{{ getCompressionMethods
    /**
     * Retrive the list of supported compression-methods
     * 
     * @access public
     * @return array
     **/
    public function getCompressionMethods () {
      return $this->CompressionMethods;
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
      if ($Length - $Offset < 38) {
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
      
      // Try to read cipher-suites
      if (($Suites = $this::readCompactString ($Data, $Offset, 2, $Length - $Offset)) === false) {
        trigger_error ('Failed to read cipher-suites');
        
        return false;
      }
      
      $Suites = unpack ('n' . ceil (strlen ($Suites) / 2), $Suites);
      
      // Try to read compression-methods
      if (($CompressionMethods = $this::readCompactString ($Data, $Offset, 1, $Length - $Offset)) === false) {
        trigger_error ('Failed to read compression-methods');
        
        return false;
      }
      
      $CompressionMethods = unpack ('C' . strlen ($CompressionMethods), $CompressionMethods);
      
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
      $this->Suites = $Suites;
      $this->CompressionMethods = $CompressionMethods;
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
        $Extensions .= pack ('n', $ID) . $this::writeCompactString ($Data, 2);
      
      return
        pack ('nNa28', $this->Version, $this->Time, $this->Random) .
        $this::writeCompactString ($this->SessionID, 1) .
        $this::writeCompactString (call_user_func_array ('pack', array_merge (array (str_repeat ('n', count ($this->Suites))), $this->Suites)), 2) .
        $this::writeCompactString (call_user_func_array ('pack', array_merge (array (str_repeat ('C', count ($this->CompressionMethods))), $this->CompressionMethods)), 1) .
        $this::writeCompactString ($Extensions, 2);
    }
    // }}}
  }

?>