<?PHP

  abstract class TLS_Handshake_Message {
    /* Type of this handshake-message */
    const HANDSHAKE_TYPE = 0xFF;
    
    // {{{ fromBinary
    /**
     * Create a ClientHello-Instance from a binary string
     * 
     * @param TLS_Context $Context
     * @param string $Data
     * @param int &$Offset (optional)
     * 
     * @access public
     * @return TLS_Handshake_ClientHello
     **/
    public static function fromBinary (TLS_Context $Context, $Data, &$Offset = 0) {
      $Instance = new static ($Context);
      
      if (!$Instance->parse ($Data, $Offset))
        return false;
      
      return $Instance;
    }
    // }}}
    
    // {{{ readCompactString
    /**
     * Try to read a lengthy string from binary data
     * 
     * @param string $Data
     * @param int $Offset
     * @param int $Size
     * @param int $avLength (optional)
     * 
     * @access protected
     * @return string
     **/
    protected static function readCompactString ($Data, &$Offset, $Size, $avLength = null) {
      // Make sure we have the available length
      if ($avLength === null)
        $avLength = strlen ($Data) - $Offset;
      
      // Try to read size of string
      if ($avLength < $Size)
        return false;
      
      $Length = 0;
      
      for ($i = 0; $i < $Size; $i++)
        $Length = ($Length << 8) | ord ($Data [$Offset++]);
      
      // Try to read the string
      if ($avLength < $Size + $Length)
        return false;
      
      $Value = substr ($Data, $Offset, $Length);
      $Offset += $Length;
      
      return $Value;
    }
    // }}}
    
    // {{{ writeCompactString
    /**
     * Generate a compact string
     * 
     * @param string $Data
     + @param int $Size
     * 
     * @access protected
     * @return string
     **/
    protected static function writeCompactString ($Data, $Size) {
      $Length = strlen ($Data);
      $Prefix = '';
      
      for ($i = 0; $i < $Size; $i++) {
        $Prefix = chr ($Length & 0xFF) . $Prefix;
        $Length >>= 8;
      }
      
      return $Prefix . $Data;
    }
    // }}}
    
    // {{{ __debugInfo
    /**
     * Prepare output for var_dump()
     * 
     * @access friendly
     * @return array
     **/
    abstract function __debugInfo ();
    // }}}
    
    // {{{ getType
    /**
     * Retrive the type of this message
     * 
     * @access public
     * @return int
     **/
    public function getType () {
      return $this::HANDSHAKE_TYPE;
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
    abstract public function parse ($Data, &$Offset = 0);
    // }}}
    
    // {{{ toBinary
    /**
     * Convert this message to binary format
     * 
     * @access public
     * @return string
     **/
    abstract public function toBinary ();
    // }}}
  }

?>