<?PHP

  require_once ('TLS/Handshake/Message.php');
  
  class TLS_Handshake_ServerHelloDone extends TLS_Handshake_Message {
    /* Type of this message */
    const HANDSHAKE_TYPE = 0x0E;
    
    // {{{ __debugInfo
    /**
     * Prepare output for var_dump()
     * 
     * @access friendly
     * @return array
     **/
    function __debugInfo () {
      return array ();
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
      return '';
    }
    // }}}
  }

?>