<?PHP

  require_once ('TLS/Handshake/Message.php');
  
  class TLS_Handshake_Finished extends TLS_Handshake_Message {
    /* Type of this message */
    const HANDSHAKE_TYPE = 0x14;
    
    /* Data to verify the finished handshake */
    private $verifyData = '';
    
    // {{{ __debugInfo
    /**
     * Prepare output for var_dump()
     * 
     * @access friendly
     * @return array
     **/
    function __debugInfo () {
      return array (
        'verifyData' => bin2hex ($this->verifyData),
      );
    }
    // }}}
    
    // {{{ getVerifyData
    /**
     * Retrive data for verifycation
     * 
     * @access public
     * @return string
     **/
    public function getVerifyData () {
      return $this->verifyData;
    }
    // }}}
    
    // {{{ setVerifyData
    /**
     * Set data for verification
     * 
     * @param string $VerifyData
     * 
     * @access public
     * @return void
     **/
    public function setVerifyData ($VerifyData) {
      $this->verifyData = $VerifyData;
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
      # TODO: Data-Length may be defined by cipher-suite
      $this->verifyData = substr ($Data, $Offset, 12);
      
      return (strlen ($this->verifyData) == 12);
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
      return $this->verifyData;
    }
    // }}}
  }

?>