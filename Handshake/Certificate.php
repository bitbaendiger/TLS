<?PHP

  require_once ('TLS/Handshake/Message.php');
  
  class TLS_Handshake_Certificate extends TLS_Handshake_Message {
    /* Type of this message */
    const HANDSHAKE_TYPE = 0x0B;
    
    /* List of X.509-Ceritficates in DER-Format */
    private $Certificates = array ();
    
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
    
    // {{{ addCertificate
    /**
     * Append a certificate to this message
     * 
     * @param string $Certificate
     * 
     * @access public
     * @return void
     **/
    public function addCertificate ($Certificate) {
      $this->Certificates [] = $Certificate;
    }
    // }}}
    
    // {{{ setCertificates
    /**
     * Set certificates for this message
     * 
     * @param array $Certificates
     * 
     * @access public
     * @return void
     **/
    public function setCertificates (array $Certificates) {
      $this->Certificates = $Certificates;
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
      // Read all certificates from input
      if (($Input = $this::readCompactString ($Data, $Offset, 3)) === false) {
        trigger_error ('Failed to read certificates');
        
        return false;
      }
      
      // Extract certificates
      $cLength = strlen ($Input);
      $cOffset = 0;
      $Certificates = array ();
      
      while ($cOffset < $cLength) {
        if (($Certificate = $this::readCompactStirng ($Input, $cOffset, 3, $cLength)) === false) {
          trigger_error ('Failed to read certificate');
          
          return false;
        }
        
        $Certificates [] = $Certificate;
      }
      
      // Apply the changes
      $this->Certificates = $Certificates;
      
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
      $Certificates = '';
      
      foreach ($this->Certificates as $Certificate)
        $Certificates .= $this::writeCompactString ($Certificate, 3);
      
      return $this::writeCompactString ($Certificates, 3);
    }
    // }}}
  }

?>