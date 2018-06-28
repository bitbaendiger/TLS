<?PHP

  class TLS_Handshake {
    /* Registry of handshake-messages */
    private static $Messages = array (
      0x00 => 'TLS_Handshake_HelloRequest',
      0x01 => 'TLS_Handshake_ClientHello',
      0x02 => 'TLS_Handshake_ServerHello',
      0x0B => 'TLS_Handshake_Certificate',
      0x0C => 'TLS_Handshake_ServerKeyExchange', // TODO
      0x0D => 'TLS_Handshake_CertificateRequest', // TODO
      0x0E => 'TLS_Handshake_ServerHelloDone',
      0x0F => 'TLS_Handshake_CertificateVerify', // TODO
      0x10 => 'TLS_Handshake_ClientKeyExchange',
      0x14 => 'TLS_Handshake_Finished', // TODO
      # 0xFF => 'TLS_Handshake_Message',
    );
    
    /* TLS-Context */
    private $Context = null;
    
    /* The actual handshake-message */
    private $Message = null;
    
    // {{{ __construct
    /**
     * Create a new TLS-Handshake-Parser
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
    
    // {{{ getMessage
    /**
     * Retrive the message of this handshake
     * 
     * @access public
     * @return TLS_Handshake_Message
     **/
    public function getMessage () {
      return $this->Message;
    }
    // }}}
    
    // {{{ setMessage
    /**
     * Assign a message to this handshake
     * 
     * @param TLS_Handshake_Message $Message
     * 
     * @access public
     * @return void
     **/
    public function setMessage (TLS_Handshake_Message $Message) {
      $this->Message = $Message;
    }
    // }}}
    
    // {{{ parse
    /**
     * Try to parse a handshake-record into this instance
     * 
     * @param string $Data
     * @param int $Offset (optional)
     * @param int $avLength (optional)
     * 
     * @access public
     * @return bool
     **/
    public function parse ($Data, &$Offset = 0, $avLength = null) {
      // Get the length of the pending message
      if ($avLength === null)
        $avLength = strlen ($Data);
      
      if ($Offset + 4 > $avLength)
        return null;
      
      $Length = (ord ($Data [$Offset + 1]) << 16) | (ord ($Data [$Offset + 2]) << 8) | ord ($Data [$Offset + 3]);
      
      // Check if there is enough data on the buffer
      if ($Offset + $Length + 4 > $avLength)
        return null;
      
      // Get type of the message
      $Type = ord ($Data [$Offset]);
      
      if (!isset ($this::$Messages [$Type])) {
        trigger_error ('Unknown message-type ' . $Type);
        
        return false;
      }
      
      // Process the message
      if (!is_object ($Message = call_user_func (array ($this::$Messages [$Type], 'fromBinary'), $this->Context, substr ($Data, $Offset + 4, $Length)))) {
        trigger_error ('Failed to parse message');
        
        return false;
      }
      
      $this->Message = $Message;
      
      // Move the pointer
      $Offset += $Length + 4;
      
      return true;
    }
    // }}}
    
    // {{{ toBinary
    /**
     * Create a binary representation of this handshake
     * 
     * @access public
     * @return string
     **/
    public function toBinary () {
      if ($this->Message) {
        $Type = $this->Message->getType ();
        $Message = $this->Message->toBinary ();
      } else {
        $Type = 0;
        $Message = '';
      }
      
      $Length = strlen ($Message);
      
      return pack ('CCn', $Type, ($Length >> 16) & 0xFF, $Length & 0xFFFF) . $Message;
    }
    // }}}
  }
  
  // Preload handshake-messages
  require_once ('TLS/Handshake/HelloRequest.php');
  require_once ('TLS/Handshake/ClientHello.php');
  require_once ('TLS/Handshake/ServerHello.php');
  require_once ('TLS/Handshake/Certificate.php');
  require_once ('TLS/Handshake/ServerHelloDone.php');
  require_once ('TLS/Handshake/ClientKeyExchange.php');
  require_once ('TLS/Handshake/Finished.php');

?>