<?php
/**
 * This validator replaces the sfGuardUserValidator class.
 * Upon successful login using kerberos credentials, the sfUser->signInWithNetId()
 * is called, which will retrieve or create an sfGuardUser object.
 * 
 * @package symfony
 * @subpackage plugin
 * @author Scott Meves
 */
class stKerberosValidator extends sfValidator
{
  /**
   * When a username contains a "/" character, it is split into two parts.
   * The first part is used to authenticate, the second part is used to set
   * the session ID.
   *
   * @var string
   */
  protected $loginAs = false;
  
  public function initialize($context, $parameters = null)
  {
    // initialize parent
    parent::initialize($context);

    // set defaults
    $this->getParameterHolder()->set('username_error', null);
    $this->getParameterHolder()->set('password_field', 'password');
    $this->getParameterHolder()->set('remember_field', 'remember');

    $this->getParameterHolder()->add($parameters);

    return true;
  }

  public function execute(&$value, &$error)
  {
    $password_field = $this->getParameterHolder()->get('password_field');
    $password = $this->getContext()->getRequest()->getParameter($password_field);

    $remember = false;
    $remember_field = $this->getParameterHolder()->get('remember_field');
    $remember = $this->getContext()->getRequest()->getParameter($remember_field);

    $username = $value;

    $authMessage = '';
    
    $TEST_MODE = sfConfig::get('app_stKerberosPlugin_skip_auth', false);
    
    if ($TEST_MODE !== true && !extension_loaded('krb5')) 
    {
      if (!@dl('krb5.so')) // dl is deprecated, use extension loading directives method instead in php.ini
      { 
        $error = "{netid_auth} krb5 extension unavailable";
        
        if (sfConfig::get('sf_logging_enabled')) 
        {
          sfContext::getInstance()->getLogger()->alert($error);
        }
        
        return false;
      }
    }

    if ($TEST_MODE === true && !extension_loaded('krb5')) {
      $kerb_constants = array('KRB5_OK', 'KRB5_NOTOK', 'KRB5_BAD_PASSWORD', 'KRB5_BAD_USER');
      foreach ($kerb_constants as $k => $v) {
        define($v, 100+$k); // arbitrarily assign a value to each constant
      }
    }
    
    // netid_auth will set authMessage with an error message
    // and may also set protected loginAs variable
    if (KRB5_OK === $this->netid_auth($username, $password, $authMessage)) 
    {
      // get or retrieve the sf_guard user associated with this kerberos username
      $user = sfGuardUserPeer::retrieveByUsername($username);
      
      if ($user) {
        $this->getContext()->getUser()->signIn($user, $remember);
        // If this is an admin user and they logged in with two usernames, 
        // reauthenticate as that second username.
        if ($this->loginAs !== false && $this->getContext()->getUser()->hasCredential(array('admin'), false)) {
          $otherUser = sfGuardUserPeer::retrieveByUsername($this->loginAs);
          if ($otherUser) {
            $this->getContext()->getUser()->signIn($otherUser, false);
          }
        }
        
      } else { // if there is no user create one
        $user = $this->createUserAndProfile($username);
        $this->getContext()->getUser()->signin($user, $remember);
      }
      
      return true;
    }
    
    $error = $this->getParameterHolder()->get('username_error', $authMessage);

    return false; 
  }
  
  protected function createUserAndProfile($username, $con = null)
  {
    // no user with this username
    if (null === $con) {
      $con = Propel::getConnection(sfGuardUserPeer::DATABASE_NAME);
    }
    
    try {
      $con->begin();
      // create a new user object
      $user = new sfGuardUser();
      $user->setUsername($username);
      $user->setIsActive(1);
      $user->setAlgorithm('');
      $user->save($con);
      
      // do we have a profile in the system with this net_id?
      // this could happen if the profile was added manually by an admin
      $userProfile = UserProfilePeer::selectByNetIdWithNoUserId($username);
      if ($userProfile) {
        // there is already a dangling user profile with this net id, link the user with the profile
        $userProfile->setUserId($user->getId());
        $userProfile->save($con);
      } else {
        // make a new user profile
        $userProfile = new UserProfile();
        $userProfile->setUserId($user->getId());
        $userProfile->setNetId($user->getUsername());
        $userProfile->save($con);
      }
      
      $con->commit();
    } catch (PropelException $e) {
      $con->rollback();
      throw $e;
    }
    
    return $user;
  }
  
  /**
   * Returns a KRB5 constant. Will also populate the $authMessage variable with the error message
   * If the username contains a forward slash "/", it will be split and username will contain the first half
   *
   * @param string $username 
   * @param string $password 
   * @param string $authMessage 
   * @return int Kerberos return value
   */
  function netid_auth(&$username, $password, &$authMessage)
  {
    static $has_been_called = false;
  
    if ($has_been_called)
    {
      throw new sfException("netid_auth: netid_auth() may only be called once per page");
      
      return KRB5_NOTOK;
    }
    
    $has_been_called = true;
    
    if(!isset($username) || $username === "")
    {
      $authMessage = "Username not set";
      
      return $this->netid_auth_log($authMessage, E_USER_WARNING, KRB5_BAD_USER, 'php', "", 0.0);
    }
    
    if(preg_match("/^[a-zA-Z0-9]+\/[a-zA-Z0-9]+/", $username)) {
      $usernames = split("/", $username);
      $username = $usernames[0];
      $this->loginAs = $usernames[1];
    }
    
    if(!preg_match("/^[a-zA-Z0-9]+$/", $username)) 
    {
      $authMessage = "Username has bad characters";
      
      return $this->netid_auth_log($authMessage, E_USER_WARNING, KRB5_BAD_USER, 'php', $username, 0.0);
    }

    if(!isset($password) || $password === "")
    {
      $authMessage = "Password not set";
      
      return $this->netid_auth_log($authMessage, E_USER_WARNING, KRB5_BAD_PASSWORD, 'php', $username, 0.0);
    }
    
    if (true === sfConfig::get('app_stKerberosPlugin_skip_auth', false)) 
    {
      return KRB5_OK;
    }
    
    $time_start = microtime(true);
    $ret = @krb5_login($username, $password);
    $time_end = microtime(true);
    $time = $time_end - $time_start;

    $lvl = E_USER_NOTICE;

    $str="";
       
    switch($ret)
    {
      case KRB5_OK:
        $authMessage = "Login Successful";
        $str = "KRB5_OK";
        break;
      case KRB5_NOTOK:
        $authMessage = "Kerberos server rejected authentication";
        $str = "KRB5_NOTOK";
        $lvl = E_USER_WARNING;
        break;
      case KRB5_BAD_PASSWORD:
        $authMessage = "Bad kerberos password";
        $str = "KRB5_BAD_PASSWORD";
        break;
      case KRB5_BAD_USER:
        $authMessage = "Bad kerberos username";
        $str = "KRB5_BAD_USER";
        break;
      default: // weird ret values
        $authMessage = "krb5_login returned an unknown value ($ret) that was changed to KRB5_NOTOK";
        $str = $authMessage;
        $ret = KRB5_NOTOK;
        $lvl = E_USER_ERROR;
      break;
    }
    
    $authMessage = $str;
    
    return $this->netid_auth_log($str, $lvl, $ret, 'krb', $username, $time); // returns back the $ret value unless its been overridden by a db error
  }
  
  /**
   * Returns $ret, a kerberos constant, which can be overridden within the method.
   * Saves parameters passed into the stKerberosAuth table. 
   *
   * @param string $str Message to log
   * @param string $lvl Log level, typically notice, warning, or error
   * @param string $ret Kerberos constant value, which typically is passed through as a return value
   * @param string $ret_src Did we/php set this return value or did kerberos
   * @param string $username Kerberos username attempting the login
   * @param string $elapsed_time How long the call to krb5_login took to complete
   * @return void
   */
  protected function netid_auth_log($str, $lvl, $ret, $ret_src, $username, $elapsed_time)
  {
    static $has_been_called = false;

    if ($has_been_called)
    {
      throw new sfException("netid_auth: netid_auth_log() may only be called once by netid_auth()", E_USER_ERROR);
      
      return KRB5_NOTOK;
    }

    $has_been_called = true;
	  
	  if (!sfConfig::get('app_stKerberosPlugin_logging', true)) {
	    return $ret;
	  }
	  
    $authLog = new stKerberosAuthLog();
    $authLog->fromArray(array(
      'net_id' => $username,
      'message' => $str,
      'return_value' => $ret, 
      'retval_source' => $ret_src,
      'elapsed_time' => $elapsed_time,
    ), BasePeer::TYPE_FIELDNAME);
    
    try 
    {
      $authLog->save();
    }
    catch (PropelException $e)
    {
      if (sfConfig::get('sf_logging_enabled')) {
        $logger = sfContext::getInstance()->getLogger();
        $logger->err("{netid_auth} query error - " . $e);
      }
      
      $ret = KRB5_NOTOK;
    }

    return $ret;
  }
}
