<?php

/**
 * Class to generate a status report of an Web Application.
 */
class Archimedes {

  public $fields = array();
  public $type;
  public $author;
  public $id;

  public function __construct($type, $author, $id) {
    $this->type = $type;
    $this->author = $author;
    $this->id = $id;
  }

  public function toXML() {
    $this->validate();

    $dom = new DOMDocument('1.0', 'UTF-8');
    $dom->formatOutput = TRUE;
    $node = new DOMElement('node',null,'monitor:node');
    $dom->appendChild($node);
    $node->setAttribute('type',$this->type);
    $node->setAttribute('id',$this->id);
    $node->setAttribute('datetime',date('c'));
    $node->setAttribute('author','mailto:' . $this->author);

    foreach($this->fields as $field) {
      $field->compile($node);
    }
    return $dom->saveXML();
  }

  /**
   * Validate the structure of the report.
   */
  protected function validate() {
    if (!isset($this->id)) {
      throw new ArchimedesClientException("No ID set.");
    }
    if (!isset($this->type)) {
      throw new ArchimedesClientException("No type defined.");
    }
    if (!isset($this->author)) {
      throw new ArchimedesClientException("No author given.");
    }
    if (!isset($this->fields['title'])) {
      throw new ArchimedesClientException("No title present.");
    }
    return TRUE;
  }

  public function encrypt($key) {
    $data = $this->toXML();
    $pubkey = openssl_pkey_get_public($key);
    openssl_seal($data,$sealed,$ekeys,array($pubkey));
    openssl_free_key($pubkey);
    $this->encrypted = $sealed;
    $this->ekey = $ekeys[0];
    return $this;
  }

  /**
   * Encrypt the data.
   */
  protected function getEncrypted() {
    if (!$this->encrypted) {
      throw new Exception("Can not retrive encrypted data. Data has not yet been encrypted.");
    }
    return $this->encrypted;
  }

  public function __toString() {
    return base64_encode($this->getEncrypted());
  }

  /**
   * Post the data directly to the Archimedes Server.
   */
  public function postXML($server_url) {
    // Parse the URL and make sure we can handle the schema.
    $uri = parse_url($server_url);

    if ($uri == FALSE) {
      throw new Exception('Unable to parse URL.');
    }

    if (!isset($uri['scheme'])) {
      throw new Exception('Missing URL schema for: ['. $uri . ']' );
    }

    switch ($uri['scheme']) {
      case 'http':
        $port = isset($uri['port']) ? $uri['port'] : 80;
        $host = $uri['host'] . ($port != 80 ? ':'. $port : '');
        $fp = @fsockopen($uri['host'], $port, $errno, $errstr, 15);
        break;
      case 'https':
        // Note: Only works for PHP 4.3 compiled with OpenSSL.
        $port = isset($uri['port']) ? $uri['port'] : 443;
        $host = $uri['host'] . ($port != 443 ? ':'. $port : '');
        $fp = @fsockopen('ssl://'. $uri['host'], $port, $errno, $errstr, 20);
        break;
      default:
        throw new Exception('Invalid schema '. $uri['scheme'] . '.');
    }

    // Make sure the socket opened properly.
    if (!$fp) {
      throw new Exception(trim($errstr));
    }

    // Construct the path to act on.
    $path = isset($uri['path']) ? $uri['path'] : '/';
    if (isset($uri['query'])) {
      $path .= '?'. $uri['query'];
    }

    $content['data'] = (string) $this;
    $content['key'] = base64_encode($this->ekey);
    $content = json_encode($content);

    // Create HTTP request.
    $defaults = array(
      // RFC 2616: "non-standard ports MUST, default ports MAY be included".
      // We don't add the port to prevent from breaking rewrite rules checking the
      // host that do not take into account the port number.
      'Host' => "Host: $host",
      'User-Agent' => 'User-Agent: (Archimedes Client)',
    );

    $defaults['Content-Length'] = 'Content-Length: '. strlen($content);

    // If the server url has a user then attempt to use basic authentication
    if (isset($uri['user'])) {
      $defaults['Authorization'] = 'Authorization: Basic '. base64_encode($uri['user'] . (!empty($uri['pass']) ? ":". $uri['pass'] : ''));
    }

    $request = 'POST '. $path ." HTTP/1.0\r\n";
    $request .= implode("\r\n", $defaults);
    $request .= "\r\n\r\n";
    $request .= $content;
    fwrite($fp, $request);

    // Fetch response.
    $response = '';
    while (!feof($fp) && $chunk = fread($fp, 1024)) {
      $response .= $chunk;
    }
    fclose($fp);

    // Parse response.
    list($split, $result) = explode("\r\n\r\n", $response, 2);
    $split = preg_split("/\r\n|\n|\r/", $split);

    list($protocol, $code, $text) = explode(' ', trim(array_shift($split)), 3);

    // Parse headers.
    while ($line = trim(array_shift($split))) {
      list($header, $value) = explode(':', $line, 2);
      $headers[$header] = trim($value);
    }

    $code = floor($code / 100) * 100;

    switch ($code) {
      case 200: // OK
      case 304: // Not modified
      case 301: // Moved permanently
      case 302: // Moved temporarily
      case 307: // Moved temporarily
        break;
      default:
        return FALSE;
    }
    $status = json_decode($result);
    return $status->success;
  }

  /**
   * Send the XML report via email.
   */
  public function sendXML($email) {
    $attachment = chunk_split((string) $this);
    $site_name = (string) $this->getField('title');

    $boundary = '-----=' . md5(uniqid(rand()));
    $headers = 'From: ' . $site_name . ' <' . $this->author . '>' . "\r\n";
    $headers .= 'Content-Type: multipart/mixed; boundary="' . $boundary . '"' . "\r\n";
    $headers .= 'Mime-Version: 1.0' . "\r\n";
    $message = '--' . $boundary . "\r\n";
    $message .= "Content-Type: text/plain\r\n";
    $message .= "Content-Transfer-Encoding: 7bit\r\n\r\n";
    $message .= "Archimedes XML update attached.\r\n";
    $message .= '--' . $boundary . "\r\n";
    $message .= "Content-Type: text/plain\r\n";
    $message .= "Content-Transfer-Encoding: base64\r\n\r\n";
    $message .= chunk_split(base64_encode("EKEY: " . $this->ekey));
    $message .= '--' . $boundary . "\r\n";

    $message .= 'Content-Type: application/xml; name="data.xml"' . "\r\n";
    $message .= 'Content-Transfer-Encoding: base64' . "\r\n";
    $message .= 'Content-Disposition: attachment; filename="data.xml"' . "\r\n\r\n";
    $message .= $attachment . "\r\n";
    $message .= '--' . $boundary . "\r\n";

    return mail($email, 'XML Update from' . ' ' . $site_name, $message, $headers);
  }

  /**
   * Add a new field to the report.
   */
  public function createField($fieldID, $values = array()) {
    // Ensure the value is an array.
    // Strings will be type casted to arrays.
    $values = (array) $values;
    $field = new ArchimedesField($fieldID);
    $this->addField($fieldID,$field);
    foreach ($values as $value) {
      $field->addValue($value);
    }
    return $field;
  }

  protected function addField($fieldID,$field) {
    $this->fields[$fieldID] = $field;
  }

  public function getField($fieldID) {
    return $this->fields[$fieldID];
  }

}

Class ArchimedesField {

  public $fieldID;
  protected $facet = FALSE;
  protected $type = '';
  protected $values = array();
  protected $namespace = '';

  public function __construct($fieldID) {
    $this->fieldID = $fieldID;
  }

  public function addValue($value) {
    if (!is_object($value)) {

      $value = new ANSValue($value);
    }
    $this->values[] = $value;
    return $this;
  }

  public function getValues() {
    return $this->values;
  }

  public function invokeFacet() {
    $this->facet = TRUE;
    return $this;
  }

  public function revokeFacet() {
    $this->facet = FALSE;
    return $this;
  }

  /**
   * Compile the field into a DOMElement.
   */
  function compile($node) {
    $field = new DOMElement('field');
    $node->appendChild($field);
    $field->setAttribute('id',$this->fieldID);
    foreach($this->values as $value) {
      $value->compile($field);
      if ($this->facet) {
        $value->nodeValue = '';
        $value->appendChild(new DOMElement('facet', htmlspecialchars((string) $value)));
      }
    }
    return $field;
  }

  public function __toString() {
    $list = array();
    foreach($this->values as $value) {
      $list[] = (string) $value;
    }
    return implode(', ',$list);
  }
  public function toArray() {
    $list = array();
    foreach($this->values as $value) {
      $list[] = $value->toArray();
    }
    return $list;
  }
}

Class ANSValue extends DOMElement {


  // Namespace attributes.
  protected $ns_attr = array();
  protected $ns = null;

  // Normal attributes.
  protected $attr = array();

  protected $value = '';

  public $facet = FALSE;

  public function __construct($val) {
    parent::__construct('value', htmlspecialchars($val));
    $this->value = $val;
  }

  public function setAttribute($name, $value) {
    $this->attr[$name] = $value;
    return $this;
  }

  public function setAttributeNS($ns, $name, $value) {
    if (strpos($name, ':') === FALSE) {
      return $this->setAttribute($name, $value);
    }
    $this->ns_attr[$name] = $value;
    return $this;
  }

  public function getAttribute($name) {
    return $this->attr[$name];
  }

  public function getAttributeNS($name, $local_name) {
    return $this->ns_attr[$name];
  }

  /**
   * Append a DOMElement to a parent node.
   */
  public function compile($field) {
    $field->appendChild($this);
    foreach ($this->attr as $key => $value) {
      parent::setAttribute($key, $value);
    }
    foreach ($this->ns_attr as $key => $value) {
      parent::setAttributeNS($this->ns, $key, $value);
    }
    return $this;
  }

  public function __toString() {
    return (string) $this->value;
  }
}

Class Archimedes_nodereference extends ANSValue {

  public function __construct($value) {
    if (!isset($this->ns))
      $this->ns = 'monitor-plugin:node';
    parent::__construct($value);
    $this->setAttributeNS($this->ns, 'node:title', $value);
  }
  public function addNode(Array $node) {
    $required_keys = array('title','type');
    $keys_diff = array_diff($required_keys, array_keys($node));
    if (!empty($keys_diff)) {
      throw new ArchimedesClientException("Missing required attributes for node reference: " . implode(', ', $keys_diff));
    }
    foreach ($node as $key => $value) {
      $this->setAttributeNS($this->ns, 'node:' . $key, $value);
    }
    return $this;
  }
}

Class Archimedes_userreference extends ANSValue {
  public function __construct($value) {
    $this->ns = 'monitor-plugin:user';
    parent::__construct($value);
  }
  public function addUser(Array $user) {
    $required_keys = array('type');
    $keys_diff = array_diff($required_keys, array_keys($user));
    if (!empty($keys_diff)) {
      throw new ArchimedesClientException("Missing required attributes for user reference: " . implode(', ', $keys_diff));
    }
    foreach ($required_keys as $key) {
      $this->setAttributeNS($this->ns, 'user:' . $key, $user[$key]);
    }
    return $this;
  }
}

Class Archimedes_drupalmod extends Archimedes_nodereference {

  public function __construct($value) {
    $this->ns = 'monitor-plugin:drupal-module';
    parent::__construct($value);
  }
  public function toArray() {
    return array('name' => (string) $this->value, 'version' => $this->getAttributeNS('node:field_mod_version'), 'desc' => $this->getAttributeNS('node:body'));
  }
}

Class Archimedes_moodlemod extends Archimedes_nodereference {

  public function __construct($value) {
    $this->ns = 'monitor-plugin:moodle-module';
    parent::__construct($value);
  }
  public function toArray() {
    return array('name' => (string) $this->value, 'version' => $this->getAttributeNS('node:field_mod_version','node:version'), 'instances' => $this->getAttributeNS('node:instances'));
  }
}

Class Archimedes_gitrepo extends ANSValue {
  public function __construct($value) {
    $this->ns = 'monitor-plugin:git';
    parent::__construct($value);
  }
  public function setRemoteName($name) {
    $this->setAttributeNS($this->ns,'git:remote', $name);
    return $this;
  }
  public function toArray() {
    return array('remote' => $this->getAttributeNS('git:remote'),'uri' => (string) $this->value);
  }
}

Class Archimedes_dataset extends ANSValue {
  public function __construct($value) {
    $this->ns = 'monitor-plugin:dataset';
    parent::__construct($value);
  }
  public function setTitle($title) {
    $this->setAttributeNS($this->ns, 'dataset:title', $title);
    return $this;
  }
  public function toArray() {
    return array('title' => $this->getAttributeNS('dataset:title'),'value' => (string) $this->value);
  }
}

/**
 * Archimedes Exception Class.
 */
class ArchimedesClientException extends Exception {
}

/**
 * Wrapper function for creating a new value.
 */
function archimedes_value($value, $type = '') {
  if (empty($type)) {
    return new ANSValue($value);
  }
  $class = 'Archimedes_' . $type;
  if (!class_exists($class)) {
    throw new ArchimedesClientException("No such plugin available for $type");
  }
  return new $class($value);
}

class ArchimedesRemoteRequest {

  protected $hash;

  protected $key;

  protected $token;

  /**
   * @param field_unique_hash
   * @param public key.
   */
  public function getToken($hash, $key) {
    $this->hash = $hash;
    $this->key = $key;
    foreach (array('h', 't', 'i') as $k) {
      if (!isset($_GET[$k])) {
        return FALSE;
      }
    }
    // $_GET['i'] is the unique identifier for this site md5 hashed with the time.
    // If it doesn't match then its likely this request is forged. If the requester
    // does know the unique hash of this site then we will trust this request is
    // not a spammer.
    if ($_GET['i'] != md5($_GET['t'] . $hash)) {
      return FALSE;
    }

    // Add a random number prefix incase the time here is the same as the time passed
    // in the original request (cause then the hashes would be the same).
    return $this->token = md5(mt_rand(1000, 10000) . time());
  }

  public function validateRemoteUser($redirect = FALSE) {
    if (empty($this->token)) {
      return FALSE;
    }
    if (!$redirect) {
      $redirect = 'http://' . $_SERVER['SERVER_NAME'] . $_SERVER['REDIRECT_URL'];
    }
    $query = array(
      'token' => $this->token,
      'redirect' => $redirect,
      'hash' => $this->hash,
    );

    $pubkey = openssl_pkey_get_public($this->key);
    openssl_seal(serialize($query),$sealed,$ekeys,array($pubkey));
    openssl_free_key($pubkey);

    $url = 'http://' . $_GET['h'] . '/archimedes-server/verify-user?ekey=' . rawurlencode($ekeys[0]) . '&data=' . rawurlencode($sealed);

    header("Location: $url");
    die;
  }

  public function validateToken($local_token) {
    return $local_token == $_GET['token'];
  }

}

function archimedes_directory_hash($dir, $ignore) {
  // Symlink count is important. While we don't want to follow
  // symlinks, we need to know they are there incase they are
  // introduced or removed.
  $symlinks = array();
  if (!is_dir($dir)) {
    return false;
  }

  $filemd5s = array();
  $d = dir($dir);

  while (($entry = $d->read()) !== false)  {
    if (in_array($entry, array('.', '..'))) {
      continue;
    }
    $path = realpath($dir . '/' . $entry);
    // If the begining of the path does not match exactly then
    // this directory does not lead deeper but to somewhere else which
    // may create a recursive loop.
    if (strpos($path, $dir) !== 0) {
      $symlinks[] = $path;
      continue;
    }
    // Symlinks may introduce recursive loops.
    if (is_link($path)) {
      $symlinks[] = $path;
      continue;
    }
    $ignore_entry = FALSE;
    foreach($ignore as $pattern)  {
      if(preg_match($pattern, $path)) {
        $ignore_entry = TRUE;
        break;
      }
    }
    if ($ignore_entry) {
      continue;
    }
    if (is_dir($path))  {
      $filemd5s[] = archimedes_directory_hash($path, $ignore);
    }
    elseif (is_file($path)) {
      $filemd5s[] = md5_file($path);
    }
  }

  $d->close();
  //sort the md5s before concat so ensure order of files doesn't affect it.
  asort($filemd5s);
  return md5(implode('', $filemd5s) . implode('', $symlinks));
}
