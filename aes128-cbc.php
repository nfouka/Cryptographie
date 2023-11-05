<?php 
error_reporting(E_ERROR | E_PARSE);
/**
 * abCrypt utilizes openssl to encrypt and decrypt textstrings
 *
 * This project started as a way to encrypt user information which is stored in the database.
 *
 * @package asbraCMS
 * @subpackage abCrypt
 * @author Nimpen J. Nordström <j@asbra.nu>
 * @copyright 2018 ASBRA AB
 */
/**
 * abCrypt is a class for encrypting and decrypting textstrings using openssl
 *
 * @param string $encryption_key The encryption in HEX
 */
class abCrypt
{
  /** @var string $key Hex encoded binary key for encryption and decryption */
  public $key = '';
  /** @var string $encrypt_method Method to use for encryption */
  public  $encrypt_method = 'AES-256-CBC';
  /**
   * Construct our object and set encryption key, if exists.
   * 
   *
   * @param string $encryption_key Users binary encryption key in HEX encoding
   */
  function __construct ( $encryption_key = false )
  {
    if ( $key = hex2bin ( $encryption_key ) )
    {
      $this->key = $key;
    }
    else
    {
      echo "Key in construct does not appear to be HEX-encoded...";
    }
  }
  public function encrypt ( $string )
  {
    $new_iv = bin2hex ( random_bytes ( openssl_cipher_iv_length ( $this->encrypt_method ) ) );
    if ( $encrypted = base64_encode ( openssl_encrypt ( $string, $this->encrypt_method, $this->key, 0, $new_iv ) ) )
    {
      return $new_iv.':'.$encrypted;
    }
    else
    {
      return false;
    }
  }
  public function decrypt ( $string )
  {
    $parts     = explode(':', $string );
    $iv        = $parts[0];
    $encrypted = $parts[1];
    if ( $decrypted = openssl_decrypt ( base64_decode ( $encrypted ), $this->encrypt_method, $this->key, 0, $iv ) )
    {
      return $decrypted;
    }
    else
    {
      return false;
    }
  }
}

/*
# Generate a key for encryption
$hex_key = bin2hex ( random_bytes ( 16 ) ); 
echo base64_encode($hex_key) ; exit();
# Initiate a new class object
$abCrypt = new abCrypt($hex_key);
# Perform encryption
$encrypted_txt = $abCrypt->encrypt('salut tout le monde');
# And decryption
echo $encrypted_txt."\n" ; 
echo $abCrypt->decrypt($encrypted_txt);
*/ 

/*

$plaintext = 'My secret message 1234';
$password = '3sc3RLrpd173sc3RL';
$method = 'aes-256-cbc';

// Must be exact 32 chars (256 bit)
$password = substr(hash('sha256', $password, false), 0, 32);
echo "Password:" . $password . "\n";


// IV must be exact 16 chars (128 bit)
$iv = chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0);

// av3DYGLkwBsErphcyYp+imUW4QKs19hUnFyyYcXwURU=
$encrypted = base64_encode(openssl_encrypt($plaintext, $method, $password, OPENSSL_RAW_DATA));
#$encrypted = "KwxZZLUpANg3Q4ZlGjdEiLPj8IzfoLTN2504196fOme1AU8ftAgGohghgb1YYVPtC4AoC2KzsFLqEUy/z0wl9xvgW2YGwXCGd8OaAFPG5onRLIyf0scfHcf0vcmjdXJW4qi4NyX5zjs=";

// My secret message 1234
$decrypted = openssl_decrypt(base64_decode($encrypted), $method, $password, OPENSSL_RAW_DATA);

echo 'plaintext=' . $plaintext . "\n";
echo 'cipher=' . $method . "\n";
echo 'encrypted to: ' . $encrypted . "\n";
echo 'decrypted to: ' . $decrypted . "\n\n";

*/ 

/*
$password = 'mZmA8Ay4yNJ93eUEEb5uLu8A19Dt7n' ; 


$text = "salut nadir mechant" ; 
$encrypted = base64_encode(openssl_encrypt($text, 'des', $password, OPENSSL_RAW_DATA));


$decrypted = openssl_decrypt(base64_decode($encrypted), 'des',  $password  , OPENSSL_RAW_DATA );
echo "\ndecypt  : ".$decrypted ; 
echo "\n" ; 
*/ 

$hex_key = bin2hex ( random_bytes ( 16 ) ) ;  

function encrypt_AES_CBC ($plaintext , $key , $SALT = 'GI__uTpqQcMf5tuz4xZY8CokCAk9M792' ) {
  $method = "aes-256-cbc";
  $bkey = hex2bin($key);
  $iv = hex2bin(md5(microtime().rand()));
  $data = openssl_encrypt($plaintext, $method, $bkey, OPENSSL_RAW_DATA , $iv );
  return base64_encode($iv.$SALT.$data);
}
// PHP Function to decrypt
function decrypt_AES_CBC ($encryptedText , $key , $SALT = 'GI__uTpqQcMf5tuz4xZY8CokCAk9M792' ) {
  $method = "aes-256-cbc";
  $bkey = hex2bin($key);
  $decoded = base64_decode($encryptedText);
  $iv = substr($decoded, 0, 16);
  $data = substr($decoded, 16 + strlen($SALT) );
  return base64_encode( openssl_decrypt( $data, $method, $bkey, OPENSSL_RAW_DATA , $iv )) ;
}

$plaintext = "The password_hash function generates encrypted password hashes using one-way hashing algorithms. Information about the algorithm, cost and salt used is contained as part of the returned hash." ; 
echo "\n" ; 
echo base64_decode(decrypt_AES_CBC(encrypt_AES_CBC( $plaintext ,$hex_key) , $hex_key ))  ; 
echo "\n" ; 
