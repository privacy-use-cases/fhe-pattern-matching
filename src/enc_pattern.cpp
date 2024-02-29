#include "enc_pattern.h"
#include "util.h"



EncryptedPattern::EncryptedPattern(string pattern_binary, Encryptor * encryptor, int poly_modulus_degree){
  pattern_length = pattern_binary.length();
  Plaintext pattern_plain(pack_pattern(poly_modulus_degree, pattern_binary));
  //cout << pattern_plain.to_string() << endl;
  encryptor->encrypt(pattern_plain, encrypted_pattern);
}

Ciphertext * EncryptedPattern::get_pattern_ciphertext(){
  return &encrypted_pattern;
}

int EncryptedPattern::get_pattern_length(){
  return pattern_length;
}
