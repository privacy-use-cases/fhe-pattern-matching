#include "seal/seal.h"
#include "seal/ciphertext.h"
#include <sstream>
#include <iostream>
#include <iomanip>
#include <bitset>

using namespace seal;
using namespace std;

class EncryptedPattern
{
public:
  EncryptedPattern(string pattern, Encryptor * encryptor, int poly_modulus_degree);
  Ciphertext * get_pattern_ciphertext();
  int get_pattern_length();
private:
  int pattern_length = 0;
  Ciphertext encrypted_pattern;
};
