#include "seal/seal.h"
#include "seal/ciphertext.h"
#include "enc_pattern.h"
#include <sstream>
#include <iostream>
#include <iomanip>
#include <bitset>

using namespace seal;


class Detector
{
public:
  Detector(int *  fragmentation_size, size_t poly_modulus_degree);
  Ciphertext * detect(Ciphertext * fragments, EncryptedPattern * enc_pattern, int * nb_fragments, Encryptor * encryptor, Evaluator * evaluator);
private:
  int frag_size = 0;
  size_t poly_modulus_degree;
};
