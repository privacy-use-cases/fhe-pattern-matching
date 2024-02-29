#include "detection.h"
#include "util.h"

using namespace std;

Detector::Detector(int * fragment_size, size_t poly_modulus_degree_){
  frag_size = *fragment_size;
  poly_modulus_degree = poly_modulus_degree_;
}

Ciphertext * Detector::detect(Ciphertext * fragments, EncryptedPattern * enc_pattern, int * nb_fragments, Encryptor * encryptor, Evaluator * evaluator){
  //cout << "frag_size:" << frag_size << endl;
  Ciphertext * ciphertexts;
  ciphertexts = new Ciphertext[(*nb_fragments)-1];

  Plaintext two("2");
  Plaintext one("1");


  Plaintext C_l(poly_modulus_degree);
	//Fill in the polynomial
  *C_l.data( 0 ) = poly_modulus_degree-1;
	for (int i=1 ; i < enc_pattern->get_pattern_length()+1 ; i++){
		*C_l.data( poly_modulus_degree-i ) = 1;
	}

  //cout << "Cl:" << C_l.to_string() << endl;

  Plaintext C_k(frag_size*2);
	 //Fill in the polynomial
	*C_k.data( 0 ) = 1;
	for (int i=0 ; i < frag_size*2 ; i++){
		*C_k.data( i ) = 1;
	}

  //cout << "Ck:" << C_k.to_string() << endl;


  Plaintext padding(sstr("1x^",frag_size));

  for(int i = 0; i < (*nb_fragments) - 1; i++){

    auto start = std::chrono::high_resolution_clock::now();
    Ciphertext ctxt_P1;
    Ciphertext ctxt_P1fois2;
    Ciphertext ctxt_homo_mult;


    Ciphertext pattern_ciphertext(*(enc_pattern->get_pattern_ciphertext()));
    
    

    // Compute the ciphertext of the two successive fragments.
    evaluator->multiply_plain(fragments[i+1], padding, ctxt_P1);
    evaluator->add(ctxt_P1, fragments[i], ctxt_P1);
    


    evaluator->multiply_plain(ctxt_P1, two, ctxt_P1fois2);
    evaluator->multiply(ctxt_P1fois2, pattern_ciphertext, ctxt_homo_mult);
    evaluator->multiply_plain(ctxt_P1, C_l, ctxt_P1);
    evaluator->multiply_plain(pattern_ciphertext, C_k, pattern_ciphertext);
    evaluator->sub(ctxt_homo_mult,ctxt_P1,ciphertexts[i]);
    evaluator->sub(ciphertexts[i],pattern_ciphertext,ciphertexts[i]);
    
    
  }
  return ciphertexts;
}
