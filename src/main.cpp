
#include "seal/seal.h"
#include "seal/util/galois.h"
#include "util.h"
#include "detection.h"
#include <iostream>

int main(){


  std::list<size_t> poly_modulus_degrees = {2048, 4096, 8192, 16384, 32768};
  std::list<int> fragment_sizes = {1024, 2048, 4096, 8192, 16384};

  for (int i = 0; i < poly_modulus_degrees.size(); i++){
    
    int poly_modulus = *std::next(poly_modulus_degrees.begin(), i); // Access element i from list1
    int fragment_size = *std::next(fragment_sizes.begin(), i);


    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus));

    // We set the t to be the size of the fragment size since the hamming distance cannot be greater than the fragment size
    parms.set_plain_modulus(fragment_size);

    SEALContext context(parms);
    cout << "#############################" << endl;
    print_parameters(context);
    

    SecretKey secret_key;
    PublicKey  public_key;

    KeyGenerator keygen(context);
    secret_key = keygen.secret_key();
    keygen.create_public_key(public_key);

    Evaluator evaluator(context);
    Encryptor encryptor(context ,public_key);
    Decryptor decryptor(context, secret_key);

    // generate a random bit string to be analyzed
    string random_bit_string = generateRandomBitString(32768);
    string pattern = generateSubsetOrRandom(100, random_bit_string);
    // create a pattern to be searched, 

    EncryptedPattern enc_pattern(pattern, &encryptor, poly_modulus);

    Plaintext * frags;
    int nb_fragments;
    frags = fragment(&random_bit_string, frags, &nb_fragments, fragment_size);

    auto min = std::numeric_limits<int>::max();
    auto max = std::numeric_limits<int>::min();
    auto sum = 0.0;

    Ciphertext * ciphertexts;

    for (int j = 0; j < 100; j++){
      auto start = std::chrono::high_resolution_clock::now();

      //Ciphertext * ciphertexts;
      ciphertexts = new Ciphertext[nb_fragments];
      for(int i = 0; i < nb_fragments; i++){
        //cout << i << endl;
        encryptor.encrypt(frags[i], ciphertexts[i]);
        //cout << frags[i].to_string() << endl;
      }
      auto elapsed = std::chrono::high_resolution_clock::now() - start;
      long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();

      sum = sum + microseconds;
      if (microseconds > max)
        max = microseconds;
      if (microseconds < min)
        min = microseconds;
    }

    cout << "max_encrypt_time_all_data: " << max << endl;
    cout << "max_encrypt_time_per_fragment: " << max / nb_fragments << endl;
    cout << "min_encrypt_time_all_data: " << min << endl;
    cout << "min_encrypt_time_per_fragment: " << min / nb_fragments << endl;
    cout << "average_encrypt_time_all_data: " << sum / 100 << endl;
    cout << "average_encrypt_time_per_fragment: " << (sum / 100) / nb_fragments << endl;

    cout << "####" << endl;

    min = std::numeric_limits<int>::max();
    max = std::numeric_limits<int>::min();
    sum = 0.0;

    Ciphertext * detect_res;

    for (int j = 0; j < 100; j++){
      auto start = std::chrono::high_resolution_clock::now();

      Detector detector(&fragment_size, poly_modulus);
      detect_res = detector.detect(ciphertexts, &enc_pattern, &nb_fragments, &encryptor, &evaluator);

      auto elapsed = std::chrono::high_resolution_clock::now() - start;
      long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
      sum = sum + microseconds;
      if (microseconds > max)
        max = microseconds;
      if (microseconds < min)
        min = microseconds;
    }

    cout << "max_match_time_all_data: " << max << endl;
    cout << "max_match_time_per_fragment: " << max / nb_fragments << endl;
    cout << "min_match_time_all_data: " << min << endl;
    cout << "min_match_time_per_fragment: " << min / nb_fragments << endl;
    cout << "average_match_time_all_data: " << sum / 100 << endl;
    cout << "average_match_time_per_fragment: " << (sum / 100) / nb_fragments << endl;

    cout << "####" << endl;

    min = std::numeric_limits<int>::max();
    max = std::numeric_limits<int>::min();
    sum = 0.0;

    for (int j = 0; j < 100; j++){
      auto start = std::chrono::high_resolution_clock::now();

      for(int k = 0; k < nb_fragments - 1; k++){
        Plaintext dec;
        Ciphertext temp;
        //cout << k << endl;
        //evaluator.multiply_plain(detect_res[i], xk, temp);
        decryptor.decrypt(detect_res[k], dec);
      }

      auto elapsed = std::chrono::high_resolution_clock::now() - start;
      long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
      sum = sum + microseconds;
      if (microseconds > max)
        max = microseconds;
      if (microseconds < min)
        min = microseconds;
    }

    cout << "max_decrypt_time_all_data: " << max << endl;
    cout << "max_decrypt_time_per_fragment: " << max / nb_fragments << endl;
    cout << "min_decrypt_time_all_data: " << min << endl;
    cout << "min_decrypt_time_per_fragment: " << min / nb_fragments << endl;
    cout << "average_decrypt_time_all_data: " << sum / 100 << endl;
    cout << "average_decrypt_time_per_fragment: " << (sum / 100) / nb_fragments << endl;

  }


  /*
  string plaintext = "In the vast expanse of the cosmos, where stars twinkle like scattered jewels in the velvet embrace of space, there exists a realm of infinite possibilities. It is a place where the fabric of reality bends and twists, giving rise to galaxies, nebulae, and celestial wonders beyond comprehension. Within this cosmic tapestry, civilizations rise and fall like waves upon the shore of eternity, each leaving their mark upon the sands of time. Across the endless reaches of the universe, sentient beings ponder the mysteries of existence, seeking answers to questions that have haunted the minds of philosophers and sages since the dawn of consciousness. From the blazing infernos of distant suns to the icy depths of interstellar voids, life flourishes in its myriad forms, adapting and evolving in the face of ever-changing cosmic forces. And amidst the chaos and beauty of it all, there exists a profound sense of interconnectedness, a recognition that we are but fleeting sparks in the cosmic fire, bound together by the threads of fate and destiny.";
  string pattern = "bachelor";

  //Plaintext pattern_plain(pack(TextToBinaryString(pattern)));
  //Ciphertext pattern_cipher;
  //encryptor.encrypt(pattern_plain, pattern_cipher);
  EncryptedPattern enc_pattern(pattern, &encryptor, poly_modulus_degree);

  Plaintext * frags;
  int nb_fragments;
  frags = fragment(&plaintext, frags, &nb_fragments, fragment_size);

  auto start = std::chrono::high_resolution_clock::now();

  Ciphertext * ciphertexts;
  ciphertexts = new Ciphertext[nb_fragments];
  for(int i = 0; i < nb_fragments; i++){
    //cout << i << endl;
    encryptor.encrypt(frags[i], ciphertexts[i]);
    //cout << frags[i].to_string() << endl;
  }
  auto elapsed = std::chrono::high_resolution_clock::now() - start;
  long long microseconds = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();

  cout << "encryption time : " << microseconds << endl;

  start = std::chrono::high_resolution_clock::now();

  Detector detector(&fragment_size, poly_modulus_degree);
  Ciphertext * detect_res = detector.detect(ciphertexts, &enc_pattern, &nb_fragments, &encryptor, &evaluator);

  elapsed = std::chrono::high_resolution_clock::now() - start;
  microseconds = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();

  cout << "detection time : " << microseconds << endl;




  cout << endl << endl;

  Plaintext xk("1x^4");

  start = std::chrono::high_resolution_clock::now();
  for(int i = 0; i < nb_fragments - 1; i++){
    Plaintext dec;
    Ciphertext temp;
    //cout << decryptor.invariant_noise_budget(detect_res[i]) << endl;
    //evaluator.multiply_plain(detect_res[i], xk, temp);
    decryptor.decrypt(detect_res[i], dec);
    cout << "-------" << endl << endl;
    for (int i=0; i< 2*fragment_size - TextToBinaryString(pattern).length() ; i++)
    {
        if (*dec.data(i)  == 0)
        {
          cout << "Attack dettected in position " <<  i/8  << ", you should not decrypt the receiver's cipher text. " << endl;
        }
    }
  }

  elapsed = std::chrono::high_resolution_clock::now() - start;
  microseconds = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();

  cout << "decryption time : " << microseconds << endl;


  for(int i = 0; i < 5; i++){
    evaluator.multiply(detect_res[2],detect_res[1],detect_res[2]);
  }

  */

    

    /*
    Plaintext test_value("CDx^5 + 10x^4");
    
    
    
    Ciphertext enc_test ;
    encryptor.encrypt(test_value , enc_test);

    Plaintext val("12x^0");
    Ciphertext enc_val ;
    encryptor.encrypt(val , enc_val);
    
    
    start = std::chrono::high_resolution_clock::now();
    
    
    Ciphertext res;
    evaluator.multiply(enc_test, enc_val, res);

    elapsed = std::chrono::high_resolution_clock::now() - start;
    microseconds = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();

    cout << "time : " << microseconds << endl;

    Plaintext plain_res;
    decryptor.decrypt(res, plain_res);
    //cout << plain_res.to_string() << endl;
*/
  return 0;
}
