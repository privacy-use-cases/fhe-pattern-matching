#include "seal/seal.h"
#include <sstream>
#include <iostream>
#include <iomanip>
#include <bitset>
#include <list>
#include <limits>  

using namespace std;
using namespace seal;

inline void print_parameters(const seal::SEALContext &context)
{
    auto &context_data = *context.key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "/" << std::endl;
    std::cout << "| Encryption parameters :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

    std::cout << "\\" << std::endl;
}


inline void print_line(int line_number)
{
    std::cout << "Line " << std::setw(3) << line_number << " --> ";
}

inline string TextToBinaryString(string words) {
    string binaryString = "";
    for (char& _char : words) {
        binaryString +=bitset<8>(_char).to_string();

    }
    return binaryString;
}

inline string pack_data(string poly)
{
    string v ;
    int n = poly.length();
    for (int i=n-1; i>=0; i--)
    {
           v += poly[i];

           v +="x^";
           v += to_string(i);
       if (i != 0)
           v +=" + ";
    }
    return v;
}

inline string printPolyPm1(string poly)
{
    string v ;
    int n = poly.length()/2;
    for (int i=n-1; i>=0; i--)
    {
           v += poly[i];

           v +="x^";
           v += to_string(i);
       if (i != 0)
           v +=" + ";
    }
    return v;
}

inline string printPolyPm2(string poly)
{
    string v ;
    int n = poly.length() ;
    for (int i=n-1; i>=n/2; i--)
    {
           v += poly[i];

           v +="x^";
           v += to_string(i);
       if (i != n/2)
           v +=" + ";
    }
    return v;
}

inline string pack_pattern(int t, string poly)
{
    //cout << poly << endl;
    string v ;
    int n = poly.length() ;
    for (int i=1; i<n; i++)
    {
           v += poly[i];

           v +="x^";
           v += to_string(t-i);
       if (i != n-1)
           v +=" + ";

    }
    return v;
}


inline Plaintext * fragment(string * binay_data, Plaintext * plaintext_fragments, int* nb_fragment, int frag_size){
  //string binay_data = TextToBinaryString(*data);
  *nb_fragment = (binay_data->length() / frag_size);
  if (binay_data->length() % frag_size != 0)
    *nb_fragment = *nb_fragment + 1;
  cout << "Number of fragments: " << *nb_fragment << endl;

  plaintext_fragments = new Plaintext[*nb_fragment];

  for (int i = 0; i < *nb_fragment; i++){
    plaintext_fragments[i] = Plaintext(pack_data(binay_data->substr(i*frag_size, frag_size)));
    //cout << plaintext_fragments[i].to_string() << endl;
  }
  return plaintext_fragments;
}

template <typename T>
inline void print_matrix(std::vector<T> matrix, std::size_t row_size)
{
    /*
    We're not going to print every column of the matrix (there are 2048). Instead
    print this many slots from beginning and end of the matrix.
    */
    std::size_t print_size = 5;

    std::cout << std::endl;
    std::cout << "    [";
    for (std::size_t i = 0; i < print_size; i++)
    {
        std::cout << std::setw(3) << std::right << matrix[i] << ",";
    }
    std::cout << std::setw(3) << " ...,";
    for (std::size_t i = row_size - print_size; i < row_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ((i != row_size - 1) ? "," : " ]\n");
    }
    std::cout << "    [";
    for (std::size_t i = row_size; i < row_size + print_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ",";
    }
    std::cout << std::setw(3) << " ...,";
    for (std::size_t i = 2 * row_size - print_size; i < 2 * row_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ((i != 2 * row_size - 1) ? "," : " ]\n");
    }
    std::cout << std::endl;
}

template < typename... Args >
inline string sstr( Args &&... args )
{
    std::ostringstream sstr;
    // fold expression
    ( sstr << std::dec << ... << args );
    return sstr.str();
}

/**
 * Generates a random bit string of a specified length.
 * 
 * @param length The length of the random bit string to generate.
 * 
 * @return A randomly generated bit string of the specified length.
 * 
 * The function generates a random bit string consisting of '0's and '1's.
 * The length of the generated bit string is determined by the `length` parameter.
 * 
 * Example usage:
 * int length = 10;
 * std::string randomBitString = generateRandomBitString(length);
 */
inline string generateRandomBitString(int length) {
    std::string result;
    result.reserve(length);

    // Seed the random number generator
    std::mt19937_64 rng(std::time(nullptr));
    std::uniform_int_distribution<int> distribution(0, 1);

    // Generate random bits
    for (int i = 0; i < length; ++i) {
        result += (char)('0' + distribution(rng));
    }

    return result;
}


/**
 * Generates a subset of a given size from a bit string or returns a completely
 * random bit string of the same size, based on a 1/2 probability.
 * 
 * @param l The size of the subset or the random bit string to generate.
 * @param bitString The original bit string from which the subset will be extracted.
 * 
 * @return A subset of size `l` from `bitString` if the random choice is to return a subset,
 *         or a completely random bit string of size `l` otherwise.
 * 
 * The function generates a random index within `bitString`, ensuring that there's enough
 * room to accommodate a subset of size `l`. It then randomly decides with a probability of
 * 1/2 whether to return a subset of size `l` starting from the generated random index or
 * to return a completely random bit string of size `l`.
 * 
 * If the decision is to return a subset, the function extracts a substring of size `l`
 * from `bitString` starting from the generated random index.
 * 
 * If the decision is to return a completely random bit string, the function generates
 * a new random bit string of size `l`.
 * 
 * Example usage:
 * int length = 5;
 * std::string bitString = "1101010101";
 * std::string result = generateSubsetOrRandom(length, bitString);
 */
inline string generateSubsetOrRandom(int l, const std::string& bitString) {
    std::string subset;

    // Generate a random index
    std::mt19937_64 rng(std::time(nullptr));
    std::uniform_int_distribution<int> indexDistribution(0, bitString.length() - l);
    int startIndex = indexDistribution(rng);

    // Decide with a probability of 1/2 whether to return a subset or a random bit string
    std::uniform_int_distribution<int> decisionDistribution(0, 1);
    if (decisionDistribution(rng) == 0) {
        // Return a subset
        subset = bitString.substr(startIndex, l);
    } else {
        // Return a random bit string
        subset = generateRandomBitString(l);
    }

    return subset;
}

