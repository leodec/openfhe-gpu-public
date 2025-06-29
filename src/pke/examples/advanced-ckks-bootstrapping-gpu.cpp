//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*

Example for CKKS bootstrapping with sparse packing

*/

#define PROFILE

#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "key/key-ser.h"

#include "gpu/Utils.h"

using namespace lbcrypto;

void ApproxModReduction(uint32_t numSlots);

void BootstrapExample(uint32_t numSlots);


int main(int argc, char* argv[]) {
    // We run the example with 8 slots and ring dimension 4096 to illustrate how to run bootstrapping with a sparse plaintext.
    // Using a sparse plaintext and specifying the smaller number of slots gives a performance improvement (typically up to 3x).
    // ApproxModReduction(8);
    // BootstrapExample(8);
    // BootstrapExample(256);
    // BootstrapExample(1<<10);
    // BootstrapExample(1<<11);
    // BootstrapExample(1<<14);
    // BootstrapExample(1<<15);
    BootstrapExample(1<<16);
}

void ApproxModReduction(uint32_t numSlots) {

    CCParams<CryptoContextCKKSRNS> parameters;

    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);

   
    parameters.SetSecurityLevel(HEStd_128_classic);
    // parameters.SetSecurityLevel(HEStd_NotSet);
    // parameters.SetRingDim(1 << 16);
    // parameters.SetRingDim(1 << 12);

    
    parameters.SetNumLargeDigits(3);
    parameters.SetKeySwitchTechnique(HYBRID);


    // All modes are supported for 64-bit CKKS bootstrapping.
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    usint dcrtBits               = 59;
    // usint dcrtBits               = 50;
    usint firstMod               = 60;

    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);

  
    std::vector<uint32_t> levelBudget = {3, 3};
    // std::vector<uint32_t> levelBudget = {4, 4};

    
    std::vector<uint32_t> bsgsDim = {0, 0};

    
    // uint32_t levelsAvailableAfterBootstrap = 10;
    uint32_t levelsAvailableAfterBootstrap = 20;
    // uint32_t levelsAvailableAfterBootstrap = 30;
    usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    // Generate crypto context.
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    // Enable features that you wish to use. Note, we must enable FHE to use bootstrapping.
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    usint ringDim = cryptoContext->GetRingDimension();
    std::cout << "CKKS scheme is using ring dimension " << ringDim << std::endl << std::endl;

    // Step 2: Precomputations for bootstrapping
    cryptoContext->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots);
    // const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoContext->GetCryptoParameters());
    // const auto gpu_context = GenGPUContext(cryptoParams);

    // Step 3: Key Generation
    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    // Generate bootstrapping keys.

    // const auto gpu_evk = LoadEvalMultRelinKey(cryptoContext);

    // Step 4: Encoding and encryption of inputs
    // Generate random input
    std::vector<double> x;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    for (size_t i = 0; i < numSlots; i++) {
        x.push_back(dis(gen));
    }

    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, numSlots);
    ptxt->SetLength(numSlots);
    // std::cout << "Input: " << ptxt << std::endl;

    // Encrypt the encoded vectors
    Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

    std::cout << "Initial number of levels remaining: " << depth - ciph->GetLevel() << std::endl;

    // Step 5: Perform the bootstrapping operation. The goal is to increase the number of levels remaining
    // for HE computation.
    // auto ciphertextAfter = cryptoContext->EvalBootstrap(ciph);
    cryptoContext->EvalModReduce(ciph);
}

void BootstrapExample(uint32_t numSlots) {

    std::cout << "starting bootstrapping with " << numSlots << " (2^"<<log2(numSlots)<<") slots\n";

    // Step 1: Set CryptoContext
    CCParams<CryptoContextCKKSRNS> parameters;

    // A. Specify main parameters
    /*  A1) Secret key distribution
    * The secret key distribution for CKKS should either be SPARSE_TERNARY or UNIFORM_TERNARY.
    * The SPARSE_TERNARY distribution was used in the original CKKS paper,
    * but in this example, we use UNIFORM_TERNARY because this is included in the homomorphic
    * encryption standard.
    */
    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);

    /*  A2) Desired security level based on FHE standards.
    * In this example, we use the "NotSet" option, so the example can run more quickly with
    * a smaller ring dimension. Note that this should be used only in
    * non-production environments, or by experts who understand the security
    * implications of their choices. In production-like environments, we recommend using
    * HEStd_128_classic, HEStd_192_classic, or HEStd_256_classic for 128-bit, 192-bit,
    * or 256-bit security, respectively. If you choose one of these as your security level,
    * you do not need to set the ring dimension.
    */
    // parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 17);
    // parameters.SetRingDim(1 << 16);
    // parameters.SetRingDim(1 << 12);

    /*  A3) Key switching parameters.
    * By default, we use HYBRID key switching with a digit size of 3.
    * Choosing a larger digit size can reduce complexity, but the size of keys will increase.
    * Note that you can leave these lines of code out completely, since these are the default values.
    */
    // parameters.SetNumLargeDigits(6);
    // parameters.SetNumLargeDigits(4);
    parameters.SetNumLargeDigits(3);
    // parameters.SetNumLargeDigits(2);
    parameters.SetKeySwitchTechnique(HYBRID);

    /*  A4) Scaling parameters.
    * By default, we set the modulus sizes and rescaling technique to the following values
    * to obtain a good precision and performance tradeoff. We recommend keeping the parameters
    * below unless you are an FHE expert.
    */
#if NATIVEINT == 128 && !defined(__EMSCRIPTEN__)
    // Currently, only FIXEDMANUAL and FIXEDAUTO modes are supported for 128-bit CKKS bootstrapping.
    ScalingTechnique rescaleTech = FIXEDAUTO;
    usint dcrtBits               = 78;
    usint firstMod               = 89;
#else
    // All modes are supported for 64-bit CKKS bootstrapping.
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    usint dcrtBits               = 59;
    // usint dcrtBits               = 50;
    usint firstMod               = 60;
#endif

    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);

    /*  A4) Bootstrapping parameters.
    * We set a budget for the number of levels we can consume in bootstrapping for encoding and decoding, respectively.
    * Using larger numbers of levels reduces the complexity and number of rotation keys,
    * but increases the depth required for bootstrapping.
	* We must choose values smaller than ceil(log2(slots)). A level budget of {4, 4} is good for higher ring
    * dimensions (65536 and higher).
    * These values are the depth of CoeffsToSlots and SlotsToCoeff
    */
    // std::vector<uint32_t> levelBudget = {3, 3};
    // std::vector<uint32_t> levelBudget = {3, 4};
    std::vector<uint32_t> levelBudget = {4, 4};
    // std::vector<uint32_t> levelBudget = {5, 5};

    /* We give the user the option of configuring values for an optimization algorithm in bootstrapping.
    * Here, we specify the giant step for the baby-step-giant-step algorithm in linear transforms
    * for encoding and decoding, respectively. Either choose this to be a power of 2
    * or an exact divisor of the number of slots. Setting it to have the default value of {0, 0} allows OpenFHE to choose
    * the values automatically.
    */
    std::vector<uint32_t> bsgsDim = {0, 0};

    /*  A5) Multiplicative depth.
    * The goal of bootstrapping is to increase the number of available levels we have, or in other words,
    * to dynamically increase the multiplicative depth. However, the bootstrapping procedure itself
    * needs to consume a few levels to run. We compute the number of bootstrapping levels required
    * using GetBootstrapDepth, and add it to levelsAvailableAfterBootstrap to set our initial multiplicative
    * depth.
    */
    // uint32_t levelsAvailableAfterBootstrap = 10;
    // uint32_t levelsAvailableAfterBootstrap = 20;
    // uint32_t levelsAvailableAfterBootstrap = 21;
    // uint32_t levelsAvailableAfterBootstrap = 22;
    // uint32_t levelsAvailableAfterBootstrap = 25;
    // uint32_t levelsAvailableAfterBootstrap = 30;
    // uint32_t levelsAvailableAfterBootstrap = 36;
    // uint32_t levelsAvailableAfterBootstrap = 39;
    // uint32_t levelsAvailableAfterBootstrap = 40;
    uint32_t levelsAvailableAfterBootstrap = 45;
    // uint32_t levelsAvailableAfterBootstrap = 50;
    usint depth = levelsAvailableAfterBootstrap + FHECKKSRNS::GetBootstrapDepth(levelBudget, secretKeyDist);
    parameters.SetMultiplicativeDepth(depth);

    // Generate crypto context.
    const std::string DATAFOLDER = "demoData";
    // const bool serialize = true;
    const bool serialize = false;
    // const bool deserialize = true;
    const bool deserialize = false;
    CryptoContext<DCRTPoly> cryptoContext;
    if (!deserialize) {
        cryptoContext = GenCryptoContext(parameters);
        // Serialize cryptocontext
        if (serialize) {
            if (!Serial::SerializeToFile(DATAFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY)) {
                std::cerr << "Error writing serialization of the crypto context to "
                            "cryptocontext.txt"
                        << std::endl;
                throw std::logic_error("");
            }
            std::cout << "The cryptocontext has been serialized." << std::endl;
        }

    } 
    if (deserialize) {
        std::cout << "Loading cryptocontext from " << DATAFOLDER << std::endl;

        if (!Serial::DeserializeFromFile(DATAFOLDER + "/cryptocontext.txt", cryptoContext, SerType::BINARY)) {
        std::cerr << "I cannot read serialization from " << DATAFOLDER + "/cryptocontext.txt" << std::endl;
            // return 1;
            throw std::logic_error("");
        }
        std::cout << "The cryptocontext has been deserialized." << std::endl;
    }

    // Enable features that you wish to use. Note, we must enable FHE to use bootstrapping.
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    usint ringDim = cryptoContext->GetRingDimension();
    std::cout << "CKKS scheme is using ring dimension " << ringDim << std::endl << std::endl;
    // {
    //     const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoContext->GetCryptoParameters());
    //     const auto gpu_context = GenGPUContext(cryptoParams);
    //     // minimumFailingTest(cryptoParams, gpu_context);
    //     // std::cout << "minimum failing test passed!\n";
    // }

    // Step 2: Precomputations for bootstrapping
    cryptoContext->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots);
    // const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoContext->GetCryptoParameters());
    // const auto gpu_context = GenGPUContext(cryptoParams);

    // Step 3: Key Generation
    // auto keyPair = cryptoContext->KeyGen();
    // cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    // // Generate bootstrapping keys.
    // cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);
    KeyPair<DCRTPoly> keyPair;
    
    if (!deserialize) {
        keyPair = cryptoContext->KeyGen();
        cryptoContext->EvalMultKeyGen(keyPair.secretKey);
        // Generate bootstrapping keys.
        cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

        // Serialize the public key
        if (serialize) {
            if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY)) {
                std::cerr << "Error writing serialization of public key to key-public.txt" << std::endl;
                throw std::logic_error("");
                // return 1;
            }
            std::cout << "The public key has been serialized." << std::endl;

            // Serialize the secret key
            if (!Serial::SerializeToFile(DATAFOLDER + "/key-private.txt", keyPair.secretKey, SerType::BINARY)) {
                std::cerr << "Error writing serialization of private key to key-private.txt" << std::endl;
                // return 1;
                throw std::logic_error("");
            }
            std::cout << "The secret key has been serialized." << std::endl;

            std::ofstream emkeyfile(DATAFOLDER + "/" + "key-eval-mult.txt", std::ios::out | std::ios::binary);
            if (emkeyfile.is_open()) {
                if (cryptoContext->SerializeEvalMultKey(emkeyfile, SerType::BINARY) == false) {
                    std::cerr << "Error writing serialization of the eval mult keys to "
                                "key-eval-mult.txt" << std::endl;
                    // return 1;
                    throw std::logic_error("");
                }
                std::cout << "The eval mult keys have been serialized." << std::endl;

                emkeyfile.close();
            }
            else {
                std::cerr << "Error serializing eval mult keys" << std::endl;
                // return 1;
                throw std::logic_error("");
            }

            // Generate the rotation evaluation keys

            // Serialize the rotation keyhs
            std::ofstream erkeyfile(DATAFOLDER + "/" + "key-eval-rot.txt", std::ios::out | std::ios::binary);
            if (erkeyfile.is_open()) {
                if (cryptoContext->SerializeEvalAutomorphismKey(erkeyfile, SerType::BINARY) == false) {
                    std::cerr << "Error writing serialization of the eval rotation keys to "
                                "key-eval-rot.txt" << std::endl;
                    // return 1;
                    throw std::logic_error("");
                }
                std::cout << "The eval rotation keys have been serialized." << std::endl;

                erkeyfile.close();
            }
            else {
                std::cerr << "Error serializing eval rotation keys" << std::endl;
                throw std::logic_error("");
                // return 1;
            }
        }
    } 
    
    if (deserialize) {
        std::cout << "Loading keys from " << DATAFOLDER << std::endl;

        if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", keyPair.publicKey, SerType::BINARY) == false) {
            std::cerr << "Could not read public key" << std::endl;
            // return 1;
            throw std::logic_error("");
        }
        std::cout << "The public key has been deserialized." << std::endl;

        if (Serial::DeserializeFromFile(DATAFOLDER + "/key-private.txt", keyPair.secretKey, SerType::BINARY) == false) {
            std::cerr << "Could not read secret key" << std::endl;
            // return 1;
            throw std::logic_error("");
        }
        std::cout << "The secret key has been deserialized." << std::endl;

        keyPair.publicKey->context = cryptoContext;
        keyPair.secretKey->context = cryptoContext;

        std::ifstream emkeys(DATAFOLDER + "/key-eval-mult.txt", std::ios::in | std::ios::binary);
        if (!emkeys.is_open()) {
            std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-mult.txt" << std::endl;
            // return 1;
            throw std::logic_error("");
        }
        if (cryptoContext->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the eval mult key file" << std::endl;
            // return 1;
            throw std::logic_error("");
        }
        std::cout << "Deserialized the eval mult keys." << std::endl;

        std::ifstream erkeys(DATAFOLDER + "/key-eval-rot.txt", std::ios::in | std::ios::binary);
        if (!erkeys.is_open()) {
            std::cerr << "I cannot read serialization from " << DATAFOLDER + "/key-eval-rot.txt" << std::endl;
            // return 1;
            throw std::logic_error("");
        }
        if (cryptoContext->DeserializeEvalAutomorphismKey(erkeys, SerType::BINARY) == false) {
            std::cerr << "Could not deserialize the eval rotation key file" << std::endl;
            // return 1;
            throw std::logic_error("");
        }
        std::cout << "Deserialized the eval rotation keys." << std::endl;
    }


    // Step 3.1: Load data and keys into GPU  

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cryptoContext->GetCryptoParameters());

    // const auto gpu_evk = LoadEvalMultRelinKey(cryptoContext);
    ckks::Context gpu_context = GenGPUContext(cryptoParams);
    gpu_context.EnableMemoryPool();
    std::cout << "Generated gpu context\n";
    auto evk = LoadEvalMultRelinKey(cryptoContext);
    gpu_context.preloaded_evaluation_key = &evk;

    const std::map<usint, lbcrypto::EvalKey<lbcrypto::DCRTPoly>> evalKeys = cryptoContext->GetEvalAutomorphismKeyMap(keyPair.publicKey->GetKeyTag());
    std::cout << "max rotation keys: " << evalKeys.size() << std::endl;
    // const int num_loaded_keys = 16;  // tunable parameter to account for available GPU space
    // const int num_loaded_keys = 20;  // tunable parameter to account for available GPU space
    // const int num_loaded_keys = 8;  // tunable parameter to account for available GPU space
    // const int num_loaded_keys = 6;  // tunable parameter to account for available GPU space
    // const int num_loaded_keys = 4;  // tunable parameter to account for available GPU space
    // const int num_loaded_keys = 2;  // tunable parameter to account for available GPU space
    // const int num_loaded_keys = 0;  // cache zero keys
    const int num_loaded_keys = -1;  // indicates all saved keys
    
    // std::vector<uint32_t> inds_to_cache;
    // {
    //     // compute the indices in the rot_in[][] array. The parallelization is over the outer loop.
    //     // Cache a different inner-loop index for each outer loop. 
    // }

    std::map<uint32_t, ckks::EvaluationKey> loaded_rot_keys;
    for (const auto& pair : evalKeys) {
        if (int(loaded_rot_keys.size()) >= num_loaded_keys && num_loaded_keys >= 0) break;
        loaded_rot_keys[std::get<0>(pair)] = LoadRelinKey(std::get<1>(pair));
    }
    gpu_context.preloaded_rotation_key_map = &loaded_rot_keys;


    // Step 4: Encoding and encryption of inputs
    // Generate random input
    std::vector<double> x;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> dis(0.0, 1.0);
    for (size_t i = 0; i < numSlots; i++) {
        x.push_back(dis(gen));
    }

    // Encoding as plaintexts
    // We specify the number of slots as numSlots to achieve a performance improvement.
    // We use the other default values of depth 1, levels 0, and no params.
    // Alternatively, you can also set batch size as a parameter in the CryptoContext as follows:
    // parameters.SetBatchSize(numSlots);
    // Here, we assume all ciphertexts in the cryptoContext will have numSlots slots.
    // We start with a depleted ciphertext that has used up all of its levels.
    Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, numSlots);
    // Plaintext ptxt = cryptoContext->MakeCKKSPackedPlaintext(x, 2, depth - levelsAvailableAfterBootstrap, nullptr, numSlots);
    ptxt->SetLength(numSlots);
    // std::cout << "Input: " << ptxt << std::endl;

    // Encrypt the encoded vectors
    Ciphertext<DCRTPoly> ciph = cryptoContext->Encrypt(keyPair.publicKey, ptxt);
    // Ciphertext<DCRTPoly> ciphertextAfter = cryptoContext->Encrypt(keyPair.publicKey, ptxt);

    // std::cout << "Initial number of levels remaining: " << depth - ciph->GetLevel() << std::endl;

    // Step 5: Perform the bootstrapping operation. The goal is to increase the number of levels remaining for HE computation.
    auto ciphertextAfter = cryptoContext->EvalBootstrapGPU(ciph, gpu_context);

    // This should always pass, but don't want to wait.
    // {
    //     auto correct_ciph_after = cryptoContext->EvalBootstrap(ciph);
    //     if (*correct_ciph_after != *ciphertextAfter) {
    //         throw std::logic_error("bootstrapping output mismatch");
    //     }
    // }
    

    // ciphertextAfter = cryptoContext->EvalBootstrapGPU(ciph, gpu_context);
    // ciphertextAfter = cryptoContext->EvalBootstrapGPU(ciph, gpu_context);
    // ciphertextAfter = cryptoContext->EvalBootstrapGPU(ciph, gpu_context);


    std::cout << "Number of levels remaining after bootstrapping: " << depth - ciphertextAfter->GetLevel() << std::endl
              << std::endl;

    // Step 7: Decryption and output
    Plaintext result;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAfter, &result);
    result->SetLength(numSlots);
    // std::cout << "Output after bootstrapping \n\t" << result << std::endl;
    std::cout << "Output precision after bootstrapping \n\t" << result->GetEncodingParams()->GetPlaintextModulus() - result->GetLogError() << std::endl;

    std::vector<double> real_val = result->GetRealPackedValue();
    for (size_t i = 0; i < numSlots; i++) {
        assert (std::abs(real_val[i] - x[i]) < 5e-3);
    }
    // return;
}
