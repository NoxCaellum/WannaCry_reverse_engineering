/////////////////////////////////////////////////////////////////////////////
/// Author: NoxCaellum
/// Date: 02/18/2026
/// Format: PE x86_64
/// Compilation: cl /EHsc /std:c++17 wncry_rsa_key_decryption.cpp  /I "C:\Program Files\OpenSSL-Win64\include"  /link /LIBPATH:"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD"  libcrypto.lib libssl.lib advapi32.lib
///
/// This programme aims to decrypt the WannaCry integrated DLL in t.wnry
/////////////////////////////////////////////////////////////////////////////


#include <iostream>
#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <Wincrypt.h>
#include <array>
#include <vector>
#include <cstdint>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <fstream>



HCRYPTPROV hCryptProv;
HCRYPTKEY decryptKey;
std::array<char, 256> file_data{};
std::array<char, 0x494> key_data{};
DWORD data_length = 0x494;
DWORD decrypted_data_length = 256;



int Decryption(const char* rsa_file, const char* aes_file){

    FILE *key_file = fopen(rsa_file, "rb");
    if (key_file == NULL) {
        std::cerr << "(!) Cannot open file: " << rsa_file << " (" << strerror(errno) << ")" << std::endl;
        return 1;
    }

    size_t rdata = fread(key_data.data(), 1, data_length, key_file);
    if (rdata != data_length) {
        std::cerr << "(!) Failed to read full key blob (" << rdata << " bytes read instead of " << data_length << ")" << std::endl;
        fclose(key_file);
        return 1;
    }

    std::cout << "[*] Reading: " << rsa_file << std::endl;
  


    if (CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, 0x18, 0xF0000000)){
        std::cout << "[*] Acquired Crypto Context \n";
    }
    else {
        std::cout << "[!] Failed to acquire Crypto Context";
    }


    if (CryptImportKey(hCryptProv, reinterpret_cast<BYTE*>(key_data.data()), data_length, 0, 0, &decryptKey)){
        std::cout << "[*] Imported key \n";
    }
    else {
        std::cout << "[!] Failed to import the key";
        return 1;
    }



    FILE* encrypted_file = fopen(aes_file, "rb");
    if (encrypted_file == NULL) {
        std::cerr << "(!) Cannot open encrypted file: " << aes_file     << " (" << strerror(errno) << ")" << std::endl;
        return 1;
    }

    size_t items_read = fread(file_data.data(), 256, 1, encrypted_file);
    if (items_read != 1) {
        std::cerr << "(!) Failed to read 256 bytes from " << aes_file << std::endl;
        std::cerr << "    (read " << (items_read * 256) << " bytes instead)" << std::endl;
        fclose(encrypted_file);
        return 1;
    }

std::cout << "[*] Reading: " << aes_file << std::endl;
fclose(encrypted_file);


    
    if (CryptDecrypt(decryptKey, 0, 1, 0, reinterpret_cast<BYTE*>(file_data.data()), &decrypted_data_length)){
        std::cout << "[*] AES key in " << aes_file << " decrypted" << "\n" << std::endl;
    }
    else {
        std::cout << "[!] Decryption failed";
        return 1;
    }

	for (int i = 0; i < 256; i++) {
		if (i && i % 16 == 0) {
			printf("\n");
		}
		printf("%02x ", file_data[i] & 0xFF);
    }
};

bool Decrypt_dll(const char* input_file, const char* output_file) {
    constexpr std::array<uint8_t, 16> key = {
        0xbe, 0xe1, 0x9b, 0x98, 0xd2, 0xe5, 0xb1, 0x22,
        0x11, 0xce, 0x21, 0x1e, 0xec, 0xb1, 0x3d, 0xe6
    };

    constexpr std::array<uint8_t, 16> iv = {0};

    std::ifstream in(input_file, std::ios::binary | std::ios::ate);
    if (!in.is_open()) {
        std::cerr << "[!] Cannot open input file: " << input_file << "\n";
        return false;
    }

    auto size = in.tellg();
    if (size <= 0) {
        std::cerr << "[!] Input file is empty or invalid\n";
        return false;
    }

    std::vector<uint8_t> ciphertext(static_cast<size_t>(size));
    in.seekg(0);
    in.read(reinterpret_cast<char*>(ciphertext.data()), size);
    in.close();

    if (!in) {
        std::cerr << "[!] Failed to read complete file\n";
        return false;
    }

    std::vector<uint8_t> plaintext;
    plaintext.reserve(ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "[!] EVP_CIPHER_CTX_new failed\n";
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        std::cerr << "[!] EVP_DecryptInit_ex failed\n";
        return false;
    }

    int len = 0;
    std::vector<uint8_t> block(4096 + 16);

    for (size_t offset = 0; offset < ciphertext.size(); ) {
        size_t chunk = std::min<size_t>(4096, ciphertext.size() - offset);

        if (EVP_DecryptUpdate(ctx, block.data(), &len,
                              ciphertext.data() + offset, static_cast<int>(chunk)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            std::cerr << "[!] EVP_DecryptUpdate failed\n";
            return false;
        }

        plaintext.insert(plaintext.end(), block.data(), block.data() + len);
        offset += chunk;
    }

    int final_len = 0;
    EVP_DecryptFinal_ex(ctx, block.data(), &final_len);
    plaintext.insert(plaintext.end(), block.data(), block.data() + final_len);

    EVP_CIPHER_CTX_free(ctx);

    std::ofstream out(output_file, std::ios::binary);
    if (!out.is_open()) {
        std::cerr << "[!] Cannot open output file: " << output_file << "\n";
        return false;
    }

    out.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
    if (!out) {
        std::cerr << "[!] Failed to write decrypted data\n";
        return false;
    }

    std::cout << "\n\n[*] First 16 bytes of the AES decrypted key: bee19b98d2e5b12211ce211eecb13de6" << std::endl;
    std::cout << "[*] Decrypted file saved to: " << output_file << "\n";
    std::cout << "[*] Decrypted file size: " << plaintext.size() << " bytes\n";
    return true;
}



int main(){
    std::cout << "--- WannaCry integrated DLL decryption ---\n\n";
    Decryption("rsa_key.bin", "encrypted_aes_key");
    Decrypt_dll("large_chunk.bin", "decrypted_dll.dec");
    return 0;

}