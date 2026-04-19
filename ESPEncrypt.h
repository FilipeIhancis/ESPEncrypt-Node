#ifndef ESPEncrypt_H
#define ESPEncrypt_H

// Inclusão de bibliotecas
#include <Arduino.h>
#include <string.h>
#include "mbedtls/gcm.h"            // Por enquanto a biblioteca lida apenas com GCM
#include "mbedtls/base64.h"
#include <Preferences.h>

// Variáveis globais
#define KEY_LEN         16          // Bytes da chave AES
#define NONCE_LEN       12          // Bytes do NONCE (IV)
#define TAG_LEN         16          // Bytes da Tag Auth.
#define MAX_DATA        256         // QTD Máxima Bytes AES
#define KEY_BITS        128         // QTD de bits da Chave GCM
#define CRYPTO_DEBUG    0           // Ativa debug

extern Preferences prefs;           // Contador persistente ESP32


/**
 *  @class Classe que implementa criptografia AES-GCM 128 bits
 *  @author Filipe Ihancis (filipeihancist@gmail.com)
 */
class ESPEncrypt {

public:

    /** @brief Construtor */
    ESPEncrypt();

    /**
     *  @brief Construtor
     *  @param AES_KEY_HEX String que contém chave AES em hexadecimal
     */
    ESPEncrypt(const String &AES_KEY_HEX);
    
    /** Destructor */
    ~ESPEncrypt();

    /**
     *  @brief Realiza a criptografia de uma string com a chave privada
     *  @param plainText Texto a ser criptografado
     *  @return Plaintext criptografado utilizando algoritmo AES-GCM-128bits
     */
    String encryptString(const String &plainText);

    /**
     *  @brief Realiza decodificação de uma string utilizando a chave AES
     *  @param cipherText texto a ser decodificado (cipher text)
     *  @return cipherText decodificado em formato plaintext
     */
    String decryptString(const String &cipherText);

    /**
     *  @brief Insere a chave criptográfica AES (adaptado para strings com conteúdo em formato ASCII)
     *  @param key String chave criptográfica AES
     *  @warning Caso o ASCII seja inválido, completa com 0s
     */
    void setAesKeyAscii(const String &key);

    /**
     *  @brief Insere a chave criptográfica AES (adaptado para strings com conteúdo em formato hexadecimal)
     *  @param hexKey String chave criptográfica AES
     */
    bool setAesKeyHex(const String &hexKey);

    /**
     *  @brief
     *  @param plainText
     *  @param cipherText
     */
    bool validation(const String &plainText, const String &cipherText);

    /**
     *  @brief Exibe no monitor serial o conteúdo (hexadecimal) armazenado em um vetor uint8_t
     *  @param label Nome do conteúdo (label)
     *  @param data Vetor a ser lido e exibido
     *  @param len Tamanho do vetor (geralmente padrão e definido na primeira seção deste arquivo)
     */
    void printHex(const char* label, const uint8_t* data, size_t len);

    /**
     *  @brief Exibe no monitor serial o conteúdo (hexadecimal) do nonce (IV) atual
     */
    void printNonce();


protected:

    // Variável que armazena a chave privada AES
    static uint8_t  privateCipherKey[KEY_LEN], nonce[NONCE_LEN];

    /**
     *  @brief Gera um NONCE baseado no contador persistente e números aleatórios
     */
    void generateNonce();

    /**
     *  @brief Obtém o contador atual (persistente)
     *  @return Contador atual
     */
    uint32_t getCounter();

    /**
     *  @brief Realiza a criptografia de dados 
     *  @param plainText Plaintext em hex
     *  @param len Tamanho do plaintext em hex
     *  @param output Vetor de saída
     *  @param out_len Tamanho da saída 
     *  @return
     */
    int encrypt(const uint8_t *plainText, size_t len, uint8_t *output, size_t *out_len);
};


#endif