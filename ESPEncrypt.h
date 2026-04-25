#ifndef ESPEncrypt_H
#define ESPEncrypt_H

// Bibliotecas & APIs ******************************************************
#include <Arduino.h>
#include <string.h>
#include "mbedtls/gcm.h"
#include "mbedtls/base64.h"
#include <Preferences.h>

// DEFINIÇÕES PADRÃO ********************************************************
#define KEY_LEN             16          // Bytes da chave AES
#define NONCE_LEN           12          // Bytes do NONCE (IV)
#define TAG_LEN             16          // Bytes da Tag Auth.
#define MAX_DATA            256         // QTD Máxima Bytes AES
#define KEY_BITS            128         // QTD de bits da Chave GCM
#define CRYPTO_DEBUG        0           // Ativa ou não debug interno da biblioteca
#define ENCRYPT_SUCCESS     0           // Padrão de flag sucesso da espressif
extern Preferences          prefs;      // Contador persistente ESP32


/*********************************************************************************
 *  @class Classe que implementa criptografia AES-GCM 128 bits
 *  @author Filipe Ihancis (filipeihancist@gmail.com)
 *********************************************************************************/
class ESPEncrypt 
{
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
     *  @return True se a chave for inserida corretamente
     */
    bool setAesKeyHex(const String &hexKey);

    /**
     *  @brief Verifica se uma mensagem codificada tem o mesmo conteúdo de um texto (plaintext)
     *  @param plainText Texto simples
     *  @param cipherText Texto codificado a ser comparado
     *  @return True se o conteúdo da mensagem criptografada for igual ao texto simples, falso se for diferente
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

    static uint8_t  privateCipherKey[KEY_LEN],      // Variável que armazena a chave privada
                    nonce[NONCE_LEN];               // Variávek que armazena Nonce/IV único

    /**
     *  @brief Gera um NONCE (IV) baseado no contador persistente e números aleatórios
     */
    void generateNonce();

    /**
     *  @brief Obtém o contador atual (persistente)
     *  @return Contador atual (pref)
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