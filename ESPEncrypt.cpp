#include "ESPEncrypt.h"

ESPEncrypt::ESPEncrypt() {}

ESPEncrypt::ESPEncrypt(const String &AES_KEY_HEX) 
{
    if(!this->setAesKeyHex(AES_KEY_HEX)) {
        Serial.println("[ERROR] INVALID AES KEY");
        // Caso chave seja inválida, inicia com 0s
        memset(privateCipherKey, 0x00, KEY_LEN);
    }
}

ESPEncrypt::~ESPEncrypt() {}

// Inicia contador persitente
Preferences prefs;

// Inicia uma chave AES aleatória (NAO USAR ESSA/apenas por padrão)
uint8_t ESPEncrypt::privateCipherKey[KEY_LEN] = {
    0x31,0x32,0x33,0x34,
    0x35,0x36,0x37,0x38,
    0x39,0x30,0x61,0x62,
    0x63,0x64,0x65,0x66
};

// Inicia o vetor NONCE (IV)
uint8_t ESPEncrypt::nonce[NONCE_LEN];


void ESPEncrypt::setAesKeyAscii(const String &key)
{
    memset(privateCipherKey, 0x00, KEY_LEN);

    int len = key.length();

    // Caso tamanho seja inconsistente
    if (len > KEY_LEN)  len = KEY_LEN;

    memcpy(privateCipherKey, key.c_str(), len);
}


bool ESPEncrypt::setAesKeyHex(const String &hexKey)
{
    memset(privateCipherKey, 0x00, KEY_LEN);

    int hexLen = hexKey.length();

    // Cada byte = 2 caracteres hex
    if (hexLen % 2 != 0) {
        Serial.println("[ERROR] INVALID AES KEY");
        return false;
    }
    int byteLen = hexLen / 2;

    // Validar tamanho AES
    if (byteLen != 16 && byteLen != 24 && byteLen != 32)
        return false;

    // Converter hex pra bytes
    for (int i = 0; i < byteLen; i++)
    {
        char high = hexKey[2 * i];
        char low  = hexKey[2 * i + 1];
        uint8_t highVal, lowVal;
        auto hexToNibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
        };
        highVal = hexToNibble(high);
        lowVal  = hexToNibble(low);
        if (highVal < 0 || lowVal < 0)
            return false;

        privateCipherKey[i] = (highVal << 4) | lowVal;
    }
    return true;
}


void ESPEncrypt::printHex(const char* label, const uint8_t* data, size_t len)
{
    #if CRYPTO_DEBUG
        Serial.print(label);
        Serial.print(" [");
        for (size_t i = 0; i < len; i++) {
            if (data[i] < 0x10) Serial.print("0");
            Serial.print(data[i], HEX);
        }
        Serial.println("]");
    #endif
}


void ESPEncrypt::printNonce()
{
    for (size_t i = 0; i < NONCE_LEN; i++) {
        if (nonce[i] < 0x10) Serial.print("0");
        Serial.print(nonce[i], HEX);
    }
}


uint32_t ESPEncrypt::getCounter()
{
    prefs.begin("crypto", false);
    uint32_t c = prefs.getUInt("ctr", 0);
    prefs.putUInt("ctr", c + 1);
    prefs.end();
    return c;
}


void ESPEncrypt::generateNonce()
{
    uint32_t counter = getCounter();
    uint32_t rnd1 = esp_random();
    uint32_t rnd2 = esp_random();
    memcpy(&nonce[0],  &counter, 4);
    memcpy(&nonce[4],  &rnd1, 4);
    memcpy(&nonce[8],  &rnd2, 4);
}


int ESPEncrypt::encrypt(const uint8_t *plainText, size_t len, uint8_t *output, size_t *out_len)
{
    // Inicia contexto
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    // Tag de autenticação
    uint8_t tag[TAG_LEN];

    // Gera Nonce/IV a partir do contador persistente
    generateNonce();

    #if CRYPTO_DEBUG
        Serial.println("=== AES GCM ENCRYPT ===");
        printHex("PLAINTEXT", plainText, len);
        printHex("NONCE", nonce, NONCE_LEN);
    #endif

    // Insere chave criptográfica AES no contexto
    int ret = mbedtls_gcm_setkey(
        &ctx,
        MBEDTLS_CIPHER_ID_AES,
        privateCipherKey,
        KEY_BITS
    );
    // Verifica se conseguiu inserir chave
    if (ret != 0) {
        mbedtls_gcm_free(&ctx);
        Serial.println("[AES-ERROR] Não conseguiu definir chave AES.");
        return -1;
    }

    // Realiza a criptografia (output) e forma a tag através da API da espressif
    ret = mbedtls_gcm_crypt_and_tag(
        &ctx,                           // Contexto GCM
        MBEDTLS_GCM_ENCRYPT,            // Modo criptografia
        len,                            // Tamanho do plaintext
        nonce, NONCE_LEN,               // Nonce, Tamanho do Nonce (IV)
        NULL, 0,                        // AAD , Tamanho AAD (não implementado ainda)
        plainText,                      // Conteúdo descriptografado
        output + NONCE_LEN,             // Saída criptografada (buffer)
        TAG_LEN,                        // Tamanho da tag
        tag                             // Conteúdo tag
    );
    // Verifica se conseguiu criptografar conteúdo
    if (ret != 0) {
        mbedtls_gcm_free(&ctx);
        Serial.println("[AES-ERROR] Falha de criptografia");
        return -1;
    }

    // Copia conteúdo nos buffers
    // Estrutura: [NONCE | CIPHERTEXT | TAG]
    memcpy(output, nonce, NONCE_LEN);
    memcpy(output + NONCE_LEN + len, tag, TAG_LEN);
    *out_len = NONCE_LEN + len + TAG_LEN;

    #if CRYPTO_DEBUG
        printHex("CIPHERTEXT", output + NONCE_LEN, len);
        printHex("TAG", tag, TAG_LEN);
    #endif

    mbedtls_gcm_free(&ctx);     // libera ctx para nova criptografia 
    return 0;                   // Retorna sucesso
}


String ESPEncrypt::encryptString(const String &plainText)
{
    uint8_t input[MAX_DATA];
    uint8_t encrypted[MAX_DATA + 32];
    uint8_t base64Out[512];
    size_t len = plainText.length();
    size_t enc_len, b64_len;

    memcpy(input, plainText.c_str(), len);

    #if CRYPTO_DEBUG
        Serial.println("=== INPUT STRING ===");
        Serial.println(plainText);
    #endif

    if (encrypt(input, len, encrypted, &enc_len) != 0)  return "";

    #if CRYPTO_DEBUG
        printHex("FULL PACKET (nonce+cipher+tag)", encrypted, enc_len);
    #endif

    // Codifica hex para base64 (cipher)
    mbedtls_base64_encode(
        base64Out,
        sizeof(base64Out),
        &b64_len,
        encrypted,
        enc_len
    );

    #if CRYPTO_DEBUG
        Serial.println("BASE64 OUTPUT:");
        Serial.println((char*)base64Out);
        printHex("AES KEY", privateCipherKey, 16);
    #endif

    return String((char*)base64Out).substring(0, b64_len);
}


String ESPEncrypt::decryptString(const String &cipherText)
{
    uint8_t decoded[512];
    uint8_t output[MAX_DATA];

    size_t decoded_len, out_len;

    #if CRYPTO_DEBUG
        Serial.println("=== DECRYPT INPUT (BASE64) ===");
        Serial.println(cipherText);
    #endif

    // decodifica a string para binário
    int ret = mbedtls_base64_decode(
        decoded,
        sizeof(decoded),
        &decoded_len,
        (const uint8_t*)cipherText.c_str(),
        cipherText.length()
    );

    if (ret != 0) {
        #if CRYPTO_DEBUG
            Serial.println("Base64 decode error");
        #endif
        return "";
    }

    #if CRYPTO_DEBUG
        printHex("DECODED PACKET", decoded, decoded_len);
    #endif

    // valida tamanho mínimo do pacote
    if (decoded_len < NONCE_LEN + TAG_LEN) {
        return "";
    }

    uint8_t *nonce_ptr = decoded;
    uint8_t *cipher_ptr = decoded + NONCE_LEN;

    size_t cipher_len = decoded_len - NONCE_LEN - TAG_LEN;

    uint8_t *tag_ptr = decoded + NONCE_LEN + cipher_len;

    #if CRYPTO_DEBUG
        printHex("NONCE", nonce_ptr, NONCE_LEN);
        printHex("CIPHERTEXT", cipher_ptr, cipher_len);
        printHex("TAG", tag_ptr, TAG_LEN);
    #endif

    // Cria o contexto
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    // Insere chave criptográfica AES no contexto
    ret = mbedtls_gcm_setkey(
        &ctx,
        MBEDTLS_CIPHER_ID_AES,
        privateCipherKey,
        KEY_BITS
    );

    if (ret != 0) {
        mbedtls_gcm_free(&ctx); return "";
    }

    // decodifica mensagem (cipher) utilizando chave anexada
    ret = mbedtls_gcm_auth_decrypt(
        &ctx,
        cipher_len,
        nonce_ptr, NONCE_LEN,
        NULL, 0,                    // AAD (não implementado ainda)
        tag_ptr, TAG_LEN,
        cipher_ptr,
        output
    );

    mbedtls_gcm_free(&ctx);

    if (ret != 0) {
        #if CRYPTO_DEBUG
            Serial.println("AUTH FAIL");
        #endif
        return "AUTH_FAIL";
    }

    out_len = cipher_len;

    #if CRYPTO_DEBUG
        printHex("PLAINTEXT", output, out_len);
        Serial.println("DECRYPTED STRING:");
        Serial.println(String((char*)output).substring(0, out_len));
    #endif

    // Retorna string em formato plaintext
    return String((char*)output).substring(0, out_len);
}


bool ESPEncrypt::validation(const String &plainText, const String &cipherText)
{
    return plainText.equals( this->decryptString(cipherText) );
}