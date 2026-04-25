#include "ESPEncrypt.h"

/**************************************************************************************************************************************/

ESPEncrypt::ESPEncrypt() {}

ESPEncrypt::ESPEncrypt(const String &AES_KEY_HEX) 
{
    if(!this->setAesKeyHex(AES_KEY_HEX)) {
        Serial.println("[ERROR] INVALID AES KEY");
        // Caso chave seja inválida, inicia com 0s
        memset(privateCipherKey, 0x00, KEY_LEN);
    }
}

ESPEncrypt::~ESPEncrypt() {}        // Destrutor da classe

Preferences prefs;                  // Contador persistente

// Inicia uma chave AES aleatória (NAO USAR ESSA/apenas por padrão)
uint8_t ESPEncrypt::privateCipherKey[KEY_LEN] = {
    0x31,0x32,0x33,0x34,
    0x35,0x36,0x37,0x38,
    0x39,0x30,0x61,0x62,
    0x63,0x64,0x65,0x66
};

// Inicia o vetor NONCE (IV)
uint8_t ESPEncrypt::nonce[NONCE_LEN];

/**************************************************************************************************************************************/
void ESPEncrypt::setAesKeyAscii(const String &key)
{
    // Armazena x0 na chave privada interna AES
    memset(privateCipherKey, 0x00, KEY_LEN);

    // Obtém tamanho da chave privada inserida pelo usuário
    int len = key.length();

    // Caso tamanho seja inconsistente, considera tamanho máximo definida
    if (len > KEY_LEN)  len = KEY_LEN;

    // Realiza cópia do conteúdo da chave inserida na variável interna
    memcpy(privateCipherKey, key.c_str(), len);
}
/**************************************************************************************************************************************/
bool ESPEncrypt::setAesKeyHex(const String &hexKey)
{
    // Cria uma chave aleatória base contendo x0
    memset(privateCipherKey, 0x00, KEY_LEN);

    // Obtém tamanho da chave AES inserida pelo usuário
    int hexLen = hexKey.length();

    // Verifica se o tamanho é par (cada byte = 2 caracteres hex)
    if (hexLen % 2 != 0) {
        Serial.println("[ERROR] INVALID AES KEY");
        return false;
    }
    // Obtém bytes
    int byteLen = hexLen / 2;

    // Valida tamanho da chave inserida
    if (byteLen != 16 && byteLen != 24 && byteLen != 32)
        return false;

    // Converte hexadecimal para bits
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
    // Chave inserida com sucesso:
    return true;
}
/**************************************************************************************************************************************/
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
/**************************************************************************************************************************************/
void ESPEncrypt::printNonce()
{
    // Realiza leitura do buffer interno Nonce (IV)
    for (size_t i = 0; i < NONCE_LEN; i++) {
        if (nonce[i] < 0x10) Serial.print("0");
        Serial.print(nonce[i], HEX);
    }
}
/**************************************************************************************************************************************/
uint32_t ESPEncrypt::getCounter()
{
    // Inicia variável persistente
    prefs.begin("crypto", false);

    // Obtém conteúdo em int
    uint32_t c = prefs.getUInt("ctr", 0);

    // Atualiza contador (contador = contador + 1)
    prefs.putUInt("ctr", c + 1);

    // Fecha variável persistente e retorna valor
    prefs.end();
    return c;
}
/**************************************************************************************************************************************/
void ESPEncrypt::generateNonce()
{
    uint32_t counter = getCounter();    // Obtém contador persistente
    uint32_t rnd1 = esp_random();       // Obtém dados aleatórios hex
    uint32_t rnd2 = esp_random();       // Obtém dados aleatórios hex
    memcpy(&nonce[0],  &counter, 4);    // Armazena bytes no buffer IV
    memcpy(&nonce[4],  &rnd1, 4);       // Armazena bytes no buffer IV
    memcpy(&nonce[8],  &rnd2, 4);       // Armazena bytes no buffer IV
}
/**************************************************************************************************************************************/
int ESPEncrypt::encrypt(const uint8_t *plainText, size_t len, uint8_t *output, size_t *out_len)
{
    // Inicia contexto AES-GCM
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    // Inicia buffer da tag de finalização
    uint8_t tag[TAG_LEN];

    // Gera um Nonce IV único com base na variável persistente (contador)
    this->generateNonce();

    #if CRYPTO_DEBUG
        Serial.println("=== AES GCM ENCRYPT (ESP32 STREAM) ===");
        printHex("PLAINTEXT", plainText, len);
        printHex("NONCE", nonce, NONCE_LEN);
    #endif

    // Insere a chave privada do usuário no contexto GCM
    int ret = mbedtls_gcm_setkey(
        &ctx,                       // Contexto GCM
        MBEDTLS_CIPHER_ID_AES,      // Define lgoritmo de criptografia
        privateCipherKey,           // Chave privada AES
        KEY_BITS                    // Bits definido da chave (tamanho da chave)
    );

    // Verifica se conseguiu inserir a chave
    if (ret != ENCRYPT_SUCCESS) {
        mbedtls_gcm_free(&ctx);
        Serial.println("[AES-ERROR] setkey falhou");
        return -1;
    }

    // Inicia o stream (fluxo de criptografia)
    ret = mbedtls_gcm_starts(
        &ctx,                   // Contexto GCM
        MBEDTLS_GCM_ENCRYPT,    // Define como criptografia GCM
        nonce,                  // Nonce (IV) único
        NONCE_LEN               // Tamanho do IV
    );

    // Verifica se conseguiu iniciar o processo de criptografia
    if (ret != ENCRYPT_SUCCESS) {
        mbedtls_gcm_free(&ctx);
        Serial.println("[AES-ERROR] starts falhou");
        return -1;
    }

    // Inicialmente, copia o Nonce (IV) para o início da saída (seguindo estrutura do payload)
    memcpy(output, nonce, NONCE_LEN);

    // Realiza criptografia em chunks de MAX_DATA bytes cada ------------------------------

    size_t offset = 0;                  // Variável de controle
    const size_t CHUNK = MAX_DATA;      // Tamanho do chunk por vez

    while (offset < len) {

        // Obtém tamanho do chunk atual:
        size_t chunk_len = (len - offset > CHUNK) ? CHUNK : (len - offset);
        size_t out_chunk_len = 0;

        ret = mbedtls_gcm_update(
            &ctx,                              // Contexto GCM
            plainText + offset,                // input 
            chunk_len,                         // tamanho do input
            output + NONCE_LEN + offset,       // saída
            chunk_len,                         // tamanho do buffer de saída
            &out_chunk_len                     // criptografia do chunk
        );

        // Verifica se realizou update da criptografia em buffer corretamente e verifica se tamanhos são compatíveis
        if (ret != ENCRYPT_SUCCESS || out_chunk_len != chunk_len) {
            mbedtls_gcm_free(&ctx);
            Serial.println("[AES-ERROR] update falhou");
            return -1;
        }
        // Próximo chunk
        offset += chunk_len;
    }

    size_t final_len = 0;

    // Finaliza operação de criptografia AES
    // Finalização gera a tag de autenticação da criptografia
    ret = mbedtls_gcm_finish(
        &ctx,                       // Contexto GCM
        NULL,                       // GCM não gera saída final
        0,                          // --
        &final_len,                 // Tamanho da saída (será atualizada)
        tag,                        // Variável tag (buffer)
        TAG_LEN                     // Tamanho fixo da tag
    );

    // Verifica se conseguiu finalizar a criar tag de autenticação
    if (ret != ENCRYPT_SUCCESS) {
        mbedtls_gcm_free(&ctx);
        Serial.println("[AES-ERROR] finish falhou");
        return -1;
    }

    // Adiciona tag na estrutura do pacote cipher
    memcpy(output + NONCE_LEN + len, tag, TAG_LEN);

    // Tamanho da saída (cipher)
    *out_len = NONCE_LEN + len + TAG_LEN;

    #if CRYPTO_DEBUG
        printHex("CIPHERTEXT", output + NONCE_LEN, len);
        printHex("TAG", tag, TAG_LEN);
    #endif

    mbedtls_gcm_free(&ctx);
    return ENCRYPT_SUCCESS;
}
/**************************************************************************************************************************************/
String ESPEncrypt::encryptString(const String &plainText)
{   
    // Obtém tamanho da string plaintext
    size_t len = plainText.length();

    // Aloca memória dinamicamente para os vetores de saída (cipher) e entrada (para os chunks)
    uint8_t *input = (uint8_t*) malloc(len);
    uint8_t *encrypted = (uint8_t*) malloc(len + NONCE_LEN + TAG_LEN);

    // Base64 de saída (precisa de ~4/3 do tamanho)
    size_t b64_size = ((len + NONCE_LEN + TAG_LEN) * 4 / 3) + 16;
    uint8_t *base64Out = (uint8_t*) malloc(b64_size);

    // Verifica se conseguiu realizar malloc
    if (!input || !encrypted || !base64Out) {
        Serial.println("[AES-ERROR] malloc falhou");
        free(input); free(encrypted); free(base64Out);
        return "";
    }

    // Copia conteúdo do plaintext para buffer de entrada input do passo de cript.
    memcpy(input, plainText.c_str(), len);

    // Tamanho (inicial) dos vetores de saída base64 e cript
    size_t enc_len = 0;
    size_t b64_len = 0;

    #if CRYPTO_DEBUG
        Serial.println("=== INPUT STRING ===");
        Serial.println(plainText);
    #endif

    // Realiza criptografia AES-GCM da string
    if (encrypt(input, len, encrypted, &enc_len) != ENCRYPT_SUCCESS) {
        Serial.println("[AES-ERROR] Falha encrypt()");
        free(input); free(encrypted); free(base64Out);
        return "";
    }

    // Codifica resultado para base64
    mbedtls_base64_encode(
        base64Out,              // Buffer de destino
        b64_size,               // Tamanho do buffer de destino
        &b64_len,               // Número de bytes a escrever
        encrypted,              // Buffer de entrada (criptografado hexadecimal)
        enc_len                 // Tamanho do buffer de entrada
    );

    // Obtém resultado em formato string/base64
    String result = String((char*)base64Out).substring(0, b64_len);

    #if CRYPTO_DEBUG
        Serial.println("BASE64:");
        Serial.println(result);
    #endif

    // Libera memória
    free(input); free(encrypted); free(base64Out);

    // Retorna resultado
    return result;
}
/**********************************************************************************************************/
String ESPEncrypt::decryptString(const String &cipherText)
{
    // Obtém tamanho do cipher (mensagem decodificada)
    size_t input_len = cipherText.length();

    // Calcula tamanho máximo da saída decodificada para não alocar fora de faixa (economiza memória)
    size_t decoded_max = (input_len * 3) / 4 + 4;

    // Cria buffer de saída decodificada com tamanho máximo da mensagem decodificada
    uint8_t *decoded = (uint8_t*) malloc(decoded_max);

    // Verifica se realizou malloc corretamente
    if (!decoded) {
        Serial.println("[AES-ERROR] malloc decoded falhou");
        return "";
    }

    // Tamanho da mensagem decodificada (será avaliado através dos chunks)
    size_t decoded_len = 0;

    #if CRYPTO_DEBUG
        Serial.println("=== DECRYPT INPUT (BASE64) ===");
        Serial.println(cipherText);
    #endif

    // Decodifica base64 
    int ret = mbedtls_base64_decode(
        decoded,                                    // Buffer de destino
        decoded_max,                                // Tamanho do buffer de destino (maximo)
        &decoded_len,                               // Número de bytes escritos (será atualizado)
        (const uint8_t*)cipherText.c_str(),         // Buffer do cipher (mensagem criptografada)
        input_len                                   // Tamanho da entrada a ser decodificada
    );

    // Verifica se conseguiu decodificar base64 corretamente
    if (ret != ENCRYPT_SUCCESS) {
        free(decoded);
        Serial.println("[AES-ERROR] base64 decode falhou");
        return "";
    }

    #if CRYPTO_DEBUG
        printHex("DECODED PACKET", decoded, decoded_len);
    #endif

    // Verifica se tamanho é válido
    if (decoded_len < NONCE_LEN + TAG_LEN) {
        free(decoded);
        return "";
    }

    // Cria varíaveis de controle
    uint8_t *nonce_ptr  = decoded;
    uint8_t *cipher_ptr = decoded + NONCE_LEN;
    size_t cipher_len   = decoded_len - NONCE_LEN - TAG_LEN;
    uint8_t *tag_ptr    = decoded + NONCE_LEN + cipher_len;

    // Cria buffer dinâmico para saída bom base na cipher
    uint8_t *output = (uint8_t*) malloc(cipher_len);

    if (!output) {
        free(decoded);
        Serial.println("[AES-ERROR] malloc output falhou");
        return "";
    }

    #if CRYPTO_DEBUG
        printHex("NONCE", nonce_ptr, NONCE_LEN);
        printHex("CIPHERTEXT", cipher_ptr, cipher_len);
        printHex("TAG", tag_ptr, TAG_LEN);
    #endif

    // Cria contexto AES-GCM
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    // Insere chave criptográfica
    ret = mbedtls_gcm_setkey( &ctx, MBEDTLS_CIPHER_ID_AES, privateCipherKey, KEY_BITS );

    // Verifica se conseguiu inserir chave corretamente
    if (ret != ENCRYPT_SUCCESS) {
        free(decoded); free(output);
        mbedtls_gcm_free(&ctx);
        return "";
    }

    // Inicia stream/fluxo de criptografia
    ret = mbedtls_gcm_starts( &ctx, MBEDTLS_GCM_DECRYPT, nonce_ptr, NONCE_LEN );

    // Verifica se conseguiu iniciar corretamente o fluxo/stream
    if (ret != ENCRYPT_SUCCESS) {
        free(decoded); free(output);
        mbedtls_gcm_free(&ctx);
        return "";
    }

    // Descriptografia do fluxostream -----------------------------------------
    size_t offset = 0;
    const size_t CHUNK = MAX_DATA;

    while (offset < cipher_len) 
    {
        size_t chunk_len = (cipher_len - offset > CHUNK) ? CHUNK : (cipher_len - offset);
        size_t out_chunk_len = 0;
        ret = mbedtls_gcm_update(&ctx,cipher_ptr + offset,chunk_len,output + offset,chunk_len,&out_chunk_len);

        if (ret != 0 || out_chunk_len != chunk_len) {
            free(decoded); free(output);
            mbedtls_gcm_free(&ctx);
            Serial.println("[AES-ERROR] update decrypt falhou");
            return "";
        }
        offset += chunk_len;
    }

    // Tamanho final (será obtida no finish)
    size_t final_len = 0;

    // Finaliza fluxo/stream (realiza autenticação da tag nesse processo)
    ret = mbedtls_gcm_finish( &ctx, NULL, 0, &final_len, tag_ptr, TAG_LEN );
    mbedtls_gcm_free(&ctx);

    // Verifica se tag de autenticação é válida
    if (ret != ENCRYPT_SUCCESS) {
        free(decoded); free(output);
        #if CRYPTO_DEBUG
            Serial.println("AUTH FAIL");
        #endif
        return "AUTH_FAIL";
    }

    #if CRYPTO_DEBUG
        printHex("PLAINTEXT", output, cipher_len);
    #endif

    // Obtém resultado em string
    String result = String((char*)output).substring(0, cipher_len);

    // Libera memória alocada
    free(decoded);
    free(output);

    // Retorna resultado
    return result;
}


bool ESPEncrypt::validation(const String &plainText, const String &cipherText)
{   
    // Verifica se uma plaintext contém mesmo conteúdo de uma string criptografada
    return plainText.equals( this->decryptString(cipherText) );
}