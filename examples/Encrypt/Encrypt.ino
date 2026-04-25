/*******************************************************************************************************************************
 *  @brief Código de exemplo da biblioteca ESPEncrypt
 *  @details Cria uma plaintext (texto simples), podendo ser um Json simples ou grande, e realiza a criptografia.
 *  @author Filipe Ihancis Teixeira <filipeihancist@gmail.com>
 *  @warning AES_KEY precisa ter exatamente 32 caracteres (string hex)
 *  @warning Não coloque pontuações (´, ~) e/ou caracteres especiais na mensagem
 ******************************************************************************************************************************/

#include "ESPEncrypt.h"                                 // Inclusão da biblioteca
#define AES_KEY "7cc7f46dd4a82b10b23388c7eda6379b"      // Define a chave AES (precisa ter 32 caracteres e é uma string hex)
ESPEncrypt crypto(AES_KEY);                             // Cria instância para utilização da bib.


void jsonPequeno()
{
    // Mensagem (payload, plaintext) **********************************
    String msg = "Hello World teste";
    Serial.println("Mensagem: " + msg);
    
    // Encrypt Data ***************************************************
    String cipher = crypto.encryptString(msg);
    Serial.println("Mensagem Criptografada: " + cipher);

    // Decrypt Data ***************************************************
    String plainText = crypto.decryptString(cipher);
    Serial.println("Mensagem Decodificada: " + plainText);
    
    Serial.println("----");
}

void jsonGrande()
{
    // Mensagem (payload, plaintext) **********************************
    String msg = R"({"s":1,"p":1,"x":[196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196,196],"y":[203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203,203],"z":[211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211,211]})";
    Serial.println("Mensagem: " + msg);
    
    // Encrypt Data ***************************************************
    String cipher = crypto.encryptString(msg);
    Serial.println("Mensagem Criptografada: " + cipher);

    // Decrypt Data ***************************************************
    String plainText = crypto.decryptString(cipher);
    Serial.println("Mensagem Decodificada: " + plainText);
    Serial.println("----");
}

void setup() {
    // Inicia monitor serial
    Serial.begin(9600);
}

void loop()
{
    jsonPequeno();
    delay(10000); // espera 5 s para repetir o processo

}