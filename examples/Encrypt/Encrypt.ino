/*******************************************************************************************************************************
 *  @brief
 *  @author Filipe Ihancis (filipeihancist@gmail.com)
 *  @warning AES_KEY precisa ter exatamente 32 caracteres (string hex)
 *  @warning Não coloque pontuações (´, ~) e/ou caracteres especiais na mensagem
 ******************************************************************************************************************************/


#include "ESPEncrypt.h"                                 // Inclusão da biblioteca
#define AES_KEY "7cc7f46dd4a82b10b23388c7eda6379b"      // Define a chave AES (precisa ter 32 caracteres e é uma string hex)
ESPEncrypt crypto(AES_KEY);                             // Cria instância para utilização da bib.


void setup() {
    // Inicia monitor serial
    Serial.begin(9600);
}


void loop()
{   
    // Mensagem (payload, plaintext) **********************************
    String msg = "Hello World";
    Serial.println("Mensagem: " + msg);
    
    // Encrypt Data ***************************************************
    String cipher = crypto.encryptString(msg);
    Serial.println("Mensagem Criptografada: " + cipher);

    // Decrypt Data ***************************************************
    String plainText = crypto.decryptString(cipher);
    Serial.println("Mensagem Decodificada: " + plainText);
    
    
    Serial.println("----");
    delay(5000); // espera 5 s para repetir
}