/**
 *  @brief
 *  @author Filipe Ihancis (filipeihancist@gmail.com)
 *  @warning AES_KEY precisa ter exatamente 32 caracteres (string hex)
 *  @warning Não coloque pontuações (´, ~) e/ou caracteres especiais na mensagem
 */


 // Inclusão da biblioteca
#include "ESPEncrypt.h"

// Define a chave AES (precisa ter 32 caracteres e é uma string hex)
#define AES_KEY "7cc7f46dd4a82b10b23388c7eda6379b"

// Cria instância para utilização da bib.
ESPEncrypt crypto(AES_KEY);


void setup() 
{
    Serial.begin(9600);

    String msg = "Hello World";
    String cipher = crypto.encryptString(msg);
    
    Serial.println("Mensagem: " + msg);
    Serial.println("Mensagem Criptografada: " + cipher);
}

void loop()
{   
    // Do nothing
    delay(1000);
}