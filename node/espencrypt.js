const crypto = require('crypto');

// Cria uma função node
module.exports = function(RED) 
{
    function AESGCMDecryptNode(config) 
    {
        RED.nodes.createNode(this, config);
        const node = this;

        // Obtém dados cadastrados do usuário em int (str para int)
        this.keyStr = config.key;
        this.ivLen = parseInt(config.ivLen) || 16;
        this.tagLen = parseInt(config.tagLen) || 16;

        node.on('input', function(msg) 
        {
            try 
            {
                // ETAPA 1. Converter Base64 para Buffer
                let buf = Buffer.from(msg.payload, 'base64');

                // ETAPA 2. Extrair IV, Tag e Cipher da msg.payload
                let iv = buf.slice(0, node.ivLen);
                let tag = buf.slice(buf.length - node.tagLen);
                let cipher = buf.slice(node.ivLen, buf.length - node.tagLen);

                // ETAPA 3. Chave AES do nó configurado
                const key = Buffer.from(node.keyStr, "hex");

                // ETAPA 4. Decifrar Cipher através da chave cadastrada
                const decipher = crypto.createDecipheriv("aes-128-gcm", key, iv);
                decipher.setAuthTag(tag);
                let decrypted = decipher.update(cipher);
                decrypted = Buffer.concat([decrypted, decipher.final()]);

                // ETAPA 5. Saída
                msg.payload = decrypted.toString();
                
                // Metadados para debug (verificar Nonce/IV e tag, em hex)
                msg.iv = iv.toString("hex");
                msg.tag = tag.toString("hex");
                node.send(msg);

            } catch (err)
            {
                // Caso obtenha erro, informa no debug
                node.error("[DECRYPT ERROR]: " + err.message, msg);
            }
        });
    }
    // Cadastra o nó
    RED.nodes.registerType("lite-aes-gcm-decrypt", AESGCMDecryptNode);
}