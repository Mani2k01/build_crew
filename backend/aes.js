const crypto = require('crypto');

const KEY = Buffer.from("1234567890123456", "utf8");

class Encryption{
    encrypt(data){
        try{
            if(!data) throw new Error("No data to encrypt");
            const iv = crypto.randomBytes(12);
            const cipher = crypto.createCipheriv('aes-128-gcm', KEY, iv);

            const ciphertext = Buffer.concat(
                [
                    cipher.update(Buffer.from(data)),
                    cipher.final()
                ]
            );

            const tag = cipher.getAuthTag();

            return { iv, ciphertext, tag};
        }catch(err){
            console.log("Encryption error: ", err);
            return null;
        }
    }

    decrypt(iv, ciphertext, tag){
        try{
            const decipher = crypto.createDecipheriv('aes-128-gcm', KEY, iv);

            decipher.setAuthTag(tag);

            const plaintext = Buffer.concat([
                decipher.update(ciphertext),
                decipher.final()
            ]);

            return plaintext.toString();
        }catch(err){
            console.log("error while decrypt : ", err);
            return null;
        }
    }
}

module.exports = Encryption;