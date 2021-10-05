import * as CryptoJS from 'crypto-js';

export class Faramis{
    secretKey: CryptoJS.lib.WordArray;
    iv: CryptoJS.lib.WordArray;

    constructor(data: any) {
        this.secretKey = CryptoJS.enc.Utf8.parse(data.secretKey);
        this.iv = CryptoJS.enc.Utf8.parse(data.iv);
    }

    Encrypt(message: string): string{
        return CryptoJS.AES.encrypt(
            CryptoJS.enc.Utf8.parse(message), 
            this.secretKey, {
                iv: this.iv,
                padding: CryptoJS.pad.Pkcs7,
                mode: CryptoJS.mode.CBC,
            })
            .toString();
    } 

    Decrypt(ciphertext: string): string{
        var decrypted = CryptoJS.AES.decrypt(
            ciphertext, 
            this.secretKey,{
                iv: this.iv,
                padding: CryptoJS.pad.Pkcs7,
                mode: CryptoJS.mode.CBC,
            });
        return CryptoJS.enc.Utf8.stringify(decrypted).toString();
    }
}