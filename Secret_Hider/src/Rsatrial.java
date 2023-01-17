
    import javax.crypto.Cipher;
    import java.security.KeyPair;
    import java.security.KeyPairGenerator;
    import java.security.*;
    import java.security.spec.*;
    import java.util.Base64;
    
public class Rsatrial {
        public PrivateKey privateKey;
        public PublicKey publicKey;

        public String public_key_string = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAvPgdJY/O+rCyNOtKrtfA+TkyiWs/P5Z2T9wAsBBbzuS3jqYUBrmc44R77gqCAqywoWK4EUdFL8VrDChkfiatp3rPCnhOaX9qlJ8KtAvbiOkMYBmEbkOq4Zv1iWG29MH3Og6q0UKEZZKDR3RkTO7MyTpwiDPI7kZAmrXC5q5dBwIDAQAB";
        public static String private_key_string = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMC8+B0lj876sLI060qu18D5OTKJaz8/lnZP3ACwEFvO5LeOphQGuZzjhHvuCoICrLChYrgRR0UvxWsMKGR+Jq2nes8KeE5pf2qUnwq0C9uI6QxgGYRuQ6rhm/WJYbb0wfc6DqrRQoRlkoNHdGRM7szJOnCIM8juRkCatcLmrl0HAgMBAAECgYARaQCAoYP8Dmknr+ARPvn+VIT2K7OkYvoUdeJJrZ3MrUO70QbviCv8IBE3oKkSVWuECRAB0I2/kjEjGlYLvdmAbhXCjALsQ4ZKZq5Suoh7JmMlDv06BXZ38zEOrzCi/P76zJgAFs8NhYO/i6MFrZCwHfwH0UDFjtzK4EmuSbRVAQJBANTacdEyC3ckuw03BIQhoDSMUXe6tHQ0V4bPB87lY24Fzjze94pgBLvFvRWSmj6yWY2M7UA2brL/MQWE4zHQTdsCQQDnzrGO1SASw0BD6mKEiG3i9zgMP/rB/tUDO4zaV4/SwgzQF6CltgfEupDyHe1REwluWjwiQY4jptAOEy8gsHNFAkEAtZR0rCWpKkanW6qnq6CT7sAVb7JS5x8P2+0ZmCKQI/fH7J25Rs6KuzUBDTo3Y2z6gIrMio7k+MZCp5apyoENKQJAI5uBdNJSKe+qKISRe5BFaO7WwjL1vuT5LZTxLvzyT8qVE0X93FaY3ORXrYlhUendsgDUaeKuBdXy8aaKv7e7DQJBAL1qFqId8Beno2dWyIX28pRIFX1Lb//UKbGuwTxhq86MvtbiLCUtCNepdYknh4iAO+aa7gDO0SHYusVmMNh7tN8=";

        public String get_public_key;
        public static String get_private_key;

        /*public void init(){
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(1024);
                KeyPair pair = generator.generateKeyPair();
                privateKey = pair.getPrivate();
                publicKey = pair.getPublic();
            } catch (Exception ignored) {}
        }*/

        public void initFromStrings(){
            try{
                X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(decode(public_key_string));
                PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decode(private_key_string));

                KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                publicKey = keyFactory.generatePublic(keySpecPublic);
                privateKey = keyFactory.generatePrivate(keySpecPrivate);

            }catch(Exception ignored){}
        }

        public void printKeys(){
            System.err.println("Public Key:\n" + encode(publicKey.getEncoded()));
            System.err.println("Private Key:\n" + encode(privateKey.getEncoded()));

        }
        public void getKeys(){
            get_public_key = encode(publicKey.getEncoded());
            get_private_key = encode(privateKey.getEncoded());

            //System.err.println(GET_PUBLIC_KEY + "\n\n "+GET_PRIVATE_KEY);
        }

        public String encrypt(String message) throws Exception{
            byte[] messageToBytes = message.getBytes();
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            byte[] encryptedBytes = cipher.doFinal(messageToBytes);
            return encode(encryptedBytes);
        }
        private String encode(byte[] data){
            return Base64.getEncoder().encodeToString(data);
        }

        public String decrypt(String encryptedMessage,String pkey) throws Exception{
            byte[] encryptedBytes = decode(encryptedMessage);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decode(pkey));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpecPrivate);
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
            String finalData = new String(decryptedMessage);
            return finalData;
        }
        private byte[] decode(String data){
            return Base64.getDecoder().decode(data);
        }

      /*public static void main(String[] args) {
           Rsatrial rsa = new Rsatrial();
           rsa.initFromStrings();
            
            
           
           
           try{
               String encryptedMessage = "E9otA89NEeKxlHsDd0BOSo2fTnTXE3e3loFMXw0sr3D+O8ww9wz/g4ZdGKiNLRBZAC8JorKQXepJpDX1VUiXQQwNLHD3HBbTiDFBETt6hr84qZiY549CkSn2yhkzL0SYj3ERFcfR5UXmJwQ5U0gT44+2y6Prymm5xxDleQKYKcw=";
               String pkey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMC8+B0lj876sLI060qu18D5OTKJaz8/lnZP3ACwEFvO5LeOphQGuZzjhHvuCoICrLChYrgRR0UvxWsMKGR+Jq2nes8KeE5pf2qUnwq0C9uI6QxgGYRuQ6rhm/WJYbb0wfc6DqrRQoRlkoNHdGRM7szJOnCIM8juRkCatcLmrl0HAgMBAAECgYARaQCAoYP8Dmknr+ARPvn+VIT2K7OkYvoUdeJJrZ3MrUO70QbviCv8IBE3oKkSVWuECRAB0I2/kjEjGlYLvdmAbhXCjALsQ4ZKZq5Suoh7JmMlDv06BXZ38zEOrzCi/P76zJgAFs8NhYO/i6MFrZCwHfwH0UDFjtzK4EmuSbRVAQJBANTacdEyC3ckuw03BIQhoDSMUXe6tHQ0V4bPB87lY24Fzjze94pgBLvFvRWSmj6yWY2M7UA2brL/MQWE4zHQTdsCQQDnzrGO1SASw0BD6mKEiG3i9zgMP/rB/tUDO4zaV4/SwgzQF6CltgfEupDyHe1REwluWjwiQY4jptAOEy8gsHNFAkEAtZR0rCWpKkanW6qnq6CT7sAVb7JS5x8P2+0ZmCKQI/fH7J25Rs6KuzUBDTo3Y2z6gIrMio7k+MZCp5apyoENKQJAI5uBdNJSKe+qKISRe5BFaO7WwjL1vuT5LZTxLvzyT8qVE0X93FaY3ORXrYlhUendsgDUaeKuBdXy8aaKv7e7DQJBAL1qFqId8Beno2dWyIX28pRIFX1Lb//UKbGuwTxhq86MvtbiLCUtCNepdYknh4iAO+aa7gDO0SHYusVmMNh7tN8=";
               String decryptedMessage = rsa.decrypt(encryptedMessage,pkey);
           
              System.err.println("Encrypted:\n"+encryptedMessage);
              System.err.println(private_key_string);
              System.err.println("Decrypted:\n"+decryptedMessage);
    
               //rsa.printKeys();
               
         }catch (Exception ingored){}
      }*/ 
}
