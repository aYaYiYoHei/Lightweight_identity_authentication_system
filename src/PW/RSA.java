package PW;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSA {

    public static byte[] encrypt(RSAPublicKey publicKey, byte[] srcBytes) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (publicKey != null) {
            // Cipher负责完成加密或解密工作，基于RSA
            Cipher cipher = Cipher.getInstance("RSA");
            // 根据公钥，对Cipher对象进行初始化
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] resultBytes = cipher.doFinal(srcBytes);
            return resultBytes;
        }
        return null;
    }

    protected byte[] decrypt(RSAPrivateKey privateKey, byte[] srcBytes) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if (privateKey != null) {
            // Cipher负责完成加密或解密工作，基于RSA
            Cipher cipher = Cipher.getInstance("RSA");
            // 根据公钥，对Cipher对象进行初始化
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] resultBytes = cipher.doFinal(srcBytes);
            return resultBytes;
        }
        return null;
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, IOException {
        RSA rsa = new RSA();
        BufferedReader buffer = new BufferedReader(new InputStreamReader(System.in));
        System.out.println("请输入一串字符串：");
        String msg = buffer.readLine();
        // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        // 初始化密钥对生成器，密钥大小为1024位
        keyPairGen.initialize(1024);
        // 生成一个密钥对，保存在keyPair中
        KeyPair keyPair = keyPairGen.generateKeyPair();
        // 得到私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        // 得到公钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        // 用公钥加密
        byte[] srcBytes = msg.getBytes();
        byte[] resultBytes = rsa.encrypt(publicKey, srcBytes);

        // 用私钥解密
        byte[] decBytes = rsa.decrypt(privateKey, resultBytes);

        System.out.println("明文是:" + msg);
        System.out.println("加密后是:" + new String(resultBytes));
        System.out.println("解密后是:" + new String(decBytes));
    }

}
