package com.bh;

import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;
import java.io.IOException;


import java.security.*;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class DesForce {
    private static final String Algorithm = "DESede/ECB/PKCS5Padding";// DESede/ECB/PKCS5Padding;DESede

    private static final String DESede = "DESede";

    /**
     * 3DES加密
     * */
    public static byte[] encrypt(byte[] keybyte, byte[] src)
            throws NoSuchAlgorithmException, NoSuchPaddingException, Exception {
        SecretKey deskey = new SecretKeySpec(keybyte, DESede);
        Cipher c1 = Cipher.getInstance(Algorithm);
        c1.init(Cipher.ENCRYPT_MODE, deskey);
        return c1.doFinal(src);
    }

    /**
     * 3DES解密
     * */
    public static byte[] decrypt(byte[] keybyte, byte[] src)
            throws NoSuchAlgorithmException, NoSuchPaddingException, Exception {
        SecretKey deskey = new SecretKeySpec(keybyte, DESede);
        Cipher c1 = Cipher.getInstance(Algorithm);
        c1.init(Cipher.DECRYPT_MODE, deskey);
        return c1.doFinal(src);
    }

    /**
     * 加密后的字节数组转成授权码
     * */
    public static String byte2hex(byte[] b) {
        StringBuffer hs = new StringBuffer();
        String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = (Integer.toHexString(b[n] & 0XFF));
            if (stmp.length() == 1)
                hs.append("0").append(stmp);
            else
                hs.append(stmp);
        }
        return hs.toString().toUpperCase(Locale.getDefault());
    }

    /**
     * 授权码转字节数组
     * */
    public static byte[] hex2byte(String hexStr) {
        if (hexStr.length() % 2 != 0) {
            // AppLogger.error("hex2bytes's hexStr length is not even.");
            return null;
        }

        byte[] toBytes = new byte[hexStr.length() / 2];
        for (int i = 0, j = 0; i < hexStr.length(); j++, i = i + 2) {
            int tmpa = Integer.decode(
                    "0X" + hexStr.charAt(i) + hexStr.charAt(i + 1)).intValue();
            toBytes[j] = (byte) (tmpa & 0XFF);
        }
        return toBytes;
    }

    /**
     * 使用huaweimd5算法对原文密码进行运算
     * */
    public static String getHuaweimd5Pwd(String plainPwd)
            throws NoSuchAlgorithmException {
        byte[] id = plainPwd.getBytes();
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(id);
        md.update("99991231".getBytes()); // “99991231” mentioned in XML-API
        byte[] buffer = md.digest();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < buffer.length; i++) {
            sb.append(Integer.toHexString((int) buffer[i] & 0xff));
        }
//		String md5Pwd = sb.substring(0, 8); // only use first 8 characters
//		return md5Pwd;
        return sb.toString();
    }

    /**
     * 获得DES运算之前的明文
     *
     * @throws Exception
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * */
    public static String getStringBeforeDes(String authenticator, String pwd)
            throws NoSuchAlgorithmException, NoSuchPaddingException, Exception {
        final byte[] rawKey = pwd.getBytes();
        final byte[] keyBytes = new byte[24];
        for (int i = 0; i < rawKey.length; i++) {
            keyBytes[i] = rawKey[i];
        }
        for (int i = rawKey.length; i < keyBytes.length; i++) {
            keyBytes[i] = (byte) '0';
        }
        byte[] encoded = hex2byte(authenticator);
        byte[] srcBytes = decrypt(keyBytes, encoded);

//		return new String(srcBytes);
        return jdkBase64String(srcBytes);

    }

    public static String jdkBase64String(byte[] secretKey) {
        BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(secretKey);
    }


    public static String jdkBase64Decoder(String str) throws IOException {
        BASE64Decoder decoder = new BASE64Decoder();
        return new String(decoder.decodeBuffer(str),"utf-8");
    }

    public static String getPwdString(int i,int num){
        String plainPwd = ""+i;
        while (plainPwd.length() <num){
            plainPwd = "0"+plainPwd;
        }
        return  plainPwd;
    }
    public static int getUpNum(int num){
        String upNum = "1";
        while (upNum.length() <num){
            upNum = "1"+upNum;
        }
        return  9 * Integer.parseInt(upNum);
    }
    public static boolean isChinese(char c) {
        Character.UnicodeBlock ub = Character.UnicodeBlock.of(c);
        if (ub == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS
                || ub == Character.UnicodeBlock.CJK_COMPATIBILITY_IDEOGRAPHS
                || ub == Character.UnicodeBlock.CJK_UNIFIED_IDEOGRAPHS_EXTENSION_A
                || ub == Character.UnicodeBlock.GENERAL_PUNCTUATION
                || ub == Character.UnicodeBlock.CJK_SYMBOLS_AND_PUNCTUATION
                || ub == Character.UnicodeBlock.HALFWIDTH_AND_FULLWIDTH_FORMS) {
            return true;
        }
        return false;
    }

    /**
     * 判断字符串是否是乱码
     *
     * @param strName 字符串
     * @return 是否是乱码
     */
    public static boolean isMessyCode(String strName) {
        Pattern p = Pattern.compile("\\s*|t*|r*|n*");
        Matcher m = p.matcher(strName);
        String after = m.replaceAll("");
        String temp = after.replaceAll("\\p{P}", "");
        char[] ch = temp.trim().toCharArray();
        float chLength = ch.length;
        float count = 0;
        for (int i = 0; i < ch.length; i++) {
            char c = ch[i];
            if (!Character.isLetterOrDigit(c)) {
                if (!isChinese(c)) {
                    count = count + 1;
                }
            }
        }
        float result = count / chLength;
        if (result > 0.4) {
            return true;
        } else {
            return false;
        }

    }

    public static void getDecryptStr(String authenticator,int num,Boolean md5Flag){
        int count = 0;
        for (int i =0;i<=getUpNum(num);i++){
            String plainPwd = getPwdString(i,num);
            String srcPwd = plainPwd;
            if(md5Flag){
                try {
                    plainPwd = getHuaweimd5Pwd(plainPwd);
                }catch (Exception e){
                    System.out.print(e);
                }
                plainPwd = plainPwd.substring(0, 8);
            }

            try {
                String str = getStringBeforeDes(authenticator, plainPwd);
                if(!isMessyCode(jdkBase64Decoder(str))){
                    if(md5Flag){
                        System.out.println("before md5->"+srcPwd);
                    }
                    System.out.println("plainPwd->"+plainPwd);
                    System.out.println(jdkBase64Decoder(str));
                    count ++;
                    System.out.println("=======================================");
                }
            }catch (Exception e){}
        }
        System.out.println("总共"+count+"个可用结果");
    }

    public static void main(String[] args) throws NoSuchPaddingException, Exception {
        String authenticator = "14A630274D701FB36567E58008A1D5F98FE55470BF27B1BA5C314382AA6C5DF6C6A1B2406A5687DCE6A8BF4FABC891E3FA04AE980C75103A8270B8EAA4D2D78DA5B7D88A16A9ED9F5EF04EC09CA32B29A428B8128BC1FD4882230E4B11899A650EBCDA35719FF3FD14B418E15758FF1441568C21B7533E9C4896313F19292883";
        System.out.println("des:");
        getDecryptStr(authenticator,8,false);//参数1：认证码，参数2：密码位数，参数3：是否对密码进行md5加密


    }
}
