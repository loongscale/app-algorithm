package com.bh;

import java.security.*;
import java.util.Locale;
import java.util.UUID;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class DESUtil {
    private static final String Algorithm = "DESede/ECB/PKCS5Padding";// DESede/ECB/PKCS5Padding;DESede

    private static final String DESede = "DESede";

    /**
     * 3DES加密
     */
    public static byte[] encrypt(byte[] keybyte, byte[] src)
            throws NoSuchAlgorithmException, NoSuchPaddingException, Exception {
        SecretKey deskey = new SecretKeySpec(keybyte, DESede);
        Cipher c1 = Cipher.getInstance(Algorithm);
        c1.init(Cipher.ENCRYPT_MODE, deskey);
        return c1.doFinal(src);
    }

    /**
     * 3DES解密
     */
    public static byte[] decrypt(byte[] keybyte, byte[] src)
            throws NoSuchAlgorithmException, NoSuchPaddingException, Exception {
        SecretKey deskey = new SecretKeySpec(keybyte, DESede);
        Cipher c1 = Cipher.getInstance(Algorithm);
        c1.init(Cipher.DECRYPT_MODE, deskey);
        return c1.doFinal(src);
    }

    /**
     * 加密后的字节数组转成授权码
     */
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
     */
    public static byte[] hex2byte(String hexStr) {
        if (hexStr.length() % 2 != 0) {
            // AppLogger.error("hex2bytes's hexStr length is not even.");
            return null;
        }

        byte[] toBytes = new byte[hexStr.length() / 2];
        for (int i = 0, j = 0; i < hexStr.length(); j++, i = i + 2) {
            int tmpa = Integer.decode("0X" + hexStr.charAt(i) + hexStr.charAt(i + 1)).intValue();
            toBytes[j] = (byte) (tmpa & 0XFF);
        }
        return toBytes;
    }

    /**
     * 使用huaweimd5算法对原文密码进行运算
     */
    public static String getHuaweimd5Pwd(String plainPwd) throws NoSuchAlgorithmException {
        byte[] id = plainPwd.getBytes();
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(id);
        md.update("99991231".getBytes()); // “99991231” mentioned in XML-API
        byte[] buffer = md.digest();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < buffer.length; i++) {
            sb.append(Integer.toHexString((int) buffer[i] & 0xff));
        }
        // String md5Pwd = sb.substring(0, 8); // only use first 8 characters
        // return md5Pwd;
        return sb.toString();
    }

    /**
     * 获得DES运算之前的明文
     *
     * @throws Exception
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     */
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

        return new String(srcBytes);
    }

    /**
     * 计算授权码
     *
     * @param random
     * @param strEncryToken
     * @param userId
     * @param pwd
     * @param stbId
     * @param ip
     * @param mac
     * @param reserved
     * @return
     */
    public static String getAuthInfo(String random, String strEncryToken, String userId, String pwd, String stbId,
                                     String ip, String mac, String reserved) {
        String _Gb_inputStr = random + "$" + strEncryToken + "$" + userId + "$" + stbId + "$" + ip + "$" + mac + "$"
                + reserved;
        DESede des = new DESede();
        String auth = des.StringToHex(des.Triple_Des(pwd, _Gb_inputStr));
        return auth;
    }

    public static void main(String[] args) throws NoSuchPaddingException, Exception {
        // 解密
        String plainPwd = "21191917";
        //// String pwd = getHuaweimd5Pwd(plainPwd).substring(0,8);
        String authenticator = "04409CF4F6076B6E02F0C8BCE916F5C2509103D07CEE7F73A307A472CCA4C92E0C24C9749BEF3A247031A4684F13B112F430EB0221BD6E6170588F65F483F8561F3383DD03A60AE4B414878A1FD534BCAB37B1EEC2548E8528CBA4833C10DA94BD97B85E0724352344D264EE7DAB46EC726CF4110A69FD87C76D66C029E89B5AB394D5CEB9DBE861";
        System.out.println(getStringBeforeDes(authenticator, plainPwd));

        // //加密
        // String auth = getAuthInfo("91889",
        // "E9C89EDAE0351B1222D5F730D6D55F3C", "dsw1840887533501", "852077",
        // "0056030000010900000BC0132B23515D", "39.128.247.134",
        // "c0:13:2b:23:51:5d", "Reserved$OTT");
        // System.out.println(auth);
        //
        // System.out.println("0DDFE64073336F28E904134658327C33".toLowerCase());

//		for (int i = 0; i < 99999999; i++) {
//
//			String[] chars = new String[] { "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o",
//					"p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8",
//					"9", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S",
//					"T", "U", "V", "W", "X", "Y", "Z" };
//			StringBuffer shortBuffer = new StringBuffer();
//			String uuid = UUID.randomUUID().toString().replace("-", "");
//			for (int j = 0; j < 8; j++) {
//				String str = uuid.substring(j * 4, j * 4 + 4);
//				int x = Integer.parseInt(str, 16);
//				shortBuffer.append(chars[x % 0x3E]);
//			}
//			String suffix = shortBuffer.toString();
//			String plainPwd = "";
//			plainPwd = plainPwd + i;
//			int length = plainPwd.length();
//			plainPwd = insertZero(length, plainPwd);
        // System.out.println("plainPwdss "+plainPwd);


//			} catch (Exception e) {
//				// TODO: handle exception
//			}
//
//		}
    }

    public static String insertZero(int length, String string) {
        for (int i = 0; i < 6 - length; i++) {
            string = "0" + string;
        }
        return string;
    }

}

