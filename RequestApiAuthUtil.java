
public class RequestApiAuthUtil {

    static final Base64.Encoder encoder = Base64.getEncoder();

    /**
     * 请求授权码加密算法
     *
     * @param publicKey  公钥
     * @param privateKey 私钥
     * @param timestamp  时间戳
     */
    public static String ecode(String publicKey, String privateKey, Long timestamp) {
        String authCode = "";
        try {
            authCode = encoder.encodeToString(HmacSHA1Encrypt(publicKey, privateKey + timestamp.toString()));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return authCode;
    }


    private static final String MAC_NAME = "HmacSHA1";
    private static final String ENCODING = "UTF-8";

    public static byte[] HmacSHA1Encrypt(String encryptText, String encryptKey) throws Exception {
        byte[] data = encryptKey.getBytes(ENCODING);
        // 根据给定的字节数组构造一个密钥,第二参数指定一个密钥算法的名称
        SecretKey secretKey = new SecretKeySpec(data, MAC_NAME);
        // 生成一个指定 Mac 算法 的 Mac 对象
        Mac mac = Mac.getInstance(MAC_NAME);
        // 用给定密钥初始化 Mac 对象
        mac.init(secretKey);

        byte[] text = encryptText.getBytes(ENCODING);
        // 完成 Mac 操作
        return mac.doFinal(text);
    }
}
