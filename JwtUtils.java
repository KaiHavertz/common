package org.jnr.regcal.utils.jwt;

import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson.JSONObject;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import org.jnr.regcal.entity.Subscriber;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.util.Calendar;

/**
 * JWT凭证验证工具
 *
 * @author LuoJianXing
 */
public class JwtUtils {

    private static Algorithm ALGORITHM;
    /**
     * token名
     */
    public static final String Token_Name = "j-token";

    static {
        try {
            ALGORITHM = Algorithm.HMAC256("jnr");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }


    /**
     * 登录Token有效期
     */
    public static final Integer VALID_SECONDS = 3600 * 10;

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);


    /**
     * 编码登录用户
     *
     * @param subscriber
     * @param validSecond
     * @return
     */
    public static String encodeToken(Subscriber subscriber, int validSecond) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, validSecond);

        JSONObject obj = new JSONObject();
        obj.put("account", subscriber.getAccount());
        obj.put("usertype", subscriber.getUserType());
        String token = JWT.create()
                .withClaim("subscriber", obj.toJSONString())//生成携带自定义信息
                .withExpiresAt(calendar.getTime())//设置 载荷 签名过期的时间
                .withIssuer("SERVICE")// 签名是有谁生成 例如 服务器
                .withSubject("this is test token")// 签名的主题
                .withAudience("APP")// 签名的观众 也可以理解谁接受签名的
                .sign(ALGORITHM);//签名

        return token;
    }


    public static String encodeToken(Subscriber user) {
        return encodeToken(user, VALID_SECONDS);
    }

    /**
     * 解码登录用户
     *
     * @param token
     * @return
     */
    public static Subscriber decodeToken(String token) {
        DecodedJWT decodedJWT = JWT.decode(token);
        String userStr = decodedJWT.getClaim("subscriber").as(String.class);
        return JSONObject.parseObject(userStr, Subscriber.class);
    }


    /**
     * 验证JWT Token
     *
     * @param token
     * @return
     */
    public static boolean validToken(String token) {
        if (StrUtil.isEmpty(token)) {
            return false;
        }
//        return JWT.decode(token).getExpiresAt().after(Calendar.getInstance().getTime());
        try {
            Subscriber subscriber = decodeToken(token);
            JSONObject obj = new JSONObject();
            obj.put("account", subscriber.getAccount());
            obj.put("usertype", subscriber.getUserType());
            JWTVerifier verifier = JWT.require(ALGORITHM)
                    .withClaim("subscriber", obj.toJSONString())
                    .build();
            verifier.verify(token);
            //验证失败会抛出异常
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            logger.error("验证失败");
            return false;
        }
    }


    //编码api方式登录用户
    public static String encode(String openid, int validSecond) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, validSecond);
        return JWT.create()
                .withClaim("openid", openid)
                .withExpiresAt(calendar.getTime()).sign(ALGORITHM);
    }


    //解码api方式登录用户
    public static String decode(String token) {
        DecodedJWT decodedJWT = JWT.decode(token);
        return decodedJWT.getClaim("openid").as(String.class);
    }


}