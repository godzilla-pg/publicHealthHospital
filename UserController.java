package com.zxd.controller;

import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.zxd.enums.ResultCode;
import com.zxd.model.requestVo.LoginVo;

import com.zxd.model.result.Result;
import com.zxd.model.user.User;
import com.zxd.service.LoginService;
import com.zxd.service.UserService;
import com.zxd.shiro.JWTsToken;
import com.zxd.shiro.ThreadLocalToken;
import com.zxd.utils.JwtUtils;
import com.zxd.utils.RedisUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.DigestUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;

/**
 * @Description TODO
 * @Author ZXD
 * @Date 2022/4/19 16:59
 * @Version 1.0
 **/
@Slf4j
@RestController
@RequestMapping("/api")
public class UserController {
    private static Logger logger = LoggerFactory.getLogger(UserController.class);
    @Autowired
    UserService userService;

    @Autowired
    LoginService loginService;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    RedisUtils redisUtils;

    @Autowired//引入媒介类，获取里面的令牌
    private ThreadLocalToken threadLocalToken;

    //缓存中存取的时间
    @Value("${emos.jwt.cache-expire}")
    private int cacheExpire;

    @PostMapping("/checkUser")
    public Result getUserByAccount(@RequestParam("phoneNumber") String phoneNumber) {
        Result userResult = userService.getUserByAccount(phoneNumber);
        return userResult;
    }

    @PostMapping("/register")
    public Result Register(@RequestBody User user) {
        Result userResult = loginService.Register(user);
        return userResult;
    }


    // 登录
    @PostMapping ("/login")
//    @RequiresRoles(value = {"user","guest"},logical=Logical.OR)
    public Object login(@RequestBody LoginVo loginVo, HttpServletRequest request) {
        Result resultMes = new Result();

        try {
            Map<String, String> loginMd5Map = new HashMap<>();
            loginMd5Map.put("password", DigestUtils.md5DigestAsHex(loginVo.getPassword().getBytes()));

            String account = loginVo.getPhoneNumber();
            String passwd = loginMd5Map.get("password");
            Result checkAccount = userService.getUserByAccount(loginVo.getPhoneNumber());
            Result accountMsg  = userService.getUserList(loginVo.getPhoneNumber(),passwd);

            String passCode  = userService.getUserList(loginVo.getPhoneNumber(),passwd).getCode();

            if(passCode.equals("200")){
                String Msg = checkAccount.getMsg();
                Map<String,Object> statusMap = (Map<String,Object>)checkAccount.getData();
                // 只有两种情况(缓存令牌是客户端令牌存活时间的2倍)，一种是缓存令牌没失效，客户端失效 第二种 缓存令牌、客户端令牌都失效
                String localTokenToken = request.getHeader("token");
                if(redisUtils.hasKey("token:" + loginVo.getPhoneNumber()) && !StrUtil.isBlank(localTokenToken)){   //缓存中令牌没有失效，客户端没有失效
                    threadLocalToken.setToken(localTokenToken);
                    String token = threadLocalToken.getToken();
                    resultMes.StrResult("登录成功",ResultCode.SUCCESS.code(),statusMap,token,true);
                }else if (redisUtils.hasKey("token:" + account) && StrUtil.isBlank(localTokenToken)) { //缓存中令牌没有失效，客户端失效
                    String token = jwtUtils.generateToken(account);
                    //客户端token
                    threadLocalToken.setToken(token);

                    resultMes.StrResult("登录成功",ResultCode.SUCCESS.code(),statusMap,token,true);

                    logger.info("用户: {}，新token令牌: {},",loginVo.getPhoneNumber(),token);
                }else if (!redisUtils.hasKey("token:" + account) && StrUtil.isBlank(localTokenToken)) { //缓存中令牌失效，客户端失效，从新生成
                    String token = jwtUtils.generateToken(account);//电话号码来生成Token
                    Map<String, Object> tokenPhoneNumberMap = new HashMap<>();
                    tokenPhoneNumberMap.put(loginVo.getPhoneNumber(), token);
                    //缓存token
                    redisUtils.set("token:" + loginVo.getPhoneNumber(),JSON.toJSONString(tokenPhoneNumberMap), cacheExpire);
                    //客户端token
                    threadLocalToken.setToken(token);
                    resultMes.StrResult("登录成功",ResultCode.SUCCESS.code(),statusMap,token,true);
                }
            }else{
                return  accountMsg;
            }

//            if (Msg != null && Msg.equals("用户账号存在")) {
//                resultMes = userService.getUserList(account, passwd);
//                if (Objects.equals(resultMes.getCode(), ResultCode.UNAUTHORIZED.code())) {
//                    resultMes.setToken("用户登录失败,token令牌无效");
//                }
//                else if (Objects.equals(resultMes.getCode(), ResultCode.LOCKED.code())) {//用户status 为-1 表示账户锁定
//                    resultMes.setToken("用户被锁定...");
//                }
//                else {
//                    // 只有两种情况(缓存令牌是客户端令牌存活时间的2倍)，一种是缓存令牌没失效，客户端失效 第二种 缓存令牌、客户端令牌都失效
//                    String localTokenToken = request.getHeader("token");
//                    if(redisUtils.hasKey("token:" + loginVo.getPhoneNumber()) && !StrUtil.isBlank(localTokenToken)){   //缓存中令牌没有失效，客户端没有失效
//                        threadLocalToken.setToken(localTokenToken);
//                        String token = threadLocalToken.getToken();
//                        resultMes.StrResult("登录成功",ResultCode.SUCCESS.code(),statusMap,token,true);
//                    }else if (redisUtils.hasKey("token:" + account) && StrUtil.isBlank(localTokenToken)) { //缓存中令牌没有失效，客户端失效
//                        String token = jwtUtils.generateToken(account);
//                        //客户端token
//                        threadLocalToken.setToken(token);
//
//                        resultMes.StrResult("登录成功",ResultCode.SUCCESS.code(),statusMap,token,true);
//
//                        //logger.info("用户: {}，新token令牌: {},",loginVo.getPhoneNumber(),token);
//                    }else if (!redisUtils.hasKey("token:" + account) && StrUtil.isBlank(localTokenToken)) { //缓存中令牌失效，客户端失效，从新生成
//                        String token = jwtUtils.generateToken(account);//电话号码来生成Token
//                        Map<String, Object> tokenPhoneNumberMap = new HashMap<>();
//                        tokenPhoneNumberMap.put(loginVo.getPhoneNumber(), token);
//                        //缓存token
//                        redisUtils.set("token:" + loginVo.getPhoneNumber(),JSON.toJSONString(tokenPhoneNumberMap), cacheExpire);
//                        //客户端token
//                        threadLocalToken.setToken(token);
//                        resultMes.StrResult("登录成功",ResultCode.SUCCESS.code(),statusMap,token,true);
//                    }

//                }
//            } else {
//                resultMes.StrResult("用户不存在，请检查账号是否正确...",ResultCode.FAIL.code(),"","",false);
//            }
        } catch (Exception e) {
            e.printStackTrace();
            resultMes.StrResult("登录失败" + e.getMessage(),ResultCode.FAIL.code(),"","",false);
        }

         return resultMes;
    }

    /***
     * 这个请求需要验证token才能访问
     *
     * @author: MRC
     * @date 2019年5月27日 下午5:45:19
     * @return String 返回类型
     */
//    @UserLoginToken
//    @GetMapping("/getMessage")
//    public String getMessage() {
//
//        // 取出token中带的用户id 进行操作
//        System.out.println(TokenUtil.getTokenUserId());
//
//        return "你已通过验证";
//    }

}
