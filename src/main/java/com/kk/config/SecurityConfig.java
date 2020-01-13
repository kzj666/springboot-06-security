package com.kk.config;

/*
@author kzj
@date 2020/1/5 - 14:38
*/

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

//AOP
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //授权
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //首页所有人可以访问，但是功能页只有有权限的人才能访问
        //请求授权的规则
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3")
                .antMatchers("/level0/**").hasRole("vip0");

        //没有权限默认会到登录页面,需要开启登录的页面
        //这是使用spring默认的登录页面
//        http.formLogin();//查看源码注释，可知默认是请求/login，即spring的默认页面

        //定制登录页面
        http.formLogin().loginPage("/toLogin");//此处的参数/toLogin必须跟form表单提交的action地址一致

        //如果form表单的action地址是 login ,与此处的loginPage地址不一致，可通过loginProcessingUrl属性设置
//        http.formLogin().loginPage("/toLogin").loginProcessingUrl("login");
        /*这里的loginPage()是跳到登录页面的请求，后面的loginProcessingUrl是form提交登录的请求*/
        //表示表单请求的action地址是login，但是loginPage("/toLogin")的请求是/toLogin

        //当表单中的name属性不为默认的username和password时，需要配置一下
        //.usernameParameter("user")和.passwordParameter("pwd")设置表单中属性name的值，默认为username和password，如有不同需配置
        //http.formLogin().loginPage("/toLogin").usernameParameter("user").passwordParameter("pwd").loginProcessingUrl("/login");


        //开启了注销功能，跳到首页,默认是/logout请求
        http.logout().logoutSuccessUrl("/");

        //登出时是get方式，为了防止网站攻击，spring开启了防止跨站请求攻击，这里需要关闭
        http.csrf().disable();//关闭csrf功能

        //开启记住我功能
        http.rememberMe().rememberMeParameter("remember");//默认保存两周


    }

    //认证
    //密码编码：PasswordEncoder
    //在Spring Security 5.0+ 新增了很多加密方法,密码必须加密
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        //正常的话该从数据库中拿，这里是在内存中拿
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("kk").password(new BCryptPasswordEncoder().encode("123")).roles("vip1","vip2","vip3","vip0")
                .and()
                .withUser("ll").password(new BCryptPasswordEncoder().encode("123")).roles("vip2","vip3","vip0")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123")).roles("vip1","vip0");
        //从数据库中查出
        //auth.jdbcAuthentication()...
    }
}

