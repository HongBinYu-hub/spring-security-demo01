package com.example.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.sql.DataSource;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    //授权规则
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //首页所有人能访问，功能页只有对应权限才能访问
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");
        //没有权限自动跳转登录页面,需要开启登录页面
        http.formLogin();
        //注销
        http.logout().logoutSuccessUrl("/");
        //记住我
        http.rememberMe();
        //更改默认登录界面
        http.formLogin().loginPage("/toLogin");
    }
    //认证
    //密码需要进行加密
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("liziqi").password(new BCryptPasswordEncoder().encode("3333")).roles("vip1","vip2")
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("3333")).roles("vip1","vip2","vip3")
                .and()
                .withUser("student").password(new BCryptPasswordEncoder().encode("3333")).roles("vip1");
    }
}
