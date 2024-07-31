package com.EcomVerse.user_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class UserServiceApplication {

	public static void main(String[] args) {

		SpringApplication.run(UserServiceApplication.class, args);
		PasswordEncoder encoder = new BCryptPasswordEncoder();
		String encodedPassword = encoder.encode("Shubhendu@123");
		System.out.println("encodedPassword: "+encodedPassword);
	}

}
