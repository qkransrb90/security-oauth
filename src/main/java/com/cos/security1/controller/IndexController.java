package com.cos.security1.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Controller
public class IndexController {
	
	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bcryptPasswordEncoder;
	
	@Autowired
	public IndexController(UserRepository userRepository, BCryptPasswordEncoder bcryptPasswordEncoder) {
		this.userRepository = userRepository;
		this.bcryptPasswordEncoder = bcryptPasswordEncoder;
	}
	
	@GetMapping("/test/login")
	@ResponseBody
	public String testLogin(Authentication authentication, @AuthenticationPrincipal PrincipalDetails userDetails) {
		System.out.println("/test/login =====================>>>");
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("authentication: " + principalDetails.getUser());
		System.out.println("userDetails: " + userDetails.getUser());
		return "session 정보 확인";
	}
	
	@GetMapping("/test/oauth/login")
	@ResponseBody
	public String testOAuthLogin(Authentication authentication, @AuthenticationPrincipal OAuth2User oauth) {
		System.out.println("/test/oauth/login =====================>>>");
		OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
		System.out.println("authentication: " + oauth2User.getAttributes());
		System.out.println("oauth2User: " + oauth.getAttributes());
		return "oauth2-session 정보 확인";
	}

	@GetMapping({"", "/"})
	public String index() {
		return "index";
	}
	
	@GetMapping("/user")
	@ResponseBody
	public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
		System.out.println("##principalDetails: " + principalDetails.getUser());
		return "user";
	}
	
	@GetMapping("/admin")
	@ResponseBody
	public String admin() {
		return "admin";
	}
	
	@GetMapping("/manager")
	@ResponseBody
	public String manager() {
		return "manager";
	}
	
	@GetMapping("/loginForm")
	public String loginForm() {
		return "loginForm";
	}
	
	@GetMapping("/joinForm")
	public String joinForm() {
		return "joinForm";
	}
	
	@PostMapping("/join")
	public String join(@ModelAttribute User user) {
		user.setRole("ROLE_USER");
		user.setPassword(bcryptPasswordEncoder.encode(user.getPassword()));;
		userRepository.save(user);
		return "redirect:/loginForm";
	}
	
	@GetMapping("/info")
	@ResponseBody
	@Secured("ROLE_ADMIN")
	public String info() {
		return "private information";
	}
	
	@GetMapping("/data")
	@ResponseBody
	@PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
	public String data() {
		return "private data";
	}
}
