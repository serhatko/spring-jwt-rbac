package com.example.springboot.jwt.security.rbac;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import com.example.springboot.jwt.security.rbac.RoleLookup.Roles;

@Component("customRbacAuthorizationHandler")
public class CustomRbacAuthorizationHandler {

	public boolean isPrivilegeAssigned(String privilege) {
		if (SecurityContextHolder.getContext().getAuthentication().isAuthenticated()) {
			for (GrantedAuthority g : SecurityContextHolder.getContext().getAuthentication().getAuthorities()) {
				for (Roles r : RoleLookup.Roles.values()) {
					if (r.getValue().toString().equals(g.getAuthority())) {
						return r.getValue().getPrivileges().stream().anyMatch(x -> x.getName().equals(privilege));
					}
				}
			}
		}
		return false;
	}
}