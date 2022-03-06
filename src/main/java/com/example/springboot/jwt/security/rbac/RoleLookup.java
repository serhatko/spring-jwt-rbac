package com.example.springboot.jwt.security.rbac;

import java.util.ArrayList;
import java.util.List;

public class RoleLookup {
	
	
	public enum Roles {
	    ADMIN_ROLE(new Role(0, "adminRole", getAdminRolePrivileges())),
	    PRODUCT_VIEWER_ROLE(new Role(1, "productViewerRole", getProductViewerRolePrivileges())),
	    PRODUCT_WRITER_ROLE(new Role(2, "productWriterRole", getProductWriterRolePrivileges())),
	    PRODUCT_ORGINIZER_ROLE(new Role(3, "productOrganizerRole", getProductOrganizerRolePrivileges()));
		
	    private final Role value;

	    private Roles(Role role) {
	        this.value = role;
	    }
	    
	    public Role getValue() {
	    	return this.value;
	    }
	}
	
	private static List<Privilege> getAdminRolePrivileges() {
		List<Privilege> adminRolePrivileges = new ArrayList<>();
		adminRolePrivileges.add(PrivilegeLookup.Privileges.PRODUCTS_WRITE.getValue());
		adminRolePrivileges.add(PrivilegeLookup.Privileges.PRODUCTS_READ.getValue());
		adminRolePrivileges.add(PrivilegeLookup.Privileges.PRODUCTS_DELETE.getValue());
		return adminRolePrivileges;
	}
	private static List<Privilege> getProductViewerRolePrivileges(){
		List<Privilege> productViewerRolePrivileges = new ArrayList<>();
		productViewerRolePrivileges.add(PrivilegeLookup.Privileges.PRODUCTS_READ.getValue());
		return productViewerRolePrivileges;
	}
	private static List<Privilege> getProductWriterRolePrivileges(){
		List<Privilege> productWriterPrivileges = new ArrayList<>();
		productWriterPrivileges.add(PrivilegeLookup.Privileges.PRODUCTS_WRITE.getValue());
		productWriterPrivileges.add(PrivilegeLookup.Privileges.PRODUCTS_READ.getValue());
		return productWriterPrivileges;
	}
	private static List<Privilege> getProductOrganizerRolePrivileges(){
		List<Privilege> productOrganizerRolePrivileges = new ArrayList<>();
		productOrganizerRolePrivileges.add(PrivilegeLookup.Privileges.PRODUCTS_WRITE.getValue());
		productOrganizerRolePrivileges.add(PrivilegeLookup.Privileges.PRODUCTS_READ.getValue());
		productOrganizerRolePrivileges.add(PrivilegeLookup.Privileges.PRODUCTS_DELETE.getValue());
		return productOrganizerRolePrivileges;
	}

}