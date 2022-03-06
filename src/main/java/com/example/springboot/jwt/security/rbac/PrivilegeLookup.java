package com.example.springboot.jwt.security.rbac;

import org.springframework.stereotype.Component;

@Component("privilegeLookup")
public class PrivilegeLookup {
	
	public enum Privileges {
	    PRODUCTS_READ(new Privilege(0,"PRODUCTS_READ")),
	    PRODUCTS_WRITE(new Privilege(1,"PRODUCTS_WRITE")),
	    PRODUCTS_DELETE(new Privilege(2,"PRODUCTS_DELETE"));
		
	    private final Privilege value;

	    private Privileges(Privilege privilege) {
	        this.value = privilege;
	    }
	    
	    public Privilege getValue() {
	    	return this.value;
	    }
	}

}
