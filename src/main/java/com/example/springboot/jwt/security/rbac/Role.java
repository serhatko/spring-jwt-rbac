package com.example.springboot.jwt.security.rbac;

import java.util.List;

public class Role {
	private int id;
	private String name;
	private List<Privilege> privileges;
	public Role(int id, String name, List<Privilege> privileges) {
		super();
		this.id = id;
		this.name = name;
		this.privileges = privileges;
	}
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public List<Privilege> getPrivileges() {
		return privileges;
	}
	public void setPrivileges(List<Privilege> privileges) {
		this.privileges = privileges;
	}
	
	
	@Override
	public String toString() {
		return name;
		
	}
	
	

}
