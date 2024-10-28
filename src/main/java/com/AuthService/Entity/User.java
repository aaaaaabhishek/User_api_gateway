package com.AuthService.Entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class User {
    public String user_id;
    public String user_name;
    public String adress;
    public String accounttype;
    public String password;
    public String email;
    public Set<Role> role;
}