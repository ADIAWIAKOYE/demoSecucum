package com.example.demosecucume.Web;

import com.example.demosecucume.Entities.AppRole;
import com.example.demosecucume.Entities.AppUser;
import com.example.demosecucume.Repository.AppRoleRepo;
import com.example.demosecucume.service.AccountService;
import lombok.Data;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class AccountRestController {

    private AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }
    @GetMapping("/user")
    @PreAuthorize("hasAuthority('SCOPE_USER') or hasAuthority('SCOPE_ADMIN')")
    public List<AppUser> appUsers(){

        return accountService.afficherUser();
    }

    @PostMapping("/saveusers")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser){

        return accountService.addUser(appUser);
    }

   /* @PostMapping("/saveusers")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole){

        return accountService.addRole(appRole);
    }

    @PostMapping("/addRoleToUser")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm){

         accountService.addRoleToUser(roleUserForm.getNom(), roleUserForm.getNomrole());
    }*/
}

/*@Data
class RoleUserForm{
    private String nom;
    private String nomrole;
}*/