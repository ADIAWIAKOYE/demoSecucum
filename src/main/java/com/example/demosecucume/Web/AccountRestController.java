package com.example.demosecucume.Web;

import com.example.demosecucume.Entities.AppRole;
import com.example.demosecucume.Entities.AppUser;
import com.example.demosecucume.Repository.AppRoleRepo;
import com.example.demosecucume.service.AccountService;
import lombok.Data;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/colaborateur")
public class AccountRestController {

    private AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }
    @GetMapping("/afficheruser")
    @PreAuthorize("hasAuthority('SCOPE_USER') or hasAuthority('SCOPE_ADMIN')")
    public List<AppUser> appUsers(){

        return accountService.afficherUser();
    }

    @PostMapping("/saveusers")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public AppUser saveUser(Authentication authentication, @RequestBody AppUser appUser){

        return accountService.addUser(appUser);
    }

    @PostMapping("/saverole")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public AppRole saveRole(Authentication authentication, @RequestBody AppRole appRole){

        return accountService.addRole(appRole);
    }

    @PostMapping("/addRoleToUser")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public void addRoleToUser(Authentication authentication, @RequestBody RoleUserForm roleUserForm){

         accountService.addRoleToUser(roleUserForm.getNom(), roleUserForm.getNomrole());
    }
}

@Data
class RoleUserForm{
    private String nom;
    private String nomrole;
}