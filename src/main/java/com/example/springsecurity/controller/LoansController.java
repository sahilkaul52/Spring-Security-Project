package com.example.springsecurity.controller;

import com.example.springsecurity.model.Loans;
import com.example.springsecurity.repository.LoanRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class LoansController {

    @Autowired
    private LoanRepository loanRepository;

    @GetMapping("/myLoans")
    @PostAuthorize("hasRole('USER')") // method ka result tabhi return hoga if user has that role warna 403 error
    public List<Loans> getLoanDetails(@RequestParam int id) {
        List<Loans> loans = loanRepository.findByCustomerIdOrderByStartDtDesc(id);
        if(loans != null ) {
            return loans;
        }else {
            return null;
        }
    }

}
