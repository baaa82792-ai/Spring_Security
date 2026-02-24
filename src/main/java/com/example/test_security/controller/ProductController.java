package com.example.test_security.controller;

import com.example.test_security.entities.Product;
import com.example.test_security.repository.ProductRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController

@RequestMapping("/api/products")
public class ProductController {

    private final ProductRepository repository;

    public ProductController(ProductRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    // Tout le monde (USER et ADMIN) peut voir les produits
    @PreAuthorize("hasAnyAuthority('SCOPE_ROLE_USER', 'SCOPE_ROLE_ADMIN')")
    public List<Product> getAll() {
        return repository.findAll();
    }

    @PostMapping
    // Seul l'ADMIN peut ajouter un produit
    @PreAuthorize("hasAuthority('SCOPE_ROLE_ADMIN')")
    public Product create(@RequestBody Product product) {
        return repository.save(product);
    }
}