
### core.ghost.htb / Port 8443 SSL

![image-center](/assets/images/{E77ABBF2-F74C-4507-B01E-CF19C91266E0}.png)

Haciendo click en el boton , nos redirige a un nuevo subdominio.

```bash
https://federation.ghost.htb/adfs/ls/?SAMLRequest=nVNNc9owEP0rHt3xF4YQDSZDzaHMpIkH3B566cjSOnhGllztOiH%2FPmODEw4tB656u2%2Ffvn1aPhwb7b2Cw9qalEV%2ByB5WSxSNbvm6o4PZwd8OkLxjow3yAUhZ5wy3AmvkRjSAnCTfr3888tgPeessWWk187ablP0Jq7vyflGVoYqm8UKoqYxKuI%2FnFcwUJFNQ1bwsBcyZ92sUEfsh87aIHWwNkjCUsjiMZ5MomkRRESY8Svgs9Od38W%2Fm5edx32qjavNyXVt5KkL%2BvSjySf68L5i3AaTaCBpGH4ha5EFQgQI3vPkvB4vkH6gMhKow0Bgwb40Irkcza7BrwO3BvdYSfu4evzikdfDVzRdJMj1R9CYGrUXaAbbWILCT43zY2V1YfX0bMapgqyszl8EF93jaJ9HAdpNbXcv3W0671tq%2BZQ4EQcrIdcCCkfocGFBDfDJrCI43xSezTStcjf1d4CgkjTZdEmdaIO6gusW0q2WSy54akOcC8c061ScNJIEqnDDYWkdna%2F%2BlZ3XC%2FmPHJ3r5xVYf&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256&Signature=cWdHoPH4c4NPjf4euLsyaUYfg3eRMw8fUx0nfQ1%2FjFus3jPUOLL2ctGzaV4hLXF%2BKZrt3n5XhgkytrP9i%2BXGCPf2B5I5oYSX5z5yCO7IeHy0cHfUFlWB6iGUByxOhke%2Bv0%2FLNzk0tjDu01B9KgCorblg60IhkhKu%2BFkeTUgPxZKSe%2FpAMEqwwyH8JpzrzYvniegcIG%2BEvRQrvXlqnPjd6UvceAMiEV8akSwBnxkbRRYjunejmP%2F%2BthgSK96xvYcvftJ2YLM%2FVijAb6J3F6KFnfkReNWmShHENvk39HpYI3KIMlxYplneSejHbBePJ2DZ%2BMP9hQJL%2BhXhpbyZictMHw%3D%3D
```

Lo agrego al `/etc/hosts` para que mi maquina pueda resolver a la `ip`.

### federation.ghost.htb

Lo que veo es un panel de login.

![image-center](/assets/images/{5899B2B9-BA7B-4942-AFD4-B9A2F44AFEDF}.png)

Al parecer el mismo tiene una validacion en cuanto a la representacion del usuario validando que tenga un formato asi: `user\domain.com`

![image-center](/assets/images/{4B73EC6A-8415-485E-9B68-2712280644C7}.png)

Debido a que es una maquina `Windows` y emplea `ldap`, podría en el panel de login intentar `Inyecciones LDAP` como en el siguiente ejemplo:

```bash
username=administrator)(description=a*
```

Puedo ver un error distinto al que si ingreso un formato común de `user/password`.

![image-center](/assets/images/{2309F7C1-6FE4-4D12-B5E2-4200EBDC0CDE}.png)



## Shell as 

## Shell as 

## Shell as 
