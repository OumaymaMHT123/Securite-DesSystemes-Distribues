# Securite-DesSystemes-Distribues

Partie 1 : Configuration de l'environnment


1. Création d'un nouveau realm "wallet-realm"
   
Un realm dans Keycloak est équivalent à un locataire. Chaque realm permet à un administrateur de créer des groupes isolés d'applications et d'utilisateurs. Initialement, Keycloak inclut un seul realm, appelé "master".
Voici les etapes a suivre pour créer le premier realm.

 -Ouvrez la console d'administration Keycloak.
 -Cliquez sur le mot "master" dans le coin supérieur gauche, puis cliquez sur "Create Realm" (Créer un royaume).
 -Entrez "myrealm" dans le champ "Realm name" (Nom du royaume).

   <img width="435" alt="image" src="https://github.com/OumaymaMHT123/Securite-DesSystemes-Distribues/assets/95369549/2882bf18-c9fd-413c-b030-697efa26f4ee">

2. Création d'un user

   les eapes a suivre pour créer un utilisateur :
 -Ouvrez la console d'administration Keycloak.
 -Cliquez sur le mot "master" dans le coin supérieur gauche, puis cliquez sur "myrealm".
 -Cliquez sur "Users" dans le menu de gauche.
 -Cliquez sur "Add user" (Ajouter un utilisateur).
 -Remplissez le formulaire avec les valeurs suivantes :
    Nom d'utilisateur : user1
    Prénom : n'importe quel prénom
    Nom de famille : n'importe quel nom de famille
 -Cliquez sur "Create" (Créer).

<img width="530" alt="image" src="https://github.com/OumaymaMHT123/Securite-DesSystemes-Distribues/assets/95369549/81b6c3c9-e6f1-4b86-9b3d-b59dd070b2ad">


   3. Création d'un nouveau client "wallet-client"

   <img width="555" alt="image" src="https://github.com/OumaymaMHT123/Securite-DesSystemes-Distribues/assets/95369549/0c09ace7-ccfc-46dc-afe4-79ceca5fb4d8">

<img width="588" alt="image" src="https://github.com/OumaymaMHT123/Securite-DesSystemes-Distribues/assets/95369549/6a911d9a-d1fe-481d-b310-9017bd73ae09">

4. Test sur Postman
- 1er test
<img width="564" alt="image" src="https://github.com/OumaymaMHT123/Securite-DesSystemes-Distribues/assets/95369549/a2d75867-acd8-4993-aa73-f44ea07607dd">

<img width="553" alt="image" src="https://github.com/OumaymaMHT123/Securite-DesSystemes-Distribues/assets/95369549/c9cdd681-8256-4b72-96e0-def02be7d57e">

- 2eme test
<img width="550" alt="image" src="https://github.com/OumaymaMHT123/Securite-DesSystemes-Distribues/assets/95369549/d7864f3c-7d01-4261-8f0b-612944d662c4">

- 3eme test

  <img width="459" alt="image" src="https://github.com/OumaymaMHT123/Securite-DesSystemes-Distribues/assets/95369549/4584aa2a-e03e-45fa-96bb-8caac73313ed">


Partie 2: Sécurite
1. E-Bank
   -Configuration "application.properties"

keycloak.realm=wallet-realm 
keycloak.resource=wallet-client
keycloak.bearer-only=true 
keycloak.auth-server-url=http://Localhost:8080
keycloak.ssl-required=none

  -Dependancies
  
  <dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>org.keycloak</groupId>
			<artifactId>keycloak-spring-boot-starter</artifactId>
			<version>19.0.2</version>
		</dependency>


  - Descativation du SSL
    <img width="536" alt="image" src="https://github.com/OumaymaMHT123/Securite-DesSystemes-Distribues/assets/95369549/5486cb01-6cfa-4aa1-a78b-bdf3e44309a0">
   


  - Creation du package security

    @Configuration
public class KeycloakAdapterConfig {
    @Bean
    KeycloakSpringBootConfigResolver springBootConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }
}


@KeycloakConfiguration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends KeycloakWebSecurityConfigurerAdapter {
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Override
    protected void configure(org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(keycloakAuthenticationProvider());
    }

    @Override
    protected void configure(org.springframework.security.config.annotation.web.builders.HttpSecurity http) throws Exception {
        super.configure(http);
        http.csrf().disable();
        http.authorizeRequests().anyRequest().authenticated();
    }
}

<img width="328" alt="image" src="https://github.com/OumaymaMHT123/Securite-DesSystemes-Distribues/assets/95369549/91c1d5c3-0c9e-480b-93fc-00b6e3582d7d">

  2. Wallet-Service
  -Depandencies

npm install keycloak-angular keycloak-js --force
```bash
  2. security.guard.ts


```bash
import { Injectable } from '@angular/core';
import {
  ActivatedRouteSnapshot,
  Router,
  RouterStateSnapshot
} from '@angular/router';
import { KeycloakAuthGuard, KeycloakService } from 'keycloak-angular';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard extends KeycloakAuthGuard {
  constructor(
    protected override readonly router: Router,
    protected readonly keycloak: KeycloakService
  ) {
    super(router, keycloak);
  }

  public async isAccessAllowed(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ) {
    if (!this.authenticated) {
      await this.keycloak.login({
        redirectUri: window.location.origin
      });
    }

    const requiredRoles = route.data['roles'];
    if (!Array.isArray(requiredRoles) || requiredRoles.length === 0) {
      return true;
    }

    return requiredRoles.every((role) => this.roles.includes(role));
  }
}




export function KcFactory(KcService : KeycloakService){
 return ()=>{
   KcService.init({
     config :{
       realm :"wallet-realm",
       clientId :"wallet-client",
       url :"http://localhost:8080"
     },
     initOptions : {
       onLoad :"check-sso",
       checkLoginIframe: true
     }
   })
 }
}



