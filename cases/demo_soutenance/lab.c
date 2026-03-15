#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void open_vault() {
    printf("\n[!!!] ALERTE DE SECURITE : DETOURNEMENT DE FLUX DETECTE [!!!]\n");
    printf("[+] Acces Administrateur Accorde. Ouverture du shell root...\n");
    system("/bin/sh");
}

void check_auth() {
    char pin[64];
    printf("--- SYSTEME HAUTE SECURITE TDS GLOBAL ---\n");
    printf("Veuillez entrer votre code PIN d'acces : ");
    
    // La nouvelle faille (scanf ne vérifie pas la taille de l'entrée !)
    scanf("%s", pin); 
    
    printf("Verification du code '%s'... ACCES REFUSE.\n", pin);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    
    check_auth();
    
    return 0;
}
