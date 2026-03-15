#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int system_ready = 0; // Variable globale de sécurité

// Fonction 1 : Doit être appelée en premier
void prepare_system() {
    printf("\n[*] Etape 1 : Initialisation des systemes validee...\n");
    system_ready = 1;
}

// Fonction 2 : Doit être appelée en second
void open_vault() {
    if (system_ready == 1) {
        printf("[!!!] Etape 2 : ACCES AUTORISE. Ouverture du shell root...\n");
        system("/bin/sh");
    } else {
        printf("\n[X] ERREUR FATALE : Le systeme n'est pas pret ! Echec.\n");
        exit(1);
    }
}

void read_profile() {
    char buffer[64];
    printf("=== SYSTEME A DOUBLE VERIFICATION ===\n");
    printf("Saisissez la cle de diagnostic : ");
    
    // Faille critique de lecture
    read(0, buffer, 256);
    
    printf("Cle traitee.\n");
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    read_profile();
    return 0;
}
