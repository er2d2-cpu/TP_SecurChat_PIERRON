import logging
import base64
import dearpygui.dearpygui as dpg
from cryptography.fernet import Fernet
from hashlib import sha256
from CipheredGUI import CipheredGUI

class FernetGUI(CipheredGUI):  
    def __init__(self) -> None:
        super().__init__()  # Initialisation de la classe parente
        self._key = None  # La clé sera définie après la connexion

    def run_chat(self, sender, app_data) -> None:
        # Surcharge la méthode pour dériver la clé spécifiquement pour Fernet
        password = dpg.get_value("connection_password").encode("utf-8")
        
        # Génération de la clé en utilisant SHA256, puis encodage en base64
        key_hash = sha256(password).digest()
        self._key = base64.urlsafe_b64encode(key_hash)
        
        # Appel de la méthode parente pour poursuivre la logique de connexion
        super().run_chat(sender, app_data)

    def encrypt(self, plaintext: str) -> str:
        fernet = Fernet(self._key)  # Initialisation de l'instance Fernet avec la clé
        encrypted_message = fernet.encrypt(plaintext.encode("utf-8"))  # Chiffrement du message
        return encrypted_message.decode("utf-8")  # Retourne le message chiffré sous forme de chaîne

    def decrypt(self, encrypted: str) -> str:
        fernet = Fernet(self._key)  # Initialisation de l'instance Fernet avec la clé
        try:
            decrypted_message = fernet.decrypt(encrypted.encode("utf-8"))  # Déchiffrement du message
            return decrypted_message.decode("utf-8")  # Retourne le message déchiffré sous forme de chaîne
        except Exception as e:
            self._log.error(f"Erreur lors du déchiffrement : {e}")  # Journalise l'erreur
            return "[Erreur de déchiffrement]"  # Retourne un message d'erreur

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)  # Configuration du logging
    client = FernetGUI()  # Création d'une instance de FernetGUI
    client.create()  # Création de l'interface
    client.loop()  # Démarrage de la boucle principale
