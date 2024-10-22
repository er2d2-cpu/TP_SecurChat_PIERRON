import time
import logging
from cryptography.fernet import Fernet, InvalidToken
import base64
import dearpygui.dearpygui as dpg
from hashlib import sha256
from FernetGUI import FernetGUI

class TimeFernetGUI(FernetGUI):
    def __init__(self) -> None:
        super().__init__()  # Appel au constructeur de la classe parente
        self._ttl = 30  # Durée de vie du message en secondes

    def encrypt(self, plaintext: str) -> bytes:
        # Chiffrement du message avec une durée de vie (TTL)
        current_time = int(time.time())
        return self._fernet.encrypt_at_time(plaintext.encode('utf-8'), current_time, self._ttl)

    def decrypt(self, token: bytes) -> str:
        try:
            # Déchiffrement du message avec vérification de la durée de vie
            current_time = int(time.time())
            return self._fernet.decrypt_at_time(token, current_time).decode('utf-8')
        except InvalidToken as e:
            # Journalisation d'une erreur en cas d'expiration du TTL
            logging.error(f"Erreur de déchiffrement : {e}")
            return "[Message expiré ou invalide]"  # Retourne un message d'erreur en cas de problème

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)  # Configuration du niveau de logging
    client = TimeFernetGUI()  # Création d'une instance de TimeFernetGUI
    client.create()  # Initialisation de l'interface graphique
    client.loop()  # Démarrage de la boucle principale
