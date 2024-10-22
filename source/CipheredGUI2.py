import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from os import urandom
from base64 import urlsafe_b64encode

import dearpygui.dearpygui as dpg
from basic_gui import BasicGUI

# Constants
SALT = b'salt_value'  # Utiliser un salt constant pour le TP
KEY_LENGTH = 16  # Taille de la clé AES (128 bits)
IV_LENGTH = 16  # Longueur du vecteur d'initialisation (IV)
PBKDF2_ITERATIONS = 100000  # Nombre d'itérations pour la dérivation de clé

class CipheredGUI(BasicGUI):

    def _init_(self) -> None:
        super()._init_()
        self._key = None  # Clé de chiffrement, dérivée à partir du mot de passe

    def _create_connection_window(self) -> None:
        # Surcharge la fonction de création de la fenêtre de connexion pour ajouter un champ de mot de passe
        super()._create_connection_window()
        with dpg.group(horizontal=True):
            dpg.add_text("password")
            dpg.add_input_text(tag="connection_password", password=True)

    def run_chat(self, sender, app_data) -> None:
        # Récupère le mot de passe, génère la clé et lance la session de chat
        super().run_chat(sender, app_data)
        password = dpg.get_value("connection_password").encode("utf-8")
        
        # Dérivation de la clé avec PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=SALT,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        self._key = urlsafe_b64encode(kdf.derive(password))  # Dérive et encode la clé

    def encrypt(self, plaintext: str) -> tuple:
        iv = urandom(IV_LENGTH)  # Générer un vecteur d'initialisation (IV) aléatoire
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        return iv, ciphertext

    def decrypt(self, encrypted: tuple) -> str:
        iv, ciphertext = encrypted
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')

    def send(self, text: str) -> None:
        iv, encrypted_message = self.encrypt(text)
        self._client.send_message((iv, encrypted_message))

    def recv(self) -> None:
        if self._callback is not None:
            for user, (iv, encrypted_message) in self._callback.get():
                message = self.decrypt((iv, encrypted_message))
                self.update_text_screen(f"{user}: {message}")
            self._callback.clear()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # instanciate the class, create context and related stuff, run the main loop
    client = BasicGUI()
    client.create()
    client.loop()