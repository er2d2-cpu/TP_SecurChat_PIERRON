import logging
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import dearpygui.dearpygui as dpg
from basic_gui import BasicGUI
from chat_client import ChatClient
from generic_callback import GenericCallback

# Constantes
SALT = b'salt_value'  # Sel constant pour les opérations cryptographiques
KEY_LENGTH = 16  # Longueur de la clé AES (128 bits)
PBKDF2_ITERATIONS = 100000  # Nombre d'itérations pour la dérivation de clé
STATIC_SALT = os.urandom(16)  # Génération d'un sel unique

# Paramètres de connexion par défaut
DEFAULT_VALUES = {
    "host": "127.0.0.1",
    "port": "6666",
    "name": "foo"
}

class CipheredGUI(BasicGUI):

    def __init__(self) -> None:
        self._key = None  # Variable pour stocker la clé de chiffrement dérivée
        super().__init__()  # Appel du constructeur de la classe parente

    def _create_connection_window(self) -> None:
        # Création de la fenêtre de connexion avec les champs de saisie
        with dpg.window(label="Connexion", pos=(200, 150), width=400, height=300, show=False, tag="connection_windows"):
            for field in ["host", "port", "name"]:
                with dpg.group(horizontal=True):
                    dpg.add_text(field)
                    dpg.add_input_text(default_value=DEFAULT_VALUES[field], tag=f"connection_{field}")
            with dpg.group(horizontal=True):
                dpg.add_text("mot de passe")
                dpg.add_input_text(default_value="", tag="connection_password", password=True)  # Champ de mot de passe
            dpg.add_button(label="Se connecter", callback=self.run_chat)

    def run_chat(self, sender, app_data) -> None:
        # Récupération des informations de connexion et dérivation de la clé de chiffrement
        host = dpg.get_value("connection_host")
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name")
        password = dpg.get_value("connection_password").encode("utf-8")

        # Dérivation de la clé avec PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=SALT,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        self._key = kdf.derive(password)  # Dérive la clé à partir du mot de passe fourni

        self._log.info(f"Connexion de {name}@{host}:{port}")

        self._callback = GenericCallback()
        self._client = ChatClient(host, port)
        self._client.start(self._callback)
        self._client.register(name)

        dpg.hide_item("connection_windows")
        dpg.show_item("chat_windows")
        dpg.set_value("screen", "Connexion en cours")

    def encrypt(self, plaintext: str) -> tuple:
        iv = os.urandom(16)  # Génération d'un vecteur d'initialisation (IV) aléatoire
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        return iv, encrypted

    def decrypt(self, iv: bytes, ciphertext: bytes) -> str:
        try:
            cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
            return decrypted_bytes.decode('utf-8')
        except UnicodeDecodeError as e:
            self._log.error(f"Erreur de décodage UTF-8 lors du déchiffrement : {e}")
            return "[Message corrompu ou erreur de déchiffrement]"
        except Exception as e:
            self._log.error(f"Erreur générale lors du déchiffrement : {e}")
            return "[Erreur de déchiffrement]"

    def send(self, message: str) -> None:
        iv, encrypted_message = self.encrypt(message)
        iv_base64 = base64.b64encode(iv).decode('utf-8')
        encrypted_base64 = base64.b64encode(encrypted_message).decode('utf-8')
        self._client.send_message(f"{iv_base64}:{encrypted_base64}")

    def recv(self):
        if self._callback is not None:
            for user, message in self._callback.get():
                try:
                    if ':' in message:
                        iv_base64, encrypted_base64 = message.split(':')
                        iv = base64.b64decode(iv_base64)
                        encrypted = base64.b64decode(encrypted_base64)
                        self._log.debug(f"IV: {iv}, Chiffré: {encrypted}")
                        decrypted_message = self.decrypt(iv, encrypted)
                        self.update_text_screen(f"{user}: {decrypted_message}")
                    else:
                        self.update_text_screen(f"{user}: {message}")
                except Exception as e:
                    self._log.error(f"Erreur lors du déchiffrement du message : {e}")
                    self.update_text_screen(f"Erreur lors du déchiffrement du message de {user}")
            self._callback.clear()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    client = CipheredGUI()
    client.create()
    client.loop()
