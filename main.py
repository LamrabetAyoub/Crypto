import os
import cv2
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox, QPushButton


class CryptoSystem(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Système Crypto Hybride (ECC + AES)")
        self.setGeometry(200, 200, 400, 200)

        # Boutons pour chiffrement et déchiffrement
        self.encrypt_button = QPushButton("Chiffrer Vidéo", self)
        self.encrypt_button.setGeometry(50, 50, 300, 40)
        self.encrypt_button.clicked.connect(self.encrypt_video)

        self.decrypt_button = QPushButton("Déchiffrer Vidéo", self)
        self.decrypt_button.setGeometry(50, 120, 300, 40)
        self.decrypt_button.clicked.connect(self.decrypt_video)

    def encrypt_video(self):
        # Sélectionnez la vidéo à chiffrer
        video_path, _ = QFileDialog.getOpenFileName(self, "Choisir la vidéo", "", "Video Files (*.mp4 *.avi)")
        if not video_path:
            return

        # Définir les répertoires pour les frames temporaires
        temp_frames_dir = "temp_frames"
        encrypted_frames_dir = "encrypted_frames"
        os.makedirs(temp_frames_dir, exist_ok=True)
        os.makedirs(encrypted_frames_dir, exist_ok=True)

        # Extraire les frames de la vidéo
        cap = cv2.VideoCapture(video_path)
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        frame_index = 0

        while True:
            success, frame = cap.read()
            if not success:
                break
            frame_path = os.path.join(temp_frames_dir, f"frame_{frame_index}.jpg")
            cv2.imwrite(frame_path, frame)
            frame_index += 1
        cap.release()

        # Générer une clé ECC et AES
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # Échange ECC pour dériver la clé AES
        shared_key = private_key.exchange(ec.ECDH(), public_key)
        aes_key = sha256(shared_key).digest()  # Générer une clé AES-256
        iv = os.urandom(16)  # Générer un IV aléatoire

        # Chiffrer les frames avec AES-CBC
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
        for i in range(frame_count):
            frame_path = os.path.join(temp_frames_dir, f"frame_{i}.jpg")
            with open(frame_path, "rb") as f:
                frame_data = f.read()
            encrypted_data = cipher.encrypt(pad(frame_data, AES.block_size))

            encrypted_frame_path = os.path.join(encrypted_frames_dir, f"encrypted_frame_{i}.bin")
            with open(encrypted_frame_path, "wb") as f:
                f.write(encrypted_data)

        # Sauvegarder les métadonnées
        metadata = {
            "aes_key": aes_key.hex(),
            "iv": iv.hex(),
            "frame_count": frame_count
        }
        with open("metadata.txt", "w") as f:
            f.write(str(metadata))

        QMessageBox.information(self, "Succès", "La vidéo a été chiffrée avec succès.")

    def decrypt_video(self):
        # Sélectionnez le fichier de métadonnées
        metadata_path, _ = QFileDialog.getOpenFileName(self, "Choisir le fichier de métadonnées", "", "Text Files (*.txt)")
        if not metadata_path:
            return

        with open(metadata_path, "r") as f:
            metadata = eval(f.read())

        encrypted_frames_dir = "encrypted_frames"
        decrypted_frames_dir = "decrypted_frames"
        os.makedirs(decrypted_frames_dir, exist_ok=True)

        # Charger les métadonnées
        aes_key = bytes.fromhex(metadata["aes_key"])
        iv = bytes.fromhex(metadata["iv"])
        frame_count = metadata["frame_count"]

        # Initialiser le déchiffreur AES
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)

        # Déchiffrer les frames
        for i in range(frame_count):
            encrypted_frame_path = os.path.join(encrypted_frames_dir, f"encrypted_frame_{i}.bin")
            if not os.path.exists(encrypted_frame_path):
                print(f"Frame chiffrée manquante : {encrypted_frame_path}")
                continue

            with open(encrypted_frame_path, "rb") as f:
                encrypted_data = f.read()

            try:
                decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            except ValueError as e:
                print(f"Erreur lors du déchiffrement de la frame {i}: {e}")
                continue

            decrypted_frame_path = os.path.join(decrypted_frames_dir, f"frame_{i}.jpg")
            with open(decrypted_frame_path, "wb") as f:
                f.write(decrypted_data)

        # Reconstruire la vidéo
        print("Reconstruction de la vidéo déchiffrée...")
        frame = cv2.imread(os.path.join(decrypted_frames_dir, "frame_0.jpg"))
        height, width, layers = frame.shape
        video = cv2.VideoWriter("decrypted_video.avi", cv2.VideoWriter_fourcc(*'DIVX'), 30, (width, height))

        for i in range(frame_count):
            frame_path = os.path.join(decrypted_frames_dir, f"frame_{i}.jpg")
            frame = cv2.imread(frame_path)
            if frame is not None:
                video.write(frame)
        video.release()

        QMessageBox.information(self, "Succès", "La vidéo a été déchiffrée avec succès.")


if __name__ == "__main__":
    app = QApplication([])
    window = CryptoSystem()
    window.show()
    app.exec_()
