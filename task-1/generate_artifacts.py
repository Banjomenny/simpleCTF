import os
import zipfile
import random
import base64
import piexif
from PIL import Image

SSH_USER = "sysadmin"
SSH_PASS = "super_secure_p@ssw0rd"
SOURCE_IMAGE = "source.jpg" 
OUTPUT_IMAGE = "evidence.jpg"
TXT_FILENAME = "secret.txt"

DIR_NAMES = [
    "var", "log", "backup", "www", "html", "nginx", "apache2", "old", 
    "2022", "2023", "tmp", "cache", "usr", "local", "bin", "sys_backup",
    "restore", "data", "files", "images", "assets", "js", "css", "audit"
]

def create_image_with_metadata(source_path, dest_path):
    try:
        img = Image.open(source_path)
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")
            
        zeroth_ifd = {piexif.ImageIFD.ImageDescription: f"User: {SSH_USER}".encode('utf-8')}
        exif_dict = {"0th": zeroth_ifd}
        exif_bytes = piexif.dump(exif_dict)
        
        img.save(dest_path, "JPEG", exif=exif_bytes)
        print(f"[+] Image created with metadata.")
    except Exception as e:
        print(f"[-] Image error: {e}")
        img = Image.new('RGB', (100, 100), color = (73, 109, 137))
        img.save(dest_path)

def create_base64_txt(filename):
    content = f"SSH Password is: {SSH_PASS}"
    encoded = base64.b64encode(content.encode('utf-8')).decode('utf-8')
    with open(filename, 'w') as f:
        f.write(f"Decode this to find access:\n{encoded}")

def generate_random_path(depth=4):
    path_parts = [random.choice(DIR_NAMES) for _ in range(depth)]
    return "/".join(path_parts)

def create_zip_structure():
    if not os.path.exists('static'):
        os.makedirs('static')
    
    zip_path = 'static/files.zip'
    
    create_image_with_metadata(SOURCE_IMAGE, OUTPUT_IMAGE)
    create_base64_txt(TXT_FILENAME)
    
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        all_paths = []
        for _ in range(100):
            depth = random.randint(2, 5)
            path = generate_random_path(depth)
            all_paths.append(path)
        
        all_paths = list(set(all_paths))
        
        secret_paths = random.sample(all_paths, 2)
        path_img = secret_paths[0]
        path_txt = secret_paths[1]
        
        print(f"[?] Hidden: {path_img}/{OUTPUT_IMAGE}")
        print(f"[?] Hidden: {path_txt}/{TXT_FILENAME}")

        zipf.write(OUTPUT_IMAGE, arcname=f"{path_img}/{OUTPUT_IMAGE}")
        zipf.write(TXT_FILENAME, arcname=f"{path_txt}/{TXT_FILENAME}")
        
        dummy_files = ["access.log", "error.log", "debug.txt", "config.old", "readme", "license"]
        
        for path in all_paths:
            if random.random() > 0.3:
                f_name = random.choice(dummy_files)
                zipf.writestr(f"{path}/{f_name}", "Log entry: nothing suspicious here.\nSystem check: OK.")

    if os.path.exists(OUTPUT_IMAGE): os.remove(OUTPUT_IMAGE)
    if os.path.exists(TXT_FILENAME): os.remove(TXT_FILENAME)
        
    print(f"[+] Archive created: {zip_path}")

if __name__ == "__main__":
    create_zip_structure()