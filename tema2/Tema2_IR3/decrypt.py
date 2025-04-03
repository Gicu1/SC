import sys

def decrypt(data, key):
    # decriptarea utilizand cifrul cezar pe fiecare octet
    # cheia e intre 0 si 255
    return bytes((b - key) % 256 for b in data)

def match_signature(data, signature):
    # verifica daca semnatura data se potriveste cu semnatura unui tip de fisier
    return data.startswith(signature)

# Dicționar cu semnăturile unor fișiere cunoscute
signatures = {
    'BMP': b'BM',
    'JPG': b'\xff\xd8',
    'PNG': b'\x89PNG\r\n\x1a\n',
    'PDF': b'%PDF',
    'EXE': b'MZ',
    # Formate Office pre-2007 (DOC, XLS, PPT)
    'DOC/XLS/PPT': bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
    # Pentru DOCX, XLSX, PPTX (fișiere ZIP)
    'ZIP': b'PK\x03\x04',
    # MP3 cu tag ID3
    'MP3': b'ID3',
    # GZIP (pentru TAR.GZ)
    'GZIP': b'\x1f\x8b\x08',
    # AVI: semnătura "RIFF" la început și "AVI " la offsetul 8
    'AVI': b'RIFF',
    # MP4/3GP: de obicei conține "ftyp" în primele 12 octeți
    'MP4/3GP': b'ftyp'
}

def identify_file(decrypted_data):
    # verifica daca decrypted_data incepe cu semnatura unui tip de fisier cunoscut 
    for file_type, signature in signatures.items():
        if decrypted_data.startswith(signature):
            if file_type == 'AVI':
                # Pentru AVI se verifică suplimentar dacă octeții 8-12 sunt 'AVI '
                if len(decrypted_data) >= 12 and decrypted_data[8:12] == b'AVI ':
                    return 'AVI'
            elif file_type == 'MP4/3GP':
                # În MP4/3GP, semnătura "ftyp" se găsește adesea între octeții 4 și 12
                if b'ftyp' in decrypted_data[4:12]:
                    return 'MP4/3GP'
            else:
                return file_type
    return None

def main():
    if len(sys.argv) < 2:
        print("Utilizare: python decrypt.py <fisier_criptat>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()

    # Testăm toate cheile posibile de la 0 la 255
    for key in range(256):
        decrypted_data = decrypt(encrypted_data, key)
        file_type = identify_file(decrypted_data)
        if file_type:
            print(f"Cheia corectă găsită: {key}")
            print(f"Tipul de fișier identificat: {file_type}")
            output_filename = f"decrypted_{input_file}"
            with open(output_filename, 'wb') as out_file:
                out_file.write(decrypted_data)
            print(f"Fișierul decriptat a fost salvat ca: {output_filename}")
            break
    else:
        print("Nu a fost găsită o cheie de decriptare validă.")

if __name__ == '__main__':
    main()
    
'''
pentru fisierul meu:
Cheia corectă găsită: 119
Tipul de fișier identificat: DOC/XLS/PPT
Fișierul decriptat a fost salvat ca: decrypted_GICU_RATA
'''
