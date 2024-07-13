from PIL import Image
import numpy as np
from algorithm import RC6Encryption
from hashlib import sha256
import math
import climage

input_key = b'1234567891011'
key = sha256(input_key).digest()
rc6 = RC6Encryption(key)

print("\n")
print("#"*20,"Key Expend...","#"*20)

print(
"""
RC6 Key Expension Algorithm:

    S [0] = P32
    for i = 1 to 2r + 3 do
    {
        S [i] = S [i - 1] + Q32
    }
    A = B = i = j = 0
    v = 3 X max{c, 2r + 4}
    for s = 1 to v do
    {
        A = S [i] = (S [i] + A + B) <<< 3
        B = L [j] = (L [j] + A + B) <<< (A + B)
        i = (i + 1) mod (2r + 4)
        j = (j + 1) mod c
    }

"""
)

print("P: ", hex(rc6.P32), f"({rc6.P32})")
print("Q: ", hex(rc6.Q32), f"({rc6.Q32})")

print("w_bit: ", rc6.w_bit)
print("Modulo: ", rc6.modulo, f"(2^{int(math.log2(rc6.modulo))})")
print("lgw: ", rc6.lgw)

print("Rounds(r) : ", rc6.rounds)
print("Round 2r+2: ", rc6.round2_2)
print("Round 2r+3: ", rc6.round2_3)
print("Round 2r+4: ", rc6.round2_4)


print("user input key: ", input_key)
print("hash key: ", key)
print("Key Blocks", [(hex(i)) for i in rc6.key_integer_reverse_blocks])
print("Key Block size: ", rc6.key_blocks_number)

print("init Expended key (S): ", rc6.rc6_key)

print("Expending key...")

rc6.key_generation()


print("Expended key (S): ",  rc6.rc6_key)
print("Expended key (S) block size: ", len(rc6.rc6_key), end="\n\n")


print("#"*20 + "#"*15 + "#"*20,end="\n\n")



def load_image(path):
    # read image file as bytes string
    with open(path, 'rb') as file:
        image_bytes = file.read()

    img = Image.open(path)

    print("Image size: ", len(image_bytes), " bytes")

    # padding need to fill 16bytes block
    padding_size = (16-len(image_bytes)%16)
    print("Padding need for 16bytes block: ", padding_size, "bytes")

    # add padding to image's bytes
    image_bytes += b'\x00' * padding_size

    return image_bytes, img.size


def encryptImage(path):

    print("\n")
    print("#"*20,"Encrypt Image","#"*20,end="\n\n")


    print(
    """
RC6 Encryption Algorithm:
    B = B + S[0]
    D = D + S[1]
    for i = 1 to r do
    {
        t = (B * (2B + 1)) <<< lg w
        u = (D * (2D + 1)) <<< lg w
        A = ((A ^ t) <<< u) + S[2i]
        C = ((C ^ u) <<< t) + S[2i + 1] 
        (A, B, C, D)  =  (B, C, D, A)
    }
    A = A + S[2r + 2]
    C = C + S[2r + 3]

    """
    )

    # load image as raw bytes
    image_bytes, image_size = load_image(path)

    print("Resolution: ", image_size)

    # init
    encrypted_bytes = b''


    zero_need_to_fill = len(str(len(image_bytes)))


    print("\n", "*"*14, "encrypting...", "*"*14, end="\n\n")

    # Iterate through the image bytes in chunks of 16 bytes
    for i in range(0, len(image_bytes), 16):
        # Extract a block of 16 by207808tes from the image data
        block = image_bytes[i:i+16]
        
        # Encrypt the 16-byte block using RC6 encryption algorithm
        encrypted_block = rc6.blocks_to_data(rc6.encrypt(block))
        
        # Append the encrypted block to the encrypted bytes result
        encrypted_bytes += encrypted_block


        if not (i%10000):
            print(f"({str(i).zfill(zero_need_to_fill)}) block: ", block, rc6.get_blocks(block)[1] )
            print(f"({str(i).zfill(zero_need_to_fill)}) block: ", encrypted_block, rc6.get_blocks(encrypted_block)[1], "(encrypted)")
            print("...")

    print("\n", "*"*14, "completely encrypted!", "*"*14, end="\n\n")
    print("Encrypted bytes: ", len(encrypted_bytes), "bytes")

    # calcuate encrypted image width based on encrypted bytes size
    width = math.floor(math.sqrt(len(encrypted_bytes)))

    # padding need to fill (width * height).
    padding_size = (width - (len(encrypted_bytes)%width))

    # padding_size = (width * height) - len(encrypted_bytes)

    print("Padding need for reshaping image: ", padding_size , "bytes")
    # add padding
    encrypted_bytes += b'\x00'* padding_size
    # calcuate encrypted image height based on width
    height = int(len(encrypted_bytes)/width)
    print("Calculated encrypted image width: ", width)
    print("Calculated encrypted image height: ", height)

    # transform bytes to vector
    encrypted_data = np.frombuffer(encrypted_bytes, dtype=np.uint8)
    # reshape matrix (520 x height)
    encrypted_data = encrypted_data.reshape((width, height))

    # save encrypted image
    image = Image.fromarray(encrypted_data)
    image.save('encrypted_img.png')



    print("\n")
    print(climage.convert('encrypted_img.png', width=50, is_unicode=True))
    print("\n")
    print("saved encrypted image!")
    print("\n")
    print("#"*20 + "#"*15 + "#"*20,end="\n\n")



def decryptImage(path):

    print("\n")
    print("#"*20,"Decrypt Image","#"*20,end="\n\n")


    print(
    """
RC6 Decryption Algorithm:
    C = C - S[2r + 3]
    A = A - S[2r + 2]

    for i = r downto 1 do
    {
        (A, B, C, D) = (D, A, B, C)
        u = (D * (2D + 1)) <<< lg w
        t = (B * (2B + 1)) <<< lg w
        C = ((C - S[2i + 1]) >>> t) ^ u
        A = ((A - S[2i]) >>> u) ^ t
    }
    D = D - S[1]
    B = B - S[0]

    """
    )

    # init image
    img = Image.open(path)
    # extract image's bytes 
    img_bytes = img.tobytes()
    print("Encrypted Image Size: ", len(img_bytes), "bytes")
    # clean tailing null bytes
    cleaned_content = img_bytes.rstrip(b'\x00')
    print("Cleaned tailing null bytes")

    zero_need_to_fill = len(str(len(cleaned_content)))

    # decrypt and save
    with open('decrypted_image.png', 'wb') as file:
        decrypted_bytes = b'' 
        print("total blocks: ", int(len(cleaned_content)/16), "blocks")
        print("block size: 16 bytes")

        for i in range(0, len(cleaned_content), 16):
            # Extract a block of 16 bytes from the image dataes
            block = cleaned_content[i:i+16]

            # Decrypt the 16-byte block using RC6 encryption algorithm
            decrypted_block = rc6.blocks_to_data(rc6.decrypt(block))

            # Append the decrypted block 
            decrypted_bytes += decrypted_block


            if not (i%10000):
                print(f"({str(i).zfill(zero_need_to_fill)}) block: ", block, rc6.get_blocks(block)[1] )
                print(f"({str(i).zfill(zero_need_to_fill)}) block: ", decrypted_block, rc6.get_blocks(decrypted_block)[1], "(decrypted)")
                print("...")
        
        print("*"*10, "completely decrypted!", "*"*10, end="\n\n")

        # clear tailing null bytes
        decrypted_bytes.rstrip(b'\x00')

        # save file
        file.write(decrypted_bytes)
        print("saved decrypted image!", end="\n\n")


    print(climage.convert('decrypted_image.png', width=50, is_unicode=True), end='\n\n')
    
    print("#"*20 + "#"*15 + "#"*20,end="\n\n")


encryptImage('test_images/mountain-scenery-backgrround-huawei-mate-hd-wallpaper-uhdpaper.com-250@0@f.jpg')
# decryptImage('encrypted_img.png')
