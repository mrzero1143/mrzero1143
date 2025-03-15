from PIL import Image
from PIL.ExifTags import TAGS

image = Image.open("test.jpg")
exif_data = image.getexif()
exif_data[0x9286] = "MALWARE_TEST_STRING"  # Tambahkan string mencurigakan
image.save("malicious_image.jpg", exif=exif_data)