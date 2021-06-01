#!/usr/bin/env python3

import os 
import subprocess
import shutil
import glob
import pathlib
import platform
import time
import sys
import base64
import argparse
import socket
import binascii
import requests
from pathlib import Path
from urllib.request import getproxies
from Cryptodome.Hash import CMAC
from Cryptodome.Hash import SHA1
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pss

import license_protocol_pb2

PRIVATE_KEY = "308204a30201000282010100b5d1dc441883596c5d2722832d33cef4e4daa6e9959d6fbd83a9374527e533408448512e7d9509182ef750a7bd7bebbbf3d1d5653d38a41e68af7581d173b168e89b26494b06477b61f9f53a7755ade9cc293135178ffa8e0e6b9b0cafe2a150d6ef0cfd385952b0206fca5398a7dbf6faefd55f00029c15cdc420dece3c7844a72a3054f7d564f1a94f4e33d27ce8284c396e1b140e3568b009a3307ed36c62b3b395d7be57750e6f9155ccf72b3a668445fcae8d5de1e2c1c645b4c2b2a615c0c6a53bb866366b5e9b0b74c41b9fe49ba26bbb75b1cb89ca943c948d6212c07e259568dd4a2f7daf67357d209794c0ab5b4087a339e7fb6da56022ad61ef0902030100010282010018e3c326f1421dde373c51bdaa54f2ca547fd82496ce280b45f846b0295f776e280dac4b5476aff98708651aa9564af57e51a5c847a2b6d8d0d4e01da6da1319bce9ec4a5142694bab24681d1a53f8cc4e1dff75f8a54593e7c67441bedc23e028a42ddf8634b81c933c2a72da2d746fb1775e7ab44a272ad6f1b7dc38584fd03f0d122362bf18d00568bead150e35aa035156e4e3bda7bbe4cba7be3c3323487b9c43eb9a2f355949ceef58e874b47e4cd06564d7b62906207f893a70e3305421c6a77905f779a21f4820c72b44820fa21117b925fae391cef5aa896946ce9746d81f7abb23f885ddd6a0f7199ed33bf4f2a6e1d028b5d8266a56ee78525fa702818100d4cb413203d16ad1a3c5e0b2031ea0cf76e226e2110065feac40b77c15eeb2c0ce29f4a384571ed83da1714071528088965ecc2295d3c997c0a0e5c336132314d6d767e71691e1520393c7b62440df84fb5a5ac929269dab536c07bc05ce780112ed414cae484a56aa9539d6e822194b75c629e4ac622779b020d4923bde128702818100dabc9bc5f9cf0020d7c268ca1c517d249d7cfec42c1d3f8df41a83d00876b5ad48f96d9dea9f75ccc1259ae7b278c77a558589a026fe23a442be2c150b15eccd2d5e4de02eef1fadda668e0e17b21479d1414b9079d3cc80abb4623e137654e0bc2d1743879a2a9c5b9f8da7c5f36cbd77efdccc2ad5206e370fe28eda3e05ef028180383f1d9585d2d60461e0cd1ae09e38ed7dc41b7907fb6dfa5a37a5086497baa2221c8ef0a5eb8d58a539c640bd738c4c0e4b327435dc4c5e1369b431dc5a449c9e89438a9eb9a2b05607baf35733daa140fb4a220001980d90386ef6f125f92c777f45126ac2eafb6b8d94434d0aae5af6df91754367927da4e398acaaac7183028180393adddae7a86455337e7722625463d4bfabe3907a2650e9983393c74b5f9bdb31dba8f5875c9f5aaa32679c3592ea4634b812b1276298fab247c58adff2a5996d445e45c8a1e1fcffc693665686ce5aad08537802980acaa3a2378e1c537a93ae4871ecc63eece52a07cded569a8119f5967983a5b54b9deaa42a57cbfc2c5b028181009ceabe2ecf3709a1c85828e955f8960be47b9aa5beaa5d4e1ada1a6a3b40e00ce15f35fc1c85e9623ba93c1957950d4515f3de9ba8f06b551365ff02a486fca4f50b00df5946bc46f15f9bbe465655110f4d98fbc4f0b03da64734aa009a2dc36efed2e521180db057fcdc8f08b138b23fc08133db52c52d6a2c394efacfb051"

PUBLIC_KEY = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100b5d1dc441883596c5d2722832d33cef4e4daa6e9959d6fbd83a9374527e533408448512e7d9509182ef750a7bd7bebbbf3d1d5653d38a41e68af7581d173b168e89b26494b06477b61f9f53a7755ade9cc293135178ffa8e0e6b9b0cafe2a150d6ef0cfd385952b0206fca5398a7dbf6faefd55f00029c15cdc420dece3c7844a72a3054f7d564f1a94f4e33d27ce8284c396e1b140e3568b009a3307ed36c62b3b395d7be57750e6f9155ccf72b3a668445fcae8d5de1e2c1c645b4c2b2a615c0c6a53bb866366b5e9b0b74c41b9fe49ba26bbb75b1cb89ca943c948d6212c07e259568dd4a2f7daf67357d209794c0ab5b4087a339e7fb6da56022ad61ef090203010001"

def read_pssh(path: str):
	raw = Path(path).read_bytes()
	pssh_offset = raw.rfind(b'pssh')
	_start = pssh_offset - 4
	_end = pssh_offset - 4 + raw[pssh_offset-1]
	pssh = raw[_start:_end]
	return pssh

class WidevineCDM:
	def __init__(self, license_url: str):
		self.private_key = binascii.a2b_hex(PRIVATE_KEY)
		self.public_key = binascii.a2b_hex(PUBLIC_KEY)
		self.proxies = getproxies()
		self.license_url = license_url
		self.header={"Cookie": ""}
		
	def generateRequestData(self, pssh: bytes):
		_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		_socket.settimeout(1)
		try:
			_socket.connect(("127.0.0.1", 8888))
			_socket.send(pssh)
			recv = _socket.recv(10240)
		except Exception as e:
			print(f"socket recv data failed. --> {e}")
			_socket.close()
			return
		_socket.close()
		return recv
	
	def verify(self, msg: bytes, signature: bytes):

		_hash = SHA1.new(msg)
		public_key = RSA.importKey(self.public_key)
		verifier = pss.new(public_key)
		res = verifier.verify(_hash, signature)
		print(f"verify result is --> {res}")
		
	def license_request(self, payload):
		try:
			r = requests.post(self.license_url, data=payload, headers=self.header, proxies=self.proxies)
		except Exception as e:
			sys.exit(f"request license failed. --> {e}")
		return r.content
	
	def getContentKey(self, license_request_data: bytes, license_response_data: bytes):
		licenseMessage = license_protocol_pb2.License()
		requestMessage=license_protocol_pb2.SignedMessage()
		responseMessage = license_protocol_pb2.SignedMessage()
		requestMessage.ParseFromString(license_request_data)
		responseMessage.ParseFromString(license_response_data)
		
		oaep_key = RSA.importKey(self.private_key)
		cipher = PKCS1_OAEP.new(oaep_key)
		cmac_key = cipher.decrypt(responseMessage.session_key)
		
		_cipher = CMAC.new(cmac_key, ciphermod=AES)
		_auth_key = b'\x01ENCRYPTION\x00' + requestMessage.msg + b"\x00\x00\x00\x80"
		enc_cmac_key = _cipher.update(_auth_key).digest()
		
		licenseMessage.ParseFromString(responseMessage.msg)
		global KEY_ARRAY
		KEY_ARRAY=[]
		for key in licenseMessage.key:
			cryptos = AES.new(enc_cmac_key, AES.MODE_CBC, iv=key.iv[0:16])
			dkey = cryptos.decrypt(key.key[0:16])
#			print("KID:", binascii.b2a_hex(key.id).decode('utf-8'), "KEY:",binascii.b2a_hex(dkey).decode('utf-8'))
			KEY_ARRAY.append("%s:%s"%(binascii.b2a_hex(key.id).decode('utf-8'),binascii.b2a_hex(dkey).decode('utf-8')))
		KEY_ARRAY.remove(KEY_ARRAY[0])
		for item in KEY_ARRAY:
			print("[info][Found KEY] %s"%item)
		
	def work(self, pssh: bytes):
		license_request_data = self.generateRequestData(pssh)
		if license_request_data is None:
			sys.exit("generate requests data failed.")
		license_response_data = self.license_request(license_request_data)
		self.getContentKey(license_request_data, license_response_data)
		
def getkeys(init_path,license_url):
	pssh =  read_pssh(init_path)
	cdm = WidevineCDM(license_url)
	cdm.work(pssh)
	
FILE_DIRECTORY=str(pathlib.Path(__file__).parent.absolute())
TEMPORARY_PATH = FILE_DIRECTORY+"/cache"
OUTPUT_PATH = FILE_DIRECTORY+"/output"
VIDEO_ID = "bv"
AUDIO_ID = "ba"

def osinfo():
	global PLATFORM
	if platform.system()== "Darwin":
		PLATFORM = "Mac"
	else:
		PLATFORM = platform.system()

def divider():
	count = int(shutil.get_terminal_size().columns)
	count = count - 1
	print ('-' * count)
	
def empty_folder(folder):
	files = glob.glob('%s/*'%folder)
	for f in files:
		os.remove(f)
	print("Emptied Temporary Files!")
	divider()
	quit()
	
def parse_key (prompt):
	global key,kid,keys
	key = prompt[30 : 62]
	kid = prompt[68 : 100]
	keys = "--key %s:%s"%(kid,key)
	return key,kid,keys

def download_drm_content(mpd_url):
	divider()
	print("Processing Video Info..")
	os.system('yt-dlp --external-downloader aria2c --no-warnings --allow-unplayable-formats --no-check-certificate -F "%s"'%mpd_url)
	divider()
	VIDEO_ID = input("ENTER VIDEO_ID (Press Enter for Best): ")
	if VIDEO_ID == "":
		VIDEO_ID = "bv"
	
	AUDIO_ID = input("ENTER AUDIO_ID (Press Enter for Best): ")
	if AUDIO_ID == "":
		AUDIO_ID = "ba"
	
	divider()
	print("Downloading Encrypted Video from CDN..")	
	os.system(f'yt-dlp -o "{TEMPORARY_PATH}/encrypted_video.%(ext)s" --no-warnings --external-downloader aria2c --allow-unplayable-formats --no-check-certificate -f {VIDEO_ID} "{mpd_url}" -o "{TEMPORARY_PATH}/encrypted_video.%(ext)s"')
	print("Downloading Encrypted Audio from CDN..")
	os.system(f'yt-dlp -o "{TEMPORARY_PATH}/encrypted_audio.%(ext)s" --no-warnings --external-downloader aria2c --allow-unplayable-formats --no-check-certificate -f {AUDIO_ID} "{mpd_url}"')

def decrypt_content():
	if PLATFORM == "Windows":		
		key_arg = ""
		for items in KEY_ARRAY:
			key_temp = " --key %s"%items
			key_arg += key_temp
			key_temp = ""
		keys = key_arg
			
	else:
		parse_key(KEY_PROMPT)
		
	divider()
	print("Decrypting WideVine DRM.. (Takes some time)")
	osinfo()
	if PLATFORM == "Mac":
		MP4DECRYPT_PATH = "%s/mp4decrypt/mp4decrypt_mac"%FILE_DIRECTORY
	elif PLATFORM == "Windows":
		MP4DECRYPT_PATH = "%s/mp4decrypt/mp4decrypt_win.exe"%FILE_DIRECTORY
	elif PLATFORM == "Linux":
		MP4DECRYPT_PATH = "%s/mp4decrypt/mp4decrypt_linux"%FILE_DIRECTORY
	else:
		MP4DECRYPT_PATH = MP4DECRYPT_PATH = "mp4decrypt"
		
	os.system('%s %s/encrypted_video.mp4 %s/decrypted_video.mp4 %s --show-progress'%(MP4DECRYPT_PATH,TEMPORARY_PATH,TEMPORARY_PATH,keys))
	os.system('%s %s/encrypted_audio.m4a %s/decrypted_audio.m4a %s --show-progress'%(MP4DECRYPT_PATH,TEMPORARY_PATH,TEMPORARY_PATH,keys))
	print("[info] Decryption Complete!")

def merge_content():
	global FILENAME
	FFMPEG_PATH = "%s/ffmpeg.exe"%FILE_DIRECTORY
	divider()
	FILENAME=input("Enter File Name (with extension): \n> ")
	divider()
	print("Merging Files and Processing %s.. (Takes a while)"%FILENAME)
	time.sleep(2)
	if PLATFORM == "Windows":
		os.system('%s -i %s/decrypted_video.mp4 -i %s/decrypted_audio.m4a -c:v copy -c:a copy %s/"%s"'%(FFMPEG_PATH,TEMPORARY_PATH,TEMPORARY_PATH,OUTPUT_PATH,FILENAME))
	else: 
		os.system('ffmpeg --hide-banner -i %s/decrypted_video.mp4 -i %s/decrypted_audio.m4a -c:v copy -c:a copy %s/"%s"'%(TEMPORARY_PATH,TEMPORARY_PATH,OUTPUT_PATH,FILENAME))
		
parser=argparse.ArgumentParser()
parser.add_argument('-mpd', required=False, default="NULL")
parser.add_argument('-license', required=False, default="NULL")
args = parser.parse_args()

MPD_URL = args.mpd
LICENSE_URL = args.license

def manual_input():
	global MPD_URL, LICENSE_URL
	MPD_URL = input("Enter MPD URL: \n> ")
	divider()
	LICENSE_URL = input("Enter License URL: \n> ")
	if PLATFORM == "Windows":
		pass
	else:
		KEY_PROMPT = input("Enter WideVineDecryptor Prompt: \n> ")

osinfo()
divider()
print("**** NARROWVINE by vank0n **** (%s Detected)"%PLATFORM)
divider()

if PLATFORM == "Windows":
	if MPD_URL == "NULL" or LICENSE_URL == "NULL":
		manual_input()
	else:
		pass
else:
	manual_input()
	divider()

if PLATFORM == "Windows":
	divider()
	print("Starting Widevine Proxy.. (DO NOT CLOSE THE PROXY WINDOW!)")
	os.startfile("%s/license_proxy.exe"%FILE_DIRECTORY)
	download_drm_content(MPD_URL)
	divider()
	print("Extracting Widevine Keys..")
	getkeys("%s/encrypted_video.mp4"%TEMPORARY_PATH,LICENSE_URL)
else:
	download_drm_content(MPD_URL)
	divider()
	decrypt_content()
	
decrypt_content()
merge_content()
divider()
print("[info] Process Finished. Final Video File is saved in /output directory.")
os.startfile("%s/%s"%(OUTPUT_PATH,FILENAME))
divider()

delete_choice = input("Delete cache files? (y/n)\ny) Yes (default)\nn) No\ny/n> ")

if delete_choice == "n":
	divider()
else:
	empty_folder(TEMPORARY_PATH)

time.sleep(2)


		
	