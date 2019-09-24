from distutils.core import setup, Extension

ext_sources = ['./cryptbuf.c', './src/base64.c', './src/murmur3.c', './src/xxtea.c'];
cryptbuf = Extension('cryptbuf', sources = ext_sources)

setup(
	name = "cryptbuf",
	version = "1.0.0",
	description = "Cryptbuf package for getpay payment gateway engine.",
	author = "Paulus Gandung Prakosa",
	author_email = "paulus.gandung@digitalsekuriti.id",
	ext_modules = [cryptbuf]
)
