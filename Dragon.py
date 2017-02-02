import os, random 
from Crypto.Cipher import AES			#This is our encryption method
from Crypto.Hash import SHA256			#This is our hashing the password method 
from time import sleep

def encrypt(key, filename, path):
    chunksize = 64*1024	        #Chunks you pull out of the file
    location = path+filename
    outFile = path+'Dragon'+'.'+filename
    create = 'touch '+outFile               #creates our file 
    filesize = str(os.path.getsize(location)).zfill(16)    #Takes the file size and fills it with padding to add up to 16 bytes 
    IV = ''

    for i in range(16):    #creates our 16byte  IV
        IV += chr(random.randint(0, 0xFF))    #creates our random IV that we will use to encrypt our file with1

    encryptor = AES.new(key, AES.MODE_CBC, IV)  #creats our encryptor with our key and IV

    with open(location, 'rb') as infile:        #opens our file that we want to read and encrypt 
        with open(outFile, 'wb') as outfile:    #Opens our file replacer we named Encrypted + filename
            outfile.write(filesize)           #writes data about our file, size and the unique IV we used
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)    #This loop will read chunks at a time, then check to see if the whole chunk
						  #is holding data from our file, if it's not it will pad it until it fills the
                if len(chunk) == 0:		  #chunk. Then it'll write the data after encrypting it into our encrypted file
                    break
                elif len(chunk) %16 != 0:
                    chunk += ' '  * (16 - (len(chunk) % 16))   #this will pad our chunk if it doesn't have 16 bytes
                outfile.write(encryptor.encrypt(chunk))
        remove = "rm -rf %s"%(location)
        os.system(remove)



def decrypt(key, filename, path):
    chunksize = 64*1024
    location = path+filename
    filename = filename[7:]        #will remove the encrpted word from our file
    outFile = path+filename
    with open (location, 'rb') as infile :
        filesize = long(infile.read(16))
        IV = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outFile, 'wb') as outfile: 
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)   #removes padding we added when encrypting 
        remove = "rm -rf %s"%(location)
        os.system(remove)
            

def encryptDir(key, path):
    filename = path.split('/',-1)[-1]  #mydirectory2
    path2 = path.split('/',-1)[:-1]    #/root/Desktop/
    path2.append('')
    path2 = '/'.join(path2)
    archive = "cd %s && tar -cf %s.tar %s"%(path2, filename, filename)
    os.system(archive)
    remove = "cd %s && rm -rf %s.tar"%(path2, filename)
    os.system(remove)
    location = path2+filename+'.tar'   #/root/Desktop/mydirectory2.tar
    outFile = path2+'Dragon.'+filename+'.tar'  #/root/Desktop/Dragon.mydirectory2.tar
    
    chunksize = 64*1024	        #Chunks you pull out of the file
    filesize = str(os.path.getsize(location)).zfill(16)    #Takes the file size and fills it with padding to add up to 16 bytes 
    IV = ''

    for i in range(16):    #creates our 16byte  IV
        IV += chr(random.randint(0, 0xFF))    #creates our random IV that we will use to encrypt our file with1

    encryptor = AES.new(key, AES.MODE_CBC, IV)  #creats our encryptor with our key and IV

    with open(location, 'rb') as infile:        #opens our file that we want to read and encrypt 
        with open(outFile, 'wb') as outfile:    #Opens our file replacer we named Encrypted + filename
            outfile.write(filesize)           #writes data about our file, size and the unique IV we used
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)    #This loop will read chunks at a time, then check to see if the whole chunk
						  #is holding data from our file, if it's not it will pad it until it fills the
                if len(chunk) == 0:		  #chunk. Then it'll write the data after encrypting it into our encrypted file
                    break
                elif len(chunk) %16 != 0:
                    chunk += ' '  * (16 - (len(chunk) % 16))   #this will pad our chunk if it doesn't have 16 bytes
                outfile.write(encryptor.encrypt(chunk))
    
    
    
def decryptDir(key, path):
    chunksize = 64*1024
    filename = path.split('/',-1)[-1]
    filename = filename[7:-4]        #will remove the encrpted word from our file
    path2 = path.split('/',-1)[:-1]
    path2.append('')
    path2 = '/'.join(path2)
    outFile = path2+filename
    with open (path, 'rb') as infile :
        filesize = long(infile.read(16))
        IV = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outFile, 'wb') as outfile: 
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)   #removes padding we added when encrypting
        archive = "cd %s && tar -xf %s %s"%(path2, filename, filename)
        os.system(archive)
        remove = "rm -rf %s"%(path)
        os.system(remove)


def getKey(password):     #creates our hash for our password
    hasher = SHA256.new(password)
    return hasher.digest()




def main():
    while 1:
        os.system('clear')
        print("""
            A) Encrypt File
            B) Encrypt Directory 
            C) Decrypt File
            D) Decrypt Directory 
            Q) Quit
            """)
        choice = raw_input('Dragon: ')
        
        if choice.lower() == 'q':
            raise SystemExit
        elif choice.lower() == 'a':
            filename = raw_input('Name of file: ')
            path = raw_input('Exact path of file: ')
            print('[+] Checking for existance...')
            sleep(1)
            if os.path.isfile(path+filename) == True: 
                password = raw_input('Password: ')
                encrypt(getKey(password), filename, path)
                print('[+] Dragons at work...')
                sleep(1)
                print('[+] Encrypting...')
                sleep(1)
                print('[+] Encryption succesful!')
                sleep(1)
            else:
                print('[-] Dragon could not find this file.')
                sleep(3)
        elif choice.lower() == 'c':
            filename =  raw_input('Name of encrypted file: ')
            path = raw_input('Exact location of encrypted file: ')
            print('[+] Checking for existance...')
            sleep(1)
            if os.path.isfile(path+filename) == True:
                password = raw_input('Password: ')
                decrypt(getKey(password), filename, path)
                print('[+] Dragons at work...')
                sleep(1)
                print('[+] Decrypting...')
                sleep(1)
                print('[+] Decryption succesful!')
                sleep(1)
            else:
                print('[-] Dragon could not find this file.')
                sleep(3)
                
        elif choice.lower() == 'b':
            path = raw_input('Full path to directory: ')
            print('[+] Checking for existance...')
            sleep(1)
            if os.path.exists(path) == True:
                password  = raw_input('Password: ')
                encryptDir(getKey(password), path)
                print('[+] Dragons at work...')
                sleep(1)
                print('[+] Encrypting...')
                sleep(1)
                print('[+] Encryption succesful!')
                sleep(1)
            else:
                print('[-] Dragon could not find this directory. ')
                
                
        elif choice.lower() == 'd':
            path = raw_input('Full path to encrypted directory: ')
            print('[+] Checking for existance...')
            sleep(1)
            if os.path.exists(path):
                password = raw_input('Password: ')
                decryptDir(getKey(password), path)
                print('[+] Dragons at work...')
                sleep(1)
                print('[+] Decrypting...')
                sleep(1)
                print('[+] Decryption succesful!')
                sleep(1)
            else:
                print('[-] Dragon could not find this directory. ')
                
        else:
            print('Invalid choice')
            


if  __name__=='__main__':
    main()
