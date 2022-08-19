#===============================================================
# By Phoenix Dimagiba
# Summer 2022
#
# This program finds/extracts information from Defender
# MpWppTracing files.
#===============================================================
import re
import binascii

def main():

    inputFilename = input("Enter the file name: ")

    with open(inputFilename, 'rb') as f:
        text = f.read().decode(errors='replace')   
    #print(text)

    with open(inputFilename, 'rb') as g:
        hexdata = g.read().hex()
    #print(hexdata)

    dllResults = re.findall(r'[A-Za-z]*\.dll', text)
    dllResults = list(set(dllResults))
    if not dllResults:
        print("No .dll files detected.\n")
    else:
        print(dllResults, '\n')

    pdbResults = re.findall(r'[A-Za-z]*\.pdb', text)
    pdbResults = list(set(pdbResults))
    if not pdbResults:
        print("No .pdb files detected.\n")
    else:
        print(pdbResults, '\n')

    #binFilepathResults = re.findall(r'C:\\[\S\s]*\.bin?', text)
    #print(binFilepathResults)

    '''
    pidResults = re.findall(r'7000690064003a.*?2c', hexdata)
    pidResults = list(set(pidResults))
    print(pidResults)
    if not pidResults:
        print("No PIDs detected.\n")
    else:    
        print("PIDs detected:")
        for i in range(len(pidResults)):
            ba  = bytearray.fromhex(pidResults[i])
            print(ba.decode())
        print()
    
    '''
    pidProcessTimeResults = re.findall(r'7000690064003a.*?0000', hexdata)
    pidProcessTimeResults = list(set(pidProcessTimeResults))
    print(pidProcessTimeResults)
    if not pidProcessTimeResults:
        print("No PIDs detected.\n")
    else:    
        print("PIDs detected:")
        for i in range(len(pidProcessTimeResults)):
            ba  = bytearray.fromhex(pidProcessTimeResults[i])
            print(ba.decode())
        print()
    

    mimikatzResults = re.findall(r'6d0069006d0069006b00610074007a00', hexdata)
    ba  = bytearray.fromhex(mimikatzResults[0])
    if not mimikatzResults:
        print("No 'mimikatz' string detected.\n")
    else:
        print("'", ba.decode(), "' string detected")


main()