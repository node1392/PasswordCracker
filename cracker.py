
import hashlib
import os
# returns a translation table that maps each character in the
# intabstring into the character at the same position in the outtab string
# then the table is passed to the translate function
from string import maketrans
import threading
import time
import sys

def main(passwordFile, results_file, timout, salt=None):
    """Main method (entry point) of the program.
    
    Args:
        passwordFile: path of password file.
        results_file: path of result file.
        timeout: timeout in seconds.
        salt: optional salt."""
        
    # declare global variable so that they can be accessed in threaded methods
    global solved
    global transtab
    global passwords
    global listDict
    global listABCDEFG
    global listLeet
    global listPQR
    global listXYZ
    global listNum
    global listNumSmall
    global lock
    global lock2
    global lock3
    global resultsFile
    global generated
    global attempted
    
    startTime = time.time() 
    
    print "Password Cracker is running...\n"
    
    # delete already existing content of results file
    resultsFile = results_file
    open(resultsFile, "w").close()
    
    
    solved = []
    generated = 0
    attempted = set()
 
    # open password file and store all the passwords in a list
    hPasswordFile = open(passwordFile, "r")
    passwords = hPasswordFile.readlines()
    hPasswordFile.close()
    passwords = [password.split("::")[2].strip() for password in passwords]
    
    # open dictionary file and store all the items in a list
    hDictFile = open("john.txt", "r")
    listDict = hDictFile.readlines()
    hDictFile.close()
     
    # apply salt to dictionary list if salt is specified
    if salt:
        listDict = [(item.strip() + salt).encode('utf-8') for item in listDict]
    else:
        listDict = [item.strip().encode('utf-8') for item in listDict]
    
    # make a trans table for leet characters (hacker language)
    # maps each character in the intab string into the character in the outtab string
    intab =  "aegiost" # the string having actual characters
    outtab = "4361057" # the string having corresponding mapping character
    transtab = maketrans(intab, outtab)
    
    # create a brute-force list using alphabets "abcdef"
    alpha = 'abcdef'
    listABCDEFG = []
    for current in xrange(2, 7):
        a = [i for i in alpha]
        for y in xrange(current):
            a = [x+i for i in alpha for x in a]
        listABCDEFG = listABCDEFG + a
        
    # apply salt to brute-force list "abcdef" if salt is specified
    if salt:
        listABCDEFG = [(item + salt) for item in listABCDEFG] 
     
    # create a brute-force list using leets "4bcd3f"
    leet = '4bcd3f'
    listLeet = []
    for current in xrange(2, 7):
        a = [i for i in leet]
        for y in xrange(current):
            a = [x+i for i in leet for x in a]
        listLeet = listLeet + a

    # apply salt to brute-force list "4bcd3f" if salt is specified
    if salt:
        listLeet = [(item + salt) for item in listLeet] 
     
    # create a brute-force list using alphabets "pqr"
    alpha = 'pqr'
    listPQR = []
    for current in xrange(2, 4):
        a = [i for i in alpha]
        for y in xrange(current):
            a = [x+i for i in alpha for x in a]
        listPQR = listPQR + a
     
    # apply salt to brute-force list "pqr" if salt is specified
    if salt:
        listPQR = [(item + salt) for item in listPQR] 

    # create a brute-force list using alphabets "xyz"
    alpha = 'xyz'
    listXYZ = []
    for current in xrange(2, 4):
        a = [i for i in alpha]
        for y in xrange(current):
            a = [x+i for i in alpha for x in a]
        listXYZ = listXYZ + a
     
    # apply salt to brute-force list "xyz" if salt is specified
    if salt:
        listXYZ = [(item + salt) for item in listXYZ] 

    # create a brute-force list using numbers "123456"
    nums = '123456'
    listNum = []
    for current in xrange(2, 7):
        a = [i for i in nums]
        for y in xrange(current):
            a = [x+i for i in nums for x in a]
        listNum = listNum + a
        
    # apply salt to brute-force list "123456" if salt is specified
    if salt:
        listNum = [(item + salt) for item in listNum] 

    # create a brute-force list using numbers "123456" (2 and 3 numbers) that 
    # will be appended to other words 
    nums = '123456'
    listNumSmall = []
    for current in xrange(2, 4):
        a = [i for i in nums]
        for y in xrange(current):
            a = [x+i for i in nums for x in a]
        listNumSmall = listNumSmall + a
    
    # list of methods that will be running using threads
    methods = [crackListDict, crackListNum, crackListABCDEFG, 
               crackListLeet, crackListPQR, crackListXYZ, 
               crackListABCDEFGWithNum, crackListLeetWithNum, 
               crackListPQRWithNum, crackListXYZWithNum]
    
    # events to stop threads
    events = []
    # list of threads
    threads = []
    
    # lock to write to file in exclusive mode
    lock = threading.Lock()
    # lock to updated 'generated' variable
    lock2 = threading.Lock()
    # lock to updated 'attempted' set
    lock3 = threading.Lock()
    
    totalMethods = len(methods)
    
    # create thread for each method and assign an event to each
    for i in range(totalMethods):
        events.append(threading.Event())
        threads.append(threading.Thread(target=methods[i], args=(events[i], )))
    
    # start all the threads
    for i in range(totalMethods):
        threads[i].start()
    
    diff = time.time() - startTime
    timeoutRemaining = round(timeout - diff, 0)
    
    # sleep for timeout
    time.sleep(timeoutRemaining)
    
    # stop all the threads by setting their events
    for i in range(totalMethods):
        events[i].set()

    # write total number of cracked passwords in results file
    f = open(resultsFile, "a+")
    f.write("Total cracked: " + str(len(solved)))
    f.close()

    print "\nProgram ran for:", timeout, "seconds"
    print "Generated passwords:", generated
    print "User passwords attempted to crack:", len(attempted) 
    print "Successfully cracked:", len(solved)

def writeToFile(encrypted, decrypted):
    """This method writes cracked password to results file.
    
    Args:
        encrypted: encrypted hash password.
        decrypted: decrypted string password.
    """
    
    # acquire lock for exclusive use of file
    lock.acquire()
    
    # write password to file
    f = open(resultsFile, "a+")
    f.write("Cracked: " + encrypted + ", Password: " + decrypted + os.linesep)
    f.close()
    
    # release the lock
    lock.release()

def updateGenerated():
    """This method increments 'generated' value by one."""
    global generated
    
    # acquire lock for exclusive use of file
    lock2.acquire()
    
    generated += 1
    
    # release the lock
    lock2.release()


def updateAttempted(password):
    """This method updates 'attempted' set by adding password into it."""
    # acquire lock for exclusive use of file
    lock3.acquire()
    
    attempted.add(password)
    
    # release the lock
    lock3.release()


def crackListDict(stopEvent):
    """This method cracks the passwords using dictionary method.
    
    Args:
        stopEvent: threading.Event object used to stop this thread.    
    """
    
    for password in passwords:
        updateAttempted(password)
                
        # Stop the thread if event is set
        if stopEvent.is_set():
            return
        
        # Skip current password if it already cracked
        if password in solved:
            continue

        for word in listDict:
            # Stop the thread if event is set
            if stopEvent.is_set():
                return
        
            # create hashed password for each word in dictionary
            hashed = hashlib.sha256(word).hexdigest()
            
            updateGenerated()
            
            # checks if hashed password matches the password in passwordsFile,
            # if it does, writes the cracked password to results file
            if hashed == password:
                solved.append(password)
                writeToFile(password, word)
                print "Cracked: " + password + ", Password: " + word
                break
             
            else:
                # Stop the thread if event is set
                if stopEvent.is_set():
                    return
        
                # create a leetspeak password from dictionary
                tmpWord = word.translate(transtab)
                
                # create hashed password for leetspeak word
                hashed = hashlib.sha256(tmpWord).hexdigest()
                
                updateGenerated()
                
               # checks if hashed password matches the password in passwordsFile,
               # if it does, writes the cracked password to results file
                if hashed == password:
                    solved.append(password)
                    writeToFile(password, tmpWord)
                    print "Cracked: " + password + ", Password: " + tmpWord
                    break
            
                
def crackListNum(stopEvent):
    """This method cracks the passwords using brute-force list of numbers.
    
    Args:
        stopEvent: threading.Event object used to stop this thread.    
    """
    
    for password in passwords:
        updateAttempted(password)
        
        # Stop the thread if event is set
        if stopEvent.is_set():
            return

        # Skip current password if it already cracked
        if password in solved:
            continue
        
        for word in listNum:
            # Stop the thread if event is set
            if stopEvent.is_set():
                return
        
            # create hashed password for each word in brute-force list
            hashed = hashlib.sha256(word).hexdigest()
            
            updateGenerated()
            
            # checks if hashed password matches the password in passwordsFile,
            # if it does, writes the cracked password to results file
            if hashed == password:
                solved.append(password)
                writeToFile(password, word)
                print "Cracked: " + password + ", Password: " + word
                break

def crackListABCDEFG(stopEvent):
    """This method cracks the passwords using brute-force list "abcdef".
    
    Args:
        stopEvent: threading.Event object used to stop this thread.    
    """
    
    for password in passwords:
        updateAttempted(password)
        
        # Stop the thread if event is set
        if stopEvent.is_set():
            return

        # Skip current password if it already cracked
        if password in solved:
            continue
        
        for word in listABCDEFG:
            # Stop the thread if event is set
            if stopEvent.is_set():
                return
        
            # create hashed password for each word in brute-force list
            hashed = hashlib.sha256(word).hexdigest()
            
            updateGenerated()
            
            # checks if hashed password matches the password in passwordsFile,
            # if it does, writes the cracked password to results file
            if hashed == password:
                solved.append(password)
                writeToFile(password, word)
                print "Cracked: " + password + ", Password: " + word
                break

def crackListLeet(stopEvent):
    """This method cracks the passwords using brute-force list "4bcd3f".
    
    Args:
        stopEvent: threading.Event object used to stop this thread.    
    """
    
    for password in passwords:
        updateAttempted(password)
        
        # Stop the thread if event is set
        if stopEvent.is_set():
            return

        # Skip current password if it already cracked
        if password in solved:
            continue
        
        for word in listLeet:
            # Stop the thread if event is set
            if stopEvent.is_set():
                return
        
            # create hashed password for each word in brute-force list
            hashed = hashlib.sha256(word).hexdigest()
            
            updateGenerated()
            
            # checks if hashed password matches the password in passwordsFile,
            # if it does, writes the cracked password to results file
            if hashed == password:
                solved.append(password)
                writeToFile(password, word)
                print "Cracked: " + password + ", Password: " + word
                break

def crackListPQR(stopEvent):
    """This method cracks the passwords using brute force list "pqr".
    
    Args:
        stopEvent: threading.Event object used to stop this thread.    
    """
    
    for password in passwords:
        updateAttempted(password)
        
        # Stop the thread if event is set
        if stopEvent.is_set():
            return

        # Skip current password if it already cracked
        if password in solved:
            continue
        
        for word in listPQR:
            # Stop the thread if event is set
            if stopEvent.is_set():
                return
        
            # create hashed password for each word in brute-force list
            hashed = hashlib.sha256(word).hexdigest()
            
            updateGenerated()
            
            # checks if hashed password matches the password in passwordsFile,
            # if it does, writes the cracked password to results file
            if hashed == password:
                solved.append(password)
                writeToFile(password, word)
                print "Cracked: " + password + ", Password: " + word
                break

def crackListXYZ(stopEvent):
    """This method cracks the passwords using brute-force list "xyz".
    
    Args:
        stopEvent: threading.Event object used to stop this thread.    
    """
    
    for password in passwords:
        updateAttempted(password)
        
        # Stop the thread if event is set
        if stopEvent.is_set():
            return

        # Skip current password if it already cracked
        if password in solved:
            continue
        
        for word in listXYZ:
            # Stop the thread if event is set
            if stopEvent.is_set():
                return
        
            # create hashed password for each word in brute-force list
            hashed = hashlib.sha256(word).hexdigest()
            
            updateGenerated()
            
            # if hashed password matches the password in passwordsFile,
            #  write the cracked password to results file
            if hashed == password:
                solved.append(password)
                writeToFile(password, word)
                print "Cracked: " + password + ", Password: " + word
                break

def crackListABCDEFGWithNum(stopEvent):
    """This method cracks the passwords using brute-force list "abcdefg" by 
    appending different numbers to it.
    
    Args:
        stopEvent: threading.Event object used to stop this thread.    
    """
    
    for password in passwords:
        updateAttempted(password)
        
        # Stop the thread if event is set
        if stopEvent.is_set():
            return
        
        # Skip current password if it already cracked
        if password in solved:
            continue
        
        for word in listABCDEFG:
            # Stop the thread if event is set
            if stopEvent.is_set():
                return
        
            found = False
            
            for num in listNumSmall:
                # append each number to brute-force list word
                tmpWord = word + num
                
                # create hashed password for each word in brute-force list
                hashed = hashlib.sha256(tmpWord).hexdigest()
                
                updateGenerated()
                
                # if hashed password matches the password in passwordsFile,
                #  write the cracked password to results file
                if hashed == password:
                    found = True
                    solved.append(password)
                    writeToFile(password, tmpWord)
                    print "Cracked: " + password + ", Password: " + tmpWord
                    break
            
            if found:
                break
                
def crackListLeetWithNum(stopEvent):
    """This method cracks the passwords using brute-force list "4bcd3fg" by 
    appending different numbers to it.
    
    Args:
        stopEvent: threading.Event object used to stop this thread.    
    """
    
    for password in passwords:
        updateAttempted(password)
        
        # Stop the thread if event is set
        if stopEvent.is_set():
            return
        
        # Skip current password if it already cracked
        if password in solved:
            continue
        
        for word in listLeet:
            # Stop the thread if event is set
            if stopEvent.is_set():
                return
        
            found = False
            
            for num in listNumSmall:
                # append each number to brute-force list word
                tmpWord = word + num
                
                # create hashed password for each word in brute force list
                hashed = hashlib.sha256(tmpWord).hexdigest()
                
                updateGenerated()
                
                # if hashed password matches the password in passwordsFile,
                #  write the cracked password to results file
                if hashed == password:
                    found = True
                    solved.append(password)
                    writeToFile(password, tmpWord)
                    print "Cracked: " + password + ", Password: " + tmpWord
                    break
            
            if found:
                break

def crackListPQRWithNum(stopEvent):
    """This method cracks the passwords using brute-force list "pqr" by 
    appending different numbers to it.
    
    Args:
        stopEvent: threading.Event object used to stop this thread.    
    """
    
    for password in passwords:
        updateAttempted(password)
        
        # Stop the thread if event is set
        if stopEvent.is_set():
            return
        
        # Skip current password if it already cracked
        if password in solved:
            continue
        
        for word in listPQR:
            # Stop the thread if event is set
            if stopEvent.is_set():
                return
        
            found = False
            
            for num in listNumSmall:
                # append each number to brute-force list word
                tmpWord = word + num
                
                # create hashed password for each word in brute force list
                hashed = hashlib.sha256(tmpWord).hexdigest()
                
                updateGenerated()
                
                # if hashed password matches the password in passwordsFile,
                #  write the cracked password to results file
                if hashed == password:
                    found = True
                    solved.append(password)
                    writeToFile(password, tmpWord)
                    print "Cracked: " + password + ", Password: " + tmpWord
                    break
            
            if found:
                break

def crackListXYZWithNum(stopEvent):
    """This method cracks the passwords using brute-force list "xyz" by 
    appending different numbers to it.
    
    Args:
        stopEvent: threading.Event object used to stop this thread.    
    """
    
    for password in passwords:
        updateAttempted(password)
        
        # Stop the thread if event is set
        if stopEvent.is_set():
            return
        
        # Skip current password if it already cracked
        if password in solved:
            continue
        
        for word in listXYZ:
            # Stop the thread if event is set
            if stopEvent.is_set():
                return
        
            found = False
            
            for num in listNumSmall:
                # append each number to brute-force list word
                tmpWord = word + num
                
                # create hashed password for each word in brute force list
                hashed = hashlib.sha256(tmpWord).hexdigest()
        
                updateGenerated()
                
                # if hashed password matches the password in passwordsFile,
                #  write the cracked password to results file
                if hashed == password:
                    found = True
                    solved.append(password)
                    writeToFile(password, tmpWord)
                    print "Cracked: " + password + ", Password: " + tmpWord
                    break
            
            if found:
                break

# Start the application when run from command line
if __name__ == '__main__':
    argv = sys.argv
    count = len(argv)

    # if wrong number of arguments received, show usage and exit
    if count < 4 or count > 5:
        print "Usage: cracker.py password_file results_file timeout [salt]"
        sys.exit(0)
    
    # if timeout argument is not numeric, show usage, error and exit
    timeout = 0
    try:
        timeout = int(argv[3])
        if timeout <= 0:
            raise(ValueError())
    except:
        print "Usage: cracker.py password_file results_file timeout [salt]"
        print "Wrong timeout"
        sys.exit(0)
    
    # manage non specified salt argument
    if count == 4:
        argv.append(None)
        
    # call main() function with arguments
    main(argv[1], argv[2], argv[3], argv[4])
    
