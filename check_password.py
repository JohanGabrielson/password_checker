import hashlib
import requests 

#Check length and complexity, validate set rules for password
def check_length_and_complexity(pw: str) -> bool:
    #Check min length requirment
    if len(pw) < 8:
        print("Password is too short (min 8 characters).")
        return False

    #Must contain upper case, lower case, digit  
    if not any(c.isupper() for c in pw):
        print("Password lacks upperase letters")
        return False
    if not any(c.islower() for c in pw):
        print("Password lacks lowercase letters")
        return False
    if not any(c.isdigit() for c in pw):
        print("Password lacks digits")
        return False        
    return True

 #Check rockyou.txt

def check_local_wordlist(pw : str, wordlist_path="/usr/share/wordlists/rockyou.txt") -> bool:
    try:
 #Open wordlist, ignoring encoding errors 
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
               #Compare each line stripped of newliine characters
                if line.strip() == pw:
                    print("Password found in rockyou.txt - choose another password.")
                    return False
    except FileNotFoundError:
       #If wordlist is missing, password is allowed but a warning is given
        print("Wordlist not found. Cannot validate password")
        return True
    
    return True

   #Check online leak: check password against haveibeenpwned  

def check_online_leak(pw: str) -> bool:
        #Hash password using SHA1 and convert to uppercase  
    sha1_pw = hashlib.sha1(pw.encode('utf-8')).hexdigest().upper()
    
     #split into prefix (first five characters) and suffix (remaining) 
    prefix, suffix = sha1_pw[:5], sha1_pw[5:]
    
     #Query api with prefix for K-anonymity
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

     #If API fails, warn user   
    if response.status_code != 200:
        print("Error fetching data from Have I Been Pwned API.")
        return True

    # Check if suffix appears in returned list  
    for line in response.text.splitlines():
        if line.startswith(suffix + ":"):      
            count = line.split(":")[1]
            print(f"Password found {count} times in data breaches - choose another password.")
            return False

    return True

def main():
    pw = input("Enter a password to check: ")
     #Runs in order, stop on first failure  
    if not check_length_and_complexity(pw):
        return
    if not check_local_wordlist(pw):
        return
    if not check_online_leak(pw):
        return                          
    print("Password is strong and not found in leaks or wordlists.")    

if __name__ == "__main__":
    main()
