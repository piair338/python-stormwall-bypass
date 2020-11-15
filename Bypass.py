import re

STORMWALL_DETECTION_REGEXP = "https://static.stormwall.pro/jsav1.3.js"
STORMWALL_DETECTION_REGEXP_2 = "https://static.stormwall.pro/jsv1.3.js"                   
SUBSTITUTION_ALPHABET = '0123456789qwertyuiopasdfghjklzxcvbnm:?!'


def extract(string, regexp, errorMessage) :    
  match = re.search(regexp,string)            
  if (match) :  
    return match[1] 
  
  if (errorMessage) :
    print(errorMessage) 
  
def decipherChar(startIndex, char) :            
    charIndex = SUBSTITUTION_ALPHABET.find(char) 
    if (charIndex != -1) : 

        index = startIndex + charIndex 

        if (index < 0) :
            index += len(SUBSTITUTION_ALPHABET)
		
        return SUBSTITUTION_ALPHABET[index]
	
    return char

def getCookie(cE, cK) :                      
    ce1 = ""
    swpToken = cE
    cE = [lettre for lettre in cE]
    for i in cE:
        if cK > 38:
            cK = 0
        ce1 += decipherChar(-cK,i)
        cK = cK + 1

    return (ce1+";path=/;max-age=1800")

def getStormwallCookie(body) :                
    cE = extract(body, 'cE = "(.+)"', "could't find cE variable to bypass stormwall")  
    cK = extract(body, 'cK = (.+);', "could't find cK variable to bypass stormwall")   
    
    return getCookie(cE, int(cK))

def isProtectedByStormwall(body):                             
    return (STORMWALL_DETECTION_REGEXP in body or STORMWALL_DETECTION_REGEXP_2 in body)  
