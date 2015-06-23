#
# NLTK Query Support Methods
# Python-Forensics
# No Hasp Required
#
# Function to print the NLTK Query Option Menu
def printMenu():
    print "==========NLTK Query Options=========="
    print "[1] Print Length of Corpus"
    print "[2] Print Number of Tokens Found"
    print "[3] Print Vocabulary Size"
    print "[4] Print Sorted Vocabulary"
    print "[5] Print Collocation"
    print "[6] Search for Word Occurrence"
    print "[7] Generate Concordance"
    print "[8] Generate Similarities"
    print "[9] Print Word Index"
    print "[10] Print Vocabulary"
    print
    print "[0] Exit NLTK Experimentation"
    print
# Function to obtain user input
def getUserSelection():
    printMenu()
    try:
        menuSelection = int(input('Enter Selection (0-10) >>'))
    except ValueError:
        print 'Invalid input. Enter a value between 0-10.'
        return -1
    if not menuSelection in range(0, 11):
        print 'Invalid input. Enter a value between 0-10.'
        return -1
    return menuSelection