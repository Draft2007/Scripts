#
# NLTK QUERY CLASS MODULE
# Python-Forensics
# No HASP required
#
import os
import sys
import logging
import nltk
from nltk.corpus import PlaintextCorpusReader

# NLTKQuery Class
class classNLTKQuery:
    def textCorpusInit(self, thePath):
        # Validate the path is a directory
        if not os.path.isdir(thePath):
            return "Path is not a Directory"
        if not os.access(thePath, os.R_OK):
            return "Directory is not Readable"
        # Attempt to Create a corpus with all .txt files found in directory
        try:
            self.Corpus = PlaintextCorpusReader(thePath,'.*')
            print "Processing Files : "
            print self.Corpus.fileids()
            print "Please wait..."
            self.rawText = self.Corpus.raw()
            self.tokens = nltk.word_tokenize(self.rawText)
            self.TextCorpus = nltk.Text(self.tokens)
        except:
            print "failure"
            return "Corpus Creation Failed"
        self.ActiveTextCorpus = True
        print "Great Success"
        return "Success"
    def printCorpusLength(self):
        print "Corpus Text Length: ",
        print len(self.rawText)
    def printTokensFound(self):
        print "Tokens Found: ",
        print len(self.tokens)
    def printVocabSize(self):
        print "Calculating..."
        print "Vocabulary Size: ",
        vocabularyUsed = set(self.TextCorpus)
        vocabularySize = len(self.tokens)
        print vocabularySize
    def printSortedVocab(self):
        print "Compiling..."
        print "Sorted Vocabulary ",
        print sorted(set(self.TextCorpus))
    def printCollocation(self):
        print "Compiling Collocations..."
        self.TextCorpus.collocations()
    def searchWordOccurence(self):
        myWord = raw_input("Enter Search Word : ")
        if myWord:
            wordCount = self.TextCorpus.count(myWord)
            print myWord+" occured: ",
            print wordCount,
            print " times"
        else:
            print "Word Entry is Invalid"
    def generateConcordance(self):
        myWord = raw_input("Enter word to Concord : ")
        if myWord:
            self.TextCorpus.concordance(myWord)
        else:
            print "Word is Invalid"
    def generateSimilarities(self):
        myWord = raw_input("Enter seed word : ")
        if myWord:
            self.TextCorpus.similar(myWord)
        else:
            print "Word Entry is Invalid"
    def printWordIndex(self):
        myWord = raw_input("Find first occurence of what Word? : ")
        if myWord:
            wordIndex = self.TextCorpus.index(myWord)
            print "First Occurence of : " +myWord + "is at offset: ",
            print wordIndex
        else:
            print "Word Entry is Invalid"
    def printVocabulary(self):
        print "Compiling Vocabulary Frequencies ",
        vocabFreqList = self.TextCorpus.vocab()
        print vocabFreqList.items()
    
    
        