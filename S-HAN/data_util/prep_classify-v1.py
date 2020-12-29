# -*- coding: UTF-8 -*-
# !/usr/bin/python
# @function:
"""
train/test classifier pre step
1. process:
    train dataset(get pos/neg from csv to sents=pos+neg);
    test dataset(get preprocessed lib sent to sents)
2. preprocess for classifying:
    replace api/param, remove if/when clauses, and necessary steps before NLP
    train dataset(aug first and pre 3=aug+neg+pos)
    test dataset(pre sents)
    cve sents(aug and pre 2)
3. copy train dataset(aug+pos+neg) to corpus
"""

import os, re, pdb, csv, csv, sys, spacy, string, enchant, nltk
from nltk.tree import ParentedTree
from nltk.parse.stanford import StanfordParser
from multiprocessing import Process, Manager
from stanfordcorenlp import StanfordCoreNLP
from nltk.tree import ParentedTree
from copy import deepcopy
from tqdm import tqdm
from utils import *

nlp = StanfordCoreNLP(r"http://localhost", port=9000)


class PreprocessWords():
    def __init__(self):
        self.infile = ''
        self.outfile = ''
        self.reffile = ''
        self.api_list_file = ''
        self.uselessNN_file = ''
        self.lib = ''
        self.rough = False
        self.unrelated_conj = ['if', 'when']
        self.abbrs = {"don't": "do not", "Don't": "do not", "doesn't": "does not", "Doesn't": "does not",
                      "didn't": "did not",
                      "couldn't": "could not", "Couldn't": "could not", "can't": "can not", "Can't": "can not",
                      "ca n't": "can not", "Ca n't": "can not",
                      "shouldn't": "should not", "Shouldn't": "should not", "should've": "should have",
                      "mightn't": "might not", "mustn't": "must not", "Mustn't": "must not", "needn't": "need not",
                      "haven't": "have not", "hadn't": "had not", "hasn't": "has not",
                      "you'd": "you should", "You'd": "you should", "you're": "you are", "You're": "you're",
                      "it's": "it is", "It's": "it is", "won't": "will not", "wo n't": "will not",
                      "isn't": "is not", "Isn't": "is not", "aren't": "are not", "Aren't": "are not"}

    def start_from_file(self, infile, outfile, reffile, api_list_file, uselessNN_file, lib, rough=False):
        self.infile = infile
        self.outfile = outfile
        self.reffile = reffile
        self.api_list_file = api_list_file
        self.uselessNN_file = uselessNN_file
        self.lib = lib
        self.rough = rough
        self.mul_thread_pre_words()

    def rough_pre_words(self, sent, result):
        """
        preprocess for pattern-VC when get semantic similarity
        :param sent: one sentence
        :param result: the preprocessed result list. each time we append [original sentence, roughly preprocessed sentence]
        :return:
        """
        sent_bk = deepcopy(sent)

        '''rm (xx)'''
        sent = re.sub(r'\(.*?\)|#', ' ', sent.lower())

        '''expand abbreviations'''
        for abbr in self.abbrs:
            if re.search(abbr, sent):
                sent = re.sub(abbr, self.abbrs[abbr], sent)
        # to check if needed
        abbrs = {" n't": " not", "'s": "", "'d": ""}
        for abbr in abbrs:
            sent = re.sub(abbr, abbrs[abbr], sent)

        '''time'''
        sent = re.sub(r'\d+:\d+:\d+', 'time', sent)
        sent = re.sub(r'(\w{2,}\.)+\w{2,}', '', sent)  # Java, except e.g. etc.
        sent = re.sub(r' \-?\d+[\-\.\d]* ', ' # ', sent)  # number
        sent = re.sub(r'^\-?\d+[\-\.\d]* ', '# ', sent)
        sent = re.sub(r' \-?\d+[\-\.\d]*$', ' #', sent)
        sent = sent.replace('-', '_')
        sent = re.sub(r'(\w+[\\/])+\w*|\.\w+', '', sent)
        sent = re.sub(r'[^,\.:;_#\w ]', ' ', sent)

        '''remove stop words'''
        stop_words = ['the', 'being', 'been', 'to', 'and', 'of', 'use', 'in', 'for', 'it', 'will', 'a', 'an', 'some',
                      'I', 'they', 'ourselves', 'hers', \
                      'this', 'that', 'with', 'not', 'on', 'from', 'there', 'their', 'very', 'he', 'own', 'its',
                      'itself', 'me', \
                      'any', 'may', 'all', 'do', 'theirs', 'themselves', 'his', 'himself', 'herself', 'him', \
                      'new', 'these', 'those', 'at', 'same', 'also']
        tokens = nltk.word_tokenize(sent)
        tmp = list()
        for word in tokens:
            if word not in stop_words:
                if word in ['id', 'ID']:
                    tmp.append('identifier')
                else:
                    tmp.append(word)

        '''lemmatization'''
        nlps = spacy.load('en_core_web_sm')
        n_sent = nlps(sent)
        sent = " ".join([token.lemma_ for token in n_sent])
        sent = re.sub(r'^_ | _ | _$', ' ', sent)
        sent = re.sub(r'^[^\w#]+|[^\w#]+$', '', sent)

        ''' skip too short sentence '''
        puncs = string.punctuation
        pure_sent = list()
        for word in sent.split():
            if word not in puncs:
                pure_sent.append(word)
        if len(pure_sent) < 2:
            return

        result.append([sent_bk, sent])

    def pre_words(self, sent, api_names, useless_NN, result):
        """
        preprocess for sentence before being classified
        :param sent: sentence to be preprocessed
        :param api_names: the list of API names of this library
        :param useless_NN: the list of words with low frequency
        :param result: the preprocessed result list. each time we append [original sentence, roughly preprocessed sentence]
        :return:
        """
        sent_bk = deepcopy(sent)

        '''expand abbreviations'''
        sent = sanitization_abbr(sent)

        sent = re.sub('note that|Note that|#', ' ', sent)
        '''rm (xx) #'''
        sent = re.sub(r'\([^\)]+?\)|#', ' ', sent)
        '''time'''
        sent = re.sub(r'\d+:\d+:\d+', 'time', sent)

        '''replace api, NEEDED'''
        sent = re.sub(r'methods?|interfaces?|routines?', 'api', sent)  # Java
        sent = re.sub(r'\S+_APIName', 'api', sent)
        sent = re.sub(r'\S+\(\)', 'api', sent)
        new_words = list()
        for word in sent.split():
            if word.lower() in api_names:
                new_words.append('api')
            else:
                new_words.append(word)
        sent = ' '.join(new_words)
        sent = re.sub('func ', 'function ', sent)

        '''replace param, NEEDED'''
        sent = re.sub(r'\S+_APIParam\S+', 'param', sent)
        sent = re.sub(r'(\w{2,}\.)+\w{2,}', 'param', sent)  # Java, except e.g. etc.
        sent = re.sub(r'parameters?|arguments?', 'param', sent)
        sent = re.sub(r'\w+_\S+ structure|\w+_\S+ type|\w+_\S+ object', 'param', sent)

        '''replace AA_BB with constant, NEEDED'''
        sent = re.sub(r'([A-Z]+\d*_)+[A-Z\d\.]+', 'constant', sent)
        sent = re.sub(r'\S+_constant', 'constant', sent)

        ''' DOUBTED '''
        sent = re.sub(r'[A-Z]+_\S+', 'api', sent).lower()  # TODO:?

        '''rp number to constant, NEEDED '''
        sent = re.sub(r' zero| true| false', ' constant', sent)
        sent = re.sub(r' \-?\d+[\-\.\d]* ', ' constant ', sent)
        sent = re.sub(r'^\-?\d+[\-\.\d]* ', 'constant ', sent)
        sent = re.sub(r' \-?\d+[\-\.\d]*$', ' constant', sent)

        sent = sent.replace('-', '_')
        sent = sent.replace(' _ ', ' ')

        ''' DOUBTED, try rp with variable'''
        sent = re.sub(r'\w+_\S+', 'param', sent)  # TODO: var?

        sent = re.sub(r'(api[ ,]+)*api', 'api', sent)
        sent = re.sub(r'(constant[ ,]+)*constant', 'constant', sent)
        sent = re.sub(r'(param[ ,]+)*param', 'param', sent)
        sent = re.sub(r' (var[ ,]+)*var ', ' var ', sent)

        '''del ATA-100, .NET, sth like version, path'''
        sent = re.sub(r'(\w+[\\/])+\w*|\.\w+', '', sent)

        sent = re.sub(r'[^,\.:;_\w ]', ' ', sent)
        sent = re.sub(r'\s\d+\s|^\d+|\d+$', ' constant ', sent)
        sent = re.sub(r'(constant[ ,]+)*constant ', 'constant ', sent)
        sent = re.sub(r'(, )+,', ',', sent)
        sent = re.sub(r'^\W+|\W+$', '', sent)
        sent = sent.lower()

        '''remove stop words'''
        stop_words = ['i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves', 'your', 'yours', 'yourself',
                      'yourselves', 'he',
                      'him', 'his', 'himself', 'she', "she's", 'her', 'hers', 'herself', 'it', 'its', 'itself', 'they',
                      'them', 'their',
                      'theirs', 'themselves', 'what', 'who', 'whom', 'this', 'that', "that'll", 'these', 'those', 'am',
                      'being', 'do', 'a',
                      'an', 'the', 'and', 'or', 'of', 'for', 'with', 'about', 'between', 'into', 'through', 'above',
                      'below', 'to', 'from',
                      'up', 'down', 'in', 'out', 'on', 'off', 'over', 'under', 'again', 'further', 'then', 'once',
                      'here', 'there', 'when',
                      'where', 'why', 'how', 'all', 'any', 'both', 'each', 'few', 'more', 'most', 'other', 'some',
                      'such', 'own', 'same', 'so',
                      'than', 'too', 'very', 's', 't', 'will', 'just', 'don', 'now', 'd', 'll', 'm', 'o', 're', 've',
                      'y', 'ain', 'aren',
                      "aren't", 'ma', 'mightn', "mightn't", 'mustn', "mustn't", 'needn', "needn't", 'shan', "shan't",
                      'shouldn', "shouldn't",
                      'wasn', "wasn't", 'weren', "weren't", 'won', "won't", 'wouldn', "wouldn't", 'at', 'new', 'also',
                      'I'
                      ]

        tokens = nltk.word_tokenize(sent)
        sent = ' '.join([word for word in tokens if word not in stop_words])

        '''lemmatization'''
        nlps = spacy.load('en_core_web_sm')
        n_sent = nlps(sent)
        sent = " ".join([token.lemma_ for token in n_sent])

        '''replace useless NN '''
        new_words = list()
        puncs = string.punctuation
        for word in sent.split():
            if word in ['api', 'param', 'constant', 'var']:
                new_words.append(word)
            elif len(word) == 1 and word not in puncs:
                continue
            elif word.lower() in useless_NN and not re.search('_', word):
                continue  # skip specific word
            elif re.search(r'[a-z_]+[0-9]+', word):
                if re.search(r'utf', word):
                    new_words.append(word)
            else:
                new_words.append(word)
        sent = ' '.join(new_words)

        '''remove SBAR/PP clause('if/when') and only save sentence whose length > 2 '''
        new_sent = self.del_clause(sent)
        if new_sent != '':
            sent = new_sent

        sent = re.sub(r'(constant[ ,]+)*constant', 'constant', sent)
        sent = re.sub(r'(api[ ,]+)*api', 'api', sent)
        sent = re.sub(r'(param[ ,]+)*param', 'param', sent)

        ''' skip too short sentence '''
        # if len(sent.split()) < 2:
        #     return

        result.append([sent_bk, sent])

    def del_subtree(self, tree, labels, conj):

        debug_ret = False

        for idx, subtree in enumerate(tree):
            if type(subtree) != nltk.tree.ParentedTree:
                continue

            if self.del_subtree(subtree, labels, conj):
                debug_ret = True

            if subtree.label() in labels and re.match(conj, ' '.join(subtree.leaves()), flags=re.IGNORECASE):
                tree[idx] = nltk.tree.ParentedTree('NN', [''])
                debug_ret = True

        return debug_ret

    def del_clause(self, sent):
        new_sent = ''

        try:
            tree_str = nlp.parse(sent)
            tree = nltk.tree.Tree.fromstring(tree_str)
            tree = nltk.tree.ParentedTree.convert(tree)
        except Exception as e:
            print(e)
            return new_sent

        debug_ret = False
        for idx, conj in enumerate(self.unrelated_conj):
            ret = self.del_subtree(tree, ['SBAR', 'PP'], conj)
            if ret:
                debug_ret = True
            if not debug_ret and conj in sent:
                return new_sent

        new_sent = ' '.join(tree.leaves())
        if debug_ret:
            if len(re.sub(r'[^\w ]+', '', new_sent).split()) > 2:
                return new_sent

        return ''

    def mul_thread_pre_words(self):

        with open(self.infile, 'r') as f:
            data = f.read().split('\n')[:-1]

        ''' get api name and useless NN , or just pass list '''
        try:
            api_names = file2list(self.api_list_file)
            api_names = [one.lower() for one in api_names]
        except:
            api_names = list()
            print('api list empty')
        try:
            useless_NN = file2list(self.uselessNN_file)
            useless_NN = [one.lower() for one in useless_NN]
        except:
            useless_NN = list()
            print('useless NN empty')

        manager, jobs = Manager(), list()
        processed_data_list = manager.list()

        for data in tqdm(data):

            if len(jobs) > 100:
                for proc in jobs:
                    proc.join(30)
                jobs = list()

            if self.rough:
                p = Process(target=self.rough_pre_words, args=(data, processed_data_list))
            else:
                p = Process(target=self.pre_words, args=(data, api_names, useless_NN, processed_data_list))
            jobs.append(p)
            p.start()

        for proc in jobs:
            proc.join(30)

        output, ref = '', ''
        for idx, item in enumerate(processed_data_list):
            if item[1]:
                output += item[1] + '\n'
            ref += str(item) + '\n'

        with open(self.outfile, 'w') as f:
            f.write(output)
        with open(self.reffile, 'w') as f:
            f.write(ref)

