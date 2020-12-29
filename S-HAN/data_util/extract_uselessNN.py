import os, re, yaml, spacy, json
from multiprocessing import Process, Manager
from stanfordcorenlp import StanfordCoreNLP
from tqdm import  tqdm

from utils import list2file

nlp = StanfordCoreNLP(r"http://localhost", port=9000)
nlps = spacy.load('en_core_web_sm')

class GetUselessNN():
    def __init__(self, for_pattern=False):
        self.cfg = None

        with open('../config.yml', 'r') as yml:
            self.cfg = yaml.load(yml, Loader=yaml.FullLoader)
        self.libs = self.cfg['train']['train_libs'] + self.cfg['train']['test_libs'] + self.cfg['predict']['predict_libs']
        self.libs_NN, self.libs_uselessNN = dict(), dict()

    def libs_sent_uselessNN(self):
        """
        load all the sentences of all the libs(train, test, predict);
        then extract their useless NN to dict 'self.libs_NN';
        last, compare each lib pairly and get uselessNN results
        :return:
        """
        '''load NNs of library'''
        for lib_other in self.libs:
            lib_sent = list()
            crawled_file = os.path.join(self.cfg['train']['basedir'], lib_other, 'crawled_data', 'crawled.json')

            if not os.path.exists(crawled_file):
                crawled_file = os.path.join(self.cfg['predict']['basedir'], lib_other, 'crawled_data', 'crawled.json')
            if not os.path.exists(crawled_file):
                print('{} not exists'.format(crawled_file))
                continue

            with open(crawled_file, 'r') as f:
                for line in json.load(f):
                    lib_sent.append(line['sent'])

            self.libs_NN[lib_other] = self.extract_lib_NN(lib_sent)

        '''extract uselessNN and save'''
        self.cmp_libs()
        self.save()

    def save(self):
        for lib in self.libs_uselessNN:
            if lib in self.cfg['train']['test_libs']:
                lib_basedir = os.path.join(self.cfg['train']['basedir'], lib)
            else:
                lib_basedir = os.path.join(self.cfg['predict']['basedir'], lib)

            save_file = os.path.join(lib_basedir, 'useless_NN')
            self.cfg['libs_uselessNN'][lib] = save_file
            list2file(self.libs_uselessNN[lib], save_file)

        with open('../config.yml', 'w') as yml:
            yaml.dump(self.cfg, yml)

    def cmp_libs(self):
        '''
        compare every pairs of 'self.libs_NN' except the training libs
        store the uselessNN results at 'self.libs_uselessNN'
        :return:
        '''
        for lib in self.libs_NN:  # the lib to be examined
            if lib in self.cfg['train']['train_libs']:  # skip the training libs
                continue
            inter = list()

            for lib_a in self.libs_NN:  # loop other libs(except lib)
                if lib_a != lib:

                    for lib_b in self.libs_NN:  # loop other libs(except lib and lib_a)
                        if lib_b != lib and lib_b != lib_a:

                            lib_NN = self.libs_NN[lib]
                            lib_a_NN = self.libs_NN[lib_a]
                            lib_b_NN = self.libs_NN[lib_b]
                            inter += list(set(lib_a_NN).intersection(set(lib_b_NN)))  # append the intersection of every pair
                            self.libs_uselessNN[lib] = list(set(lib_NN).difference(set(inter)))

    def extract_lib_NN(self, lines):
        manager, jobs = Manager(), list()
        processed_data_list = manager.list()

        for line in tqdm(lines):

            if len(jobs) > 100:
                for proc in jobs:
                    proc.join(30)
                jobs = list()

            p = Process(target=self.extract_line_NN, args=(line, processed_data_list))
            jobs.append(p)
            p.start()

        for proc in jobs:
            proc.join(30)

        return list(set(processed_data_list))

    def extract_line_NN(self, line, results):
        pos = nlp.pos_tag(line.lower())
        for pair in pos:
            if pair[1] in ['NN', 'NNS', 'NNP', 'NNPS']:
                if not re.search(r'api', pair[0]):
                    '''filter NN first'''
                    word = re.sub(r'\([^\)]+?\)', '', pair[0].lower())
                    word = word.replace('-', '_')
                    word = re.sub(r'(\w+[\\/])+\w*|\.\w+', '', word)
                    word = re.sub(r'[^_\w]', '', word)
                    n_word = nlps(word)
                    word = " ".join([token.lemma_ for token in n_word])

                    if word and len(word) > 1 and len(word.strip('_')) > 1:
                        results.append(word)
