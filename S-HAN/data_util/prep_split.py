# -*- coding: UTF-8 -*-
# !/usr/bin/python
# @function: the preprocess-A after crawling
# including deleting unrelated components and splitting condition and proposition

import time, pdb, json, string, re, sys, multiprocessing, nltk, os, csv, pdb, copy, yaml
from nltk.parse.stanford import StanfordParser
from multiprocessing import Process, Manager
from stanfordcorenlp import StanfordCoreNLP
from nltk.tree import ParentedTree
from copy import deepcopy
from tqdm import tqdm

nlp = StanfordCoreNLP(r"http://localhost", port=9000)

'''
TODO: 1) conjunction
'''


class DelUnrelatedComponent:
    """
    input: json file after crawling
    output: new json file with conciser data['sent']
    functions:
    1. expand abbreviations, e.g. don't -> do not
    2. delete unrelated component
    """

    def __init__(self):
        self.data = list()
        self.in_file, self.out_file = '', ''
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
        self.unrelated_conj = ['although', 'though', 'because', 'since', 'due to', 'in order to', 'for example',
                               'even if', 'even though', 'otherwise', 'for which', 'whether']
        '''
        how much, how many, ^To do, (...), instead
        1) how much memory must be allocated for the shared secret computed by DH_compute_key_APIName
        2) To process KEKRecipientInfo types CMS_set1_key_APIName or CMS_RecipientInfo_set0_key_APIName and CMS_ReceipientInfo_decrypt_APIName should be called before CMS_decrypt_APIName and CMS_decrypt_APIParam_3 and CMS_decrypt_APIParam_2 set to NULL
        3) It should equal half of the targeted security level in bits (rounded up to the next integer if necessary).
        4) applications should generally avoid using RSA structure elements directly and instead use API functions to query or modify keys.
        '''

    def start_from_file(self, in_file, out_file):
        print('[+] del_unlreated_component')
        self.in_file = in_file
        self.out_file = out_file
        print(in_file)
        with open(self.in_file, 'r') as f:
            self.data = json.load(f)
        self.multi_del_clause()
        print('all sents:%d' % len(self.data))

    def debug_line(self, line):
        ret_data = list()
        self.del_clause(line, ret_data)
        #print(ret_data)

    def del_subtree(self, tree, labels, conj):

        debug_ret = False

        for idx, subtree in enumerate(tree):
            if type(subtree) != nltk.tree.ParentedTree:
                continue

            if self.del_subtree(subtree, labels, conj):
                debug_ret = True

            if subtree.label() in labels and re.match(conj, ' '.join(subtree.leaves()), flags=re.IGNORECASE):
                #print(' '.join(tree.root().leaves()))
                #print(' '.join(subtree.leaves()))
                #print('\n')
                tree[idx] = nltk.tree.ParentedTree('NN', [''])
                debug_ret = True

        return debug_ret

    def del_clause(self, data, ret_data):

        if re.search(r'^see also|^See also', data['sent']):
            return
        sent = re.sub(r'\(.+?\)', '', data['sent'])

        '''map api/param name temporarily'''
        map_dict = dict()
        for idx, name in enumerate(re.findall(r'\S+_APIName|\S+_APIParam_\d+', sent)):
            new_name = 'Mapping_' + str(idx)
            map_dict[new_name] = name
            sent = re.sub(name, new_name, sent)

        '''expand abbreviations'''
        for abbr in self.abbrs:
            if re.search(abbr, sent):
                sent = re.sub(abbr, self.abbrs[abbr], sent)
        # to check if needed
        abbrs = {" n't": " not", "'s": "", "'d": ""}
        for abbr in abbrs:
            sent = re.sub(abbr, abbrs[abbr], sent)

        '''delete unrelated part'''
        try:
            tree_str = nlp.parse(sent)
            tree = nltk.tree.Tree.fromstring(tree_str)
            tree = nltk.tree.ParentedTree.convert(tree)
        except Exception as e:
            #print(e)
            ret_data.append(data)
            return

        changed = False
        for idx, conj in enumerate(self.unrelated_conj):
            ret = self.del_subtree(tree, ['SBAR'], conj)
            if ret:
                changed = True
            if not changed and conj in sent:  # we can not delete the conjunction
                ret_data.append(data)
                return

        '''save the change to data['sent']'''
        new_sent = ' '.join(tree.leaves())
        if changed:
            if len(re.sub(r'[^\w ]+', '', new_sent).split()) > 2:
                '''map back to api/param'''
                if map_dict:
                    for new_name in map_dict:
                        new_sent = re.sub(new_name, map_dict[new_name], new_sent)
                data['sent'] = new_sent
            else:
                ret_data.append(data)
                return
        ret_data.append(data)

    def multi_del_clause(self):

        manager, jobs = Manager(), list()
        ret_data = manager.list()

        for data in tqdm(self.data):

            if len(jobs) > 100:
                for proc in jobs:
                    proc.join(30)
                jobs = list()

            p = Process(target=self.del_clause, args=(data, ret_data))
            jobs.append(p)
            p.start()

        for proc in jobs:
            proc.join(30)

        ret_data = [x for x in ret_data]
        print('Advance sents:%d' % len(ret_data))
        with open(self.out_file, 'w') as f:
            json.dump(ret_data, f)


class Compound2Simple:
    """
    input: json file after deleting unrelated components
    output: new json file with data['cond'] + data['prop']
    functions:
    1. split compound sentence having keyword 'cond_conj'
    2. delete unrelated words
    """

    def __init__(self):
        self.trees = list()
        self.SBAR_trees = list()
        self.data = list()
        self.in_file, self.out_file, self.debug_sents = '', '', list()
        self.cond_conj = ['if', 'when', 'whenever', 'while', 'during']
        self.del_words = ['then', 'for example', 'in other words', 'in particular', 'for this reason', 'in this case',
                          'therefore', 'for instance', 'for this reason', 'in such cases', 'in both cases']

    def start_from_file(self, in_file, out_file):
        print('[+] compound-2-con-main')
        self.in_file = in_file
        self.out_file = out_file
        with open(self.in_file, 'r') as f:
            self.data = json.load(f)
        self.multi_c2s()
        print('all sents:%d' % len(self.data))

    def debug_line(self, line):
        ret_data = list()
        self.c2s(line, ret_data)
        #print(ret_data)

    def split_proposition_cond(self, tree, cond_prop_pairs):

        for subtree in tree:
            if type(subtree) != nltk.tree.ParentedTree:
                continue

            if self.split_proposition_cond(subtree, cond_prop_pairs):
                return True

            if subtree.leaves()[0].lower() in self.cond_conj:

                parent_f = subtree.parent()
                while len(parent_f.leaves()) == 1:
                    parent_f = parent_f.parent()

                '''check if/whether should not be split'''
                if re.search(r'(decide|determine|check)s? if', ' '.join(parent_f.parent().leaves())):
                    return True
                cond = ' '.join(parent_f.leaves())
                cond_ano = ''

                parent_s = parent_f.parent()
                parent_s.remove(parent_f)

                '''
                to(TO): This integer must be initialized to zero when ivec_APIParam_None is initialized.
                by(IN): This can be done by calling BIO_pending_APIName on the other half of the pair and, if any data is pending, reading it and sending it to the underlying transport.
                num(CD): ASN1_TIME_set_string_APIName returns 1 if the time value is successfully set and 0 otherwise.
                '''
                while (parent_s and (
                        parent_s.label() not in ['S', 'ROOT'] or nltk.pos_tag([parent_s.leaves()[0].lower()])[0][
                    1] == 'TO' or nltk.pos_tag(
                    parent_s.root().leaves()[parent_s.root().leaves().index(parent_s.leaves()[0]) - 1])[0][
                            1] == 'IN')):
                    if parent_s.label() == 'SBAR' and parent_s[0].label() == 'CC' and parent_s[1].label() == 'SBAR':
                        parent_s.pop()
                    elif parent_s.label() == 'SBAR':
                        break
                    parent_s = parent_s.parent()

                if not parent_s:
                    return True

                prop = ' '.join(parent_s.leaves())
                if parent_s.label() == 'ROOT':
                    parent_s.pop()
                else:
                    parent_t = parent_s.parent()
                    parent_t.remove(parent_s)

                cond_prop_pairs.append([cond, prop])
                if cond_ano:
                    cond_prop_pairs.append([cond_ano, prop])

                return True

    def c2s(self, data, results):

        sent = data['sent']

        '''map api/param name temporarily'''
        map_dict = dict()
        for idx, name in enumerate(re.findall(r'\S+_APIName|\S+_APIParam_\d+', sent)):
            new_name = 'Mapping_' + str(idx)
            map_dict[new_name] = name
            sent = re.sub(name, new_name, sent)
        ''''''
        sent = re.sub(r'\(.+?\)', '', sent)
        sents = re.split(r';|:', sent)

        for sent in sents:
            if len(sent.split()) < 2:
                continue

            cond_prop_pairs = list()
            ''' chk rm CC 'and|or' '''
            sent = re.sub(r'^(and|or)', '', sent)
            ''' chk "return" '''
            # cond_prop_pairs=self.chkreturn(sent)
            if re.search(r'return', sent):
                cond_prop_pairs.append(['null', sent])

            if len(cond_prop_pairs) == 0:
                tree_str = nlp.parse(sent)
                tree = nltk.tree.Tree.fromstring(tree_str)
                tree = nltk.tree.ParentedTree.convert(tree)

                self.split_proposition_cond(tree, cond_prop_pairs)

                if ' '.join(tree.leaves()) != '':
                    cond_prop_pairs.append(['null', ' '.join(tree.leaves())])

            tmp_pairs, cond_prop_pairs = cond_prop_pairs, list()
            for pair in tmp_pairs:

                cond, prop = pair[0], pair[1]
                for del_word in self.del_words:
                    cond = re.sub(r'(^|\s){}($|\s|,)'.format(del_word), ' ', cond, flags=re.IGNORECASE)
                    cond = re.sub(r'^[,\. ]+', '', cond)
                    cond = re.sub(r'[,\. ]+$', '', cond)

                    prop = re.sub(r'(^|\s){}($|\s|,)'.format(del_word), ' ', prop, flags=re.IGNORECASE)
                    prop = re.sub(r'^[,\. ]+', '', prop)
                    prop = re.sub(r'[,\. ]+$', '', prop)

                new_data = copy.deepcopy(data)
                new_data['cond'] = cond
                new_data['prop'] = prop

                '''remap to api/param'''
                if map_dict:
                    for new_name in map_dict:
                        new_data['cond'] = re.sub(new_name, map_dict[new_name], new_data['cond'])
                        new_data['prop'] = re.sub(new_name, map_dict[new_name], new_data['prop'])

                results.append(new_data)

    def multi_c2s(self):

        manager, jobs = Manager(), list()
        ret_data = manager.list()
        for data in tqdm(self.data):

            if len(jobs) > 100:
                for proc in jobs:
                    proc.join(30)
                jobs = list()

            p = Process(target=self.c2s, args=(data, ret_data))
            jobs.append(p)
            p.start()

        for proc in jobs:
            proc.join(30)

        ret_data = [x for x in ret_data]
        with open(self.out_file, 'w') as f:
            json.dump(ret_data, f)

        '''save prop, cond, sent, paragraph to csv file in order to label data'''
        csv_data = list()
        csv_header = ['prop', 'cond', 'sent', 'paragraph']
        for data in ret_data:
            brief_data = {'prop': data['prop'], 'cond': data['cond'], 'sent': data['sent'], 'paragraph': data['paraph']}
            csv_data.append(brief_data)
        with open(self.out_file + '.csv', 'w', newline='') as f:
            csvW = csv.DictWriter(f, fieldnames=csv_header)
            csvW.writerows(csv_data)


if __name__ == "__main__":
    os.chdir('../..')
    with open("../config.yml", 'r') as ymlfile:
        cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

    train_libs = cfg["train"]["test_libs"]
    train_dir = cfg["predict"]["basedir"]
    train_libs = ['libxml2']
    for lib in train_libs:
        lib_basedir = os.path.join(train_dir, lib, "IA_discovery")
        lib_crawled_dir = os.path.join(train_dir, lib, "crawled_data")
        os.makedirs(lib_basedir, exist_ok=True)

        original_json = os.path.join(lib_crawled_dir, "crawled.json")
        del_unrelated_json = os.path.join(lib_crawled_dir, "crawled_del.json")
        cond_prop_json = os.path.join(lib_crawled_dir, "crawled_del_split.json")

        duc = DelUnrelatedComponent()
        c2s = Compound2Simple()
        duc.start_from_file(original_json, del_unrelated_json)
        c2s.start_from_file(del_unrelated_json, cond_prop_json)

        print('Done delete and split. The Advance json file is ', cond_prop_json)
