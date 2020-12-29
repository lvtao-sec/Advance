import re, os, nltk, sys
import multiprocessing
from gensim.models import Word2Vec


def train_w2v(input_dir, model_path, embedding_dim=300, iteration=100):
    cores = multiprocessing.cpu_count()

    sents = list()

    for File in os.listdir(input_dir):
        try:
            with open('{}/{}'.format(input_dir, File, encoding='ISO-8859-1'), 'r') as f:
                sents += f.read().split('\n')[:-1]
        except:
            print(File)

    corpus, ret_corpus = list(), list()

    for sent in list(set(sents)):
        sent_tokens = nltk.word_tokenize(sent)
        corpus.append(sent_tokens)
        ret_corpus.append([sent])

    w2v_model = Word2Vec(size=embedding_dim, window=3, min_count=1, workers=cores - 1, compute_loss=True)
    w2v_model.build_vocab(corpus, progress_per=10000)
    w2v_model.train(corpus, total_examples=w2v_model.corpus_count, epochs=iteration, report_delay=1)
    w2v_model.save(model_path)

    return ret_corpus


def load_w2v(input_dir):
    sents = list()

    for File in os.listdir(input_dir):
        try:
            with open('{}/{}'.format(input_dir, File, encoding='utf-8'), 'r') as f:
                sents += f.read().split('\n')[:-1]
        except:
            print(File)

    corpus, ret_corpus = list(), list()

    for sent in list(set(sents)):
        sent_tokens = nltk.word_tokenize(sent)
        corpus.append(sent_tokens)
        ret_corpus.append([sent])

    return ret_corpus
