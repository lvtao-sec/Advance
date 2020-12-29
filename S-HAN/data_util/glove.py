import numpy as np
from tqdm import tqdm
import pdb
from gensim.models import word2vec
from keras.preprocessing.text import Tokenizer

# _*_ coding:utf-8 _*_

def load_glove_embedding(path, dim, word_index):
	embeddings_index = {}

	embedding_model = word2vec.Word2Vec.load(path)

	'''
	f = open(path, encoding='latin-1')
	print('Generating GloVe embedding...')
	for line in tqdm(f):
	    values = line.split()
	    word = values[0]
	    coefs = np.asarray(values[1:], dtype='float32')
	    embeddings_index[word] = coefs
	f.close()
	'''

	embedding_matrix = np.zeros((len(word_index) + 1, dim))
	
	has = 0
	not_has = 0

	for word, i in word_index.items():
		try:
			embedding_vector = embedding_model.wv[word]
			if embedding_vector is not None:
			# words not found in embedding index will be all-zeros.
				embedding_matrix[i] = embedding_vector
				has += 1
			else:
				#print("else not ", word)
				not_has += 1
		except:
			not_has += 1
			#print("except not ", word)
	print('Loaded GloVe embedding has:{} not_has:{}'.format(has, not_has))

	return embedding_matrix