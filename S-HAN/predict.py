import os, sys, yaml, json, ast
from keras import backend as K
import numpy as np

sys.path.append('data_util')
from prep_split import DelUnrelatedComponent, Compound2Simple
from prep_classify import PreprocessWords
from s_han import HNATT
from extract_uselessNN import GetUselessNN
from utils import *


def split(lib_dir):
    lib_basedir = os.path.join(lib_dir, "IA_discovery")
    lib_crawled_dir = os.path.join(lib_dir, "crawled_data")
    os.makedirs(lib_basedir, exist_ok=True)

    original_json = os.path.join(lib_crawled_dir, "crawled.json")
    del_unrelated_json = os.path.join(lib_crawled_dir, "crawled_del.json")
    cond_prop_json = os.path.join(lib_crawled_dir, "crawled_del_split.json")

    duc = DelUnrelatedComponent()
    c2s = Compound2Simple()
    duc.start_from_file(original_json, del_unrelated_json)
    c2s.start_from_file(del_unrelated_json, cond_prop_json)

    print('Done delete and split. The Advance json file is ', cond_prop_json)
    return cond_prop_json


def preprocessing(lib_dir, cond_prop_json, API_list_file, uselessNN_file):
    prepWords = PreprocessWords()
    data = ''

    discovery_dir = os.path.join(lib_dir, "IA_discovery")
    preprocessed_dir = os.path.join(discovery_dir, "preprocessed")
    os.makedirs(preprocessed_dir, exist_ok=True)

    prop_file = os.path.join(discovery_dir, 'prop_split')
    outfile = os.path.join(preprocessed_dir, 'prop_split.pred')

    with open(cond_prop_json, 'r') as f:
        json_data = json.load(f)

    for one in json_data:
        data += one['prop'] + '\n'

    with open(prop_file, 'w') as f:
        f.write(data)

    prepWords.start_from_file(prop_file, outfile, outfile + '.ref', API_list_file, uselessNN_file, lib)

    print('done del and split com and preprocess{}'.format(outfile))
    return outfile


def predict(lib, filein, prop_cond_file, res_dir):
    """
    predict and get original sent and condition
    :param lib: the name of library
    :param filein: the preprocessed file, which is the input to the classifier
    :param prop_cond_file: the json file of proposition and condition
    :param res_dir: the dir to store the predicted IA
    :return:
    """
    test_data, data_ref, ia_cond, ia_pair, ia_all, result = list(), list(), list(), list(), list(), ''

    file_ref = filein + '.ref'
    file_all = os.path.join(res_dir, 'IA.prop.bef')  # IAs before being split
    file_ia = os.path.join(res_dir, 'IA.prop')  # IAs after being split
    file_cond = os.path.join(res_dir, 'IA.cond')  # conditions after being split
    file_json = os.path.join(res_dir, 'IA.json')  # json file: IAs after being split with their conditions
    os.makedirs(res_dir, exist_ok=True)

    '''load original data'''
    with open(file_ref, 'r', newline='') as f:
        tmp = f.read().split('\n')[:-1]
        for each in tmp:
            data_ref.append(ast.literal_eval(each)) # result: type=list, ['original', 'modified']

    '''load predict data'''
    with open(filein, 'r') as f:
        for one in f.read().split('\n')[:-1]:
            test_data.append([one])

    '''load prop-cond json'''
    with open(prop_cond_file, 'r') as f:
        pro_cond_json = json.load(f)

    '''predict'''
    json_idxy = 0
    preds = h.predict(test_data)

    log_res = dict()
    for idx, data in enumerate(test_data):
        label = np.argmax(preds[idx]).astype(float)
        if label == 0:
            if not log_res.get(data[0]):
                log_res[data[0]] = True
                # new: data_ref[idx], v1:data_ref[idx][0]
                for data_pair in data_ref:
                    if data[0] == data_pair[1]:
                        found_cond = False
                        for idxy, pair in enumerate(pro_cond_json):
                            if pair['prop'] == data_pair[0]:
                                result += data_pair[0] + '\n'
                                ia_pair.append({'prop': data_pair[0], 'cond': pair['cond']})
                                ia_cond.append(pair['cond'])
                                ia_all.append(pair['sent'])
                                found_cond = True
                        if not found_cond:
                            result += data_pair[0] + '\n'
                            ia_pair.append({'prop': data_pair[0], 'cond': 'null'})
                            ia_cond.append('null')
                            ia_all.append(data_pair[0])

    with open(file_ia, 'w') as f:
        f.write(result)
        f.write('\n')
    with open(file_cond, 'w') as f:
        f.write('\n'.join(ia_cond))
        f.write('\n')
    with open(file_json, 'w') as f:
        json.dump(ia_pair, f)
    with open(file_all, 'w') as f:
        f.write('\n'.join(ia_all))
        f.write('\n')
    print('done predict {}, save proposition to {} and conditions to {} and "prop:cond" to {}'.format(filein, file_ia, file_cond, file_json))

if __name__ == '__main__':

    with open("../config.yml", 'r') as ymlfile:
        cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)
    
    if len(sys.argv) < 2:
        predict_libs = cfg["predict"]["predict_libs"]
    else:
        predict_libs = [sys.argv[1]]
    basedir = cfg["predict"]["basedir"]
    apilist_paths = cfg["libs_apilist"]
    uselessNN_files = cfg["libs_uselessNN"]

    '''load model'''
    SAVED_MODEL_DIR = cfg["train"]["save_model_dir"]
    saved_model = cfg["train"]["save_model"]
    K.clear_session()
    h = HNATT()
    h.load_weights(SAVED_MODEL_DIR, saved_model)

    for idx, lib in enumerate(predict_libs):
        print('\nPredict', lib)
        lib_dir = os.path.join(basedir, lib)
        crawled_dir = os.path.join(lib_dir, "crawled_data")
        discovery_dir = os.path.join(lib_dir, "IA_discovery")
        preprocessed_dir = os.path.join(discovery_dir, "preprocessed")
        extracted_dir = os.path.join(discovery_dir, "extracted")

        '''split crawled json lib doc'''
        print('\n\033[1;33;44m Split crawled lib doc !\033[0m')
        split_json = os.path.join(crawled_dir, "crawled_del_split.json")
        split_json = split(lib_dir)

        '''check api_list uselessNN files'''
        if not (apilist_paths.get(lib) and os.path.exists(apilist_paths[lib])):
            print('\n\033[1;33;44m Prepare api list file !\033[0m')
            api_list_file = extract_apilist(lib_dir, lib)
            cfg["libs_apilist"][lib] = api_list_file
            with open('../config.yml', 'w') as yml:
                yaml.dump(cfg, yml)
        else:
            api_list_file = apilist_paths[lib]

        if not (uselessNN_files.get(lib) and os.path.exists(uselessNN_files[lib])):
            print('\n\033[1;33;44m Prepare uselessNN file !\033[0m')
            guNN = GetUselessNN()
            guNN.libs_sent_uselessNN()
        uselessNN_file = uselessNN_files[lib]

        '''preprocessing'''
        print('\n\033[1;33;44m Preprocess doc !\033[0m')
        file_to_be_classified = os.path.join(preprocessed_dir, 'prop_split.pred')
        file_to_be_classified = preprocessing(lib_dir, split_json, api_list_file, uselessNN_file)
        
        '''predict using classifier'''
        print('\n\033[1;33;44m Predict !\033[0m')
        predict(lib, file_to_be_classified, split_json, extracted_dir)
        print('\n\033[1;33;44m Predict Done !\033[0m')