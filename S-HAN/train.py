import os, sys, yaml, time, random
import numpy as np
import tensorflow as tf
from keras import backend as K

sys.path.append('data_util')
from extract_label_data import prepare_classifier_dataset
from utils import *
from extract_uselessNN import GetUselessNN
from prep_classify import PreprocessWords
from w2v import *
from s_han import HNATT

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'


def preprocessing(output_dir, test_lib=None, apilist=None, uselessNN_file=None):
    '''
    prepare training/testing data
    :param output_dir: the dir to store pos/neg/aug files
    :param test_lib: the testing lib. If none, it means preprocessing training data; else handle testing lib data
    :param apilist: the apilist for testing lib
    :param uselessNN_file: the uselessNN_file for testing lib
    :return:
    '''
    train_libs = cfg["train"]["train_libs"]
    train_dir = cfg["train"]["basedir"]
    data_dir = cfg["predict"]["basedir"]
    apilist_paths = cfg["libs_apilist"]

    prepWords = PreprocessWords()
    neg_data, pos_data, aug_data = list(), list(), list()
    neg_file = os.path.join(output_dir, 'neg')
    pos_file = os.path.join(output_dir, 'pos')
    aug_file = os.path.join(output_dir, 'aug')

    '''handle testing'''
    if test_lib:
        train_libs = [test_lib]

    for idx, lib in enumerate(train_libs):
        lib_basedir = os.path.join(data_dir, lib)
        discovery_dir = os.path.join(lib_basedir, "IA_discovery")
        extracted_dir = os.path.join(discovery_dir, "extracted")
        preprocessed_dir = os.path.join(discovery_dir, "preprocessed")

        os.makedirs(extracted_dir, exist_ok=True)
        os.makedirs(preprocessed_dir, exist_ok=True)

        labeled_file = os.path.join(discovery_dir, "labelled_data.csv")
        '''handle testing'''
        print('prepare api list file')
        if apilist:
            api_list_file = apilist
        else:
            try:
                api_list_file = apilist_paths[lib]
            except:
                api_list_file = extract_apilist(lib_basedir, lib)
                cfg["libs_apilist"][lib] = api_list_file
                with open('../config.yml', 'w') as yml:
                    yaml.dump(cfg, yml)
            if not os.path.exists(api_list_file):
                api_list_file = extract_apilist(lib_basedir, lib)
                cfg["libs_apilist"][lib] = api_list_file
                with open('../config.yml', 'w') as yml:
                    yaml.dump(cfg, yml)

        '''split csv'''
        print('split csv file to prop and cond')
        prepare_classifier_dataset(labeled_file, extracted_dir)

        '''preprocessing and prepare training dataset'''
        print('preprocessing and prepare training dataset')
        for name in ['IA.prop', 'non-IA.prop', 'IA.prop.aug']:
            file = os.path.join(extracted_dir, name)

            if os.path.exists(file):
                '''preprocessing'''
                outfile = os.path.join(preprocessed_dir, name + '.pred')
                prepWords.start_from_file(file, outfile, outfile + '.ref', api_list_file, uselessNN_file, lib)
                print("S1: done pre_words {}".format(file))
            else:
                print("cannot find file {}, skip it".format(file))
                continue

            '''prepare training dataset'''
            if name == 'IA.prop':
                pos_data += file2list(outfile)
            elif name == 'IA.prop.aug':
                aug_data += file2list(outfile)
            else:
                neg_data += file2list(outfile)
            print("pos_data length:{} neg_data length:{} aug_data length:{}".format(len(pos_data), len(neg_data),
                                                                                    len(aug_data)))

        list2file(neg_data, neg_file)
        list2file(pos_data, pos_file)
        list2file(aug_data, aug_file)


def load_training_data(seed, train_dir):
    """
    when training, load preprocessed data to the classifier
    :param seed: seed for random
    :param train_dir: dir of training dataset
    :return:
    """
    neg_data, pos_data, aug_data = list(), list(), list()
    pos_data = file2labeljson(os.path.join(train_dir, 'pos'), 0, 2)
    aug_data = file2labeljson(os.path.join(train_dir, 'aug'), 0, 2)
    neg_data = file2labeljson(os.path.join(train_dir, 'neg'), 1, 2)

    random.seed(seed)
    random.shuffle(pos_data)
    random.seed(seed)
    random.shuffle(aug_data)
    random.seed(seed)
    random.shuffle(neg_data)

    # postive data
    raw_x, raw_y, trans_aug_x, trans_aug_y, test_x, test_y = list(), list(), list(), list(), list(), list()
    ret_train_x, ret_train_y, ret_test_x, ret_test_y, ret_test_x_imp = list(), list(), list(), list(), list()

    pos_data_tmp = aug_data + pos_data
    pos_len = min(len(pos_data_tmp), len(neg_data))
    print('pos/neg len:%d' % pos_len)
    pos_train_len = pos_len * 0.8
    for idx in range(pos_len):
        if idx < pos_train_len:
            raw_x.append(pos_data_tmp[idx])
        else:
            test_x.append(pos_data_tmp[idx])

    # negative data
    neg_test_len = len(test_x)
    test_x += neg_data[:neg_test_len]

    neg_tmp = neg_data[neg_test_len:]
    neg_len = min(len(raw_x), len(neg_tmp))
    train_x = raw_x + neg_tmp[:neg_len]
    # test_x += neg_tmp[neg_len:]

    # all
    random.seed(seed)
    random.shuffle(train_x)

    for eachdata in train_x:
        ret_train_x.append([eachdata['sent']])
        ret_train_y.append(eachdata['label'])
    for eachdata in test_x:
        ret_test_x.append([eachdata['sent']])
        ret_test_x_imp.append(eachdata['sent'])
        ret_test_y.append(eachdata['label'])

    print(
        'train len: {}, test_len:{}'.format(len(ret_train_x), len(ret_test_x)))
    return ret_train_x, ret_train_y, ret_test_x, ret_test_y, ret_test_x_imp


def load_testing_data(seed, basedir):
    pos_data = file2labeljson(os.path.join(basedir, 'pos'), 0, 2)
    neg_data = file2labeljson(os.path.join(basedir, 'neg'), 1, 2)

    random.seed(seed)
    random.shuffle(pos_data)
    random.seed(seed)
    random.shuffle(neg_data)

    ret_test_x, ret_test_y, ret_test_x_imp = list(), list(), list()
    test_x = pos_data + neg_data

    for eachdata in test_x:
        ret_test_x.append([eachdata['sent']])
        ret_test_x_imp.append(eachdata['sent'])
        ret_test_y.append(eachdata['label'])

    print('pos_data len: {}, neg_data len:{}'.format(len(pos_data), len(neg_data)))
    return ret_test_x, ret_test_y, ret_test_x_imp


def imperative_predict(test_x):
    """
    get the predict result using the imperative method
    :param test_x: data to be predicted
    :return: the predict results in order
    """
    markers = ["should", "must", "need", "ought to", "has to", "had to", "have to", "remember", "make sure",
               "makes sure", "made sure"]
    pred = list()
    for each_x in test_x:
        flag = False
        # test_x_str = ' '.join(each_x)
        for marker in markers:
            if marker in each_x:
                # pdb.set_trace()
                flag = True
                break
        pred.append([1, 0]) if flag else pred.append([0, 1])

    return pred


def save_data(test_x, test_y, train_x, train_y, model_name, cur_data_dir):
    """
    save data(with label) for testing and training in this running to files
    :param test_x: data for testing
    :param test_y: the labels of data for testing
    :param train_x: data for training
    :param train_y: the labels of data for training
    :param model_name:
    :param cur_data_dir: the dir for files to be saved
    :return:
    """
    test_out = ''
    for idx in range(len(test_x)):
        label = np.argmax(test_y[idx]).astype(float)
        data = ''.join(test_x[idx])
        test_out += "{} {}\n".format(label, data)
    with open(os.path.join(cur_data_dir, model_name + ".test"), "w") as f:
        f.write(test_out)

    train_out = ''
    for idx in range(len(train_x)):
        label = np.argmax(train_y[idx]).astype(float)
        data = ''.join(train_x[idx])
        train_out += "{} {}\n".format(label, data)

    with open(os.path.join(cur_data_dir, model_name + ".test"), "w") as f:
        f.write(train_out)


def save_preds(test_y, test_x, predict_y, model_name, cur_data_dir):
    res_list = []
    for idx in range(len(test_y)):
        preds_res = {}
        label = np.argmax(test_y[idx]).astype(float)
        pred_l = np.argmax(predict_y[idx]).astype(float)
        preds_res['sent'] = test_x[idx]
        preds_res['label'] = label
        preds_res['pred'] = pred_l
        preds_res['predict_y'] = predict_y[idx]
        res_list.append(preds_res)
    header = [k for k in res_list[0]]
    file = os.path.join(cur_data_dir, "pred_res_{}".format(model_name))
    with open(file, 'w') as f:
        csvw = csv.DictWriter(f, fieldnames=header)
        csvw.writeheader()
        csvw.writerows(res_list)


def get_metrics(test_y, test_x, predict_y, model_name, cur_data_dir):
    fn, fp, tn, tp = 0, 0, 0, 0

    false_data = "{}\n".format(model_name)

    for idx in range(len(test_y)):

        label = np.argmax(test_y[idx]).astype(float)
        pred_l = np.argmax(predict_y[idx]).astype(float)

        if label == pred_l:
            if label == 0:
                tp += 1
            else:
                tn += 1
        else:
            false_data += "{}  {}\n".format(int(label), test_x[idx])
            if label == 0:
                fn += 1
            else:
                fp += 1
    fdr = round(tp / float(tp + fp), 3)
    fnr = round(fn / float(tp + fn), 3) if (tp + fn) else 0
    fpr = round(fp / float(fp + tn), 3) if (fp + tn) else 0
    acc = round((tp + tn) / float(len(test_y)), 3)
    info = "{}, fn:{}, fnr:{}, fp:{}, fpr:{}, acc:{}, fdr:{}, test_len{}\n".format(model_name, fn, fnr ,
            fp, fpr, acc, fdr, len(test_y))
    with open(os.path.join(cur_data_dir, "log"), "a+") as f:
        f.write(info)
    print(info)

    with open(os.path.join(cur_data_dir, "false-data"), "a+") as f:
        f.write(false_data)
    
    return acc, fpr, fnr, fdr


def train():
    """train the classifier"""
    train_dir = cfg["train"]["basedir"]
    SAVED_MODEL_DIR = cfg["train"]["save_model_dir"]
    SAVE_DATA_DIR = cfg["train"]["save_data_dir"]
    w2v_corpus_path = cfg["train"]["w2v_corpus_path"]
    w2v_model_path = cfg["train"]["w2v_model_path"]
    w2v_model_dir = cfg["train"]["w2v_model_dir"]
    EMBEDDING_DIM = cfg["train"]["embedding_dim"]
    epoch = cfg["train"]["epoch"]

    '''load/train w2v'''
    if not os.path.exists(w2v_model_path):
        start_time = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())
        w2v_model_path = os.path.join(w2v_model_dir, "{}.model".format(start_time))
        os.makedirs(w2v_model_dir, exist_ok=True)
        w2v_corpus = train_w2v(w2v_corpus_path, w2v_model_path, embedding_dim=EMBEDDING_DIM)
    else:
        start_time = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())
        w2v_corpus = load_w2v(w2v_corpus_path)
    print('load w2v ', w2v_model_path)

    cur_model_dir = os.path.join(SAVED_MODEL_DIR, start_time)
    cur_data_dir = os.path.join(SAVE_DATA_DIR, start_time)
    os.makedirs(cur_data_dir, exist_ok=True)
    os.makedirs(cur_model_dir, exist_ok=True)

    '''load training data'''
    seed = random.randint(1, 4000)
    train_x, train_y, test_x, test_y, ret_test_x_imp = load_training_data(seed, train_dir)
    train_x = np.array(train_x)
    train_y = np.array(train_y)

    ''' test imperative method '''
    preds = imperative_predict(ret_test_x_imp)
    save_preds(test_y, ret_test_x_imp, preds, 'imperatives', cur_data_dir)
    get_metrics(test_y, test_x, preds, "imperatives", cur_data_dir)

    '''train'''
    model_name = 'trans_aug'

    K.clear_session()
    h = HNATT()
    h.train(train_x, train_y, w2v_corpus,
            batch_size=16,
            epochs=epoch,
            embedding_dim=EMBEDDING_DIM,
            embeddings_path=w2v_model_path,
            # embeddings_path = None,
            saved_model_dir=cur_model_dir,
            saved_model_filename=model_name)

    save_data(test_x, test_y, train_x, train_y, model_name, cur_data_dir)

    preds = h.predict(test_x)
    save_preds(test_y, test_x, preds, model_name, cur_data_dir)
    get_metrics(test_y, test_x, preds, model_name, cur_data_dir)

    '''modify save_model in yaml'''
    cfg["train"]["save_model"] = start_time
    cfg["train"]["w2v_model_path"] = w2v_model_path
    with open('../config.yml', 'w') as yml:
        yaml.dump(cfg, yml)
    print('model: ', start_time)


def test(input_dir, lib):
    cur_data_dir = os.path.join(SAVE_DATA_DIR, saved_model)

    '''load testing data'''
    seed = random.randint(1, 4000)
    test_x, test_y, ret_test_x_imp = load_testing_data(seed, input_dir)

    '''test'''
    preds = imperative_predict(ret_test_x_imp)
    save_preds(test_y, ret_test_x_imp, preds, 'imperatives {}'.format(lib), cur_data_dir)
    get_metrics(test_y, ret_test_x_imp, preds, 'imperatives {}'.format(lib), cur_data_dir)

    preds = h.predict(test_x)
    save_preds(test_y, test_x, preds, 'trans_aug {}'.format(lib), cur_data_dir)
    get_metrics(test_y, test_x, preds, 'trans_aug {}'.format(lib), cur_data_dir)


def test_files(pos_file, neg_file, lib):
    """
    use the setting in config file and test pos_file and neg_file
    :param pos_file:
    :param neg_file:
    :return:
    """
    os.chdir('..')
    with open("../config.yml", 'r') as ymlfile:
        cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

    # load model
    SAVED_MODEL_DIR = cfg["train"]["save_model_dir"]
    SAVE_DATA_DIR = cfg["train"]["save_data_dir"]
    # saved_model = cfg["train"]["save_model"]
    saved_model = '2020-08-13-20-35-44'
    saved_model_path = os.path.join(SAVED_MODEL_DIR, saved_model)
    cur_data_dir = os.path.join(SAVE_DATA_DIR, saved_model)

    model_name = 'trans_aug'
    K.clear_session()
    h = HNATT()
    h.load_weights(saved_model_path, model_name)

    # load data
    pos_data = file2labeljson(pos_file, 0, 2)
    neg_data = file2labeljson(neg_file, 1, 2)
    test_x, test_y, test_x_imp = list(), list(), list()

    for eachdata in pos_data + neg_data:
        test_x.append([eachdata['sent']])
        test_x_imp.append(eachdata['sent'])
        test_y.append(eachdata['label'])

    # test
    preds = imperative_predict(test_x_imp)
    save_preds(test_y, test_x_imp, preds, "sam_imp_{}".format(lib), cur_data_dir)
    get_metrics(test_y, test_x_imp, preds, "sam_imp_{}".format(lib), cur_data_dir)

    preds = h.predict(test_x)
    save_preds(test_y, test_x, preds, "sam_our_{}".format(lib), cur_data_dir)
    get_metrics(test_y, test_x, preds, "sam_our_{}".format(lib), cur_data_dir)

if __name__ == '__main__':

    if len(sys.argv) < 2:
        print("python train.py train/test")
        exit()
    else:
        mode = sys.argv[1]

    os.chdir('..')
    with open("../config.yml", 'r') as ymlfile:
        cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

    train_dir = cfg["train"]["basedir"]
    data_dir = cfg['predict']['basedir']

    if mode == "train":
        # preprocessing(train_dir)
        train()
    elif mode == "test":
        test_libs = cfg["train"]["test_libs"]
        apilist_paths = cfg["libs_apilist"]
        uselessNN_files = cfg["libs_uselessNN"]

        '''testing: load model'''
        SAVED_MODEL_DIR = cfg["train"]["save_model_dir"]
        SAVE_DATA_DIR = cfg["train"]["save_data_dir"]
        # saved_model = cfg["train"]["save_model"]
        saved_model = '2020-08-13-19-56-46'

        '''check the model'''
        saved_model_path = os.path.join(SAVED_MODEL_DIR, saved_model)
        if not os.path.exists(saved_model_path):
            print("no trained classifier yet, run 'python train.py train' first")
            exit()

        model_name = 'trans_aug'

        K.clear_session()
        h = HNATT()
        h.load_weights(saved_model_path, model_name)

        for idx, lib in enumerate(test_libs):
            print('\ntesting ', lib)

            lib_basedir = os.path.join(data_dir, lib)
            discovery_dir = os.path.join(lib_basedir, "IA_discovery")

            '''check api_list uselessNN files'''
            if not (apilist_paths.get(lib) and os.path.exists(apilist_paths[lib])):
                print('\nprepare api list file')
                api_list_file = extract_apilist(lib_basedir, lib)
                cfg["libs_apilist"][lib] = api_list_file
                with open('../config.yml', 'w') as yml:
                    yaml.dump(cfg, yml)

            if not (uselessNN_files.get(lib) and os.path.exists(uselessNN_files[lib])):
                print('\nprepare uselessNN file')
                guNN = GetUselessNN()
                guNN.libs_sent_uselessNN()
            api_list_file = apilist_paths[lib]
            uselessNN_file = uselessNN_files[lib]

            preprocessing(discovery_dir, lib, api_list_file, uselessNN_file)
            test(discovery_dir, lib)
    else:
        print("python train.py train/test")
