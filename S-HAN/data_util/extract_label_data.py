# -*- coding: UTF-8 -*-
# !/usr/bin/python

import os, csv
from back_translation_google import back_trans_aug


def prepare_classifier_dataset(labeled_file, dataset_dir):
    """
    prepare the training dataset for classifier, including data augmentation
    save proposition, condition to files
    :param labeled_file: the labeled csv file with 3 columns without fieldname: label, proposition, condition
    :param dataset_dir: the dir that positive and negative file will be saved
    :return:
    """
    pos, neg, conds = "", "", ""
    with open(labeled_file, "r", encoding='ISO-8859-1') as f:
        reader = csv.reader(f)
        for item in reader:
            # TODO: change column to 0/1/2, tag/prop/cond
            if item[0] in ['0']:
                neg += item[2] + '\n'
            elif item[0] in ['1', '2', '3', '4', '5', '6', '8', '9']:
                pos += item[2] + '\n'
                conds += item[5] + '\n'
            else:
                continue
    with open(os.path.join(dataset_dir, 'IA.prop'), "w") as f:
        f.write(pos)
    with open(os.path.join(dataset_dir, 'non-IA.prop'), "w") as f:
        f.write(neg)
    with open(os.path.join(dataset_dir, 'IA.cond'), "w") as f:
        f.write(conds)

    ia_prop_aug_file = os.path.join(dataset_dir, 'IA.prop.aug')
    if not os.path.exists(ia_prop_aug_file):
        back_trans_aug(os.path.join(dataset_dir, 'IA.prop'))
    
    # back_trans_aug(os.path.join(dataset_dir, 'IA.prop'))

