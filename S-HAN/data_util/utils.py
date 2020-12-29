import ast, json, csv, os, re
from tqdm import tqdm

def sanitization_abbr(sent):
    abbrs = {"don't": "do not", "Don't": "do not", "doesn't": "does not", "Doesn't": "does not",
            "didn't": "did not",
            "couldn't": "could not", "Couldn't": "could not", "can't": "can not", "Can't": "can not",
            "ca n't": "can not", "Ca n't": "can not",
            "shouldn't": "should not", "Shouldn't": "should not", "should've": "should have",
            "mightn't": "might not", "mustn't": "must not", "Mustn't": "must not", "needn't": "need not",
            "haven't": "have not", "hadn't": "had not", "hasn't": "has not",
            "you'd": "you should", "You'd": "you should", "you're": "you are", "You're": "you're",
            "it's": "it is", "It's": "it is", "won't": "will not", "wo n't": "will not",
            "isn't": "is not", "Isn't": "is not", "aren't": "are not", "Aren't": "are not"}
    
    for abbr in abbrs:
        if re.search(abbr, sent):
            sent = re.sub(abbr, abbrs[abbr], sent)
    # to check if needed
    abbrs = {" n't": " not", "'s": "", "'d": "", " 'll": " will"}
    for abbr in abbrs:
        sent = re.sub(abbr, abbrs[abbr], sent)
    
    sent = re.sub('``', '', sent)
    sent = re.sub('\'\'', '', sent)
    sent = re.sub(r'[^\w]+$', '', sent)

    return sent


def extract_apilist(lib_basedir, lib):
    crawled_json = os.path.join(lib_basedir, "crawled_data", "crawled.json")
    api_list = list()

    with open(crawled_json, 'r') as f:
        for one in tqdm(json.load(f)):
            if one.get('key'):
                api_list.append(one['key'])
            if one.get('API_info'):
                if lib in ['openssl', 'sqlite', 'libpcap']:
                    api_infos = one['API_info']
                    if type(api_infos) == dict and not api_infos.get('API_desc'):
                        api_list += list(api_infos.keys())
    
    api_list = list(set(api_list))
    api_file = os.path.join(lib_basedir, "apilist")
    with open(api_file, 'w') as f:
        f.write('\n'.join(api_list) + '\n')
    
    return api_file


def list2file(alist, file):
    with open(file, 'w') as f:
        f.write('\n'.join(alist))
        f.write('\n')
    print('[-]list to file %s' % file)


def file2list(file):
    print('[+]doing file %s to list' % file)
    with open(file, 'r') as f:
        return f.read().split('\n')[:-1]


def fileL2list(file):
    print('[+]doing file of list %s to list ' % file)
    with open(file, 'r') as f:
        tmp = f.read().split('\n')[:-1]
        return [ast.literal_eval(each) for each in tmp]


def Llist2file(Llist, file):
    print('[-]doing list of list %s to file ' % file)
    with open(file, 'w') as f:
        for each in Llist:
            f.write(str(each) + '\n')


def dict2json(adict, file):
    print('load json file to dict. file:', file)
    with open(file, 'w') as f:
        json.dump(adict, f)


def json2dict(file):
    print('save dict to json file ', file)
    with open(file, 'r') as f:
        return json.load(f)


def jsonF2list(file):
    values = []
    with open(file, 'r') as f:
        augdict = json.load(f)
        for each in augdict:
            values.append(augdict[each])
    print('[+]keys of json file %s to list ' % file)
    return values


def csv2dict(file):
    dictlist = []
    with open(file, 'r') as f:
        csvr = csv.DictReader(f)
        for each in csvr:
            dictlist.append(each)
    print('[+]csv file %s to dict ' % file)
    return dictlist


def dict2csv(adict, file):
    header = [k for k in adict[0]]
    with open(file, 'w', newline='') as f:
        csvw = csv.DictWriter(f, fieldnames=header)
        csvw.writeheader()
        csvw.writerows(adict)
    print('[-]dict %s to csv file ' % file)


def file2labeljson(file, label, count):
    results = list()
    base_y = [0] * count
    base_y[label] = 1
    with open(file, 'r') as f:
        for line in f.read().split('\n')[:-1]:
            results.append({'sent': line, 'label': base_y})
    return results