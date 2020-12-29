# -*- coding: UTF-8 -*-
# !/usr/bin/python
# @function: Back translation calls Google translation while simulating Google token access
# assign the languages within 'any_to_any_translate' func

import logging as logger
import urllib.parse as parse
import re
import execjs
import requests
import sys, json, pdb, urllib


class GoogleToken:
    def __init__(self):
        self.ctx = execjs.compile("""
        function TL(a) {
        var k = "";
        var b = 406644;
        var b1 = 3293161072;
        var jd = ".";
        var $b = "+-a^+6";
        var Zb = "+-3^+b+-f";
        for (var e = [], f = 0, g = 0; g < a.length; g++) {
            var m = a.charCodeAt(g);
            128 > m ? e[f++] = m : (2048 > m ? e[f++] = m >> 6 | 192 : (55296 == (m & 64512) && g + 1 < a.length && 56320 == (a.charCodeAt(g + 1) & 64512) ? (m = 65536 + ((m & 1023) << 10) + (a.charCodeAt(++g) & 1023),
            e[f++] = m >> 18 | 240,
            e[f++] = m >> 12 & 63 | 128) : e[f++] = m >> 12 | 224,
            e[f++] = m >> 6 & 63 | 128),
            e[f++] = m & 63 | 128)
        }
        a = b;
        for (f = 0; f < e.length; f++) a += e[f],
        a = RL(a, $b);
        a = RL(a, Zb);
        a ^= b1 || 0;
        0 > a && (a = (a & 2147483647) + 2147483648);
        a %= 1E6;
        return a.toString() + jd + (a ^ b)
    };
    function RL(a, b) {
        var t = "a";
        var Yb = "+";
        for (var c = 0; c < b.length - 2; c += 3) {
            var d = b.charAt(c + 2),
            d = d >= t ? d.charCodeAt(0) - 87 : Number(d),
            d = b.charAt(c + 1) == Yb ? a >>> d: a << d;
            a = b.charAt(c) == Yb ? a + d & 4294967295 : a ^ d
        }
        return a
    }
    """)

    def get_google_token(self, text):
        """
           Gets the Google access token
        :param text: str, input sentence
        :return:
        """
        return self.ctx.call("TL", text)


def open_url(url):
    """
      Add a header and request the access
    :param url: str, url地址
    :return: str, 目标url地址返回
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36'}
    req = requests.get(url=url, headers=headers)
    return req  # .content.decode('utf-8')


def max_length(content):
    """
      No translation beyond the maximum length
    :param content: str, need translate
    :return:
    """
    if len(content) > 4891:
        logger.info("the length of text is beyond limit")
        return 4891
    else:
        return None


def translate_result(result):
    """
      Delete irrelevant words
    :param result: str
    :return: str
    """
    result_last = ''
    for res in result[0]:
        if res[0]:
            result_last += res[0]
    return result_last


def any_to_any_translate(content, from_='zh-CN', to_='en'):
    """
       Custom selection
    :param content: str, 4891 words, user input
    :param from_: str, original language
    :param to_:   str, target language
    :return: str, result of translate
    """
    max_len = max_length(content)
    if max_len:
        content = content[0:max_len]

    google_token = GoogleToken()
    tk = google_token.get_google_token(content)
    # print(tk)
    content = parse.quote(content)

    url = "https://translate.google.cn/translate_a/single?client=webapp&sl={}&tl={}&hl=zh-CN&dt=at&dt=bd&dt=ex&dt=ld&dt=md&dt=qca&dt=rw&dt=rm&dt=ss&dt=t&otf=1&pc=1&ssel=3&tsel=3&kc=2&tk={}&q={}".format(
        from_, to_, tk, content)

    url1 = "https://translate.google.cn/translate_a/single?client=t&sl={0}&tl={1}" \
           "&hl=zh-CN&dt=at&dt=bd&dt=ex&dt=ld&dt=md&dt=qca&dt=rw&dt=rm&dt=ss&dt=t&" \
           "ie=UTF-8&oe=UTF-8&source=btn&ssel=3&tsel=3&kc=0&tk={2}&q={3}".format(from_, to_, tk, content)
    result = open_url(url)

    result_json = result.json()
    res = translate_result(result_json)
    # print(res)
    return res


def any_to_any_translate_back(content, from_='en', to_='zh-CN'):
    """
      English and Chinese translation
    :param content:str, 4891 words, user input
    :param from_: str, original language
    :param to_:   str, target language
    :return: str, result of translate
    """
    translate_content = any_to_any_translate(content, from_=from_, to_=to_)
    result = any_to_any_translate(translate_content, from_=to_, to_=from_)
    return result


def trans_and_save(sents, sents_dict):
    sents = sents[:-1]
    sents_tra = any_to_any_translate_back(sents)

    sents_tra = sents_tra.split('\n')
    sents = sents.split('\n')
    if len(sents) != len(sents_tra):
        print("not equal {} {}\n")

    for idx in range(len(sents)):
        sents_dict[sents[idx]] = sents_tra[idx]


def back_trans_aug(in_file):
    """
    the main function called outside. Perform back translation and save the list and json result to 2 files(.aug, .augRef).
    :param in_file: one sentence each line
    :return:
    """
    aug_dict = dict()

    filer = in_file
    filew = in_file + ".aug"
    file_json = in_file + ".augRef"

    with open(filer, 'r') as fr:

        content = fr.read().split('\n')[:-1]
        sents = ''

        for sent in content:

            if content.index(sent) % 1000 == 0:
                print(content.index(sent))

            if sent in aug_dict.keys() or sent == '':
                continue
            sent = re.sub(r'\w+\(\)', 'API', sent)

            if len(sents) + len(sent) > 4000:
                trans_and_save(sents, aug_dict)
                sents = ''

            sents += sent + '\n'

        if sents != '':
            trans_and_save(sents, aug_dict)

    aug_list = list(aug_dict.values())
    with open(filew, 'w') as fw:
        fw.write('\n'.join(aug_list) + '\n')

    with open(file_json, 'w') as fw:
        json.dump(aug_dict, fw)

