#!/usr/bin/python
# -*- coding: utf-8 -*-
import mechanize


def testProxy(url, proxy):
    browser = mechanize.Browser()
    browser.set_proxies(proxy)
    page = browser.open(url)
    source_code = page.read()
    print source_code


url = 'http://ip-check.info/?lang=en'
hideMeProxy = {'http': '5.135.193.216:8089'}

testProxy(url, hideMeProxy)

