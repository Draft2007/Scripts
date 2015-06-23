#!/usr/bin/python
# -*- coding: utf-8 -*-
import mechanize


def testProxy(url, proxy):
    browser = mechanize.Browser()
    browser.set_proxies(proxy)
    page = browser.open(url)
    source_code = page.read()
    print source_code


url = 'http://www.whatismyip.com'
hideMeProxy = {'http': '106.186.25.54:8080'}

testProxy(url, hideMeProxy)

