#!/usr/bin/python

import os

from setuptools import setup, find_packages

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='vipr-data',
    version='0.4.1',
    include_package_data=True,
    description='EMC ViPR Data Services SDK for Python',
    author='EMC',
    author_email='ViPR.Data.Services.SDK@emc.com',
    license='BSD',
    keywords='emc vipr dataservices sdk',
    url='https://community.emc.com/community/edn/vipr-data-services',
    packages=find_packages(),
    long_description=read('README'),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Topic :: Utilities',
        'License :: OSI Approved :: BSD License'
    ],
    install_requires=[
        'requests'
    ]
)
