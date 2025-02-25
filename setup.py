#!/usr/bin/python3

from setuptools import setup

setup(
    name='axiom-roaster',
    version='0.1.0',
    description='Zero-auth kerberoasting and AS-REQ roasting',
    url='http://localhost',
    author='mallo-m',
    author_email='none',
    license='BSD 2-clause',
    packages=[
        'AxiomRoaster',
        'AxiomRoaster.core',
        'AxiomRoaster.objects'
    ],
    install_requires=[
        'rich',
        'scapy',
        'netifaces',
        'libpcap'
    ],
    classifiers=[
        'Development Status :: 1 - Planning',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    entry_points={
        'console_scripts': ['axiom-roaster=AxiomRoaster.__main__:main'],
    }
)
