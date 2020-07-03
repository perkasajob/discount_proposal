# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

with open('requirements.txt') as f:
	install_requires = f.read().strip().split('\n')

# get version from __version__ variable in discount_proposal/__init__.py
from discount_proposal import __version__ as version

setup(
	name='discount_proposal',
	version=version,
	description='App for proposing and approval of items discount',
	author='Quantum Labs',
	author_email='perkasajob@quantum-laboratories.com',
	packages=find_packages(),
	zip_safe=False,
	include_package_data=True,
	install_requires=install_requires
)
