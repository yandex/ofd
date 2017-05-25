#!/usr/bin/env python
# encoding: utf-8

from setuptools import setup
import sys

if sys.version_info < (3, 5):
    sys.exit('Sorry, Python < 3.5 is not supported')

exec(open('ofd/version.py').read())

setup(
    name='ofd',
    version=__version__,
    author='Evgeny Safronov',
    author_email='esafronov@yandex-team.ru',
    maintainer='Yuri Fedoseev',
    maintainer_email='yfedoseev@yandex-team.ru',
    url='https://github.com/yandex/ofd',
    description='Yandex OFD',
    packages=[
        'ofd',
    ],
    platforms=["Linux", "BSD", "MacOS"],
    license='APACHE 2.0',
    install_requires=[
        'jsonschema',
        'crcmod'
    ],
    test_suite='tests',
    setup_requires=[
        'pytest-runner',
    ],
    tests_require=['pytest', 'pytest_asyncio', 'asynctest'],
    zip_safe=True,
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.5',
        # 'Development Status :: 1 - Planning',
        # 'Development Status :: 2 - Pre-Alpha',
        # 'Development Status :: 3 - Alpha',
        'Development Status :: 4 - Beta',
        # 'Development Status :: 5 - Production/Stable',
        # 'Development Status :: 6 - Mature',
        # 'Development Status :: 7 - Inactive',
    ],
)
