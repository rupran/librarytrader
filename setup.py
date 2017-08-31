from setuptools import setup, find_packages

setup(
    name = 'librarytrader',
    description = 'A library to analyze ELF imports and exports',
    author = 'Andreas Ziegler',
    author_email = 'andreas.ziegler@fau.de',
    url = 'https://github.com/rupran/librarytrader',
    version = '0.1',
    license = 'GPL-3.0',
    packages = find_packages(),
    zip_safe = False,
    install_requires = [
        'pyelftools'
    ]
)
