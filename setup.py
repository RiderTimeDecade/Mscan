from setuptools import setup, find_packages

setup(
    name="mscan",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'requests>=2.26.0',
        'urllib3>=1.26.7',
        'paramiko>=2.7.2',
        'beautifulsoup4>=4.9.3',
        'chardet>=4.0.0',
        'colorama>=0.4.4',
        'tqdm>=4.62.3',
        'ipaddress>=1.0.23',
    ],
    entry_points={
        'console_scripts': [
            'mscan=mscan:main',
        ],
    },
    python_requires='>=3.7',
) 