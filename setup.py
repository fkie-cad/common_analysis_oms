import os
import subprocess
from setuptools import setup, find_packages

setup(
    name="common_analysis_oms",
    version=subprocess.check_output(['git', 'describe', '--always'], cwd=os.path.dirname(os.path.abspath(__file__))).strip().decode('utf-8'),
    packages=find_packages(),
    install_requires=[
        'common_analysis_base',
        'common_helper_files'
    ]
)
