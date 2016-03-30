import os
import subprocess
from setuptools import setup, find_packages

setup(
    name="common_analysis_oms",
    version=subprocess.check_output(['git', 'describe', '--always'], cwd=os.path.dirname(os.path.abspath(__file__))).strip().decode('utf-8'),
    packages=find_packages(),
    data_files=[('common_analysis_oms/plugins', ['common_analysis_oms/plugins/ClamAV.json',
                                                 'common_analysis_oms/plugins/Sophos_en.json',
                                                 'common_analysis_oms/plugins/Avast.json',
                                                 'common_analysis_oms/plugins/AVG.json',
                                                 'common_analysis_oms/plugins/Bitdefender.json',
                                                 'common_analysis_oms/plugins/Comodo.json',
                                                 'common_analysis_oms/plugins/Eset.json',
                                                 'common_analysis_oms/plugins/F-Prot.json',
                                                 'common_analysis_oms/plugins/F-Secure.json',
                                                 'common_analysis_oms/plugins/McAfee.json'])],
    install_requires=[
        'common_analysis_base',
        'common_helper_files'
    ]
)
