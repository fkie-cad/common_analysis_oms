from setuptools import setup, find_packages
from common_analysis_oms import __version__

setup(
    name="common_analysis_oms",
    version=__version__,
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
    ],
    dependency_links=[
        'git+https://github.com/mass-project/common_analysis_base.git#common_analysis_base'
    ],
    author="Fraunhofer FKIE",
    author_email="peter.weidenbach@fkie.fraunhofer.de",
    url="http://www.fkie.fraunhofer.de",
    description="Offline Malware Scanner (OMS) scans files with multiple locally installed malware scanners",
    license="GPL-3.0"
)
