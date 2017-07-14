from .oms import CommonAnalysisOMS, plugin_version

__version__ = plugin_version

__all__ = [
    'CommonAnalysisOMS',
    '__version__'
]

analysis_class = CommonAnalysisOMS
