from setuptools import setup, find_packages

setup(
  name='diglet',
  version='0.0.0',
  author='Tony O\'Dell',
  author_email='tony.odell+python@live.com',
  package_dir={'': 'src'},
  packages=find_packages(where='src'),
  url='https://github.com/tony-o/python-diglet',
  license='LICENSE',
  description='A pure python dns query tool',
  long_description=open('README.md').read(),
  long_description_content_type="text/markdown",
  setup_requires=['pytest-runner'],
  tests_require=['pytest>=3.3.2','typing==3.7.4.1'],
  install_requires=[],
);
